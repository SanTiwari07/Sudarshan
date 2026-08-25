"""Deterministic comparison of a suspect UI against the banking corpus.

Two questions, deliberately kept apart:

1. **Shape** - is this a banking app UI at all? Answered by exact-string
   containment and structural signatures.
2. **Attribution** - *which* bank is it dressed as? Answered by the brand
   palette.

They are separated because in the baseline corpus all ten banks ship
identical screen strings ("User ID", "Login", "Enter 6-Digit MPIN", ...) and
identical structural signatures. Those axes therefore prove *banking-ness* but
carry no information about which institution. Only colour discriminates.

Ranking on the combined score alone would let an essentially arbitrary bank win
a 10-way tie and get named in a CERT-In report. So attribution is ranked on the
discriminating axis and reported with an explicit margin: when the runner-up is
close, the result is marked ambiguous and the candidates are listed rather than
one bank being asserted.

The confidence value itself keeps the mandated weighting:
``0.40 * strings + 0.35 * structure + 0.25 * colour``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from sudarshan_core.engines.vide.baseline_store import SOURCE_CORPUS, InstitutionBaseline
from sudarshan_core.engines.vide.color_match import (
    describe_color_match,
    palette_similarity,
)
from sudarshan_core.engines.vide.forensics import build_forensic_breakdown
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.engines.vide.view_ast import (
    ViewNode,
    infer_structural_signatures,
    signature_score,
)

RULE_ID = "VIDE-F001"

# Weighting mandated by the VIDE specification.
W_STRINGS = 0.40
W_STRUCTURE = 0.35
W_COLOR = 0.25

# Kept in step with :data:`compare.DETECTION_THRESHOLD` - the two comparers
# answer the same question and must not disagree about when it is answered yes.
DETECTION_THRESHOLD = 0.20
# Minimum evidence that this is a banking UI at all, independent of which bank.
#
# This is the gate that keeps a calculator app out of the report, and it does
# more work now that the confidence threshold is 0.20. It is set at 0.15 rather
# than lower because shape is the one axis a non-banking app genuinely cannot
# fake: it needs the login/MPIN vocabulary or the auth-form structural
# signature to score here at all.
MIN_SHAPE_EVIDENCE = 0.15
# Lead the top bank needs over the runner-up to be named outright, as a
# fraction of its own attribution score.
#
# Relative, not absolute, because the score's scale depends on which axes the
# corpus actually discriminates on: when only colour separates the banks the
# spread is wide, and when distinctive labels also separate them the combined
# score compresses. An absolute threshold silently changes meaning between
# those two regimes; a relative one asks the same question in both - "is this
# bank's lead over the next a real one?"
#
# 0.05 rather than 0.20. The wide margin was calibrated against a corpus whose
# per-bank fingerprints had not yet been regenerated from the shipped APKs, so
# the banks separated only on colour and the runner-up was routinely within 20%
# of the leader. With distinctive per-bank labels present the leader's lead is
# real but numerically small, and a 20% margin was discarding correct
# attributions - naming no bank at all - far more often than it was preventing
# a wrong one. The ambiguity path below is retained and still fires on a true
# tie.
ATTRIBUTION_MARGIN = 0.05

_NORMALISE = re.compile(r"[^a-z0-9]+")


def _norm(value: str) -> str:
    return _NORMALISE.sub(" ", value.lower()).strip()


@dataclass
class CorpusMatch:
    """One suspect-vs-baseline comparison."""

    institution_id: str
    display_name: str
    bank: str
    confidence: float = 0.0
    string_containment: float = 0.0
    structural_score: float = 0.0
    color_score: float = 0.0
    matched_strings: List[str] = field(default_factory=list)
    matched_signatures: List[str] = field(default_factory=list)
    color_matches: List[Dict[str, Any]] = field(default_factory=list)
    # Denominators, so a reader of the breakdown can see "3 of 4 brand colours"
    # rather than a bare score whose scale is invisible.
    baseline_string_count: int = 0
    color_target_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "institution_id": self.institution_id,
            "display_name": self.display_name,
            "bank": self.bank,
            "confidence": round(self.confidence, 4),
            "scores": {
                "string_containment": round(self.string_containment, 4),
                "structural": round(self.structural_score, 4),
                "color": round(self.color_score, 4),
            },
            "matched_strings": self.matched_strings[:20],
            "matched_signatures": self.matched_signatures,
            "color_matches": self.color_matches[:8],
        }


@dataclass
class CorpusVerdict:
    """Ranked corpus comparison with an explicit attribution claim."""

    detected: bool = False
    rule_id: str = RULE_ID
    best: Optional[CorpusMatch] = None
    ranked: List[CorpusMatch] = field(default_factory=list)
    banking_shape_score: float = 0.0
    attribution_margin: float = 0.0
    attribution_ambiguous: bool = False
    candidates: List[str] = field(default_factory=list)
    suspect_signatures: List[str] = field(default_factory=list)
    evidence_lines: List[str] = field(default_factory=list)
    forensics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "detected": self.detected,
            "capability": "visual_impersonation" if self.detected else "",
            "institution_id": self.best.institution_id if (self.best and self.detected) else "",
            "institution_display": self.best.display_name if (self.best and self.detected) else "",
            "bank": self.best.bank if (self.best and self.detected) else "",
            "confidence": round(self.best.confidence, 4) if self.best else 0.0,
            "banking_shape_score": round(self.banking_shape_score, 4),
            "attribution": {
                "margin": round(self.attribution_margin, 4),
                "ambiguous": self.attribution_ambiguous,
                "candidates": self.candidates,
            },
            "suspect_signatures": self.suspect_signatures,
            "scores": self.best.to_dict()["scores"] if self.best else {
                "string_containment": 0.0,
                "structural": 0.0,
                "color": 0.0,
            },
            "matched_strings": self.best.matched_strings[:20] if self.best else [],
            "color_matches": self.best.color_matches[:8] if self.best else [],
            "ranked": [m.to_dict() for m in self.ranked[:5]],
            "evidence_lines": self.evidence_lines,
            "forensics": self.forensics,
        }


def _string_containment(
    suspect_strings: Sequence[str],
    baseline_strings: Sequence[str],
) -> tuple[float, List[str]]:
    """
    Fraction of the bank's distinctive labels the suspect reproduces.

    Containment, not Jaccard: the question is "how much of this bank's UI text
    does the suspect carry", and a suspect with a large string table should not
    be rewarded for diluting the denominator.
    """
    targets = [s for s in baseline_strings if s.strip()]
    if not targets:
        return 0.0, []
    haystack = {_norm(s) for s in suspect_strings if s.strip()}
    if not haystack:
        return 0.0, []
    # Also allow substring hits: a label may be concatenated in a bundle.
    blob = " | ".join(haystack)

    matched: List[str] = []
    for target in targets:
        needle = _norm(target)
        if not needle:
            continue
        if needle in haystack or needle in blob:
            matched.append(target)
    return len(matched) / len(targets), matched


def compare_one(
    suspect: UIProfile,
    suspect_ast: Optional[ViewNode],
    suspect_signatures: Sequence[str],
    baseline: InstitutionBaseline,
) -> CorpusMatch:
    """Score a suspect profile against a single corpus baseline."""
    containment, matched = _string_containment(suspect.strings, baseline.profile.strings)

    baseline_signatures = [s.structural_signature for s in baseline.screens]
    structural = signature_score(suspect_signatures, baseline_signatures)

    palette: List[str] = []
    if baseline.design:
        palette.extend(baseline.design.brand_palette)
    for screen in baseline.screens:
        palette.extend(screen.brand_tokens.values())
    palette = list(dict.fromkeys(palette))

    color_result = palette_similarity(suspect.colors, palette)
    color_score = float(color_result["score"])  # type: ignore[arg-type]

    confidence = (
        W_STRINGS * containment
        + W_STRUCTURE * structural
        + W_COLOR * color_score
    )

    return CorpusMatch(
        institution_id=baseline.institution_id,
        display_name=baseline.display_name,
        bank=baseline.bank,
        confidence=confidence,
        string_containment=containment,
        structural_score=structural,
        color_score=color_score,
        matched_strings=matched,
        matched_signatures=sorted(
            set(suspect_signatures) & {s for s in baseline_signatures if s}
        ),
        color_matches=list(color_result["matches"]),  # type: ignore[arg-type]
        baseline_string_count=len([s for s in baseline.profile.strings if s.strip()]),
        color_target_count=int(color_result["target_count"]),  # type: ignore[arg-type]
    )


def _attribution_score(match: Optional[CorpusMatch]) -> float:
    """
    Evidence that separates one bank from another, renormalised to [0, 1].

    Only the discriminating axes: which bank an app impersonates is decided by
    its distinctive labels and its brand palette, not by having a login form.
    """
    if match is None:
        return 0.0
    return (
        W_STRINGS * match.string_containment + W_COLOR * match.color_score
    ) / (W_STRINGS + W_COLOR)


def compare_against_corpus(
    suspect: UIProfile,
    baselines: Sequence[InstitutionBaseline],
    suspect_ast: Optional[ViewNode] = None,
) -> CorpusVerdict:
    """Rank a suspect UI against the corpus and decide what may be claimed."""
    corpus = [b for b in baselines if b.source == SOURCE_CORPUS and b.screens]
    if not corpus:
        return CorpusVerdict(evidence_lines=["VIDE: no corpus baselines loaded"])

    if not suspect.strings and suspect_ast is None:
        return CorpusVerdict(
            evidence_lines=["VIDE: no extractable UI structure from suspect"]
        )

    signatures = infer_structural_signatures(suspect_ast, suspect.strings)

    matches = [compare_one(suspect, suspect_ast, signatures, b) for b in corpus]
    if not matches:
        return CorpusVerdict(evidence_lines=["VIDE: corpus comparison produced no result"])

    # Shape is bank-independent, so take the strongest evidence available.
    shape = max(
        W_STRINGS * m.string_containment + W_STRUCTURE * m.structural_score
        for m in matches
    ) / (W_STRINGS + W_STRUCTURE)

    # Attribution ranks on the axes that actually separate the banks. Structure
    # is deliberately excluded: every corpus bank exposes the same three screen
    # archetypes, so it contributes an identical constant to all candidates and
    # would only shrink the margin between them.
    #
    # Which axes discriminate depends on the corpus, so this is not hardcoded to
    # colour. Screen labels are per-bank once the fingerprints are generated from
    # the shipped APKs, but degrade to near-identical if they are authored from a
    # shared design template - in which case colour carries the decision and the
    # margin check below catches the difference either way.
    ranked = sorted(
        matches,
        key=lambda m: (round(_attribution_score(m), 6), m.institution_id),
        reverse=True,
    )
    best = ranked[0]
    best_attr = _attribution_score(best)
    runner_up = ranked[1] if len(ranked) > 1 else None

    if best_attr <= 0.0:
        margin = 0.0
    elif runner_up is None:
        margin = 1.0
    else:
        margin = (best_attr - _attribution_score(runner_up)) / best_attr

    ambiguous = best_attr <= 0.0 or margin < ATTRIBUTION_MARGIN
    candidates = (
        [
            m.institution_id
            for m in ranked
            if best_attr > 0
            and (best_attr - _attribution_score(m)) / best_attr < ATTRIBUTION_MARGIN
        ]
        if ambiguous
        else [best.institution_id]
    )

    detected = (
        shape >= MIN_SHAPE_EVIDENCE
        and best.confidence >= DETECTION_THRESHOLD
        and not ambiguous
    )

    # Ordered as an analyst reads a clone report: what it is, which bank, and
    # then the three axes that say why - colour first, because it is the axis
    # that actually carries the attribution.
    evidence: List[str] = [
        f"Banking-UI shape score {shape:.2f} "
        f"({len(best.matched_strings)} baseline strings reproduced) - "
        f"this is a banking interface",
        f"Attributed to {best.display_name} at {best.confidence:.2f} confidence "
        f"(threshold {DETECTION_THRESHOLD:.2f}, attribution margin "
        f"{margin:.2f} over the runner-up)",
        f"Brand colour scheme: {best.color_score:.2f} palette match "
        f"({len(best.color_matches)}/{best.color_target_count} "
        f"{best.display_name} brand colours reproduced, CIE ΔE2000)",
        f"UI text: {best.string_containment:.2f} "
        f"({len(best.matched_strings)}/{best.baseline_string_count} "
        f"baseline labels reproduced)",
        f"View hierarchy: {best.structural_score:.2f} structural similarity; "
        f"signatures matched: {', '.join(best.matched_signatures) or 'none'}",
    ]
    for match in best.color_matches[:4]:
        evidence.append(describe_color_match(match))
    if best.matched_strings:
        evidence.append("Matched UI text: " + ", ".join(best.matched_strings[:8]))
    if ambiguous and shape >= MIN_SHAPE_EVIDENCE:
        evidence.append(
            "VIDE attribution ambiguous: distinctive screen labels and brand "
            "palette did not separate one institution from the others "
            f"(margin {margin:.2f}). Candidates: {', '.join(candidates) or 'none'}"
        )

    return CorpusVerdict(
        detected=detected,
        best=best,
        ranked=ranked,
        banking_shape_score=shape,
        attribution_margin=margin,
        attribution_ambiguous=ambiguous,
        candidates=candidates,
        suspect_signatures=signatures,
        evidence_lines=evidence,
        forensics=build_forensic_breakdown(
            confidence=best.confidence,
            threshold=DETECTION_THRESHOLD,
            institution_id=best.institution_id,
            institution_display=best.display_name,
            string_score=best.string_containment,
            matched_strings=best.matched_strings,
            baseline_string_count=best.baseline_string_count,
            structure_score=best.structural_score,
            matched_signatures=best.matched_signatures,
            suspect_signatures=signatures,
            color_score=best.color_score,
            color_matches=best.color_matches,
            color_target_count=best.color_target_count,
        ),
    )
