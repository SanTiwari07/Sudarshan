"""Deterministic comparison of a suspect UI against the banking corpus.

Two questions, deliberately kept apart:

1. **Shape** - is this a banking app UI at all? Answered by the vocabulary and
   the structural archetypes every banking app shares.
2. **Attribution** - *which* bank is it dressed as? Answered only by evidence
   that separates one corpus baseline from the other nine.

The separation is forced by how the corpus is built. ``APP_CORPUS_SCHEMA``
mandates a shared component vocabulary, shared token names and a shared
structural-signature vocabulary across all ten baselines, and the shipped
``fingerprints.json`` files take that to its conclusion: identical screen
strings, identical structural signatures, and brand palettes that collide
across banks at ΔE₂₀₀₀ ≈ 0. Every axis a naive comparer would score is
therefore either constant across the corpus or actively misleading.

Multi-tier matching
-------------------
Each tier answers a question the tier above it cannot, and only the attribution
tiers may name a bank:

===  ==================  ====================================================
0    Shape gate          Is this a banking UI? Bank-independent, so it gates
                         but never attributes.
1    Identity            Does the suspect carry the bank's *name*? Names are
                         exclusive by construction, so this is the strongest
                         attribution evidence available.
2    Discriminative      Labels this bank ships and its peers do not, weighted
     labels              by corpus rarity. Zero for the shipped corpus, whose
                         label sets are identical - and non-zero the moment a
                         regenerated corpus carries per-bank text.
3    Discriminative      Brand palette, each colour weighted by how few banks
     palette             share it. A shared orange contributes ≈ 0 to all of
                         its owners rather than arbitrarily winning one.
===  ==================  ====================================================

The weights come from :mod:`discriminative`, computed over the loaded corpus.
Nothing here names a bank, a colour or a "generic" label, so registering an
eleventh baseline re-weights the engine without a code change.

Decision
--------
Naming an institution in a CERT-In report needs all four of:

* the shape gate cleared - it is a banking UI;
* confidence over :data:`DETECTION_THRESHOLD`;
* a real margin over the runner-up on the *attribution* score; and
* at least one **exclusive** piece of evidence - a feature no other baseline
  carries. This is the corroboration requirement, and it is what the previous
  margin-only design lacked: ten banks scoring alike leaves a margin decided by
  a rounding error, and a lead computed over indistinguishable candidates is
  not evidence of anything.

Falling short of the last two is not a non-detection. The verdict is marked
ambiguous and carries the candidate set, which :mod:`pipeline` reports as an
unattributed impersonation finding.

The confidence value keeps the weighting the VIDE specification mandates,
``0.40 * strings + 0.35 * structure + 0.25 * colour``, because the threshold,
the PDF meter and the risk engine are all calibrated against that scale. It
measures *how completely* the suspect reproduces a baseline; the attribution
score measures *which* baseline, and they are not the same question.
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
from sudarshan_core.engines.vide.discriminative import (
    CorpusDiscriminators,
    IdentityPhrase,
    discriminators_for,
    identity_coverage,
    weighted_label_containment,
    weighted_palette_match,
)
from sudarshan_core.engines.vide.forensics import build_forensic_breakdown
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.engines.vide.view_ast import (
    ViewNode,
    infer_structural_signatures,
    signature_score,
)

RULE_ID = "VIDE-F001"

# Weighting mandated by the VIDE specification, applied to the confidence value.
W_STRINGS = 0.40
W_STRUCTURE = 0.35
W_COLOR = 0.25

# Weighting across the three attribution tiers. Identity dominates because a
# name is exclusive by construction while a colour is shared by up to nine other
# banks in this corpus; labels sit between the two because a regenerated corpus
# can make them near-exclusive, and this ordering then still holds.
W_IDENTITY = 0.50
W_LABELS = 0.30
W_PALETTE = 0.20

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
# Relative, not absolute, because the score's scale depends on how much
# discriminating evidence the suspect actually carries: a clone reproducing a
# bank's name and palette scores an order of magnitude above one reproducing a
# single shared colour, and an absolute threshold would mean something
# different in each case.
#
# 0.15 is meaningful again only because the attribution score no longer carries
# the corpus's shared axes. Under the previous design every candidate received
# an identical ``0.40 * 1.0`` from the shared template strings, which compressed
# every margin toward zero and forced the threshold down to 0.05 - low enough
# that BOI, ICICI and Union Bank separated by less than 0.01 on the reference
# APKs and the leader was decided by palette collisions at ΔE 0.0. Removing the
# constant restores the spread, so the guard can guard again.
ATTRIBUTION_MARGIN = 0.15

_NORMALISE = re.compile(r"[^a-z0-9]+")


def _norm(value: str) -> str:
    return _NORMALISE.sub(" ", value.lower()).strip()


@dataclass
class AttributionEvidence:
    """Why one baseline was preferred over the other nine."""

    identity_score: float = 0.0
    label_score: float = 0.0
    palette_score: float = 0.0
    identity_matches: List[str] = field(default_factory=list)
    discriminative_labels: List[str] = field(default_factory=list)
    discriminative_colors: List[Dict[str, Any]] = field(default_factory=list)
    #: Features carried by this baseline and no other. Attribution requires at
    #: least one, so this is the corroboration record.
    exclusive_hits: List[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return (
            W_IDENTITY * self.identity_score
            + W_LABELS * self.label_score
            + W_PALETTE * self.palette_score
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "tiers": {
                "identity": round(self.identity_score, 4),
                "discriminative_labels": round(self.label_score, 4),
                "discriminative_palette": round(self.palette_score, 4),
            },
            "identity_matches": self.identity_matches,
            "discriminative_labels": self.discriminative_labels[:20],
            "discriminative_colors": self.discriminative_colors[:8],
            "exclusive_hits": self.exclusive_hits[:12],
        }


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
    attribution: AttributionEvidence = field(default_factory=AttributionEvidence)

    @property
    def attribution_score(self) -> float:
        return self.attribution.score

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
            "attribution": self.attribution.to_dict(),
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
    #: Why attribution was withheld, when it was: ``margin`` (candidates too
    #: close) or ``no_exclusive_evidence`` (nothing the corpus can tell apart).
    #: Empty when a bank was named.
    ambiguity_reason: str = ""
    candidates: List[str] = field(default_factory=list)
    suspect_signatures: List[str] = field(default_factory=list)
    evidence_lines: List[str] = field(default_factory=list)
    #: Corroboration and caveats the registration pipeline mandates on every
    #: attribution claim.
    conflicting_evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
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
                "reason": self.ambiguity_reason,
                "candidates": self.candidates,
                "evidence": self.best.attribution.to_dict() if self.best else {},
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
            "conflicting_evidence": self.conflicting_evidence,
            "limitations": self.limitations,
            "forensics": self.forensics,
        }


def _string_containment(
    suspect_strings: Sequence[str],
    baseline_strings: Sequence[str],
) -> tuple[float, List[str]]:
    """
    Fraction of the bank's labels the suspect reproduces.

    Containment, not Jaccard: the question is "how much of this bank's UI text
    does the suspect carry", and a suspect with a large string table should not
    be rewarded for diluting the denominator.

    Unweighted on purpose - this feeds the *confidence* value, which measures
    completeness of the copy. Attribution uses the weighted form in
    :func:`discriminative.weighted_label_containment` instead.
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


def _attribution_evidence(
    suspect: UIProfile,
    baseline: InstitutionBaseline,
    discriminators: CorpusDiscriminators,
    identity_hits: Sequence[IdentityPhrase],
) -> AttributionEvidence:
    """Score the three attribution tiers for one baseline."""
    entry = discriminators.for_institution(baseline.institution_id)

    identity = identity_coverage(identity_hits, entry)
    labels, matched_labels = weighted_label_containment(
        suspect.strings, entry.label_weights, entry.label_display
    )
    palette, color_matches = weighted_palette_match(
        suspect.colors, entry.color_weights
    )

    # Corroboration: features this baseline holds alone. A shared orange or a
    # template label can support an attribution but must never carry one.
    exclusive: List[str] = []
    exclusive.extend(f"name:{p.display}" for p in identity_hits if p.weight >= 1.0)
    exclusive_labels = set(entry.exclusive_labels())
    exclusive.extend(
        f"label:{label}"
        for label in matched_labels
        if _norm(label) in exclusive_labels or label in exclusive_labels
    )
    # A colour corroborates only if the suspect actually *reproduces* it. A
    # partial match on an exclusive colour is not exclusive evidence: measured
    # on the corpus, a suspect wearing a single maroon ΔE 6 from Axis's brand
    # colour cleared this check and was named an Axis clone on nothing else.
    # Score 1.0 means within :data:`ATTRIBUTION_IDENTICAL_DELTA_E`.
    exclusive.extend(
        f"colour:{match['baseline']}"
        for match in color_matches
        if float(match.get("attribution_weight", 0.0)) >= 1.0
        and float(match.get("score", 0.0)) >= 1.0
    )

    return AttributionEvidence(
        identity_score=identity,
        label_score=labels,
        palette_score=palette,
        identity_matches=[p.display for p in identity_hits],
        discriminative_labels=matched_labels,
        discriminative_colors=color_matches,
        exclusive_hits=exclusive,
    )


def compare_one(
    suspect: UIProfile,
    suspect_ast: Optional[ViewNode],
    suspect_signatures: Sequence[str],
    baseline: InstitutionBaseline,
    discriminators: Optional[CorpusDiscriminators] = None,
    identity_hits: Optional[Sequence[IdentityPhrase]] = None,
) -> CorpusMatch:
    """
    Score a suspect profile against a single corpus baseline.

    ``discriminators`` is optional so a caller comparing against one baseline in
    isolation still works; without a corpus to weigh features against there is
    no attribution evidence, and the match carries confidence only.
    """
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

    attribution = (
        _attribution_evidence(
            suspect, baseline, discriminators, list(identity_hits or [])
        )
        if discriminators is not None
        else AttributionEvidence()
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
        attribution=attribution,
    )


def _attribution_score(match: Optional[CorpusMatch]) -> float:
    """Evidence that separates this bank from the other nine, in [0, 1]."""
    if match is None:
        return 0.0
    return match.attribution_score


def _conflicting_evidence(
    best: CorpusMatch,
    runner_up: Optional[CorpusMatch],
    discriminators: CorpusDiscriminators,
) -> List[str]:
    """
    What argues against the attribution, as the registration pipeline requires.

    A similarity report that lists only supporting evidence is the failure mode
    the corpus documentation calls out by name, so the contradicting facts are
    assembled here rather than left to the reader to notice.
    """
    lines: List[str] = []
    entry = discriminators.for_institution(best.institution_id)

    if not best.attribution.identity_matches:
        lines.append(
            f"Suspect carries no {best.display_name} name or identifier; "
            f"attribution rests on palette and label evidence alone"
        )
    if not entry.label_weights:
        lines.append(
            f"{best.display_name}'s baseline labels are shared by every corpus "
            f"bank, so UI text contributed nothing to this attribution"
        )
    shared_colors = [
        str(match["baseline"])
        for match in best.attribution.discriminative_colors
        if float(match.get("attribution_weight", 0.0)) < 1.0
    ]
    if shared_colors:
        lines.append(
            "Brand colours matched but shared with other corpus banks: "
            + ", ".join(sorted(set(shared_colors))[:5])
        )
    if runner_up is not None:
        lines.append(
            f"Runner-up {runner_up.display_name} scored "
            f"{_attribution_score(runner_up):.2f} against "
            f"{_attribution_score(best):.2f} on the same evidence"
        )
    return lines


def _limitations(
    best: CorpusMatch,
    discriminators: CorpusDiscriminators,
) -> List[str]:
    """Caveats every corpus attribution carries."""
    lines = [
        "Baseline is a research prototype with approximated brand colours, not "
        "the genuine application; a colour match is a resemblance claim, not an "
        "identity proof",
        "Generic banking-UI resemblance is expected between unrelated apps and "
        "does not by itself establish impersonation - corroborate with static "
        "indicators, runtime behaviour and signing identity",
    ]
    degenerate = discriminators.degenerate_institutions()
    if degenerate:
        lines.append(
            "Corpus baselines with no distinguishing features, which can never "
            "be attributed to: " + ", ".join(degenerate)
        )
    if best.structural_score > 0 and not discriminators.for_institution(
        best.institution_id
    ).signature_weights:
        lines.append(
            "All corpus baselines declare the same structural signatures, so "
            "the structural match supports banking shape only, not attribution"
        )
    return lines


def compare_against_corpus(
    suspect: UIProfile,
    baselines: Sequence[InstitutionBaseline],
    suspect_ast: Optional[ViewNode] = None,
) -> CorpusVerdict:
    """Rank a suspect UI against the corpus and decide what may be claimed."""
    corpus = [b for b in baselines if b.source == SOURCE_CORPUS and b.screens]
    if not corpus:
        return CorpusVerdict(evidence_lines=["VIDE: no corpus baselines loaded"])

    # Colours alone are a usable profile. A Capacitor clone keeps its labels in
    # a minified bundle that static extraction often cannot read, and requiring
    # text here dropped exactly those samples before the palette tier ever ran.
    if not suspect.strings and suspect_ast is None and not suspect.colors:
        return CorpusVerdict(
            evidence_lines=["VIDE: no extractable UI structure from suspect"]
        )

    signatures = infer_structural_signatures(suspect_ast, suspect.strings)

    discriminators = discriminators_for(corpus)
    identity_hits = discriminators.identity_hits(suspect.strings)

    matches = [
        compare_one(
            suspect,
            suspect_ast,
            signatures,
            baseline,
            discriminators,
            identity_hits.get(baseline.institution_id, []),
        )
        for baseline in corpus
    ]
    if not matches:
        return CorpusVerdict(evidence_lines=["VIDE: corpus comparison produced no result"])

    # ── Tier 0: shape ──────────────────────────────────────────────────────
    # Bank-independent, so take the strongest evidence available anywhere in
    # the corpus. This gates detection and never selects a bank.
    shape = max(
        W_STRINGS * m.string_containment + W_STRUCTURE * m.structural_score
        for m in matches
    ) / (W_STRINGS + W_STRUCTURE)

    # ── Tiers 1-3: attribution ─────────────────────────────────────────────
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

    # ── Decision ───────────────────────────────────────────────────────────
    # Two independent conditions. The margin asks whether this bank leads; the
    # corroboration requirement asks whether the lead rests on anything only
    # this bank has. A ten-way tie on shared features can satisfy neither.
    has_exclusive = bool(best.attribution.exclusive_hits)
    if best_attr <= 0.0 or not has_exclusive:
        ambiguous, reason = True, "no_exclusive_evidence"
    elif margin < ATTRIBUTION_MARGIN:
        ambiguous, reason = True, "margin"
    else:
        ambiguous, reason = False, ""

    if not ambiguous:
        candidates = [best.institution_id]
    elif best_attr <= 0.0:
        # Nothing separated anything; every scored bank is equally a candidate.
        candidates = [m.institution_id for m in ranked]
    else:
        candidates = [
            m.institution_id
            for m in ranked
            if (best_attr - _attribution_score(m)) / best_attr < ATTRIBUTION_MARGIN
        ]

    detected = (
        shape >= MIN_SHAPE_EVIDENCE
        and best.confidence >= DETECTION_THRESHOLD
        and not ambiguous
    )

    # Ordered as an analyst reads a clone report: what it is, which bank, and
    # then the tiers that say why - identity first, because a name is the only
    # axis that is exclusive by construction.
    evidence: List[str] = [
        f"Banking-UI shape score {shape:.2f} "
        f"({len(best.matched_strings)} baseline strings reproduced) - "
        f"this is a banking interface",
        f"Attributed to {best.display_name} at {best.confidence:.2f} confidence "
        f"(threshold {DETECTION_THRESHOLD:.2f}, attribution score "
        f"{best_attr:.2f}, margin {margin:.2f} over the runner-up)",
    ]
    if best.attribution.identity_matches:
        evidence.append(
            "Institution named in the UI: "
            + ", ".join(best.attribution.identity_matches[:4])
        )
    if best.attribution.label_score > 0:
        evidence.append(
            f"Distinctive labels: {best.attribution.label_score:.2f} of "
            f"{best.display_name}'s discriminating text reproduced"
            + (
                " - " + ", ".join(best.attribution.discriminative_labels[:6])
                if best.attribution.discriminative_labels
                else ""
            )
        )
    evidence.append(
        f"Brand palette: {best.attribution.palette_score:.2f} weighted by "
        f"corpus rarity ({best.color_score:.2f} raw, "
        f"{len(best.color_matches)}/{best.color_target_count} "
        f"{best.display_name} brand colours reproduced, CIE ΔE2000)"
    )
    evidence.append(
        f"UI text: {best.string_containment:.2f} "
        f"({len(best.matched_strings)}/{best.baseline_string_count} "
        f"baseline labels reproduced)"
    )
    evidence.append(
        f"View hierarchy: {best.structural_score:.2f} structural similarity; "
        f"signatures matched: {', '.join(best.matched_signatures) or 'none'}"
    )
    if best.attribution.exclusive_hits:
        evidence.append(
            "Evidence unique to this institution: "
            + ", ".join(best.attribution.exclusive_hits[:6])
        )
    for match in best.color_matches[:4]:
        evidence.append(describe_color_match(match))
    if best.matched_strings:
        evidence.append("Matched UI text: " + ", ".join(best.matched_strings[:8]))
    if ambiguous and shape >= MIN_SHAPE_EVIDENCE:
        if reason == "no_exclusive_evidence":
            evidence.append(
                "VIDE attribution ambiguous: the suspect reproduces no feature "
                "that belongs to one corpus bank alone - every match is on "
                "text, structure or colour that several banks share. "
                f"Candidates: {', '.join(candidates[:6]) or 'none'}"
            )
        else:
            evidence.append(
                "VIDE attribution ambiguous: the leading institution's evidence "
                "did not separate it from the runner-up "
                f"(margin {margin:.2f} < {ATTRIBUTION_MARGIN:.2f}). "
                f"Candidates: {', '.join(candidates[:6]) or 'none'}"
            )

    return CorpusVerdict(
        detected=detected,
        best=best,
        ranked=ranked,
        banking_shape_score=shape,
        attribution_margin=margin,
        attribution_ambiguous=ambiguous,
        ambiguity_reason=reason,
        candidates=candidates,
        suspect_signatures=signatures,
        evidence_lines=evidence,
        conflicting_evidence=_conflicting_evidence(best, runner_up, discriminators),
        limitations=_limitations(best, discriminators),
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
