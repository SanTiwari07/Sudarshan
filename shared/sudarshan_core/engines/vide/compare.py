"""Deterministic UI structural comparison (VIDE verdict source)."""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import List, Optional, Set

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, shortlist_baselines
from sudarshan_core.engines.vide.ui_profile import UIProfile, VIDECompareResult

RULE_ID = "VIDE-F001"
DETECTION_THRESHOLD = 0.72


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _tree_similarity(a: List[str], b: List[str]) -> float:
    if not a or not b:
        return 0.0
    sa = " ".join(a[:80])
    sb = " ".join(b[:80])
    return SequenceMatcher(None, sa, sb).ratio()


def _color_match(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / max(len(b), 1)


def compare_profiles(suspect: UIProfile, baseline: InstitutionBaseline) -> VIDECompareResult:
    base = baseline.profile
    str_a = {s.lower().strip() for s in suspect.strings if s.strip()}
    str_b = {s.lower().strip() for s in base.strings if s.strip()}
    sj = _jaccard(str_a, str_b)
    ts = _tree_similarity(suspect.view_sequence, base.view_sequence)
    cm = _color_match(set(suspect.colors), set(base.colors))
    confidence = 0.40 * sj + 0.35 * ts + 0.25 * cm
    matched = sorted(str_a & str_b)[:20]
    evidence = [
        f"VIDE string overlap Jaccard={sj:.2f} ({len(matched)} shared strings)",
        f"VIDE view-tree similarity={ts:.2f}",
        f"VIDE brand color overlap={cm:.2f}",
    ]
    if matched:
        evidence.append("Matched strings: " + ", ".join(matched[:8]))
    detected = confidence >= DETECTION_THRESHOLD and (sj >= 0.08 or ts >= 0.35)
    return VIDECompareResult(
        rule_id=RULE_ID,
        detected=detected,
        institution_id=baseline.institution_id if detected else "",
        institution_display=baseline.display_name if detected else "",
        confidence=confidence,
        string_jaccard=sj,
        tree_similarity=ts,
        color_match=cm,
        matched_strings=matched,
        evidence_lines=evidence,
    )


def compare_against_baselines(
    suspect: UIProfile,
    baselines: List[InstitutionBaseline],
) -> VIDECompareResult:
    if not suspect.strings and not suspect.view_sequence:
        return VIDECompareResult(
            rule_id=RULE_ID,
            evidence_lines=["VIDE: no extractable UI structure from suspect"],
        )
    candidates = shortlist_baselines(suspect, baselines)
    if not candidates:
        return VIDECompareResult(
            rule_id=RULE_ID,
            detected=False,
            evidence_lines=["VIDE: no baseline candidates (insufficient string overlap)"],
        )
    best: Optional[VIDECompareResult] = None
    for bl in candidates:
        result = compare_profiles(suspect, bl)
        if best is None or result.confidence > best.confidence:
            best = result
    return best or VIDECompareResult(rule_id=RULE_ID, evidence_lines=["VIDE: no baselines loaded"])
