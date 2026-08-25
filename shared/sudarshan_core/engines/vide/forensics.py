"""Machine-readable "why is this a clone" breakdown for a VIDE verdict.

The evidence lines the comparers emit are written for a human reading a
CERT-In annexure. The investigation UI and the PDF generator need the same
facts as data - a hex pair to draw two swatches from, a ΔE to print next to
them, the list of banking labels that matched - and neither should be parsing
those sentences back apart to get them.

So the axes are assembled once, here, in the shape both consumers read:

* ``color_scheme``    - suspect hex vs baseline hex with CIE ΔE₂₀₀₀ per pair,
* ``ui_text``         - the banking tokens and labels that matched, and
* ``view_hierarchy``  - structural signatures and layout similarity.

The tier bands exist for the same reason the breakdown does. With detection at
0.20 a verdict spans a wide range of strengths, and "82% similarity" and "23%
similarity" are both findings but are not the same finding; collapsing them
into one red banner would misreport the weaker one.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from sudarshan_core.engines.vide.color_match import describe_delta_e

#: Lower bound of each confidence tier, strongest first.
TIER_HIGH = 0.60
TIER_MODERATE = 0.35
TIER_LOW = 0.20


def confidence_tier(confidence: float) -> str:
    """``high`` / ``moderate`` / ``low`` / ``none`` for a confidence score."""
    if confidence >= TIER_HIGH:
        return "high"
    if confidence >= TIER_MODERATE:
        return "moderate"
    if confidence >= TIER_LOW:
        return "low"
    return "none"


def tier_label(tier: str) -> str:
    """Analyst-facing wording for a tier."""
    return {
        "high": "High similarity",
        "moderate": "Moderate similarity",
        "low": "Low / suspicious impersonation",
    }.get(tier, "Below detection threshold")


def normalise_color_matches(
    matches: Sequence[Dict[str, Any]],
) -> list[Dict[str, Any]]:
    """
    Palette matches in the shape a swatch renderer wants.

    ``palette_similarity`` already carries the numbers; this uppercases the hex
    (so ``#eb6e1f`` and ``#EB6E1F`` do not render as two different colours in a
    report) and guarantees ``delta_e`` and ``verdict`` are present even for
    match records produced before those keys existed.
    """
    out: list[Dict[str, Any]] = []
    for match in matches:
        baseline = str(match.get("baseline") or "").upper()
        suspect = str(match.get("suspect") or "").upper()
        if not baseline or not suspect:
            continue
        distance = float(match.get("delta_e", match.get("distance", 0.0)) or 0.0)
        out.append(
            {
                "baseline_hex": baseline,
                "suspect_hex": suspect,
                "delta_e": round(distance, 2),
                "score": round(float(match.get("score") or 0.0), 4),
                "verdict": str(match.get("verdict") or describe_delta_e(distance)),
                "exact": baseline == suspect,
            }
        )
    return out


def build_forensic_breakdown(
    *,
    confidence: float,
    threshold: float,
    institution_id: str = "",
    institution_display: str = "",
    string_score: float = 0.0,
    matched_strings: Optional[Sequence[str]] = None,
    baseline_string_count: int = 0,
    reworded_labels: Optional[Sequence[Dict[str, Any]]] = None,
    structure_score: float = 0.0,
    matched_signatures: Optional[Sequence[str]] = None,
    suspect_signatures: Optional[Sequence[str]] = None,
    color_score: float = 0.0,
    color_matches: Optional[Sequence[Dict[str, Any]]] = None,
    color_target_count: int = 0,
) -> Dict[str, Any]:
    """Assemble the three-axis breakdown for one suspect-vs-baseline verdict."""
    matched = list(matched_strings or [])
    swatches = normalise_color_matches(color_matches or [])
    tier = confidence_tier(confidence)

    return {
        "threshold": round(threshold, 4),
        "confidence": round(confidence, 4),
        "tier": tier,
        "tier_label": tier_label(tier),
        "over_threshold": confidence >= threshold,
        "institution_id": institution_id,
        "institution_display": institution_display,
        "color_scheme": {
            "score": round(color_score, 4),
            "matched_count": len(swatches),
            "target_count": color_target_count or len(swatches),
            "exact_matches": sum(1 for s in swatches if s["exact"]),
            "matches": swatches[:12],
        },
        "ui_text": {
            "score": round(string_score, 4),
            "matched_count": len(matched),
            "target_count": baseline_string_count,
            "matched_strings": matched[:24],
            "reworded": [
                {
                    "baseline": str(d.get("baseline", "")),
                    "suspect": str(d.get("suspect", "")),
                    "ratio": float(d.get("ratio") or 0.0),
                }
                for d in (reworded_labels or [])
                if str(d.get("baseline", "")).lower() != str(d.get("suspect", "")).lower()
            ][:8],
        },
        "view_hierarchy": {
            "score": round(structure_score, 4),
            "matched_signatures": list(matched_signatures or []),
            "suspect_signatures": list(suspect_signatures or [])[:12],
        },
    }
