"""Perceptual brand-colour matching for VIDE.

Across the ``apk_details`` corpus every bank ships the same login/MPIN/dashboard
strings and the same structural signatures, so the *brand palette* is what
actually distinguishes "clone of HDFC" from "clone of Axis". That makes colour
comparison an attribution primitive, not a tie-breaker.

Exact hex equality is the wrong test: a clone re-drawn in Figma or re-encoded
through a screenshot lands a few units off the official value while looking
identical to a victim. Matching therefore uses the "redmean" approximation of
perceptual distance, which is cheap and tracks human colour judgement far
better than raw RGB Euclidean distance.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_HEX_RE = re.compile(r"^#?([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$")

# Distance below which two colours read as "the same brand colour", and the
# distance at which the match score decays to zero. Scale is the redmean
# metric's own (0 .. ~765).
#
# These are deliberately tight. A looser curve scored a distance of ~31 at 0.94,
# which let a bank whose whole palette was vaguely close outrank one the suspect
# had reproduced exactly - two different reds are not the same brand.
IDENTICAL_DISTANCE = 12.0
MAX_MATCH_DISTANCE = 70.0

# Greys, black and white carry no brand identity - every banking app uses them.
_ACHROMATIC_SATURATION = 0.12


def parse_hex(value: str) -> Optional[Tuple[int, int, int]]:
    """``#1B4AA0`` / ``1b4aa0`` / ``#abc`` / ``#RRGGBBAA`` -> (r, g, b)."""
    if not value:
        return None
    match = _HEX_RE.match(value.strip())
    if not match:
        return None
    digits = match.group(1)
    if len(digits) == 3:
        digits = "".join(c * 2 for c in digits)
    elif len(digits) == 8:
        digits = digits[:6]  # drop alpha
    return (
        int(digits[0:2], 16),
        int(digits[2:4], 16),
        int(digits[4:6], 16),
    )


def color_distance(a: str, b: str) -> float:
    """Perceptual distance between two hex colours (redmean approximation)."""
    rgb_a = parse_hex(a)
    rgb_b = parse_hex(b)
    if rgb_a is None or rgb_b is None:
        return float("inf")
    r1, g1, b1 = rgb_a
    r2, g2, b2 = rgb_b
    r_mean = (r1 + r2) / 2.0
    dr, dg, db = r1 - r2, g1 - g2, b1 - b2
    return (
        (2 + r_mean / 256.0) * dr * dr
        + 4.0 * dg * dg
        + (2 + (255 - r_mean) / 256.0) * db * db
    ) ** 0.5


def is_brand_color(value: str) -> bool:
    """Reject achromatic colours, which cannot attribute an app to a bank."""
    rgb = parse_hex(value)
    if rgb is None:
        return False
    r, g, b = rgb
    high, low = max(r, g, b), min(r, g, b)
    if high == 0:
        return False
    saturation = (high - low) / high
    if saturation < _ACHROMATIC_SATURATION:
        return False
    # Near-white and near-black are structurally unremarkable.
    return not (high > 240 and saturation < 0.2) and high > 24


def match_score(distance: float) -> float:
    """Graded 1.0 -> 0.0 match strength for a perceptual distance."""
    if distance <= IDENTICAL_DISTANCE:
        return 1.0
    if distance >= MAX_MATCH_DISTANCE:
        return 0.0
    span = MAX_MATCH_DISTANCE - IDENTICAL_DISTANCE
    return 1.0 - ((distance - IDENTICAL_DISTANCE) / span)


def best_match(color: str, palette: Sequence[str]) -> Tuple[Optional[str], float]:
    """Closest palette entry to ``color`` and its match score."""
    best: Optional[str] = None
    best_distance = float("inf")
    for candidate in palette:
        distance = color_distance(color, candidate)
        if distance < best_distance:
            best_distance = distance
            best = candidate
    if best is None or best_distance == float("inf"):
        return None, 0.0
    return best, match_score(best_distance)


def palette_similarity(
    suspect_colors: Iterable[str],
    baseline_palette: Sequence[str],
) -> Dict[str, object]:
    """
    How much of a bank's brand palette the suspect reproduces.

    Coverage-oriented on purpose: the question is "does this app wear the
    bank's colours", not "are the two colour sets the same size". A suspect
    with a large palette is not penalised for also containing other colours.
    """
    brand_targets = [c for c in baseline_palette if is_brand_color(c)]
    suspect_brand = [c for c in suspect_colors if is_brand_color(c)]

    if not brand_targets:
        return {"score": 0.0, "matches": [], "matched_count": 0, "target_count": 0}
    if not suspect_brand:
        return {
            "score": 0.0,
            "matches": [],
            "matched_count": 0,
            "target_count": len(brand_targets),
        }

    matches: List[Dict[str, object]] = []
    total = 0.0
    for target in brand_targets:
        found, score = best_match(target, suspect_brand)
        total += score
        if score > 0:
            matches.append(
                {
                    "baseline": target,
                    "suspect": found,
                    "score": round(score, 4),
                    "distance": round(color_distance(target, found or ""), 2),
                }
            )

    return {
        "score": total / len(brand_targets),
        "matches": sorted(matches, key=lambda m: -float(m["score"])),  # type: ignore[arg-type]
        "matched_count": len(matches),
        "target_count": len(brand_targets),
    }
