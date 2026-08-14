"""Perceptual brand-colour matching for VIDE.

Across the baseline corpus every bank ships the same login/MPIN/dashboard
strings and the same structural signatures, so the *brand palette* is what
actually distinguishes "clone of HDFC" from "clone of Axis". That makes colour
comparison an attribution primitive, not a tie-breaker.

Exact hex equality is the wrong test: a clone re-drawn in Figma or re-encoded
through a screenshot lands a few units off the official value while looking
identical to a victim. ``#1B4AA0`` and ``#1C4CA5`` are the same blue to every
person who will ever be defrauded by the app, and a comparison that calls them
different is measuring the wrong thing.

Distance is therefore CIE ΔE₂₀₀₀ over CIELAB. Two properties matter here:

* it is *perceptually uniform* - a ΔE of 5 means the same amount of visible
  difference for a deep blue as for a bright orange, which raw RGB distance and
  the older redmean approximation both get badly wrong at the extremes, and
* it is calibrated in known units - ΔE ≈ 1 is the just-noticeable difference
  under reference conditions, so the thresholds below are readable as
  statements about human vision rather than as tuned magic numbers.

ΔE₂₀₀₀ is the more elaborate of the CIE formulae precisely because it corrects
the blue-hue and low-chroma errors of ΔE₇₆/ΔE₉₄ - and bank brand palettes are
dominated by saturated blues and reds, which is exactly where those corrections
apply.
"""

from __future__ import annotations

import math
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

_HEX_RE = re.compile(r"^#?([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$")

# ΔE₂₀₀₀ below which two colours read as "the same brand colour", and the ΔE at
# which the match score decays to zero.
#
# ΔE ≈ 1.0 is the just-noticeable difference; ≈ 2.3 is the threshold at which a
# non-expert observer reliably calls two swatches different. IDENTICAL is set
# above that at 3.5 so a clone that re-encoded the palette through a screenshot
# or a design tool still matches, while MAX at 18.0 stays well inside "same
# colour family" - two different reds are not the same brand, and a curve that
# reached across hue families would let any bank with a vaguely close palette
# outrank the one the suspect actually reproduced.
IDENTICAL_DELTA_E = 3.5
MAX_MATCH_DELTA_E = 18.0

# Retained under the old names so callers and tests that import them keep
# working; the scale is now ΔE₂₀₀₀, not redmean.
IDENTICAL_DISTANCE = IDENTICAL_DELTA_E
MAX_MATCH_DISTANCE = MAX_MATCH_DELTA_E

# Greys, black and white carry no brand identity - every banking app uses them.
_ACHROMATIC_SATURATION = 0.12

# D65, the sRGB reference white.
_WHITE_X, _WHITE_Y, _WHITE_Z = 95.047, 100.000, 108.883


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


def rgb_to_lab(rgb: Tuple[int, int, int]) -> Tuple[float, float, float]:
    """sRGB (0-255) -> CIELAB under D65."""
    def _linearise(channel: int) -> float:
        value = channel / 255.0
        if value <= 0.04045:
            return value / 12.92
        return ((value + 0.055) / 1.055) ** 2.4

    r, g, b = (_linearise(c) for c in rgb)

    # sRGB -> XYZ (D65), scaled to 0..100.
    x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) * 100.0
    y = (0.2126729 * r + 0.7151522 * g + 0.0721750 * b) * 100.0
    z = (0.0193339 * r + 0.1191920 * g + 0.9503041 * b) * 100.0

    def _f(t: float) -> float:
        if t > 216.0 / 24389.0:
            return t ** (1.0 / 3.0)
        return (841.0 / 108.0) * t + 4.0 / 29.0

    fx, fy, fz = _f(x / _WHITE_X), _f(y / _WHITE_Y), _f(z / _WHITE_Z)
    return (116.0 * fy - 16.0, 500.0 * (fx - fy), 200.0 * (fy - fz))


def delta_e_2000(
    lab_a: Tuple[float, float, float],
    lab_b: Tuple[float, float, float],
) -> float:
    """CIE ΔE₂₀₀₀ between two CIELAB colours (CIE 142-2001, k_L=k_C=k_H=1)."""
    l1, a1, b1 = lab_a
    l2, a2, b2 = lab_b

    c1 = math.hypot(a1, b1)
    c2 = math.hypot(a2, b2)
    c_bar = (c1 + c2) / 2.0

    # Chroma-dependent correction to a*, which is what fixes the grey/low-chroma
    # over-sensitivity of the older formulae.
    c_bar7 = c_bar**7
    g = 0.5 * (1.0 - math.sqrt(c_bar7 / (c_bar7 + 25.0**7))) if c_bar else 0.5
    a1p = (1.0 + g) * a1
    a2p = (1.0 + g) * a2

    c1p = math.hypot(a1p, b1)
    c2p = math.hypot(a2p, b2)

    def _hue(ap: float, bp: float) -> float:
        if ap == 0.0 and bp == 0.0:
            return 0.0
        angle = math.degrees(math.atan2(bp, ap))
        return angle + 360.0 if angle < 0 else angle

    h1p = _hue(a1p, b1)
    h2p = _hue(a2p, b2)

    d_lp = l2 - l1
    d_cp = c2p - c1p

    if c1p * c2p == 0.0:
        d_hp = 0.0
    elif abs(h2p - h1p) <= 180.0:
        d_hp = h2p - h1p
    elif h2p - h1p > 180.0:
        d_hp = h2p - h1p - 360.0
    else:
        d_hp = h2p - h1p + 360.0
    d_Hp = 2.0 * math.sqrt(c1p * c2p) * math.sin(math.radians(d_hp) / 2.0)

    l_bar_p = (l1 + l2) / 2.0
    c_bar_p = (c1p + c2p) / 2.0

    if c1p * c2p == 0.0:
        h_bar_p = h1p + h2p
    elif abs(h1p - h2p) <= 180.0:
        h_bar_p = (h1p + h2p) / 2.0
    elif h1p + h2p < 360.0:
        h_bar_p = (h1p + h2p + 360.0) / 2.0
    else:
        h_bar_p = (h1p + h2p - 360.0) / 2.0

    t = (
        1.0
        - 0.17 * math.cos(math.radians(h_bar_p - 30.0))
        + 0.24 * math.cos(math.radians(2.0 * h_bar_p))
        + 0.32 * math.cos(math.radians(3.0 * h_bar_p + 6.0))
        - 0.20 * math.cos(math.radians(4.0 * h_bar_p - 63.0))
    )

    d_theta = 30.0 * math.exp(-(((h_bar_p - 275.0) / 25.0) ** 2))
    c_bar_p7 = c_bar_p**7
    r_c = 2.0 * math.sqrt(c_bar_p7 / (c_bar_p7 + 25.0**7)) if c_bar_p else 0.0
    r_t = -r_c * math.sin(math.radians(2.0 * d_theta))

    l_offset = (l_bar_p - 50.0) ** 2
    s_l = 1.0 + (0.015 * l_offset) / math.sqrt(20.0 + l_offset)
    s_c = 1.0 + 0.045 * c_bar_p
    s_h = 1.0 + 0.015 * c_bar_p * t

    return math.sqrt(
        (d_lp / s_l) ** 2
        + (d_cp / s_c) ** 2
        + (d_Hp / s_h) ** 2
        + r_t * (d_cp / s_c) * (d_Hp / s_h)
    )


def color_distance(a: str, b: str) -> float:
    """Perceptual distance between two hex colours as CIE ΔE₂₀₀₀."""
    rgb_a = parse_hex(a)
    rgb_b = parse_hex(b)
    if rgb_a is None or rgb_b is None:
        return float("inf")
    if rgb_a == rgb_b:
        return 0.0
    return delta_e_2000(rgb_to_lab(rgb_a), rgb_to_lab(rgb_b))


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
    """Graded 1.0 -> 0.0 match strength for a ΔE₂₀₀₀ distance."""
    if distance <= IDENTICAL_DELTA_E:
        return 1.0
    if distance >= MAX_MATCH_DELTA_E:
        return 0.0
    span = MAX_MATCH_DELTA_E - IDENTICAL_DELTA_E
    return 1.0 - ((distance - IDENTICAL_DELTA_E) / span)


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
