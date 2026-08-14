"""CIE ΔE₂₀₀₀ perceptual colour distance.

The reference pairs come from Sharma, Wu & Dalal (2005), the dataset published
specifically to catch implementation errors in ΔE₂₀₀₀ - the formula has several
discontinuities (hue wrap-around, the chroma-dependent a* correction, the
rotation term near 275°) that a plausible-looking implementation gets wrong
silently. Checking against it is the only way to know the metric is the metric.
"""

import pytest

from sudarshan_core.engines.vide.color_match import (
    IDENTICAL_DELTA_E,
    MAX_MATCH_DELTA_E,
    color_distance,
    delta_e_2000,
    is_brand_color,
    match_score,
    palette_similarity,
    rgb_to_lab,
)

# (lab1, lab2, expected ΔE₂₀₀₀)
SHARMA_PAIRS = [
    ((50.0, 2.6772, -79.7751), (50.0, 0.0, -82.7485), 2.0425),
    ((50.0, 3.1571, -77.2803), (50.0, 0.0, -82.7485), 2.8615),
    ((50.0, 2.8361, -74.0200), (50.0, 0.0, -82.7485), 3.4412),
    ((50.0, -1.3802, -84.2814), (50.0, 0.0, -82.7485), 1.0000),
    ((50.0, -1.1848, -84.8006), (50.0, 0.0, -82.7485), 1.0000),
    ((50.0, 2.5, 0.0), (50.0, 0.0, -2.5), 4.3065),
    ((50.0, 2.5, 0.0), (73.0, 25.0, -18.0), 27.1492),
    ((50.0, 2.5, 0.0), (50.0, 3.1736, 0.5854), 1.0000),
    ((60.2574, -34.0099, 36.2677), (60.4626, -34.1751, 39.4387), 1.2644),
    ((63.0109, -31.0961, -5.8663), (62.8187, -29.7946, -4.0864), 1.2630),
    ((22.7233, 20.0904, -46.6940), (23.0331, 14.9730, -42.5619), 2.0373),
    ((2.0776, 0.0795, -1.1350), (0.9033, -0.0636, -0.5514), 0.9082),
]


@pytest.mark.parametrize("lab_a,lab_b,expected", SHARMA_PAIRS)
def test_matches_cie_reference_data(lab_a, lab_b, expected):
    assert delta_e_2000(lab_a, lab_b) == pytest.approx(expected, abs=1e-4)


def test_delta_e_is_symmetric():
    for lab_a, lab_b, _ in SHARMA_PAIRS:
        assert delta_e_2000(lab_a, lab_b) == pytest.approx(delta_e_2000(lab_b, lab_a))


def test_srgb_to_lab_reference_points():
    assert rgb_to_lab((255, 255, 255))[0] == pytest.approx(100.0, abs=1e-3)
    assert rgb_to_lab((0, 0, 0)) == pytest.approx((0.0, 0.0, 0.0), abs=1e-6)
    # Mid grey sits at L*≈53.6, not 50 - sRGB is gamma-encoded.
    assert rgb_to_lab((128, 128, 128))[0] == pytest.approx(53.585, abs=1e-2)


# ── what the thresholds mean for detection ─────────────────────────────────


def test_prd_worked_example_is_a_full_match():
    """`#1B4AA0` vs `#1C4CA5`: the same blue to anyone being defrauded."""
    distance = color_distance("#1B4AA0", "#1C4CA5")
    assert distance < IDENTICAL_DELTA_E
    assert match_score(distance) == 1.0


def test_identical_colors_are_zero_distance():
    assert color_distance("#005A9C", "#005a9c") == 0.0


def test_different_brand_families_score_zero():
    for a, b in [
        ("#1B4AA0", "#ED232A"),  # SBI blue vs HDFC red
        ("#97144D", "#005A9C"),  # Axis magenta vs BOI blue
        ("#ffffff", "#000000"),
    ]:
        assert color_distance(a, b) > MAX_MATCH_DELTA_E
        assert match_score(color_distance(a, b)) == 0.0


def test_unparseable_color_is_infinitely_far():
    assert color_distance("not-a-colour", "#005A9C") == float("inf")
    assert match_score(color_distance("not-a-colour", "#005A9C")) == 0.0


def test_achromatic_colors_carry_no_brand_identity():
    for neutral in ("#ffffff", "#000000", "#f5f5f5", "#888888"):
        assert not is_brand_color(neutral), neutral


def test_palette_similarity_rewards_perceptual_reproduction():
    """A palette re-encoded a few units off still counts as reproduced."""
    exact = palette_similarity(["#1B4AA0", "#F58220"], ["#1B4AA0", "#F58220"])
    nudged = palette_similarity(["#1C4CA5", "#F48423"], ["#1B4AA0", "#F58220"])
    wrong = palette_similarity(["#ED232A", "#00A650"], ["#1B4AA0", "#F58220"])
    assert exact["score"] == pytest.approx(1.0)
    assert nudged["score"] == pytest.approx(1.0)
    assert wrong["score"] == 0.0
