"""
Regressions from a live false positive: a benign calculator (Fossify) was
escalated to FRS 64 "High Risk" as a low-tier VIDE-F001 impersonation of a bank.

Two defects produced it:
  * Android resource colours are #AARRGGBB, but were fed to a CSS-style
    #RRGGBBAA parser - Material purple #FF6200EE read as orange #FF6200.
  * A bare digit ("6") in the suspect's strings "reproduced" a whole bank
    label ("Enter 6-Digit MPIN") at token-set ratio 100.
"""

from sudarshan_core.engines.vide.fuzzy import fuzzy_containment, shares_any
from sudarshan_core.engines.vide.layout_extractor import (
    _parse_colors_xml,
    android_color_to_rgb_hex,
)


def test_android_argb_colours_drop_leading_alpha():
    assert android_color_to_rgb_hex("#FF6200EE") == "#6200ee"
    assert android_color_to_rgb_hex("#FF8C1D18") == "#8c1d18"
    assert android_color_to_rgb_hex("#1B4AA0") == "#1b4aa0"
    assert android_color_to_rgb_hex("#F0A") == "#ff00aa"
    assert android_color_to_rgb_hex("#8F0A") == "#ff00aa"


def test_fully_transparent_android_colours_are_ignored():
    assert android_color_to_rgb_hex("#00FFFFFF") is None
    assert android_color_to_rgb_hex("#0FFF") is None


def test_colors_xml_is_normalised(tmp_path):
    xml = tmp_path / "colors.xml"
    xml.write_text(
        '<resources><color name="purple">#FF6200EE</color>'
        '<color name="clear">#00000000</color></resources>',
        encoding="utf-8",
    )
    assert _parse_colors_xml(xml) == ["#6200ee"]


def test_bare_digits_do_not_reproduce_a_label():
    score, matched, _ = fuzzy_containment(
        ["Enter 6-Digit MPIN", "Get up to 5,00,000 instantly"], ["6", "5", "="]
    )
    assert score == 0.0 and matched == []
    assert shares_any(["Enter 6-Digit MPIN"], ["6"]) == 0


def test_real_rewording_still_matches():
    score, matched, _ = fuzzy_containment(["Enter 6-Digit MPIN"], ["Enter MPIN"])
    assert matched == ["Enter 6-Digit MPIN"]
