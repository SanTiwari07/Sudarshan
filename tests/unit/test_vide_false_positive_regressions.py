"""
Regressions from a live false positive: a benign calculator (Fossify) was
escalated to FRS 64 "High Risk" as a low-tier VIDE-F001 impersonation of a bank.

Two defects fixed previously:
  * Android resource colours are #AARRGGBB, but were fed to a CSS-style
    #RRGGBBAA parser - Material purple #FF6200EE read as orange #FF6200.
  * A bare digit ("6") in the suspect's strings "reproduced" a whole bank
    label ("Enter 6-Digit MPIN") at token-set ratio 100.

Remaining issue fixed in this audit cycle:
  * VIDE still flagged the calculator at moderate confidence (~0.38) from
    colour palette + generic structure alone, with 0/19 text labels matched.
    The fix is a text-corroboration requirement: palette-only detections must
    not fire when string_score is below MIN_STRING_FOR_COLOR_DETECTION.
"""

from sudarshan_core.engines.vide.compare import (
    MIN_STRING_FOR_COLOR_DETECTION,
    MIN_STRING_EVIDENCE,
    compare_profiles,
)
from sudarshan_core.engines.vide.fuzzy import fuzzy_containment, shares_any
from sudarshan_core.engines.vide.layout_extractor import (
    _parse_colors_xml,
    android_color_to_rgb_hex,
)
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, SOURCE_CORPUS


# ── Previously fixed: colour channel order ────────────────────────────────────


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


# ── Previously fixed: bare-digit string matching ──────────────────────────────


def test_bare_digits_do_not_reproduce_a_label():
    score, matched, _ = fuzzy_containment(
        ["Enter 6-Digit MPIN", "Get up to 5,00,000 instantly"], ["6", "5", "="]
    )
    assert score == 0.0 and matched == []
    assert shares_any(["Enter 6-Digit MPIN"], ["6"]) == 0


def test_real_rewording_still_matches():
    score, matched, _ = fuzzy_containment(["Enter 6-Digit MPIN"], ["Enter MPIN"])
    assert matched == ["Enter 6-Digit MPIN"]


# ── Palette-only detection gate ────────────────────────────────────────────────


def _make_sbi_baseline() -> InstitutionBaseline:
    """Minimal InstitutionBaseline sufficient for compare_profiles."""
    profile = UIProfile(
        source="test",
        strings=[
            "YONO SBI", "Enter 6-Digit MPIN", "Login", "Account Balance",
            "Fund Transfer", "View Statement", "Pay Now", "MPIN",
            "Forgot MPIN", "Set New MPIN", "SBI", "NetBanking",
            "Quick Transfer", "Debit Card", "Credit Card", "UPI",
            "Bhim UPI", "Mobile Banking", "Register",
        ],
        colors=["#1b4aa0", "#ffffff", "#f5a623", "#2c3e50"],
    )
    return InstitutionBaseline(
        institution_id="BASE-01-SBI",
        display_name="YONO SBI",
        bank="State Bank of India",
        source=SOURCE_CORPUS,
        profile=profile,
        package_names=["com.sbi.lotus"],
        allowed_signers_sha256=[],
    )


def test_palette_only_suspect_does_not_fire_as_detection():
    """A calculator with bank-like colours but ZERO matching labels must not be detected.

    This is the remaining VIDE false positive from the audit: the Fossify
    Calculator scored confidence >= 0.20 from colours + generic layout with
    0/19 bank text labels reproduced.  The text-corroboration gate (color_only
    guard in compare_profiles) must block the finding.
    """
    calculator_suspect = UIProfile(
        source="test_static",
        # Numeric-keypad strings - none of these appear in the SBI baseline
        strings=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
                 "+", "-", "\u00d7", "\u00f7", "=", ".", "CE", "DEL"],
        # Material 3 primary colours - similar to bank palettes
        colors=["#6200ee", "#3700b3", "#ffffff", "#000000"],
    )
    baseline = _make_sbi_baseline()
    result = compare_profiles(calculator_suspect, baseline)

    assert result.detected is False, (
        f"Palette-only detection fired at confidence {result.confidence:.3f} "
        f"with string_score={result.string_jaccard:.3f} (no bank labels matched). "
        f"Evidence: {result.evidence_lines}"
    )


def test_real_clone_with_text_and_colour_still_fires():
    """A clone that reproduces bank text AND brand palette must still be detected."""
    clone_suspect = UIProfile(
        source="test_static",
        strings=[
            "YONO SBI", "Enter 6-Digit MPIN", "Login", "Account Balance",
            "Fund Transfer", "SBI", "UPI",
        ],
        colors=["#1b4aa0", "#f5a623"],  # SBI brand colours
    )
    baseline = _make_sbi_baseline()
    result = compare_profiles(clone_suspect, baseline)

    assert result.detected is True, (
        f"Real clone not detected: confidence={result.confidence:.3f}, "
        f"string_score={result.string_jaccard:.3f}. Evidence: {result.evidence_lines}"
    )


def test_min_string_for_color_detection_constant_is_sane():
    """MIN_STRING_FOR_COLOR_DETECTION must be positive and <= MIN_STRING_EVIDENCE."""
    assert 0 < MIN_STRING_FOR_COLOR_DETECTION <= MIN_STRING_EVIDENCE
