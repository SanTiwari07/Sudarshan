"""VIDE detection calibrated to a 20% threshold, and the forensics it emits.

Two things are pinned here and they pull against each other, which is the
point:

* the threshold is 0.20, so a partial clone - one that wears a bank's colours
  but whose labels never made it out of a minified bundle - reaches a verdict
  instead of being reported clean, and
* structure alone still cannot produce one, because every banking app on earth
  ships a login form and the structure axis is worth 0.35 on its own.

The second is the regression that matters. Dropping the threshold without it
made a device-settings screen score 0.21 against the SBI baseline.
"""

from sudarshan_core.engines.vide.baseline_store import (
    InstitutionBaseline,
    shortlist_baselines,
)
from sudarshan_core.engines.vide.color_match import describe_delta_e
from sudarshan_core.engines.vide.compare import (
    DETECTION_THRESHOLD,
    MIN_COLOR_EVIDENCE,
    MIN_STRING_EVIDENCE,
    MIN_STRUCTURE_EVIDENCE,
    compare_profiles,
)
from sudarshan_core.engines.vide.corpus_compare import (
    ATTRIBUTION_MARGIN,
    MIN_SHAPE_EVIDENCE,
)
from sudarshan_core.engines.vide.corpus_compare import (
    DETECTION_THRESHOLD as CORPUS_DETECTION_THRESHOLD,
)
from sudarshan_core.engines.vide.forensics import (
    TIER_HIGH,
    TIER_LOW,
    TIER_MODERATE,
    confidence_tier,
    tier_label,
)
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile

CLONE_SIGNER = "de" * 32


def _sbi() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": [
                    "LinearLayout",
                    "ImageView",
                    "TextView",
                    "TextInputEditText",
                    "TextInputEditText",
                    "MaterialButton",
                    "TextView",
                ],
                "colors": ["#1b4aa0", "#e8a100"],
            },
        }
    )


# ─────────────────────────── threshold constants ────────────────────────────


def test_detection_threshold_is_twenty_percent():
    assert DETECTION_THRESHOLD == 0.20
    # The two comparers answer the same question; they must not disagree about
    # when it is answered yes.
    assert CORPUS_DETECTION_THRESHOLD == DETECTION_THRESHOLD


def test_supporting_constants_are_calibrated_to_the_new_threshold():
    assert MIN_STRING_EVIDENCE == 0.02
    assert MIN_STRUCTURE_EVIDENCE == 0.10
    assert MIN_SHAPE_EVIDENCE == 0.15
    assert ATTRIBUTION_MARGIN == 0.05


# ──────────────────────── what fires and what does not ──────────────────────


def test_palette_only_clone_is_detected():
    """
    The case the old 0.72 gate missed.

    A Capacitor clone keeps its labels in a minified bundle, so static
    extraction recovers the brand palette and the form skeleton and almost no
    text. That app is exactly what VIDE exists to catch, and it scored clean.
    """
    suspect = UIProfile(
        source="test",
        strings=["Continue", "Proceed"],
        view_sequence=[
            "div",
            "img",
            "label",
            "input",
            "input",
            "button",
            "span",
        ],
        colors=["#1b4aa0", "#e8a100", "#ffffff"],
    )
    result = compare_profiles(suspect, _sbi())

    assert result.detected is True
    assert result.institution_id == "demo_sbi"
    assert result.confidence >= DETECTION_THRESHOLD
    assert result.color_match >= MIN_COLOR_EVIDENCE
    # Attributed on colour, not on text - the string axis contributed nothing.
    assert result.string_jaccard == 0.0


def test_structure_alone_does_not_fire():
    """
    Regression: a settings screen is not an SBI clone.

    ``Settings`` / ``Wi-Fi`` / ``Bluetooth``, black on white, shares no label
    and no brand colour with any bank. Its layout still resembles a login form
    closely enough to clear 0.20 on the structure axis by itself, which is why
    structure is supporting evidence and never sufficient evidence.
    """
    suspect = UIProfile(
        source="test",
        strings=["Settings", "Wi-Fi", "Bluetooth", "Airplane Mode"],
        view_sequence=[
            "LinearLayout",
            "ImageView",
            "TextView",
            "TextInputEditText",
            "TextInputEditText",
            "MaterialButton",
            "TextView",
        ],
        colors=["#000000", "#ffffff"],
    )
    result = compare_profiles(suspect, _sbi())

    assert result.tree_similarity >= MIN_STRUCTURE_EVIDENCE
    assert result.detected is False


def test_unrelated_app_produces_no_findings_end_to_end():
    result = safe_run_vide_analysis(
        suspect_profile=UIProfile(
            source="test",
            strings=["Settings", "Wi-Fi", "Bluetooth", "Airplane Mode"],
            view_sequence=["ScrollView", "Switch"],
            colors=["#000000"],
        ),
        package_name="com.example.settings",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_sbi()],
    )
    assert result["findings"] == []
    assert result["visual_impersonation_detected"] is False
    assert result["visual_impersonation_tier"] == "none"


# ───────────────────────────── confidence tiers ─────────────────────────────


def test_confidence_tiers_band_the_range_above_the_threshold():
    assert confidence_tier(0.19) == "none"
    assert confidence_tier(TIER_LOW) == "low"
    assert confidence_tier(0.34) == "low"
    assert confidence_tier(TIER_MODERATE) == "moderate"
    assert confidence_tier(0.59) == "moderate"
    assert confidence_tier(TIER_HIGH) == "high"
    assert confidence_tier(0.95) == "high"


def test_tier_low_starts_at_the_detection_threshold():
    """A detection is never reported as being below the threshold."""
    assert TIER_LOW == DETECTION_THRESHOLD
    assert tier_label(confidence_tier(DETECTION_THRESHOLD)).startswith("Low")


# ─────────────────────────── forensic explanation ───────────────────────────


def test_evidence_lines_name_the_matching_colours_with_delta_e():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "YONO", "Login"],
        view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton"],
        # One exact brand colour and one a designer's-eye away from it.
        colors=["#1b4aa0", "#e8a103"],
    )
    result = compare_profiles(suspect, _sbi())
    evidence = "\n".join(result.evidence_lines)

    assert "#1B4AA0" in evidence
    assert "ΔE=" in evidence
    assert "Brand colour scheme:" in evidence
    assert "UI text:" in evidence
    assert "View hierarchy:" in evidence


def test_forensic_breakdown_carries_all_three_axes():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "Login"],
        view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton"],
        colors=["#1b4aa0", "#e8a100"],
    )
    breakdown = compare_profiles(suspect, _sbi()).forensics

    assert breakdown["threshold"] == DETECTION_THRESHOLD
    assert breakdown["institution_display"] == "SBI Demo"
    assert breakdown["tier"] in {"low", "moderate", "high"}

    colours = breakdown["color_scheme"]
    assert colours["matched_count"] >= 1
    swatch = colours["matches"][0]
    # Hex is uppercased on both sides so a report never renders the same colour
    # two ways, and the ΔE travels with the pair rather than only the score.
    assert swatch["baseline_hex"].startswith("#")
    assert swatch["baseline_hex"] == swatch["baseline_hex"].upper()
    assert swatch["suspect_hex"] == swatch["suspect_hex"].upper()
    assert swatch["delta_e"] >= 0.0
    assert swatch["verdict"] == describe_delta_e(swatch["delta_e"])
    assert swatch["exact"] is (swatch["baseline_hex"] == swatch["suspect_hex"])

    text = breakdown["ui_text"]
    assert "MPIN" in text["matched_strings"]
    assert text["target_count"] == 4

    assert breakdown["view_hierarchy"]["score"] > 0.0


def test_pipeline_exposes_the_breakdown_and_tier_at_the_top_level():
    result = safe_run_vide_analysis(
        suspect_profile=UIProfile(
            source="test",
            strings=["Enter UPI PIN", "MPIN", "YONO", "Login"],
            view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton"],
            colors=["#1b4aa0", "#e8a100"],
        ),
        package_name="com.evil.clone",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_sbi()],
    )

    assert result["visual_impersonation_detected"] is True
    assert result["visual_impersonation_institution"] == "SBI Demo"
    assert result["detection_threshold"] == DETECTION_THRESHOLD
    assert result["visual_impersonation_tier"] in {"low", "moderate", "high"}
    assert result["visual_impersonation_tier_label"]

    breakdown = result["forensic_breakdown"]
    assert breakdown["detected"] is True
    assert breakdown["institution_display"] == "SBI Demo"
    assert breakdown["color_scheme"]["matches"]

    finding = next(f for f in result["findings"] if f["rule_id"] == "VIDE-F001")
    assert finding["forensics"]["color_scheme"]["matches"]


# ───────────────────────────── candidate shortlist ──────────────────────────


def test_shortlist_qualifies_on_palette_with_no_shared_text():
    """
    The pre-filter must not drop the app the comparer would have matched.

    Filtering on shared *strings* alone discarded palette-only clones before
    the colour comparison - which is the axis that carries attribution - ever
    ran.
    """
    suspect = UIProfile(
        source="test",
        strings=["Continue", "Proceed", "Next"],
        view_sequence=["div", "input", "button"],
        colors=["#1b4aa0", "#e8a100"],
    )
    out = shortlist_baselines(suspect, [_sbi()])
    assert [b.institution_id for b in out] == ["demo_sbi"]


def test_shortlist_still_drops_a_baseline_with_no_evidence_on_any_axis():
    suspect = UIProfile(
        source="test",
        strings=["Settings", "Wi-Fi", "Bluetooth"],
        view_sequence=["ScrollView"],
        colors=["#000000", "#ffffff"],
    )
    assert shortlist_baselines(suspect, [_sbi()]) == []
