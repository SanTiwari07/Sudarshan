"""Unit tests for VIDE deterministic comparison."""

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline
from sudarshan_core.engines.vide.compare import compare_against_baselines, compare_profiles
from sudarshan_core.engines.vide.ui_profile import UIProfile


def _sbi_baseline() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": ["LinearLayout", "TextInputEditText", "MaterialButton"],
                "colors": ["#1a237e"],
            },
        }
    )


def test_compare_detects_high_overlap():
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "YONO", "Forgot Password"],
        view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton", "TextView"],
        colors=["#1a237e", "#ffffff"],
    )
    result = compare_profiles(suspect, _sbi_baseline())
    assert result.detected is True
    assert result.institution_id == "demo_sbi"
    # Not the detection threshold, which is 0.20 - this is a near-total match
    # and must score far above the bar, not merely clear it.
    assert result.confidence >= 0.72
    # Matched labels are reported in the baseline's own casing, so an analyst
    # reads the bank's actual string rather than a normalised form.
    assert "enter upi pin" in [s.lower() for s in result.matched_strings]


def test_compare_rejects_unrelated_ui():
    suspect = UIProfile(
        source="test",
        strings=["Settings", "Wi-Fi", "Bluetooth"],
        view_sequence=["ScrollView", "Switch"],
        colors=["#000000"],
    )
    result = compare_against_baselines(suspect, [_sbi_baseline()])
    assert result.detected is False


def test_signer_impersonation_registry():
    from sudarshan_core.engines.vide.signer_registry import check_signer_impersonation

    reg = {"com.sbi.lotus": ["a" * 64]}
    hit = check_signer_impersonation(
        "com.sbi.lotus",
        {"certificate_sha256": "b" * 64},
        registry=reg,
    )
    assert hit.detected is True

    miss = check_signer_impersonation(
        "com.random.app",
        {"certificate_sha256": "b" * 64},
        registry=reg,
    )
    assert miss.detected is False
