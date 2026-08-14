"""VIDE-F001 gating and the structured result contract.

Reproducing a bank's UI is exactly what that bank's own app does. What makes it
impersonation is doing so under a package name and signing certificate that are
not the bank's - so the rule is gated on identity, not on similarity alone.
"""

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline
from sudarshan_core.engines.vide.compare import (
    DETECTION_THRESHOLD,
    claims_official_identity,
    compare_profiles,
)
from sudarshan_core.engines.vide.pipeline import safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile

GENUINE_SIGNER = "ab" * 32
CLONE_SIGNER = "cd" * 32


def _baseline() -> InstitutionBaseline:
    return InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "allowed_signers_sha256": [GENUINE_SIGNER],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": ["LinearLayout", "TextInputEditText", "MaterialButton"],
                "colors": ["#1a237e"],
            },
        }
    )


def _clone_profile() -> UIProfile:
    return UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "YONO", "Forgot Password"],
        view_sequence=["LinearLayout", "TextInputEditText", "MaterialButton", "TextView"],
        colors=["#1a237e", "#ffffff"],
    )


# ── the gate ───────────────────────────────────────────────────────────────


def test_high_confidence_without_official_identity_fires():
    result = compare_profiles(_clone_profile(), _baseline(), "com.evil.clone", CLONE_SIGNER)
    assert result.confidence >= DETECTION_THRESHOLD
    assert result.detected is True
    assert result.institution_id == "demo_sbi"
    assert any("exceeds threshold" in line for line in result.evidence_lines)


def test_the_banks_own_app_is_not_impersonating_itself():
    result = compare_profiles(_clone_profile(), _baseline(), "com.sbi.lotus", GENUINE_SIGNER)
    assert result.confidence >= DETECTION_THRESHOLD
    assert result.detected is False
    assert any("suppressed" in line for line in result.evidence_lines)


def test_right_package_wrong_signer_still_fires():
    """A package name anyone can build under is not proof of identity."""
    result = compare_profiles(_clone_profile(), _baseline(), "com.sbi.lotus", CLONE_SIGNER)
    assert result.detected is True


def test_unknown_package_and_signer_do_not_confer_legitimacy():
    assert claims_official_identity(_baseline(), "", "") is False
    assert claims_official_identity(_baseline(), "com.sbi.lotus", "") is False
    assert claims_official_identity(_baseline(), "", GENUINE_SIGNER) is False
    assert claims_official_identity(_baseline(), "com.sbi.lotus", GENUINE_SIGNER) is True


def test_a_baseline_with_no_registered_signer_can_never_confer_legitimacy():
    baseline = _baseline()
    baseline.allowed_signers_sha256 = []
    assert claims_official_identity(baseline, "com.sbi.lotus", GENUINE_SIGNER) is False


def test_reworded_clone_is_still_detected():
    """The false negative the rigid comparer produced: a retyped login screen."""
    reworded = UIProfile(
        source="test",
        strings=["Please Enter UPI PIN", "Enter MPIN", "YONO App", "Forgot Password"],
        view_sequence=["LinearLayout", "EditText", "Button", "TextView"],
        colors=["#1c246f"],  # a few units off the official navy
    )
    result = compare_profiles(reworded, _baseline(), "com.evil.clone", CLONE_SIGNER)
    assert result.string_jaccard > 0.5
    assert result.color_match == 1.0
    assert result.detected is True


# ── result contract ────────────────────────────────────────────────────────


def test_result_carries_the_documented_keys():
    result = safe_run_vide_analysis(
        suspect_profile=_clone_profile(),
        package_name="com.evil.clone",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_baseline()],
    )
    assert result["status"] == "OK"
    for key in ("findings", "matched_baseline", "similarity_score", "extracted_profile"):
        assert key in result, key

    assert "VIDE-F001" in [f["rule_id"] for f in result["findings"]]
    assert result["matched_baseline"]["institution_id"] == "demo_sbi"
    assert result["similarity_score"] >= DETECTION_THRESHOLD
    assert result["extracted_profile"]["strings"]
    assert result["extracted_profile"]["colors"]


def test_findings_rank_impersonation_above_the_visual_match():
    result = safe_run_vide_analysis(
        suspect_profile=_clone_profile(),
        package_name="com.sbi.lotus",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_baseline()],
    )
    rules = [f["rule_id"] for f in result["findings"]]
    assert rules[0] == "CH06-SIGNER-IMPERSONATION"
    assert "VIDE-F001" in rules
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_unavailable_run_still_answers_the_signer_question():
    """CH06 needs only the manifest package and the certificate."""
    result = safe_run_vide_analysis(
        package_name="com.sbi.lotus",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_baseline()],
        apktool_available=False,
    )
    assert result["status"] == "UNAVAILABLE"
    assert result["signer_impersonation"]["detected"] is True
    assert [f["rule_id"] for f in result["findings"]] == ["CH06-SIGNER-IMPERSONATION"]


def test_clean_app_produces_no_findings():
    result = safe_run_vide_analysis(
        suspect_profile=UIProfile(
            source="test",
            strings=["Settings", "Wi-Fi", "Bluetooth", "Airplane Mode"],
            view_sequence=["ScrollView", "Switch"],
            colors=["#000000"],
        ),
        package_name="com.example.settings",
        certificate={"certificate_sha256": CLONE_SIGNER},
        baselines=[_baseline()],
    )
    assert result["status"] == "OK"
    assert result["findings"] == []
    assert result["visual_impersonation_detected"] is False
