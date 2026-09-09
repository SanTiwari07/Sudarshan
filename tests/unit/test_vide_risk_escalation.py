"""
VIDE + risk engine boundary tests (A–I).

Uses production ``calculate_risk_score`` with synthetic ``vide_result`` payloads.
"""

import pytest

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.engines.vide.pipeline import run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.models.schemas import StaticAnalysisFlags


def _vide_payload(
    *,
    detected: bool = True,
    confidence: float = 0.91,
    institution: str = "SBI Demo",
    critical_cluster: bool = False,
    signer: bool = False,
):
    return {
        "available": True,
        "status": "OK",
        "visual_impersonation_detected": detected,
        "visual_impersonation_institution": institution if detected else "",
        "visual_impersonation_confidence": confidence if detected else 0.0,
        "critical_visual_cluster": critical_cluster,
        "vide_compare": {
            "rule_id": "VIDE-F001",
            "detected": detected,
            "institution_id": "demo_sbi" if detected else "",
            "institution_display": institution,
            "confidence": confidence,
            "scores": {"string_jaccard": 0.94, "tree_similarity": 0.89, "color_match": 0.91},
            "matched_strings": ["login", "mpin"] if detected else [],
            "evidence_lines": ["VIDE test evidence"],
        },
        "signer_impersonation": {
            "detected": signer,
            "rule_id": "CH06-SIGNER-IMPERSONATION",
            "evidence_lines": ["Signer mismatch"] if signer else [],
        },
    }


def test_a_visual_only_not_critical():
    flags = StaticAnalysisFlags()
    risk = calculate_risk_score(flags, vide_result=_vide_payload())
    assert risk["risk_band"] != "Critical"
    assert risk["final_risk_score"] <= 89.0


@pytest.mark.parametrize(
    "flags_kwargs",
    [
        {"has_accessibility_abuse": True},
        {"has_system_alert_window": True},
        {"has_sms_read_write": True},
    ],
    ids=["accessibility", "overlay", "sms"],
)
def test_b_c_d_visual_plus_capability_critical(flags_kwargs):
    flags = StaticAnalysisFlags(**flags_kwargs)
    vide = _vide_payload(critical_cluster=True, confidence=0.85)
    risk = calculate_risk_score(flags, vide_result=vide)
    assert risk["risk_band"] == "Critical"
    assert risk["final_risk_score"] >= 88.0


def test_e_signer_impersonation_critical():
    flags = StaticAnalysisFlags()
    risk = calculate_risk_score(
        flags,
        vide_result=_vide_payload(signer=True, critical_cluster=False),
    )
    assert risk["risk_band"] == "Critical"
    assert risk["final_risk_score"] >= 92.0


def test_f_different_package_high_similarity_vide_f001():
    from sudarshan_core.engines.vide.baseline_store import load_lab_baselines

    bl = next(b for b in load_lab_baselines() if b.institution_id == "demo_sbi_yono")
    p = bl.profile
    suspect = UIProfile(
        source="test",
        strings=list(p.strings),
        view_sequence=list(p.view_sequence),
        colors=list(p.colors),
    )
    vide = run_vide_analysis(
        suspect_profile=suspect,
        package_name="com.unrelated.attacker",
        certificate={"certificate_sha256": "e" * 64},
        baselines=load_lab_baselines(),
    )
    assert vide["vide_compare"]["detected"] is True


def test_g_unrelated_no_vide_f001():
    suspect = UIProfile(source="test", strings=["Maps", "Navigation"], view_sequence=["MapView"])
    from sudarshan_core.engines.vide.baseline_store import load_lab_baselines

    vide = run_vide_analysis(
        suspect_profile=suspect,
        package_name="com.maps.app",
        baselines=load_lab_baselines(),
    )
    assert vide["vide_compare"]["detected"] is False


def test_h_allowlisted_legitimate_suppresses_detection():
    from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline

    bl = InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": ["com.sbi.lotus"],
            "allowed_signers_sha256": ["a" * 64],
            "profile": {
                "strings": ["Enter UPI PIN", "MPIN", "YONO", "Login"],
                "view_sequence": ["LinearLayout", "Button"],
                "colors": ["#1a237e"],
            },
        }
    )
    suspect = UIProfile(
        source="test",
        strings=["Enter UPI PIN", "MPIN", "YONO", "Login"],
        view_sequence=["LinearLayout", "Button"],
        colors=["#1a237e"],
    )
    vide = run_vide_analysis(
        suspect_profile=suspect,
        package_name="com.sbi.lotus",
        certificate={"certificate_sha256": "a" * 64},
        baselines=[bl],
    )
    assert vide["visual_impersonation_detected"] is False


def test_i_no_baseline_candidate_no_false_positive():
    suspect = UIProfile(
        source="test",
        strings=["Random label", "Another"],
        view_sequence=["View"],
    )
    from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline

    empty_overlap_bl = InstitutionBaseline.from_json(
        {
            "institution_id": "demo_sbi",
            "display_name": "SBI Demo",
            "package_names": [],
            "profile": {"strings": ["OnlyInternalBankString"], "view_sequence": ["X"]},
        }
    )
    vide = run_vide_analysis(
        suspect_profile=suspect,
        package_name="com.foo",
        baselines=[empty_overlap_bl],
    )
    assert vide["vide_compare"]["detected"] is False
