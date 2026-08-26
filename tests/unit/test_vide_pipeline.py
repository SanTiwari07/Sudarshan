"""End-to-end VIDE pipeline (static profile, no network/emulator)."""

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.engines.vide.baseline_store import load_baselines
from sudarshan_core.engines.vide.pipeline import run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile
from sudarshan_core.models.schemas import StaticAnalysisFlags


def _sbi_like_profile() -> UIProfile:
    bl = next(b for b in load_baselines() if b.institution_id == "demo_sbi_yono")
    p = bl.profile
    return UIProfile(
        source="apktool",
        strings=list(p.strings) + ["Username", "Password", "Continue"],
        view_sequence=list(p.view_sequence),
        colors=list(p.colors),
    )


def test_sbi_like_profile_triggers_vide_f001():
    vide = run_vide_analysis(
        suspect_profile=_sbi_like_profile(),
        package_name="com.attacker.fakebank",
        certificate={"certificate_sha256": "d" * 64},
        baselines=load_baselines(),
    )
    assert vide["visual_impersonation_detected"] is True
    assert vide["vide_compare"]["detected"] is True
    assert vide["vide_compare"]["rule_id"] == "VIDE-F001"
    # SBI is registered twice when a corpus checkout is present - as the lab
    # profile and as BASE-01-SBI - and either is the right answer to "which
    # bank". Asserting one id makes the test depend on whether the corpus
    # happens to be checked out rather than on the attribution.
    assert vide["vide_compare"]["institution_id"] in ("demo_sbi_yono", "BASE-01-SBI")

    risk = calculate_risk_score(StaticAnalysisFlags(), vide_result=vide)
    assert risk["risk_band"] != "Critical"


def test_unrelated_profile_no_vide_f001():
    suspect = UIProfile(
        source="apktool",
        strings=["Settings", "About phone", "Battery"],
        view_sequence=["ScrollView", "Switch"],
        colors=["#000000"],
    )
    vide = run_vide_analysis(
        suspect_profile=suspect,
        package_name="com.tools.settings",
        baselines=load_baselines(),
    )
    assert vide["visual_impersonation_detected"] is False
    assert vide["vide_compare"]["detected"] is False
