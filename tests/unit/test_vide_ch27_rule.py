"""CH27: visual impersonation + signer mismatch + accessibility -> CRITICAL."""

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags


def _vide(confidence: float, signer_mismatch: bool):
    return {
        "vide_compare": {"detected": confidence > 0, "evidence_lines": []},
        "corpus_compare": {"institution_id": "BASE-02-HDFC"},
        "signer_impersonation": {"detected": signer_mismatch, "evidence_lines": []},
        "visual_impersonation_detected": confidence > 0,
        "visual_impersonation_institution": "HDFC Bank MobileBanking",
        "visual_impersonation_confidence": confidence,
        "critical_visual_cluster": False,
    }


def _flags(accessibility: bool) -> StaticAnalysisFlags:
    return StaticAnalysisFlags(has_accessibility_abuse=accessibility)


def _ch27_line(result) -> bool:
    return any(
        "CH27" in line for line in (result.get("vide_evidence") or result.get("evidence") or [])
    )


def test_full_triad_is_critical():
    result = calculate_risk_score(
        flags=_flags(True), vide_result=_vide(0.91, signer_mismatch=True)
    )
    assert result["risk_band"] == "Critical"
    assert result["final_risk_score"] >= 95.0


def test_confidence_at_or_below_threshold_does_not_trigger_ch27():
    """The rule is confidence > 85%, not >= 85%."""
    result = calculate_risk_score(
        flags=_flags(True), vide_result=_vide(0.85, signer_mismatch=True)
    )
    # Signer mismatch alone still escalates, but not to the CH27 floor of 95.
    assert result["final_risk_score"] < 95.0


def test_missing_accessibility_does_not_trigger_ch27():
    with_access = calculate_risk_score(
        flags=_flags(True), vide_result=_vide(0.95, signer_mismatch=True)
    )
    without = calculate_risk_score(
        flags=_flags(False), vide_result=_vide(0.95, signer_mismatch=True)
    )
    assert with_access["final_risk_score"] >= 95.0
    assert without["final_risk_score"] < 95.0


def test_missing_signer_mismatch_does_not_trigger_ch27():
    """A high-confidence visual match alone must not reach CRITICAL."""
    result = calculate_risk_score(
        flags=_flags(True), vide_result=_vide(0.95, signer_mismatch=False)
    )
    assert result["final_risk_score"] < 95.0
    assert result["risk_band"] != "Critical"


def test_no_vide_result_is_unaffected():
    result = calculate_risk_score(flags=_flags(True), vide_result=None)
    assert result["risk_band"] != "Critical"
