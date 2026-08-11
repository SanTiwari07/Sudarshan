"""
Pinned static-only FRS scores for case-study fixtures.

Values produced by scripts/validate_static_only_frs.py on 2026-08-11 after
classifier priority fix (Drinik before Xenomorph). Re-run that script and
update pins here if risk_engine.py changes deliberately.
"""

import pytest

from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.engines.risk_engine import calculate_risk_score

from case_study_fixtures import (
    CORRELATION_UNAVAILABLE,
    case_study_scenarios,
    drinik_flags,
)


def _run_static_only(scenario):
    flags = scenario["flags"]
    family, _ = classify_family(flags)
    return calculate_risk_score(
        flags,
        ai_confidence=1.0,
        dynamic_result=None,
        correlation_result=CORRELATION_UNAVAILABLE,
        family=family,
        all_permissions=scenario["permissions"],
    )


@pytest.mark.parametrize("scenario", case_study_scenarios(), ids=lambda s: s["id"])
def test_static_only_two_axis_renormalization(scenario):
    result = _run_static_only(scenario)
    b = result["frs_breakdown"]
    assert b["axes_excluded"] == ["dynamic", "correlation"]
    assert b["axes_used"]["stei"] == pytest.approx(0.556, abs=0.001)
    assert b["axes_used"]["banking_impact"] == pytest.approx(0.444, abs=0.001)
    assert sum(b["axes_used"].values()) == pytest.approx(1.0, abs=0.01)


def test_drinik_static_only_frs_pinned():
    scenario = next(s for s in case_study_scenarios() if s["id"] == "drinik")
    family, _ = classify_family(drinik_flags())
    assert family == "Drinik"

    result = _run_static_only(scenario)
    b = result["frs_breakdown"]
    assert result["final_risk_score"] == pytest.approx(79.51, abs=0.01)
    assert result["risk_band"] == "High Risk"
    assert b["stei"] == pytest.approx(79.12, abs=0.01)
    assert b["banking_impact"] == pytest.approx(80.0, abs=0.01)
    assert b["stei_axes"]["ct"] == pytest.approx(100.0, abs=0.01)


def test_xenomorph_static_only_frs_pinned():
    scenario = next(s for s in case_study_scenarios() if s["id"] == "xenomorph")
    result = _run_static_only(scenario)
    assert result["final_risk_score"] == pytest.approx(50.82, abs=0.01)
    assert result["risk_band"] == "Suspicious"


def test_insecurebankv2_static_only_frs_pinned():
    scenario = next(s for s in case_study_scenarios() if s["id"] == "insecurebankv2")
    result = _run_static_only(scenario)
    assert result["final_risk_score"] == pytest.approx(9.17, abs=0.01)
    assert result["risk_band"] == "Safe"
