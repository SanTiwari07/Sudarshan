"""
Risk Engine regression tests.

These previously unpacked four values from ``calculate_risk_score``, which
returns a dict - every test in this module raised
``ValueError: too many values to unpack`` and the deterministic scoring engine
therefore had ZERO passing coverage. They also asserted a legacy weighted
formula (w1=25/w2=15/w3=10) that the 5-axis STEI engine replaced.

Rewritten against the current contract:

    STEI = 0.60*CT + 0.20*BT + 0.10*PR + 0.05*OB + 0.05*IR
    FRS  = 0.25*STEI + 0.35*Dynamic + 0.20*Correlation + 0.20*Banking   (dynamic available)
    FRS  = 0.50*STEI + 0.25*Correlation + 0.25*Banking                  (static only)
    final = min(FRS * clamp(ai_confidence, 0.5, 1.5), 100)

The engine is the single source of truth for the verdict, so these tests are
the guard rail for every other change in the repository.
"""

import math

import pytest

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags

# Band edges, from risk_engine: <=30 Safe, <=60 Suspicious, <=89 High Risk, else Critical
BANDS = ("Safe", "Suspicious", "High Risk", "Critical")


# ─── Contract ─────────────────────────────────────────────────────────────────

def test_returns_dict_with_documented_keys():
    """Guards the exact regression that broke this module: the return shape."""
    result = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=1.0)
    assert isinstance(result, dict)
    for key in (
        "base_score",
        "ai_confidence_multiplier",
        "final_risk_score",
        "risk_band",
        "frs_breakdown",
        "confidence",
        "severity",
        "recommended_action",
        "evidence",
    ):
        assert key in result, f"missing contract key: {key}"


def test_accepts_both_dataclass_and_dict_flags():
    as_model = calculate_risk_score(
        StaticAnalysisFlags(has_sms_read_write=True), ai_confidence=1.0
    )
    as_dict = calculate_risk_score(
        {"has_sms_read_write": True}, ai_confidence=1.0
    )
    assert as_model["final_risk_score"] == as_dict["final_risk_score"]


# ─── STEI axes ────────────────────────────────────────────────────────────────

def test_zero_signal_scores_zero_stei_and_is_safe():
    result = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=1.0)
    assert result["frs_breakdown"]["stei"] == 0.0
    assert result["frs_breakdown"]["stei_axes"] == {"ct": 0.0, "bt": 0.0, "pr": 0.0, "ob": 0.0, "ir": 0.0}
    assert result["risk_band"] == "Safe"


def test_ct_axis_weights_are_exact():
    """CT = 40 accessibility + 35 SMS + 25 overlay, capped at 100."""
    result = calculate_risk_score(
        StaticAnalysisFlags(
            has_accessibility_abuse=True,
            has_sms_read_write=True,
            has_system_alert_window=True,
        ),
        ai_confidence=1.0,
    )
    assert result["frs_breakdown"]["stei_axes"]["ct"] == 100.0


def test_ct_axis_partial_combination():
    result = calculate_risk_score(
        StaticAnalysisFlags(has_accessibility_abuse=True, has_sms_read_write=True),
        ai_confidence=1.0,
    )
    assert result["frs_breakdown"]["stei_axes"]["ct"] == 75.0


def test_ir_axis_ten_points_per_indicator_capped():
    few = calculate_risk_score(
        StaticAnalysisFlags(hardcoded_urls_ips=["http://a", "http://b"]),
        ai_confidence=1.0,
    )
    assert few["frs_breakdown"]["stei_axes"]["ir"] == 20.0

    many = calculate_risk_score(
        StaticAnalysisFlags(hardcoded_urls_ips=[f"http://h{i}" for i in range(50)]),
        ai_confidence=1.0,
    )
    assert many["frs_breakdown"]["stei_axes"]["ir"] == 100.0, "IR must cap at 100"


def test_stei_is_the_weighted_sum_of_its_axes():
    result = calculate_risk_score(
        StaticAnalysisFlags(
            has_accessibility_abuse=True,
            has_sms_read_write=True,
            has_system_alert_window=True,
            targets_indian_banks=True,
            hardcoded_urls_ips=["http://c2.example"],
        ),
        ai_confidence=1.0,
    )
    a = result["frs_breakdown"]["stei_axes"]
    expected = (0.60 * a["ct"]) + (0.20 * a["bt"]) + (0.10 * a["pr"]) \
        + (0.05 * a["ob"]) + (0.05 * a["ir"])
    assert result["frs_breakdown"]["stei"] == pytest.approx(min(expected, 100.0), abs=0.01)


# ─── FRS branches ─────────────────────────────────────────────────────────────

def test_static_only_branch_is_selected_without_dynamic():
    result = calculate_risk_score(StaticAnalysisFlags(has_sms_read_write=True), ai_confidence=1.0)
    assert result["frs_breakdown"]["formula_used"] == "static_only_frs"
    assert result["frs_breakdown"]["dynamic_available"] is False


def test_full_branch_is_selected_with_dynamic():
    dynamic = {"available": True, "engine": "frida", "bfci": 50.0, "bfci_components": {"sms": 100.0}}
    result = calculate_risk_score(
        StaticAnalysisFlags(has_sms_read_write=True),
        ai_confidence=1.0,
        dynamic_result=dynamic,
    )
    assert result["frs_breakdown"]["formula_used"] == "full_frs"
    assert result["frs_breakdown"]["dynamic_available"] is True


def test_static_only_weights_renormalise_over_available_axes():
    """
    With dynamic unavailable, the remaining axes are renormalised so their
    weights sum to 1.0.

    This replaces the previous fixed 0.50/0.25/0.25 assertion. That formula
    multiplied every unavailable axis by its weight against a value of 0, so a
    deployment without VirusTotal/OTX keys had ~20-25% of every score pinned at
    zero - absence of evidence scored as evidence of innocence. Measured on the
    labelled corpus, that alone kept real banking trojans inside the "Safe"
    band. See tests/test_detection_regressions.py.
    """
    result = calculate_risk_score(
        StaticAnalysisFlags(has_accessibility_abuse=True),
        ai_confidence=1.0,
        correlation_result={"available": True, "threat_score": 40.0},
        family="Anubis",
    )
    b = result["frs_breakdown"]

    # dynamic is the only unavailable axis here
    assert b["axes_excluded"] == ["dynamic"]
    assert abs(sum(b["axes_used"].values()) - 1.0) < 0.01

    # axes_used publishes weights rounded to 3 decimals for readability, so
    # recomputing from them cannot be exact - allow for that rounding only.
    expected = sum(w * b[axis] for axis, w in b["axes_used"].items())
    assert result["base_score"] == pytest.approx(expected, abs=0.1)


def test_full_frs_weights_sum_correctly():
    """FRS = 0.25*STEI + 0.35*Dynamic + 0.20*Correlation + 0.20*Banking."""
    result = calculate_risk_score(
        StaticAnalysisFlags(has_accessibility_abuse=True, has_sms_read_write=True),
        ai_confidence=1.0,
        dynamic_result={"available": True, "engine": "frida", "bfci": 70.0, "bfci_components": {"sms": 100.0}},
        correlation_result={"available": True, "threat_score": 30.0},
        family="Anubis",
    )
    b = result["frs_breakdown"]
    expected = (
        0.25 * b["stei"] + 0.35 * b["dynamic"]
        + 0.20 * b["correlation"] + 0.20 * b["banking_impact"]
    )
    assert result["base_score"] == pytest.approx(round(expected, 2), abs=0.01)


# ─── ai_confidence multiplier ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    "supplied,expected",
    [(1.0, 1.0), (1.2, 1.2), (1.15, 1.15), (0.1, 0.5), (9.9, 1.5), (-5.0, 0.5)],
)
def test_ai_confidence_is_clamped(supplied, expected):
    """
    The multiplier is rule-derived (1.0 / 1.15 / 1.2) and hard-clamped to
    [0.5, 1.5]. It is NOT an LLM output - clamping is the last line of defence.
    """
    result = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=supplied)
    assert result["ai_confidence_multiplier"] == expected


def test_multiplier_scales_the_base_score():
    flags = StaticAnalysisFlags(has_accessibility_abuse=True, has_sms_read_write=True)
    plain = calculate_risk_score(flags, ai_confidence=1.0)
    boosted = calculate_risk_score(flags, ai_confidence=1.2)
    assert boosted["final_risk_score"] == pytest.approx(
        min(round(plain["base_score"] * 1.2, 2), 100.0), abs=0.01
    )


# ─── Boundaries ───────────────────────────────────────────────────────────────

def test_score_never_exceeds_100():
    result = calculate_risk_score(
        StaticAnalysisFlags(
            has_accessibility_abuse=True,
            has_sms_read_write=True,
            has_system_alert_window=True,
            dangerous_apis_found=["Runtime.exec", "addJavascriptInterface", "DexClassLoader"],
            hardcoded_urls_ips=["http://evil"] * 40,
            targets_indian_banks=True,
            obfuscation_score=1.0,
            has_reflection=True,
        ),
        ai_confidence=1.5,
        dynamic_result={"available": True, "engine": "frida", "bfci": 100.0, "bfci_components": {"sms": 100.0}},
        correlation_result={"available": True, "threat_score": 100.0},
        family="Anubis",
    )
    assert result["final_risk_score"] <= 100.0
    assert result["risk_band"] == "Critical"


def test_score_never_below_zero_and_band_is_known():
    result = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=0.5)
    assert result["final_risk_score"] >= 0.0
    assert result["risk_band"] in BANDS


def test_boundary_bfci_zero_and_hundred():
    low = calculate_risk_score(
        StaticAnalysisFlags(), ai_confidence=1.0,
        dynamic_result={"available": True, "engine": "frida", "bfci": 0.0, "bfci_components": {"sms": 0.0}},
    )
    high = calculate_risk_score(
        StaticAnalysisFlags(), ai_confidence=1.0,
        dynamic_result={"available": True, "engine": "frida", "bfci": 100.0, "bfci_components": {"sms": 100.0}},
    )
    assert low["frs_breakdown"]["dynamic"] == 0.0
    assert high["frs_breakdown"]["dynamic"] == 100.0
    assert high["final_risk_score"] > low["final_risk_score"]


def test_band_edges_are_monotonic():
    """Increasing evidence must never decrease the score."""
    scores = []
    for extra in (
        {},
        {"has_system_alert_window": True},
        {"has_system_alert_window": True, "has_sms_read_write": True},
        {"has_system_alert_window": True, "has_sms_read_write": True,
         "has_accessibility_abuse": True},
    ):
        scores.append(
            calculate_risk_score(StaticAnalysisFlags(**extra), ai_confidence=1.0)["final_risk_score"]
        )
    assert scores == sorted(scores), f"non-monotonic: {scores}"


# ─── Malformed / hostile dynamic payloads ─────────────────────────────────────

def test_missing_dynamic_section_is_treated_as_unavailable():
    result = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=1.0, dynamic_result=None)
    assert result["frs_breakdown"]["dynamic_available"] is False
    assert result["frs_breakdown"]["dynamic"] == 0.0


def test_dynamic_marked_unavailable_is_ignored():
    result = calculate_risk_score(
        StaticAnalysisFlags(), ai_confidence=1.0,
        dynamic_result={"available": False, "engine": "frida", "bfci": 99.0},
    )
    assert result["frs_breakdown"]["formula_used"] == "static_only_frs"


def test_result_is_finite_for_all_scenarios():
    """No NaN/inf may reach a verdict field."""
    result = calculate_risk_score(
        StaticAnalysisFlags(has_sms_read_write=True),
        ai_confidence=1.2,
        dynamic_result={"available": True, "engine": "frida", "bfci": 55.0, "bfci_components": {"sms": 100.0}},
        correlation_result={"available": True, "threat_score": 20.0},
        family="Anubis",
    )
    for key in ("base_score", "final_risk_score", "confidence"):
        assert math.isfinite(result[key]), f"{key} is not finite"


def test_confidence_rises_with_more_sources():
    """
    A corroborating source must raise confidence - but only if it actually
    observed something. The dynamic fixture here now carries real events; it
    previously passed an empty run (bfci 10, no API/network/activity records),
    which under the corrected contract is an inconclusive run and no longer
    counts as a source. See test_confidence_does_not_rise_on_an_empty_run.
    """
    static_only = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=1.0)
    all_sources = calculate_risk_score(
        StaticAnalysisFlags(), ai_confidence=1.0,
        dynamic_result={
            "available": True, "engine": "frida", "bfci": 10.0, "bfci_components": {},
            "api_calls": ["Activity.onCreate"],
            "activities_triggered": ["MainActivity"],
            "network_logs": ["GET https://example/config"],
        },
        correlation_result={"available": True, "threat_score": 10.0},
        family="Anubis",
    )
    assert all_sources["confidence"] > static_only["confidence"]
    assert all_sources["confidence"] <= 99.0


def test_confidence_does_not_rise_on_an_empty_run():
    """A sandbox run that observed nothing is not corroboration."""
    static_only = calculate_risk_score(StaticAnalysisFlags(), ai_confidence=1.0)
    empty_run = calculate_risk_score(
        StaticAnalysisFlags(), ai_confidence=1.0,
        dynamic_result={"available": True, "engine": "frida", "bfci": 10.0, "bfci_components": {}},
    )
    assert empty_run["confidence"] <= static_only["confidence"]


# ─── Determinism ──────────────────────────────────────────────────────────────

def test_identical_inputs_produce_identical_output():
    kwargs = dict(
        flags=StaticAnalysisFlags(has_accessibility_abuse=True, has_sms_read_write=True),
        ai_confidence=1.2,
        dynamic_result={"available": True, "engine": "frida", "bfci": 61.25, "bfci_components": {"sms": 50.0}},
        correlation_result={"available": True, "threat_score": 55.0},
        family="Anubis",
    )
    first = calculate_risk_score(**kwargs)
    second = calculate_risk_score(**kwargs)
    for key in ("base_score", "final_risk_score", "risk_band", "confidence", "severity"):
        assert first[key] == second[key]
