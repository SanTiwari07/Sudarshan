"""INCOMPLETE_EXERCISE verdict: a dormant run is not an acquittal.

The governing rule under test: absence of evidence is not evidence of absence.
A sandbox run that reached none of the sample's trigger conditions and observed
no behaviour must not produce a "Safe" verdict, and must not report the
confidence it would have had if the sandbox had actually corroborated anything.
"""

import pytest

from sudarshan_core.engines.execution_assertions import (
    INCOMPLETE_EXERCISE_CONFIDENCE_PENALTY,
    VERDICT_INCOMPLETE_EXERCISE,
    build_execution_assertions,
)
from sudarshan_core.engines.risk_engine import calculate_risk_score

BANKING_FLAGS = {
    "has_accessibility_abuse": True,
    "has_sms_read_write": True,
    "has_system_alert_window": True,
    "dangerous_apis_found": ["DexClassLoader"],
    "hardcoded_urls_ips": ["http://c2.example.test"],
    "targets_indian_banks": True,
    "indian_bank_packages_found": ["com.sbi.lotus", "com.snapwork.hdfc"],
    "obfuscation_score": 0.8,
    "has_reflection": True,
}

BENIGN_FLAGS = {
    "has_accessibility_abuse": False,
    "has_sms_read_write": False,
    "has_system_alert_window": False,
    "dangerous_apis_found": [],
    "hardcoded_urls_ips": [],
    "targets_indian_banks": False,
    "indian_bank_packages_found": [],
    "obfuscation_score": 0.0,
    "has_reflection": False,
}

DORMANT_RUN = {"available": True, "api_calls": [], "frida_events": {}, "evidence": []}

EXERCISED_RUN = {
    "available": True,
    "api_calls": [
        {"hook": "AccessibilityService.onAccessibilityEvent"},
        {"hook": "WindowManager.addView", "args": ["TYPE_APPLICATION_OVERLAY"]},
    ],
    "activities_triggered": ["com.sbi.lotus/.MainActivity"],
    "frida_events": {"sms": [{"hook": "SmsMessage.createFromPdu"}]},
    "evidence": [],
}


# ── Verdict ────────────────────────────────────────────────────────────────


def test_dormant_run_yields_incomplete_exercise():
    result = calculate_risk_score(BANKING_FLAGS, dynamic_result=DORMANT_RUN)
    assert result["verdict"] == VERDICT_INCOMPLETE_EXERCISE
    assert result["incomplete_exercise"] is True


def test_exercised_run_is_not_incomplete():
    result = calculate_risk_score(BANKING_FLAGS, dynamic_result=EXERCISED_RUN)
    assert result["verdict"] != VERDICT_INCOMPLETE_EXERCISE
    assert result["incomplete_exercise"] is False


def test_no_sandbox_run_is_not_an_incomplete_exercise():
    """No run at all is already reported as 'dynamic unavailable'.

    Calling it an incomplete *exercise* would claim we tried and the sample
    stayed quiet, which is a different - and false - statement.
    """
    result = calculate_risk_score(BANKING_FLAGS, dynamic_result=None)
    assert result["incomplete_exercise"] is False
    assert result["verdict"] == result["risk_band"]


def test_benign_looking_sample_is_never_certified_safe_on_a_dormant_run():
    """The false negative this whole feature exists to prevent."""
    result = calculate_risk_score(BENIGN_FLAGS, dynamic_result=DORMANT_RUN)
    assert result["final_risk_score"] <= 30, "precondition: score is in the Safe band"
    assert result["risk_band"] != "Safe"
    assert result["risk_band"] == "Suspicious"
    assert result["frs_breakdown"]["verdict_floored_for_incomplete_exercise"] is True


def test_risk_band_keeps_its_four_value_vocabulary():
    """Downstream renderers switch on risk_band; the verdict is a separate field."""
    result = calculate_risk_score(BANKING_FLAGS, dynamic_result=DORMANT_RUN)
    assert result["risk_band"] in {"Safe", "Suspicious", "High Risk", "Critical"}


# ── Confidence penalty ─────────────────────────────────────────────────────


def test_confidence_is_halved_for_an_unexercised_run():
    dormant = calculate_risk_score(BANKING_FLAGS, dynamic_result=DORMANT_RUN)
    exercised = calculate_risk_score(BANKING_FLAGS, dynamic_result=EXERCISED_RUN)
    assert dormant["confidence"] < exercised["confidence"]
    # The penalty is applied to whatever the other axes earned.
    assert dormant["confidence"] == pytest.approx(
        round(60.0 * INCOMPLETE_EXERCISE_CONFIDENCE_PENALTY, 1), abs=0.6
    )


def test_evidence_explains_why_the_verdict_was_qualified():
    result = calculate_risk_score(BANKING_FLAGS, dynamic_result=DORMANT_RUN)
    lines = " ".join(result["risk_explanation"]["evidence_lines"])
    assert "INCOMPLETE EXERCISE" in lines
    assert "not evidence that the sample is benign" in lines


# ── Assertion derivation ───────────────────────────────────────────────────


def test_all_six_assertions_are_tracked():
    matrix = build_execution_assertions(DORMANT_RUN)
    keys = {a.key for a in matrix.all_assertions()}
    assert keys == {
        "banking_app_launched",
        "otp_sms_received",
        "accessibility_granted",
        "overlay_triggered",
        "contacts_accessed",
        "call_log_accessed",
    }


def test_assertions_fire_from_observed_telemetry():
    matrix = build_execution_assertions(
        EXERCISED_RUN, target_bank_packages=["com.sbi.lotus"]
    )
    assert matrix.banking_app_launched.fired
    assert matrix.accessibility_granted.fired
    assert matrix.overlay_triggered.fired
    assert matrix.otp_sms_received.fired
    assert not matrix.incomplete_exercise


def test_banking_app_assertion_uses_the_samples_own_targets_not_a_bank_list():
    """A package the sample never references must not satisfy the assertion."""
    run = {
        "available": True,
        "activities_triggered": ["com.unrelated.app/.MainActivity"],
        "api_calls": [{"hook": "X"}],
    }
    matrix = build_execution_assertions(run, target_bank_packages=["com.sbi.lotus"])
    assert not matrix.banking_app_launched.fired


def test_screenshot_records_cannot_satisfy_an_assertion():
    """Harness self-reporting is not a fact about the sample."""
    run = {
        "available": True,
        "evidence": [
            {"category": "SCREENSHOT", "api": "WindowManager.addView", "description": "x"}
        ],
    }
    matrix = build_execution_assertions(run)
    assert not matrix.overlay_triggered.fired
    assert matrix.incomplete_exercise


def test_unfired_assertions_carry_actionable_remediation():
    matrix = build_execution_assertions(DORMANT_RUN)
    for assertion in matrix.unfired:
        assert assertion.remediation, f"{assertion.key} has no remediation"


def test_matrix_serialises_for_the_api():
    payload = build_execution_assertions(DORMANT_RUN).to_dict()
    assert payload["verdict"] == VERDICT_INCOMPLETE_EXERCISE
    assert payload["total_count"] == 6
    assert payload["fired_count"] == 0
    assert len(payload["assertions"]) == 6
    assert set(payload["unfired_keys"]) == {a["key"] for a in payload["assertions"]}
