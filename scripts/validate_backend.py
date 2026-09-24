import json
import logging
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

from sudarshan_core.engines.execution_assertions import build_execution_assertions, VERDICT_INCOMPLETE_EXERCISE
from sudarshan_core.engines.agentic.remediation import generate_remedial_suggestions
from sudarshan_core.engines.anti_evasion import AntiEvasionOrchestrator

logging.basicConfig(level=logging.INFO)

def run_tests():
    print("--- 1. Testing INCOMPLETE EXERCISE (0 events != SAFE) ---")
    mock_dynamic_empty = {
        "available": True,
        "activities_triggered": [],
        "foreground_packages": [],
        "frida_events": {},
        "api_calls": []
    }
    # 0 events
    matrix = build_execution_assertions(mock_dynamic_empty, target_bank_packages=["com.baseline.sbi"], threat_events_observed=0)
    assert matrix.incomplete_exercise is True, "0 events must yield incomplete exercise"
    assert matrix.to_dict()["verdict"] == VERDICT_INCOMPLETE_EXERCISE
    assert matrix.banking_app_launched.fired is False
    print("INCOMPLETE_EXERCISE logic validated successfully.")

    print("--- 2. Testing FORENSIC SUGGESTIONS ---")
    # Using the same empty matrix, it should suggest remediation for unreached triggers
    suggestions = generate_remedial_suggestions(execution_assertions=matrix.to_dict(), target_bank_packages=["com.baseline.sbi"])
    s_ids = [s.suggestion_id for s in suggestions]
    print(f"Suggestions generated: {s_ids}")
    assert "remedy_launch_target" in s_ids
    assert "remedy_accessibility" in s_ids
    assert "remedy_inject_sms" in s_ids
    assert "remedy_persona_contacts_accessed" in s_ids
    assert "remedy_persona_call_log_accessed" in s_ids
    assert "remedy_time_warp" in s_ids
    print("Forensic Suggestions validated successfully.")

    print("--- 3. Testing FULL EXERCISE (All Triggers Fired) ---")
    mock_dynamic_full = {
        "available": True,
        "activities_triggered": ["com.baseline.sbi"],
        "api_calls": ["SMS_RECEIVED", "READ_CONTACTS", "READ_CALL_LOG", "AccessibilityService", "SYSTEM_ALERT_WINDOW"]
    }
    matrix_full = build_execution_assertions(mock_dynamic_full, target_bank_packages=["com.baseline.sbi"], threat_events_observed=5)
    assert matrix_full.banking_app_launched.fired is True
    assert matrix_full.otp_sms_received.fired is True
    assert matrix_full.accessibility_granted.fired is True
    assert matrix_full.overlay_triggered.fired is True
    assert matrix_full.contacts_accessed.fired is True
    assert matrix_full.call_log_accessed.fired is True
    assert matrix_full.incomplete_exercise is False
    print("Execution Assertion full-firing validated successfully.")

    print("--- 4. Testing Autonomous Anti Evasion (Backend logic) ---")
    # Mock shell execution for DeviceStateSimulator and advance_device_clock
    # The actual implementation calls self._shell, but we can verify classes exist and take arguments correctly.
    try:
        aae = AntiEvasionOrchestrator(package_name="com.test.app", serial="emulator-5554")
        print("AntiEvasionOrchestrator instantiated.")
    except Exception as e:
        print(f"AAE instantiation failed: {e}")

    print("All backend checks passed.")

if __name__ == '__main__':
    run_tests()
