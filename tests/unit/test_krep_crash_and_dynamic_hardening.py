"""
Unit tests for Krep APK crash investigation, dynamic analysis diagnostics,
anti-analysis filtering, and risk engine static floor enforcement.
"""

import unittest
from unittest.mock import MagicMock, patch
import re

from sudarshan_core.engines.frida_sandbox import (
    FridaSession,
    DynamicAnalysisStatus,
)
from sudarshan_core.engines.risk_engine import (
    calculate_risk_score,
    _count_observed_sample_behavior,
    _INCONCLUSIVE_STATUSES,
    _INCOMPLETE_DYNAMIC_STATUSES,
)
from sudarshan_core.engines.execution_assertions import (
    _OVERLAY_SIGNALS,
    build_execution_assertions,
)


class TestKrepCrashAndDynamicHardening(unittest.TestCase):
    """Regression tests for dynamic analysis crash diagnostics and static floor."""

    def test_frida_internal_dex_probe_filtered_in_on_message(self):
        """Verify that Frida's internal DEX and profile opens are filtered out of anti_analysis."""
        session = FridaSession("emulator-5554", "krep.itmtd.ywtjexf")

        # False anti-analysis event from Frida Gum loading its helper DEX
        internal_event = {
            "type": "event",
            "payload": {
                "category": "anti_analysis",
                "severity": "HIGH",
                "hook": "libc.open",
                "data": {
                    "hook": "libc.open",
                    "path": "/data/user/0/krep.itmtd.ywtjexf/code_cache/frida-129a28e8557a55ca04f86d634567ecb5.dex",
                    "description": "Internal DEX load",
                },
            },
        }
        session._on_message({"type": "send", "payload": internal_event}, None)
        self.assertEqual(len(session.collected_events["anti_analysis"]), 0)

        # Real anti-analysis event (e.g. checking su binary or emulator build properties)
        real_event = {
            "type": "event",
            "payload": {
                "category": "anti_analysis",
                "severity": "HIGH",
                "hook": "libc.open",
                "data": {
                    "hook": "libc.open",
                    "path": "/system/bin/su",
                    "description": "Root check",
                },
            },
        }
        session._on_message({"type": "send", "payload": real_event}, None)
        self.assertEqual(len(session.collected_events["anti_analysis"]), 1)

    def test_process_liveness_and_crash_info_structure(self):
        """Verify process liveness tracking and structured crash_info generation."""
        session = FridaSession("emulator-5554", "krep.itmtd.ywtjexf")
        session.target_pid = 20237
        session.liveness_checkpoints = {
            "1s": True,
            "2s": True,
            "5s": True,
            "10s": True,
            "30s": False,
        }

        # Mock adb pidof returning empty (process dead)
        with patch.object(session, "is_process_alive", return_value=False):
            with patch.object(session, "capture_logcat", return_value="Fatal signal 9 (SIGKILL) in pid 20237"):
                crash_info = session.get_crash_info()
                self.assertTrue(crash_info["detected"])
                self.assertEqual(crash_info["pid"], 20237)
                self.assertIn("SIGNAL", crash_info["type"])
                self.assertIn("1s", crash_info["details"]["liveness_checkpoints"])
                self.assertFalse(crash_info["details"]["liveness_checkpoints"]["30s"])

    def test_overlay_regex_does_not_falsely_match_krep_activity(self):
        """Verify _OVERLAY_SIGNALS does not trigger on UampleUverlayUhowUctivity classname."""
        activity_name = "krep.itmtd.ywtjexf.UampleUverlayUhowUctivity"
        match = _OVERLAY_SIGNALS.search(activity_name)
        self.assertIsNone(match, f"Regex falsely matched: {match}")

        # Legitimate overlay signals must still match
        self.assertIsNotNone(_OVERLAY_SIGNALS.search("WindowManager.addView"))
        self.assertIsNotNone(_OVERLAY_SIGNALS.search("TYPE_APPLICATION_OVERLAY"))
        self.assertIsNotNone(_OVERLAY_SIGNALS.search("SYSTEM_ALERT_WINDOW"))
        self.assertIsNotNone(_OVERLAY_SIGNALS.search("Found active overlay on screen"))

    def test_count_observed_sample_behavior_ignores_baseline_and_frida_files(self):
        """Verify baseline lifecycle calls and internal Frida DEX files do not count as conclusive evidence."""
        dynamic = {
            "api_calls": [
                "Activity.onResume",
                "ContextWrapper.getSharedPreferences",
            ],
            "files_accessed": [
                "/data/user/0/krep.itmtd.ywtjexf/code_cache/frida-129a28e8557a55ca.dex",
                "/data/misc/profiles/cur/0/krep.itmtd.ywtjexf/primary.prof",
            ],
            "frida_events": {
                "app_telemetry": [{"hook": "Activity.onResume"}],
                "smoke": [{"hook": "ContextWrapper.getSharedPreferences"}],
            },
        }
        count = _count_observed_sample_behavior(dynamic)
        self.assertEqual(count, 0, f"Expected 0 observed sample behaviors, got {count}")

    def test_static_floor_enforcement_on_incomplete_dynamic_run(self):
        """Verify that an incomplete/partial dynamic run NEVER lowers risk score below static score."""
        flags = {
            "stei": 50.0,
            "has_concealed_payload": False,
            "has_accessibility_abuse": False,
            "indian_bank_packages_found": [],
        }
        # Incomplete dynamic run that observed 1 incidental call but 0 fraud behavior (bfci = 0.0)
        dynamic_result = {
            "available": True,
            "dynamic_status": "PARTIAL",
            "api_calls": ["com.some.UncategorizedCall"],
            "bfci": 0.0,
            "bfci_components": {},
            "dynamic_coverage": {
                "dynamic_complete": False,
                "coverage_ratio": 0.10,
                "dynamic_status": "PARTIAL",
            },
        }

        # Calculate score with dynamic
        res = calculate_risk_score(
            flags=flags,
            dynamic_result=dynamic_result,
        )

        # Calculate static-only score
        res_static_only = calculate_risk_score(
            flags=flags,
            dynamic_result=None,
        )

        expected_static_score = res_static_only["final_risk_score"]
        self.assertEqual(res["final_risk_score"], expected_static_score)
        self.assertTrue(res["frs_breakdown"]["static_floor_applied"])
        self.assertEqual(res["frs_breakdown"]["static_floor_score"], expected_static_score)
        self.assertIn("Static floor enforced", res["frs_breakdown"]["static_floor_reason"])
        self.assertTrue(res["frs_breakdown"]["static_floor_applied"])
        self.assertEqual(res["frs_breakdown"]["static_floor_score"], expected_static_score)
        self.assertIn("Static floor enforced", res["frs_breakdown"]["static_floor_reason"])

    def test_dynamic_statuses_present_in_inconclusive_sets(self):
        """Verify CRASHED_BEFORE_EXPLORATION and BACKGROUND_SERVICE_RUNNING are recognized."""
        self.assertIn(DynamicAnalysisStatus.CRASHED_BEFORE_EXPLORATION.value, _INCONCLUSIVE_STATUSES)
        self.assertIn(DynamicAnalysisStatus.BACKGROUND_SERVICE_RUNNING.value, _INCONCLUSIVE_STATUSES)
        self.assertIn(DynamicAnalysisStatus.CRASHED_BEFORE_EXPLORATION.value, _INCOMPLETE_DYNAMIC_STATUSES)
        self.assertIn(DynamicAnalysisStatus.BACKGROUND_SERVICE_RUNNING.value, _INCOMPLETE_DYNAMIC_STATUSES)


if __name__ == "__main__":
    unittest.main()
