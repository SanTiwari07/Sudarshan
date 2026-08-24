"""Runtime lifecycle tracing and explorer stage bootstrap."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.investigation_controller import (
    InvestigationController,
    InvestigationState,
)
from sudarshan_core.engines.runtime_lifecycle import RuntimeLifecycleTracker
from sudarshan_core.engines.risk_engine import reconcile_frs_breakdown


class TestRuntimeLifecycleTracker(unittest.TestCase):
    def test_records_events_and_summary(self) -> None:
        tracker = RuntimeLifecycleTracker(case_id="abc123")
        tracker.mark_requested()
        tracker.record("emulator_ready", "READY", "sandbox", "serial=emulator-5554")
        summary = tracker.to_summary_dict()
        self.assertTrue(summary["dynamic_requested"])
        self.assertEqual(summary["emulator_status"], "UNKNOWN")
        self.assertEqual(len(summary["events"]), 2)

    def test_attach_marks_runtime_attempted_when_emulator_ready(self) -> None:
        tracker = RuntimeLifecycleTracker(case_id="sha")
        tracker.mark_requested()
        tracker.emulator_status = "READY"
        result: dict = {"available": False}
        tracker.attach_to_result(result)
        self.assertTrue(result["runtime_requested"])
        self.assertTrue(result["runtime_attempted"])


class TestExplorerStartsInteractive(unittest.TestCase):
    def test_frida_launch_skips_read_only_stages(self) -> None:
        ctrl = InvestigationController(package_name="com.test.app")
        self.assertEqual(ctrl.state, InvestigationState.BOOTSTRAP)
        ctrl.transition_to(
            InvestigationState.INITIAL_OBSERVATION,
            "target app launched by Frida session before explorer start",
        )
        self.assertEqual(ctrl.state, InvestigationState.INITIAL_OBSERVATION)
        self.assertIn("tap", ctrl.allowed_actions())


class TestRuntimeFailureNotCollapsed(unittest.TestCase):
    def test_emulator_unavailable_exclusion_reason(self) -> None:
        frs = {"axes_excluded": ["dynamic", "correlation"], "dynamic_ran": False}
        dyn = {
            "available": False,
            "runtime_requested": True,
            "runtime_attempted": False,
            "dynamic_status": "EMULATOR_UNAVAILABLE",
            "error": "No device",
        }
        out = reconcile_frs_breakdown(frs, dyn)
        self.assertIsNotNone(out)
        self.assertFalse(out["dynamic_conclusive"])
        self.assertEqual(out["dynamic_exclusion_reason"], "DYNAMIC_UNAVAILABLE")

    def test_frida_attach_failure_is_dynamic_ran(self) -> None:
        frs = {"axes_excluded": ["dynamic"], "dynamic_ran": False}
        dyn = {
            "available": True,
            "runtime_requested": True,
            "runtime_attempted": True,
            "dynamic_status": "FRIDA_ATTACH_FAILED",
            "error": "attach failed",
        }
        out = reconcile_frs_breakdown(frs, dyn)
        self.assertTrue(out["dynamic_ran"])
        self.assertFalse(out["dynamic_conclusive"])
        self.assertEqual(out["dynamic_exclusion_reason"], "FRIDA_ATTACH_FAILED")


if __name__ == "__main__":
    unittest.main()
