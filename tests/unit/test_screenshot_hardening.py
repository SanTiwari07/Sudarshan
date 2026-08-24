"""
Regression tests for screenshot hardening (second-phase fix).

Verifies:
  - Home screen screenshot spam elimination
  - External app deduplication
  - Permission dialog deduplication
  - Same screen + new event (screenshot reuse)
  - Crash handling
  - State/event-aware deduplication (not time-only)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.screenshot_policy import (
    ScreenshotPolicy,
    ScreenshotRequest,
    ScreenshotDecision,
    ScreenOwnership,
    resolve_screen_ownership,
    LAUNCHER_PACKAGES,
)
from sudarshan_core.engines.agentic.screen_classifier import (
    classify_screen_with_ownership,
    is_explorable_screen_type,
    should_invoke_planner,
    ScreenType,
)
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
from sudarshan_core.engines.agentic.perception import UINode, Observation


def _node(text: str, node_id: str = "n0") -> UINode:
    return UINode(
        node_id=node_id,
        class_name="android.widget.Button",
        text=text,
        desc="",
        resource_id="",
        center_x=100,
        center_y=200,
        is_input=False,
        is_clickable=True,
        is_scrollable=False,
        bounds="[0,0][200,100]",
    )


TARGET = "com.example.malware"
LAUNCHER = "com.android.launcher3"
INSTALLER = "com.android.packageinstaller"


class TestScreenOwnership(unittest.TestCase):
    def test_launcher_is_home_launcher(self):
        ow = resolve_screen_ownership(LAUNCHER, TARGET, f"{LAUNCHER}/.Launcher")
        self.assertEqual(ow, ScreenOwnership.HOME_LAUNCHER)

    def test_target_app_foreground(self):
        ow = resolve_screen_ownership(TARGET, TARGET, f"{TARGET}/.MainActivity")
        self.assertEqual(ow, ScreenOwnership.TARGET_APP)

    def test_installer_is_system_installer(self):
        ow = resolve_screen_ownership(INSTALLER, TARGET, f"{INSTALLER}/.InstallApp")
        self.assertEqual(ow, ScreenOwnership.SYSTEM_INSTALLER)

    def test_chrome_is_external(self):
        ow = resolve_screen_ownership("com.android.chrome", TARGET, "com.android.chrome/.Main")
        self.assertEqual(ow, ScreenOwnership.EXTERNAL_APP)

    def test_nexus_launcher_in_set(self):
        self.assertIn("com.google.android.apps.nexuslauncher", LAUNCHER_PACKAGES)


class TestScreenClassifierOwnership(unittest.TestCase):
    def test_home_launcher_classification(self):
        nodes = [_node("App 1"), _node("App 2")]
        res = classify_screen_with_ownership(
            f"{LAUNCHER}/.Launcher", nodes, "", TARGET, LAUNCHER,
        )
        self.assertEqual(res.screen_type, ScreenType.HOME_LAUNCHER)
        self.assertEqual(res.ownership, ScreenOwnership.HOME_LAUNCHER.value)

    def test_home_not_explorable(self):
        self.assertFalse(is_explorable_screen_type(ScreenType.HOME_LAUNCHER))
        self.assertFalse(is_explorable_screen_type(ScreenType.CRASH_STATE))
        self.assertFalse(is_explorable_screen_type(ScreenType.EXTERNAL_APP))

    def test_target_app_explorable(self):
        self.assertTrue(is_explorable_screen_type(ScreenType.UNKNOWN))
        self.assertTrue(is_explorable_screen_type(ScreenType.UPDATE_PROMPT))

    def test_planner_skipped_for_home(self):
        self.assertFalse(should_invoke_planner(ScreenType.HOME_LAUNCHER))
        self.assertFalse(should_invoke_planner(ScreenType.CRASH_STATE))
        self.assertTrue(should_invoke_planner(ScreenType.UPDATE_PROMPT))


class TestHomeScreenshotSpam(unittest.TestCase):
    """Test case 38: crash -> home -> 100 polls -> max 1 home screenshot."""

    def test_repeated_home_suppressed(self):
        policy = ScreenshotPolicy(target_package=TARGET)
        home_hash = "abc123homehash"

        captures = 0
        for i in range(100):
            req = ScreenshotRequest(
                reason="EXPLORER_ACTION",
                foreground_package=LAUNCHER,
                target_package=TARGET,
                activity=f"{LAUNCHER}/.Launcher",
                screen_hash=home_hash,
                ownership=ScreenOwnership.HOME_LAUNCHER,
                transition_event="TARGET_APP_EXITED_TO_HOME" if i == 0 else "",
            )
            decision, reason, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1
                policy.register_capture(
                    f"SCR-{captures:03d}",
                    ScreenOwnership.HOME_LAUNCHER,
                    home_hash,
                )

        self.assertLessEqual(captures, 1, f"Home screenshots must be <= 1, got {captures}")

        stats = policy.get_statistics()
        self.assertGreater(stats["suppressed"], 90)
        self.assertEqual(stats["observation_counts"].get("HOME_LAUNCHER", 0), 100)

    def test_home_observation_count_in_graph(self):
        graph = ExplorationGraph(TARGET)
        obs = Observation(
            activity=f"{LAUNCHER}/.Launcher",
            ui_nodes=[_node("App")],
            screen_hash="homehash1",
        )
        for _ in range(50):
            graph.observe(
                obs,
                semantic_type=ScreenType.HOME_LAUNCHER,
                foreground_package=LAUNCHER,
                ownership=ScreenOwnership.HOME_LAUNCHER.value,
            )
        self.assertEqual(graph._home_observation_count, 50)
        # Home should not inflate target state count
        target_states = [
            s for s in graph.states.values()
            if s.ownership == "TARGET_APP"
        ]
        self.assertEqual(len(target_states), 0)


class TestExternalAppDeduplication(unittest.TestCase):
    """Test case 39: package installer unchanged for 50 polls -> 1 screenshot."""

    def test_installer_deduplicated(self):
        policy = ScreenshotPolicy(target_package=TARGET)
        inst_hash = "installer_hash_abc"

        captures = 0
        for i in range(50):
            req = ScreenshotRequest(
                reason="PACKAGE_INSTALLER",
                foreground_package=INSTALLER,
                target_package=TARGET,
                activity=f"{INSTALLER}/.InstallApp",
                screen_hash=inst_hash,
                ownership=ScreenOwnership.SYSTEM_INSTALLER,
            )
            decision, _, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1
                policy.register_capture(
                    f"SCR-{captures:03d}",
                    ScreenOwnership.SYSTEM_INSTALLER,
                    inst_hash,
                )

        self.assertEqual(captures, 1)
        stats = policy.get_statistics()
        self.assertGreater(stats["suppressed"], 40)

    def test_external_in_separate_graph(self):
        graph = ExplorationGraph(TARGET)
        obs = Observation(
            activity=f"{INSTALLER}/.InstallApp",
            ui_nodes=[_node("Install"), _node("Cancel")],
            screen_hash="insthash",
        )
        state = graph.observe(
            obs,
            semantic_type=ScreenType.EXTERNAL_APK,
            foreground_package=INSTALLER,
            ownership=ScreenOwnership.SYSTEM_INSTALLER.value,
        )
        self.assertTrue(state.state_id.startswith("EXT-"))
        self.assertEqual(len(graph.external_states), 1)
        self.assertEqual(len(graph.states), 0)


class TestPermissionDeduplication(unittest.TestCase):
    """Test case 40: same permission dialog 20 times -> 1 screenshot."""

    def test_permission_once(self):
        policy = ScreenshotPolicy(target_package=TARGET)
        perm_hash = "perm_dialog_hash"

        captures = 0
        for _ in range(20):
            req = ScreenshotRequest(
                reason="PERMISSION_DIALOG",
                foreground_package="com.android.permissioncontroller",
                target_package=TARGET,
                screen_hash=perm_hash,
                semantic_type="SYSTEM_PERMISSION",
                ownership=ScreenOwnership.SYSTEM_PERMISSION,
            )
            decision, _, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1
                policy.register_capture(
                    f"SCR-{captures:03d}",
                    ScreenOwnership.SYSTEM_PERMISSION,
                    perm_hash,
                )

        self.assertEqual(captures, 1)


class TestSameScreenNewEvent(unittest.TestCase):
    """Test case 41: same screen + Frida events -> events recorded, screenshot reused."""

    def test_reuse_on_identical_screen(self):
        policy = ScreenshotPolicy(target_package=TARGET)
        screen_hash = "target_screen_abc"

        # First capture
        req1 = ScreenshotRequest(
            reason="EXPLORER_ACTION",
            foreground_package=TARGET,
            target_package=TARGET,
            screen_hash=screen_hash,
            ownership=ScreenOwnership.TARGET_APP,
        )
        d1, _, _ = policy.should_capture(req1)
        self.assertEqual(d1, ScreenshotDecision.CAPTURE)
        policy.register_capture("SCR-001", ScreenOwnership.TARGET_APP, screen_hash)

        # Second observation same screen - should reuse
        req2 = ScreenshotRequest(
            reason="EXPLORER_ACTION",
            foreground_package=TARGET,
            target_package=TARGET,
            screen_hash=screen_hash,
            ownership=ScreenOwnership.TARGET_APP,
        )
        d2, reason2, reuse_id = policy.should_capture(req2)
        self.assertIn(d2, (ScreenshotDecision.REUSE, ScreenshotDecision.SUPPRESSED))
        if d2 == ScreenshotDecision.REUSE:
            self.assertEqual(reuse_id, "SCR-001")


class TestNewScreenCapture(unittest.TestCase):
    """Test case 42: STATE_A -> click -> STATE_B -> both get screenshots."""

    def test_different_states_captured(self):
        policy = ScreenshotPolicy(target_package=TARGET)

        req_a = ScreenshotRequest(
            reason="EXPLORER_ACTION",
            foreground_package=TARGET,
            screen_hash="state_a_hash",
            ownership=ScreenOwnership.TARGET_APP,
        )
        d_a, _, _ = policy.should_capture(req_a)
        self.assertEqual(d_a, ScreenshotDecision.CAPTURE)
        policy.register_capture("SCR-001", ScreenOwnership.TARGET_APP, "state_a_hash")

        req_b = ScreenshotRequest(
            reason="EXPLORER_ACTION",
            foreground_package=TARGET,
            screen_hash="state_b_hash",
            ownership=ScreenOwnership.TARGET_APP,
        )
        d_b, _, _ = policy.should_capture(req_b)
        self.assertEqual(d_b, ScreenshotDecision.CAPTURE)


class TestCrashHandling(unittest.TestCase):
    """Test case 43: crash -> one screenshot, home not spammed."""

    def test_crash_once(self):
        policy = ScreenshotPolicy(target_package=TARGET)

        captures = 0
        for i in range(10):
            req = ScreenshotRequest(
                reason="APP_CRASH",
                foreground_package=TARGET,
                target_package=TARGET,
                activity=f"{TARGET}/.CrashActivity",
                state_id="STATE-12",
                action_id="ACT-05",
                ownership=ScreenOwnership.CRASH_STATE,
            )
            decision, _, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1

        self.assertEqual(captures, 1)

    def test_crash_recorded_in_graph(self):
        graph = ExplorationGraph(TARGET)
        obs = Observation(
            activity=f"{TARGET}/.CrashActivity has stopped",
            ui_nodes=[],
            screen_hash="crashhash",
        )
        state = graph.observe(
            obs,
            semantic_type=ScreenType.CRASH_STATE,
            foreground_package=TARGET,
            ownership=ScreenOwnership.CRASH_STATE.value,
        )
        self.assertEqual(len(graph._crash_events), 1)
        self.assertEqual(graph._crash_events[0]["event_type"], "APP_CRASH")


class TestLongRunBounded(unittest.TestCase):
    """Test case 45: 500 observation cycles, home bounded."""

    def test_bounded_screenshots(self):
        policy = ScreenshotPolicy(target_package=TARGET)
        home_hash = "stable_home"

        captures = 0
        for cycle in range(500):
            is_home = cycle % 3 == 0  # 167 home observations
            if is_home:
                req = ScreenshotRequest(
                    reason="EXPLORER_ACTION",
                    foreground_package=LAUNCHER,
                    screen_hash=home_hash,
                    ownership=ScreenOwnership.HOME_LAUNCHER,
                    transition_event="TARGET_APP_EXITED_TO_HOME" if cycle == 0 else "",
                )
            else:
                req = ScreenshotRequest(
                    reason="EXPLORER_ACTION",
                    foreground_package=TARGET,
                    screen_hash=f"target_{cycle % 5}",
                    ownership=ScreenOwnership.TARGET_APP,
                )
            decision, _, _ = policy.should_capture(req)
            if decision == ScreenshotDecision.CAPTURE:
                captures += 1
                ow = req.ownership
                policy.register_capture(f"SCR-{captures:03d}", ow, req.screen_hash)

        stats = policy.get_statistics()
        self.assertLessEqual(captures, 10, f"Expected bounded captures, got {captures}")
        self.assertGreater(stats["suppressed"] + stats.get("reused", 0), 400)


class TestScreenshotManagerPolicyIntegration(unittest.TestCase):
    """Verify ScreenshotManager routes through policy."""

    def test_suppressed_returns_none(self):
        from sudarshan_core.engines.screenshot_manager import ScreenshotManager

        with patch("sudarshan_core.sandbox.get_sandbox_provider") as mock_prov:
            mock_prov.return_value.adb.return_value = (True, "")
            mgr = ScreenshotManager(
                device_serial="emulator-5554",
                output_dir=Path("/tmp/test_ss"),
                package_name=TARGET,
            )

            # First home transition may capture (needs adb mock for actual capture)
            # Test policy integration directly
            stats_before = mgr.get_policy_statistics()
            self.assertEqual(stats_before["total_requests"], 0)

            # Suppress repeated home
            for i in range(10):
                mgr.capture(
                    label="home_test",
                    reason="EXPLORER_ACTION",
                    foreground_package=LAUNCHER,
                    layout_hash="same_home",
                    semantic_type=ScreenType.HOME_LAUNCHER,
                    transition_event="TARGET_APP_EXITED_TO_HOME" if i == 0 else "",
                )

            stats = mgr.get_policy_statistics()
            self.assertEqual(stats["total_requests"], 10)
            self.assertGreater(stats["suppressed"], 5)


if __name__ == "__main__":
    unittest.main()
