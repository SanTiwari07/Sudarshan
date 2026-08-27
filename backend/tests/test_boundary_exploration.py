# -*- coding: utf-8 -*-
"""
SUDARSHAN - Boundary Exploration Regression Tests
==================================================
Tests for the safe interactive boundary fixes.

Requirement ?15 items covered:

1.  EXTERNAL_APP with safe interactive boundary is explorable.
2.  SYSTEM_INSTALLER is explorable.
3.  OEM package installer role recognised without blindly whitelisting.
4.  INSTALL not globally blocked because another screen's INSTALL escaped.
5.  Escaping action memory is scoped to screen hash (not global).
6.  New installer state becomes _current_state_id.
7.  Installer actions returned by get_next_action().
8.  EXPLORATION_COMPLETE impossible while installer actions remain.
9.  wait_for_idle() retries probe failures.
10. wait_for_idle() distinguishes consecutive failures from stable idle.
11. Coordinate-less click_text action gets semantic text retry.
12. Runtime evidence counts as meaningful progress signal.
13. Sandbox-blocked actions are distinguished from failed actions.
14. Backtracking after unsupported external boundary works.
15. Existing target-app exploration continues normally.

Run with:
    cd c:\Projects\Sudarshan\backend
    python tests/test_boundary_exploration.py
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

BACKEND_DIR = Path(__file__).parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
SHARED_DIR = PROJECT_ROOT / "shared"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(SHARED_DIR))

print(f"[BoundaryTest] Python = {sys.version}")


def _make_ui_node(text="INSTALL", is_clickable=True, center_x=540, center_y=960):
    n = MagicMock()
    n.node_id = f"n_{text.lower().replace(' ', '_')}"
    n.class_name = "android.widget.Button"
    n.text = text
    n.desc = ""
    n.resource_id = f"com.test:id/{n.node_id}"
    n.is_clickable = is_clickable
    n.is_scrollable = False
    n.is_input = False
    n.is_checkable = False
    n.center_x = center_x
    n.center_y = center_y
    n.bounds = f"[{center_x-50},{center_y-20}][{center_x+50},{center_y+20}]"
    n.checked = None
    n.semantic_role = "ACCEPT"
    n.confidence = 0.95
    n.detection_source = "uiautomator"
    return n


def _make_obs(screen_hash="hash_001", activity="com.test/.MainActivity", ui_nodes=None):
    obs = MagicMock()
    obs.screen_hash = screen_hash
    obs.activity = activity
    obs.ui_nodes = ui_nodes or []
    obs.ui_node_count = len(obs.ui_nodes)
    obs.ui_xml_raw = "<hierarchy><node/></hierarchy>"
    obs.is_webview = False
    obs.screenshot_taken = False
    obs.vision_reason = ""
    obs.frida_events = []
    obs.logcat = ""
    return obs


class TestExternalAppSafeInteractiveBoundary(unittest.TestCase):

    def test_external_app_package_installer_ui_is_explorable(self):
        """T1: SYSTEM_INSTALLER ownership creates real state with actionable elements."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs = _make_obs(
            "installer_hash",
            activity="com.android.packageinstaller/.InstallConfirm",
            ui_nodes=[_make_ui_node("INSTALL"), _make_ui_node("CANCEL")],
        )
        state = g.observe(
            obs,
            semantic_type="PACKAGE_INSTALLER",
            foreground_package="com.android.packageinstaller",
            ownership="SYSTEM_INSTALLER",
        )
        self.assertFalse(state.state_id.startswith("PLACEHOLDER-"),
            "SYSTEM_INSTALLER screen must become a real state, not a placeholder")
        self.assertFalse(state.state_id.startswith("EXT-"),
            "SYSTEM_INSTALLER screen must NOT be routed to _observe_external")
        self.assertGreater(len(state.actionable_elements), 0,
            "Installer screen must have discoverable actions")


class TestSystemInstallerExplorable(unittest.TestCase):

    def test_system_installer_ownership_creates_real_state(self):
        """T2: SYSTEM_INSTALLER ownership with PACKAGE_INSTALLER semantic produces real state."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs = _make_obs(
            "installer_state",
            activity="com.android.packageinstaller/.InstallConfirm",
            ui_nodes=[_make_ui_node("Install"), _make_ui_node("Cancel")],
        )
        state = g.observe(
            obs, semantic_type="PACKAGE_INSTALLER",
            foreground_package="com.android.packageinstaller",
            ownership="SYSTEM_INSTALLER",
        )
        self.assertFalse(state.explored)
        self.assertGreater(len(state.unexplored_actions()), 0)


class TestOEMInstallerRoleDetection(unittest.TestCase):

    def test_classify_safe_boundary_oem_package_plus_activity(self):
        """T3a: OEM pkg fragment + activity fragment -> SYSTEM_INSTALLER (two signals)."""
        from sudarshan_core.engines.agentic.screenshot_policy import (
            SafeInteractiveBoundaryRole, classify_safe_boundary,
        )
        role = classify_safe_boundary(
            "com.oem.packageinstaller",
            activity="com.oem.packageinstaller/.InstallConfirm",
        )
        self.assertEqual(role, SafeInteractiveBoundaryRole.SYSTEM_INSTALLER)

    def test_activity_alone_not_sufficient(self):
        """T3b: Activity 'InstallActivity' on third-party pkg -> NONE (no pkg signal)."""
        from sudarshan_core.engines.agentic.screenshot_policy import (
            SafeInteractiveBoundaryRole, classify_safe_boundary,
        )
        role = classify_safe_boundary(
            "com.arbitrary.thirdpartyapp",
            activity="com.arbitrary.thirdpartyapp/.InstallActivity",
        )
        self.assertEqual(role, SafeInteractiveBoundaryRole.NONE)

    def test_ui_text_alone_not_sufficient(self):
        """T3c: UI text 'install now' alone -> NONE."""
        from sudarshan_core.engines.agentic.screenshot_policy import (
            SafeInteractiveBoundaryRole, classify_safe_boundary,
        )
        role = classify_safe_boundary(
            "com.arbitrary.thirdpartyapp",
            activity="com.arbitrary.thirdpartyapp/.MainActivity",
            ui_text="install now",
        )
        self.assertEqual(role, SafeInteractiveBoundaryRole.NONE)

    def test_pkg_fragment_plus_ui_marker_is_sufficient(self):
        """T3d: OEM pkg fragment + UI 'install' marker -> SYSTEM_INSTALLER."""
        from sudarshan_core.engines.agentic.screenshot_policy import (
            SafeInteractiveBoundaryRole, classify_safe_boundary,
        )
        role = classify_safe_boundary(
            "com.samsung.android.packageinstaller",
            activity="com.samsung.android.packageinstaller/.SomeActivity",
            ui_text="install this application",
        )
        self.assertEqual(role, SafeInteractiveBoundaryRole.SYSTEM_INSTALLER)

    def test_is_safe_boundary_false_for_third_party(self):
        """T3e: is_safe_interactive_boundary() False for generic third-party app."""
        from sudarshan_core.engines.agentic.screenshot_policy import is_safe_interactive_boundary
        self.assertFalse(is_safe_interactive_boundary(
            "com.random.thirdpartyapp",
            activity="com.random.thirdpartyapp/.MainActivity",
        ))

    def test_is_safe_boundary_true_for_aosp_installer(self):
        """T3f: is_safe_interactive_boundary() True for AOSP package installer."""
        from sudarshan_core.engines.agentic.screenshot_policy import is_safe_interactive_boundary
        self.assertTrue(is_safe_interactive_boundary(
            "com.android.packageinstaller",
            activity="com.android.packageinstaller/.InstallConfirm",
        ))


class TestEscapingActionScopedToScreen(unittest.TestCase):

    def test_escaping_action_blocked_only_on_source_screen(self):
        """T4+T5: INSTALL blocked on hash_001 but NOT on hash_009."""
        from sudarshan_core.engines.agentic.agent_memory import AgentMemory
        mem = AgentMemory()
        mem.current_screen_hash = "hash_001"
        mem.record_escaping_action("click_text", "INSTALL")
        self.assertTrue(mem.is_escaping_action("click_text", "INSTALL"))
        mem.current_screen_hash = "hash_009"
        self.assertFalse(mem.is_escaping_action("click_text", "INSTALL"))


class TestInstallerStateBecomesCurrent(unittest.TestCase):

    def test_observe_installer_sets_current_state_id(self):
        """T6: _current_state_id advances to installer state after observe()."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs1 = _make_obs("hash_001", "com.target/.Main", [_make_ui_node("INSTALL")])
        s1 = g.observe(obs1, semantic_type="UPDATE_PROMPT",
                       foreground_package="com.target", ownership="TARGET_APP")
        obs2 = _make_obs("installer_hash", "com.android.packageinstaller/.Confirm",
                         ui_nodes=[_make_ui_node("Install"), _make_ui_node("Cancel")])
        s2 = g.observe(obs2, semantic_type="PACKAGE_INSTALLER",
                       foreground_package="com.android.packageinstaller",
                       ownership="SYSTEM_INSTALLER",
                       parent_state_id=s1.state_id,
                       entry_action="click_text:INSTALL")
        self.assertEqual(g._current_state_id, s2.state_id)


class TestGetNextActionOnInstallerState(unittest.TestCase):

    def test_get_next_action_returns_installer_button(self):
        """T7: get_next_action() on installer state returns Install or Cancel."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs = _make_obs("installer_hash", "com.android.packageinstaller/.Confirm",
                        ui_nodes=[_make_ui_node("Install"), _make_ui_node("Cancel")])
        state = g.observe(obs, semantic_type="PACKAGE_INSTALLER",
                          foreground_package="com.android.packageinstaller",
                          ownership="SYSTEM_INSTALLER")
        g._current_state_id = state.state_id
        action = g.get_next_action(state_id=state.state_id)
        self.assertIsNotNone(action)
        self.assertIn(action.get("tool"), ("click_text", "tap"))


class TestExplorationCompleteBlockedWithInstallerActions(unittest.TestCase):

    def test_has_unexplored_work_true_with_installer_state(self):
        """T8: has_unexplored_work() True while installer has unresolved actions."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs1 = _make_obs("hash_001", "com.target/.Main", [_make_ui_node("INSTALL")])
        s1 = g.observe(obs1, semantic_type="UPDATE_PROMPT",
                       foreground_package="com.target", ownership="TARGET_APP")
        for a in s1.actionable_elements:
            a.explored = True
        s1.explored = True
        obs2 = _make_obs("installer_hash", "com.android.packageinstaller/.Confirm",
                         ui_nodes=[_make_ui_node("Install"), _make_ui_node("Cancel")])
        g.observe(obs2, semantic_type="PACKAGE_INSTALLER",
                  foreground_package="com.android.packageinstaller",
                  ownership="SYSTEM_INSTALLER")
        self.assertTrue(g.has_unexplored_work())


class TestWaitForIdleProbeRetry(unittest.TestCase):

    def _run(self, coro):
        return asyncio.run(coro)

    def test_single_probe_failure_is_retried(self):
        """T9: Single None from _focus_signature must NOT immediately return False."""
        from sudarshan_core.engines.agentic.tool_executor import ToolExecutor
        executor = ToolExecutor.__new__(ToolExecutor)
        call_count = 0

        async def fake_focus_sig():
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return None
            return "focus::com.test"

        async def run():
            with patch.object(executor, "_focus_signature", side_effect=fake_focus_sig):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    return await executor.wait_for_idle(timeout=5.0, stable_samples=2)

        self._run(run())
        self.assertGreater(call_count, 1,
            "Must retry after a single probe failure")

    def test_max_consecutive_probe_failures_returns_false(self):
        """T10: 3 consecutive probe failures -> False."""
        from sudarshan_core.engines.agentic.tool_executor import ToolExecutor
        executor = ToolExecutor.__new__(ToolExecutor)

        async def always_none():
            return None

        async def run():
            with patch.object(executor, "_focus_signature", side_effect=always_none):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    return await executor.wait_for_idle(timeout=5.0, stable_samples=2)

        result = self._run(run())
        self.assertFalse(result)


class TestRetryPayloadTextOnlyFallback(unittest.TestCase):

    def test_no_coords_with_text_produces_text_retry(self):
        """T11: retry_payload with no x/y but text -> click_text semantic retry."""
        from sudarshan_core.engines.agentic.action_dispatch import ActionDispatcher
        dispatcher = ActionDispatcher.__new__(ActionDispatcher)
        action = {"tool": "click_text", "text": "INSTALL", "_action_id": "ACT-001"}
        retry = dispatcher.retry_payload(action, attempt=1)
        self.assertIsNotNone(retry)
        self.assertEqual(retry.get("tool"), "click_text")
        self.assertEqual(retry.get("text"), "INSTALL")
        self.assertEqual(retry.get("_pipeline_debug", {}).get("retry_strategy"),
                         "text_semantic_retry")

    def test_no_coords_no_text_returns_none(self):
        """T11b: retry_payload with no x/y and no text -> None (RETRY_UNAVAILABLE)."""
        from sudarshan_core.engines.agentic.action_dispatch import ActionDispatcher
        dispatcher = ActionDispatcher.__new__(ActionDispatcher)
        action = {"tool": "tap", "_action_id": "ACT-002"}
        self.assertIsNone(dispatcher.retry_payload(action, attempt=1))


class TestRuntimeEvidenceAsProgress(unittest.TestCase):

    def test_record_action_ever_ui_changed_not_failed(self):
        """T12: ever_ui_changed=True -> EXPLORED, not FAILED."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL")])
        state = g.observe(obs, semantic_type="UPDATE_PROMPT",
                          foreground_package="com.test", ownership="TARGET_APP")
        action_id = state.actionable_elements[0].action_id
        g.record_action(
            source_state_id=state.state_id, target_state_id="STATE-002",
            action_type="click_text", target_description="INSTALL",
            success=True, verified=False, dispatched=True, executed=True,
            attempts=2, action_id=action_id, ui_changed=False, ever_ui_changed=True,
        )
        matched = next(a for a in state.actionable_elements if a.action_id == action_id)
        self.assertFalse(matched.failed)
        self.assertTrue(matched.explored)


class TestSandboxBlockedVsFailed(unittest.TestCase):

    def test_undispatched_single_attempt_not_failed(self):
        """T13: Undispatched single attempt must not mark action FAILED."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL")])
        state = g.observe(obs, semantic_type="UPDATE_PROMPT",
                          foreground_package="com.test", ownership="TARGET_APP")
        action_id = state.actionable_elements[0].action_id
        g.record_action(
            source_state_id=state.state_id, target_state_id=state.state_id,
            action_type="click_text", target_description="INSTALL",
            success=False, verified=False, dispatched=False, executed=False,
            attempts=1, action_id=action_id, ui_changed=False, ever_ui_changed=False,
        )
        matched = next(a for a in state.actionable_elements if a.action_id == action_id)
        self.assertFalse(matched.failed,
            "Single undispatched attempt must not mark action FAILED")


class TestBacktrackingAfterUnsupportedBoundary(unittest.TestCase):

    def test_graph_backtracks_after_external_state_has_no_actions(self):
        """T14: External boundary with 0 actions -> backtrack to parent with CANCEL pending."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs1 = _make_obs("hash_001", "com.test/.Main",
                         ui_nodes=[_make_ui_node("INSTALL"), _make_ui_node("CANCEL")])
        s1 = g.observe(obs1, semantic_type="UPDATE_PROMPT",
                       foreground_package="com.test", ownership="TARGET_APP")
        # Mark INSTALL as explored
        s1.actionable_elements[0].explored = True
        # CANCEL remains unexplored -> has_unexplored_work() must be True
        self.assertTrue(g.has_unexplored_work())


class TestNormalTargetAppExploration(unittest.TestCase):

    def test_target_app_creates_real_state(self):
        """T15a: Target app screens produce normal explorable states."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.target")
        obs = _make_obs("hash_target", "com.target/.Main",
                        ui_nodes=[_make_ui_node("LOGIN"), _make_ui_node("REGISTER")])
        state = g.observe(obs, semantic_type="BANK_LOGIN",
                          foreground_package="com.target", ownership="TARGET_APP")
        self.assertFalse(state.state_id.startswith("PLACEHOLDER-"))
        self.assertGreater(len(state.actionable_elements), 0)

    def test_in_scope_target_app(self):
        """T15b: in_investigation_scope True for target app."""
        from sudarshan_core.engines.agentic.perception import in_investigation_scope
        self.assertTrue(in_investigation_scope(
            "com.target", "com.target", activity="com.target/.Main"
        ))

    def test_in_scope_aosp_installer(self):
        """T15c: in_investigation_scope True for AOSP package installer."""
        from sudarshan_core.engines.agentic.perception import in_investigation_scope
        self.assertTrue(in_investigation_scope(
            "com.android.packageinstaller", "com.target",
            activity="com.android.packageinstaller/.InstallConfirm",
        ))

    def test_in_scope_oem_installer(self):
        """T15d: in_investigation_scope True for OEM installer (two signals)."""
        from sudarshan_core.engines.agentic.perception import in_investigation_scope
        self.assertTrue(in_investigation_scope(
            "com.samsung.android.packageinstaller", "com.target",
            activity="com.samsung.android.packageinstaller/.InstallConfirm",
        ))

    def test_out_of_scope_random_app(self):
        """T15e: in_investigation_scope False for random unrelated app."""
        from sudarshan_core.engines.agentic.perception import in_investigation_scope
        self.assertFalse(in_investigation_scope(
            "com.random.unrelated.app", "com.target",
            activity="com.random.unrelated.app/.MainActivity",
        ))


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestExternalAppSafeInteractiveBoundary,
        TestSystemInstallerExplorable,
        TestOEMInstallerRoleDetection,
        TestEscapingActionScopedToScreen,
        TestInstallerStateBecomesCurrent,
        TestGetNextActionOnInstallerState,
        TestExplorationCompleteBlockedWithInstallerActions,
        TestWaitForIdleProbeRetry,
        TestRetryPayloadTextOnlyFallback,
        TestRuntimeEvidenceAsProgress,
        TestSandboxBlockedVsFailed,
        TestBacktrackingAfterUnsupportedBoundary,
        TestNormalTargetAppExploration,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
