"""
SUDARSHAN — Deep Exploration Regression Tests
==============================================
Tests that target the exact failure chain that caused the explorer to stop
prematurely before exhausting actionable UI.

Root cause chain (fixed):
  INSTALL tapped
    -> wait_for_idle() fires on window focus (Activity unchanged)
    -> post-action observe runs while content is still animating
    -> ui_changed = False on first observe
    -> 3 retries -> all ui_changed=False
    -> record_action(success=True, verified=False)
    -> action.execution_attempts >= max_attempts -> action.failed = True
    -> unexplored_actions() = []
    -> get_next_action() = None
    -> EXPLORATION STOPS

Run with:
    cd c:\Projects\Sudarshan\backend
    python tests/test_deep_exploration_regression.py
"""

from __future__ import annotations

import sys
import asyncio
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Path bootstrap
BACKEND_DIR = Path(__file__).parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
SHARED_DIR = PROJECT_ROOT / "shared"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(SHARED_DIR))

print(f"[RegressionTest] sys.path[0:2] = {sys.path[0:2]}")
print(f"[RegressionTest] Python = {sys.version}")


# Helpers

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


# PART 1: record_action ever_ui_changed

class TestRecordActionEverUiChanged(unittest.TestCase):

    def setUp(self):
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        self.graph = ExplorationGraph(package_name="com.test")
        node = _make_ui_node("INSTALL")
        obs = _make_obs(ui_nodes=[node])
        self.state = self.graph.observe(
            obs, semantic_type="UPDATE_PROMPT",
            foreground_package="com.test", ownership="TARGET_APP",
        )
        self.state_id = self.state.state_id
        self.action_id = self.state.actionable_elements[0].action_id

    def test_action_marked_explored_when_ever_ui_changed_true(self):
        """T1: ADB succeeded + final ui_changed=False + ever_ui_changed=True => EXPLORED."""
        self.graph.record_action(
            source_state_id=self.state_id,
            target_state_id=self.state_id,
            action_type="click_text",
            target_description="INSTALL",
            success=True, verified=False, dispatched=True, executed=True,
            attempts=3, action_id=self.action_id,
            ui_changed=False, ever_ui_changed=True,
        )
        action = next(a for a in self.state.actionable_elements if a.action_id == self.action_id)
        self.assertTrue(action.explored, "explored must be True when ever_ui_changed=True")
        self.assertFalse(action.failed,  "failed must be False when ever_ui_changed=True")

    def test_action_marked_failed_only_when_ui_never_changed(self):
        """T4: ADB succeeded but UI never changed at all => FAILED after max attempts."""
        self.graph.record_action(
            source_state_id=self.state_id,
            target_state_id=self.state_id,
            action_type="click_text",
            target_description="INSTALL",
            success=True, verified=False, dispatched=True, executed=True,
            attempts=3, action_id=self.action_id,
            ui_changed=False, ever_ui_changed=False,
        )
        action = next(a for a in self.state.actionable_elements if a.action_id == self.action_id)
        self.assertTrue(action.failed,  "failed must be True when UI never changed")
        self.assertFalse(action.explored, "explored must be False for a truly failed action")

    def test_record_action_with_ui_changed_true_marks_explored(self):
        """T8: Happy path - ADB success + verified=True => explored."""
        self.graph.record_action(
            source_state_id=self.state_id,
            target_state_id="STATE-002",
            action_type="click_text",
            target_description="INSTALL",
            success=True, verified=True, dispatched=True, executed=True,
            attempts=1, action_id=self.action_id,
            ui_changed=True, ever_ui_changed=True,
        )
        action = next(a for a in self.state.actionable_elements if a.action_id == self.action_id)
        self.assertTrue(action.explored)
        self.assertTrue(action.verified)
        self.assertFalse(action.failed)


# PART 2: Graph navigation

class TestExplorationGraphNavigation(unittest.TestCase):

    def _two_state_graph(self):
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs1 = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL")])
        s1 = g.observe(obs1, semantic_type="UPDATE_PROMPT",
                       foreground_package="com.test", ownership="TARGET_APP")
        obs2 = _make_obs("hash_002", activity="com.test/.PostInstall",
                         ui_nodes=[_make_ui_node("CONTINUE"), _make_ui_node("SKIP")])
        s2 = g.observe(obs2, semantic_type="HOME", foreground_package="com.test",
                       ownership="TARGET_APP", parent_state_id=s1.state_id,
                       entry_action="click_text:INSTALL")
        return g, s1, s2

    def test_exploration_graph_continues_after_install_action(self):
        """T2: After INSTALL explored and cursor at STATE-002, get_next_action returns STATE-002 action."""
        g, s1, s2 = self._two_state_graph()
        s1.actionable_elements[0].explored = True
        g._current_state_id = s2.state_id

        action = g.get_next_action(state_id=s2.state_id)
        self.assertIsNotNone(action, "Must return action from STATE-002")
        self.assertIn(action.get("text"), ("CONTINUE", "SKIP"))

    def test_get_next_action_follows_current_state_not_pre_action(self):
        """T3: Without explicit state_id, get_next_action uses _current_state_id."""
        g, s1, s2 = self._two_state_graph()
        s1.actionable_elements[0].explored = True
        g._current_state_id = s2.state_id

        action = g.get_next_action()
        self.assertIsNotNone(action, "get_next_action() must use _current_state_id=STATE-002")

    def test_has_unexplored_work_true_with_pending_new_state(self):
        """T5: STATE-001 exhausted, STATE-002 has pending => has_unexplored_work=True."""
        g, s1, s2 = self._two_state_graph()
        for a in s1.actionable_elements:
            a.explored = True
        s1.explored = True

        self.assertTrue(g.has_unexplored_work())

    def test_backtrack_reaches_parent_with_unexplored_sibling(self):
        """T6: STATE-002 exhausted => backtrack returns press_back to STATE-001 (CANCEL pending)."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs1 = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL"), _make_ui_node("CANCEL")])
        s1 = g.observe(obs1, semantic_type="UPDATE_PROMPT",
                       foreground_package="com.test", ownership="TARGET_APP")
        s1.actionable_elements[0].explored = True   # INSTALL done, CANCEL pending

        obs2 = _make_obs("hash_002", ui_nodes=[_make_ui_node("DONE")])
        s2 = g.observe(obs2, semantic_type="HOME", foreground_package="com.test",
                       ownership="TARGET_APP", parent_state_id=s1.state_id)
        for a in s2.actionable_elements:
            a.explored = True
        s2.explored = True

        g._current_state_id = s2.state_id
        action = g.get_next_action(state_id=s2.state_id)
        self.assertIsNotNone(action, "Must backtrack from exhausted STATE-002")
        self.assertEqual(action.get("tool"), "press_back",
            f"Expected press_back backtrack, got: {action.get('tool')}")


# PART 3: select_canonical_action

class TestCanonicalActionSelection(unittest.TestCase):

    def test_graph_action_wins_over_none_planner(self):
        """T7: Graph click_text:INSTALL selected when planner returns None."""
        from sudarshan_core.engines.agentic.action_dispatch import select_canonical_action
        graph_action = {
            "tool": "click_text", "text": "INSTALL",
            "goal": "DEEP_EXPLORATION", "reasoning": "Explore INSTALL",
            "confidence": 0.95, "_source": "exploration_engine",
            "_action_id": "ACT-001", "_state_id": "STATE-001",
        }
        action, source = select_canonical_action(graph_action, None)
        self.assertIsNotNone(action)
        self.assertEqual(action.get("tool"), "click_text")
        self.assertEqual(action.get("text"), "INSTALL")
        self.assertIn(source, ("exploration_graph",))


# PART 4: Content settle

class TestContentSettleDelay(unittest.TestCase):

    def test_content_settle_constant_exists_and_positive(self):
        """T9: CONTENT_SETTLE_SECONDS must exist and be > 0."""
        from sudarshan_core.engines.agentic_explorer import CONTENT_SETTLE_SECONDS
        self.assertGreater(CONTENT_SETTLE_SECONDS, 0.0)
        self.assertIsInstance(CONTENT_SETTLE_SECONDS, float)

    def test_successful_action_no_immediate_ui_change_not_failed(self):
        """T11 (user-requested): ADB success + ui_changed=False on first observe + ever_ui_changed=True => NOT FAILED."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL")])
        state = g.observe(obs, semantic_type="UPDATE_PROMPT",
                          foreground_package="com.test", ownership="TARGET_APP")
        action_id = state.actionable_elements[0].action_id

        g.record_action(
            source_state_id=state.state_id,
            target_state_id="STATE-002",
            action_type="click_text", target_description="INSTALL",
            success=True, verified=False, dispatched=True, executed=True,
            attempts=2, action_id=action_id,
            ui_changed=False,       # last sample: same hash (mid-transition)
            ever_ui_changed=True,   # attempt 2 saw change
        )
        matched = next(a for a in state.actionable_elements if a.action_id == action_id)
        self.assertFalse(matched.failed,
            "Must not be FAILED when ever_ui_changed=True")
        self.assertTrue(matched.explored,
            "Must be EXPLORED when UI changed at some attempt")


# PART 5: Stop diagnostics

class TestStopDiagnostics(unittest.TestCase):

    def test_stop_reason_set_when_graph_exhausted(self):
        """T10: stop_reason surfaces in coverage_metrics after all work done."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, StopReason
        g = ExplorationGraph(package_name="com.test")
        obs = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL")])
        state = g.observe(obs, semantic_type="UPDATE_PROMPT",
                          foreground_package="com.test", ownership="TARGET_APP")
        for a in state.actionable_elements:
            a.explored = True
        state.explored = True

        self.assertFalse(g.has_unexplored_work())
        g.stop_reason = StopReason.EXPLORATION_COMPLETE
        metrics = g.coverage_metrics()
        self.assertEqual(metrics["stop_reason"], StopReason.EXPLORATION_COMPLETE.value)

    def test_coverage_metrics_has_unresolved_count(self):
        """Unresolved count must appear in coverage_metrics for STOP log lines."""
        from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph
        g = ExplorationGraph(package_name="com.test")
        obs = _make_obs("hash_001", ui_nodes=[_make_ui_node("INSTALL"), _make_ui_node("CANCEL")])
        g.observe(obs, semantic_type="UPDATE_PROMPT",
                  foreground_package="com.test", ownership="TARGET_APP")
        metrics = g.coverage_metrics()
        self.assertIn("actionable_elements_unresolved", metrics)
        self.assertEqual(metrics["actionable_elements_unresolved"], 2)


# RUNNER

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestRecordActionEverUiChanged,
        TestExplorationGraphNavigation,
        TestCanonicalActionSelection,
        TestContentSettleDelay,
        TestStopDiagnostics,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
