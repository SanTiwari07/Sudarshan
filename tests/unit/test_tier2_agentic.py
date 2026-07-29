"""
Unit Tests for Sudarshan Tier 2 Goal-Driven Autonomous Android Investigation Engine
======================================================================================
Validates ScreenClassifier, ScreenGraphBuilder, WorldModel, GoalPlanner,
CoverageTracker, and FallbackPlanner loop-prevention / action ranking logic.
"""

import time
import unittest
import sys
from pathlib import Path

# Ensure shared directory is in sys.path
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.coverage_tracker import CoverageTracker
from sudarshan_core.engines.agentic.goal_planner import (
    GoalGrantPermissions,
    GoalTriggerAccessibility,
    GoalTriggerLogin,
    get_all_goals,
)
from sudarshan_core.engines.agentic.perception import Observation, UINode
from sudarshan_core.engines.agentic.planner import FallbackPlanner
from sudarshan_core.engines.agentic.screen_classifier import ScreenType, classify_screen
from sudarshan_core.engines.agentic.screen_graph import ScreenGraphBuilder, compute_screen_hash
from sudarshan_core.engines.agentic.world_model import WorldModel


class TestScreenClassifier(unittest.TestCase):
    def test_accessibility_classification(self):
        nodes = [UINode("n0", "android.widget.TextView", "Enable Accessibility Service", "", "", 100, 100, False, True, False, "[0,0][200,200]")]
        res = classify_screen("com.example/com.example.AccessibilityActivity", nodes)
        self.assertEqual(res.screen_type, ScreenType.ACCESSIBILITY_DIALOG)

    def test_bank_login_classification(self):
        nodes = [
            UINode("n0", "android.widget.EditText", "Enter User ID", "", "", 100, 100, True, True, False, "[0,0][200,50]"),
            UINode("n1", "android.widget.Button", "Login", "", "", 100, 200, False, True, False, "[0,100][200,150]"),
        ]
        res = classify_screen("com.example/com.example.LoginActivity", nodes)
        self.assertEqual(res.screen_type, ScreenType.BANK_LOGIN)

    def test_otp_classification(self):
        nodes = [UINode("n0", "android.widget.TextView", "Enter 6-digit OTP code", "", "", 100, 100, False, True, False, "[0,0][200,200]")]
        res = classify_screen("com.example/com.example.VerifyActivity", nodes)
        self.assertEqual(res.screen_type, ScreenType.OTP_SCREEN)


class TestScreenGraphAndWorldModel(unittest.TestCase):
    def test_screen_hash_consistency(self):
        nodes = [UINode("n0", "android.widget.Button", "Submit", "", "", 100, 100, False, True, False, "[0,0][100,100]")]
        h1 = compute_screen_hash("com.app/com.app.MainActivity", nodes)
        h2 = compute_screen_hash("com.app/com.app.MainActivity", nodes)
        self.assertEqual(h1, h2)

    def test_loop_detection(self):
        sg = ScreenGraphBuilder()
        nodes = [UINode("n0", "android.widget.Button", "LoopButton", "", "", 100, 100, False, True, False, "[0,0][100,100]")]

        for _ in range(4):
            sg.process_observation("com.app/com.app.LoopActivity", "com.app", nodes)

        h = compute_screen_hash("com.app/com.app.LoopActivity", nodes)
        self.assertTrue(sg.is_loop_detected(h, max_visits=3, window=5))

    def test_world_model_failed_action(self):
        wm = WorldModel(package_name="com.app")
        wm.record_failed_action("hash123", "n0")
        self.assertTrue(wm.is_action_failed("hash123", "n0"))
        self.assertFalse(wm.is_action_failed("hash123", "n1"))


class TestGoalPlanner(unittest.TestCase):
    def test_goals_candidate_actions(self):
        goals = get_all_goals()
        self.assertGreaterEqual(len(goals), 4)

        wm = WorldModel(package_name="com.app")
        nodes = [UINode("n0", "android.widget.Button", "Allow Permission", "", "", 100, 100, False, True, False, "[0,0][100,100]")]
        node = wm.update_observation("com.app/com.app.PermissionActivity", "com.app", nodes)

        cand = goals[0].candidate_actions(wm, node, nodes)
        self.assertEqual(len(cand), 1)
        self.assertEqual(cand[0].action_type, "click")
        self.assertIn("Allow", cand[0].target_label)


class TestCoverageTracker(unittest.TestCase):
    def test_metrics_collection(self):
        tracker = CoverageTracker()
        tracker.update_screens(10, 8)
        tracker.record_action_executed("n0")
        tracker.record_loop_broken()

        summary = tracker.get_summary()
        self.assertEqual(summary["total_screens_discovered"], 10)
        self.assertEqual(summary["unique_screens_visited"], 8)
        self.assertEqual(summary["exploration_coverage_percent"], 80.0)
        self.assertEqual(summary["loops_detected_and_broken"], 1)


class TestFallbackPlannerTier2(unittest.TestCase):
    def test_loop_break_action(self):
        planner = FallbackPlanner()
        obs = Observation(
            activity="com.app/com.app.LoopActivity",
            ui_nodes=[UINode("n0", "android.widget.Button", "Repeat", "", "", 100, 100, False, True, False, "[0,0][100,100]")],
        )

        class MockGoals:
            def next_priority_goal(self): return None

        # Simulate 4 visits to trigger loop
        for _ in range(3):
            planner.decide(obs, None, MockGoals())

        # 4th decision should trigger loop breaker press_back
        action = planner.decide(obs, None, MockGoals())
        self.assertIsNotNone(action)
        self.assertEqual(action["tool"], "press_back")
        self.assertEqual(action["_source"], "loop_breaker")


if __name__ == "__main__":
    unittest.main()
