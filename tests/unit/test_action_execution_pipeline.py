"""
Regression tests: discovery must travel all the way to an Android interaction.

These tests fail if a candidate is classified but never dispatched, or if
ADB "success" is treated as verified without a UI change.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import List

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.action_dispatch import (
    ActionDispatcher,
    MAX_EXECUTION_ATTEMPTS,
    screenshot_coords_to_device,
    select_canonical_action,
    semantic_role_to_executable,
)
from sudarshan_core.engines.agentic.exploration_engine import (
    ActionItem,
    ExplorationGraph,
)
from sudarshan_core.engines.agentic.perception import PerceptionPipeline, UINode
from sudarshan_core.engines.agentic.semantic_action import SemanticRole
from sudarshan_core.engines.agentic.tool_executor import ToolResult
from sudarshan_core.engines.agentic.visual_grounding import (
    GroundedElement,
    grounded_to_ui_nodes,
)


def _node(
    node_id: str,
    text: str,
    *,
    clickable: bool = True,
    x: int = 540,
    y: int = 1600,
    bounds: str = "[400,1500][680,1700]",
    role: str = "UNKNOWN",
    source: str = "uiautomator",
) -> UINode:
    return UINode(
        node_id=node_id,
        class_name="Button",
        text=text,
        desc="",
        resource_id="",
        center_x=x,
        center_y=y,
        is_input=False,
        is_clickable=clickable,
        is_scrollable=False,
        bounds=bounds,
        semantic_role=role,
        detection_source=source,
        confidence=0.9,
    )


class MockAndroid:
    """In-memory device: TAP at a control's center transitions the graph."""

    def __init__(self) -> None:
        self.screen = "A"
        self.taps: List[tuple] = []
        self.states = {
            "A": {
                "activity": "com.unknown.app/.DialogActivity",
                "hash": "state-a",
                "nodes": [
                    _node("n0", "Arbitrary dialog", clickable=False, y=400,
                          bounds="[80,300][1000,500]"),
                    _node(
                        "n1", "Affirm",
                        clickable=True, x=540, y=1600,
                        bounds="[400,1500][680,1700]",
                        role=SemanticRole.ACCEPT.value,
                    ),
                ],
            },
            "B": {
                "activity": "com.unknown.app/.NextActivity",
                "hash": "state-b",
                "nodes": [
                    _node("n0", "Next screen", x=540, y=800,
                          bounds="[100,700][980,900]",
                          role=SemanticRole.PROGRESS.value),
                ],
            },
        }

    def observe(self):
        from sudarshan_core.engines.agentic.perception import Observation
        from sudarshan_core.engines.agentic.exploration_engine import (
            compute_composite_state_signature,
        )
        spec = self.states[self.screen]
        obs = Observation(
            activity=spec["activity"],
            ui_nodes=spec["nodes"],
            ui_node_count=len(spec["nodes"]),
            screen_hash=spec["hash"],
        )
        sh, _ = compute_composite_state_signature(
            spec["activity"], "com.unknown.app", spec["nodes"],
        )
        obs.screen_hash = sh
        return obs

    def tap(self, x: int, y: int) -> ToolResult:
        self.taps.append((x, y))
        if self.screen == "A" and 400 <= x <= 680 and 1500 <= y <= 1700:
            self.screen = "B"
        return ToolResult(
            success=True, tool="tap",
            data={
                "x": x, "y": y,
                "adb_command_generated": True,
                "adb_command_executed": True,
                "adb_return_code": 0,
            },
            adb_return_code=0,
        )


class TestCanonicalSelection(unittest.TestCase):
    def test_graph_cta_wins_over_planner_scroll(self):
        graph = {
            "tool": "click_text",
            "text": "Affirm",
            "_action_id": "ACT-001",
            "_semantic_role": "ACCEPT",
        }
        planner = {"tool": "scroll", "direction": "down", "_source": "fallback"}
        chosen, by = select_canonical_action(graph, planner)
        self.assertEqual(chosen["tool"], "click_text")
        self.assertEqual(chosen["text"], "Affirm")
        self.assertEqual(by, "exploration_graph")

    def test_privileged_planner_tool_wins(self):
        graph = {"tool": "click_text", "text": "OK"}
        planner = {"tool": "grant_permission", "permission": "x"}
        chosen, by = select_canonical_action(graph, planner)
        self.assertEqual(chosen["tool"], "grant_permission")
        self.assertEqual(by, "planner_privileged")

    def test_semantic_role_becomes_tap_not_install_verb(self):
        self.assertEqual(semantic_role_to_executable("click", "INSTALL"), "TAP")
        self.assertEqual(semantic_role_to_executable("input", "INPUT"), "TYPE_TEXT")


class TestDiscoveredActionReachesExecutor(unittest.TestCase):
    def test_get_next_action_is_executable_and_not_pre_marked_explored(self):
        graph = ExplorationGraph(package_name="com.unknown.app")
        from sudarshan_core.engines.agentic.perception import Observation
        obs = Observation(
            activity="com.unknown.app/.A",
            ui_nodes=[
                _node("n1", "Affirm", role=SemanticRole.ACCEPT.value),
            ],
            ui_node_count=1,
        )
        state = graph.observe(obs, semantic_type="UPDATE_PROMPT")
        item = state.actionable_elements[0]
        self.assertFalse(item.explored)
        self.assertFalse(item.dispatched)
        nxt = graph.get_next_action(state_id=state.state_id)
        self.assertIsNotNone(nxt)
        self.assertIn(nxt["tool"], ("click_text", "tap"))
        self.assertEqual(nxt["text"], "Affirm")
        self.assertIsNotNone(nxt.get("x"))
        self.assertIsNotNone(nxt.get("y"))
        self.assertEqual(nxt.get("_action_id"), item.action_id)
        # Selected, but not completed until verified.
        self.assertTrue(item.selected)
        self.assertFalse(item.explored)
        self.assertFalse(item.verified)
        self.assertTrue(graph.has_unexplored_work())

    def test_not_verified_until_state_changes(self):
        graph = ExplorationGraph(package_name="com.unknown.app")
        from sudarshan_core.engines.agentic.perception import Observation
        obs = Observation(
            activity="com.unknown.app/.A",
            ui_nodes=[_node("n1", "Affirm", role=SemanticRole.ACCEPT.value)],
            ui_node_count=1,
        )
        state = graph.observe(obs)
        nxt = graph.get_next_action()
        graph.record_action(
            state.state_id, state.state_id,
            nxt["tool"], nxt["text"],
            success=True, verified=False,
            dispatched=True, executed=True,
            attempts=1, action_id=nxt["_action_id"],
        )
        item = state.actionable_elements[0]
        self.assertFalse(item.verified)
        self.assertFalse(item.failed)
        self.assertTrue(graph.has_unexplored_work())


class TestSyntheticEndToEndExecution(unittest.TestCase):
    def test_discover_select_dispatch_execute_verify_edge(self):
        device = MockAndroid()
        graph = ExplorationGraph(package_name="com.unknown.app")
        dispatcher = ActionDispatcher()

        obs_a = device.observe()
        state_a = graph.observe(obs_a, semantic_type="UNKNOWN")
        nxt = graph.get_next_action(state_id=state_a.state_id)
        self.assertIsNotNone(nxt)
        planner_scroll = {"tool": "scroll", "_source": "fallback"}
        action, _ = select_canonical_action(nxt, planner_scroll)
        self.assertEqual(action["text"], "Affirm")

        trace = dispatcher.begin_trace(action, state_id=state_a.state_id)
        self.assertIn("ACTION_SELECTED", trace.lifecycle)

        payload = dict(action)
        payload["tool"] = "tap"
        result = device.tap(int(payload["x"]), int(payload["y"]))
        self.assertTrue(result.success)
        self.assertTrue(result.data["adb_command_executed"])
        trace.mark("ACTION_DISPATCHED")
        trace.mark("ACTION_EXECUTED")
        trace.executor_received = True

        obs_b = device.observe()
        state_b = graph.observe(
            obs_b, semantic_type="UNKNOWN",
            parent_state_id=state_a.state_id, entry_action="tap:Affirm",
        )
        ui_changed = obs_b.screen_hash != obs_a.screen_hash
        self.assertTrue(ui_changed)
        self.assertEqual(device.screen, "B")
        graph.record_action(
            state_a.state_id, state_b.state_id,
            "tap", "Affirm",
            success=True, verified=True,
            dispatched=True, executed=True,
            attempts=1, action_id=action["_action_id"],
        )
        trace.ui_changed = True
        trace.action_verification = "PASS"
        trace.mark("ACTION_VERIFIED")
        self.assertEqual(trace.lifecycle[-1], "ACTION_VERIFIED")
        self.assertGreaterEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[-1].source_state_id, state_a.state_id)
        self.assertEqual(graph.edges[-1].target_state_id, state_b.state_id)
        nxt_b = graph.get_next_action(state_id=state_b.state_id)
        self.assertIsNotNone(nxt_b)


class TestVisualGroundingExecution(unittest.TestCase):
    def test_visual_bounds_become_executor_tap(self):
        grounded = GroundedElement(
            node_id="vis0",
            label="Go ahead",
            class_name="VisionGrounded",
            center_x=200,
            center_y=400,
            bounds="[160,360][240,440]",
            semantic_role=SemanticRole.PROGRESS,
            confidence=0.8,
            detection_source="visual_grounding",
        )
        nodes = grounded_to_ui_nodes([grounded])
        graph = ExplorationGraph(package_name="com.unknown.app")
        from sudarshan_core.engines.agentic.perception import Observation
        obs = Observation(
            activity="com.unknown.app/.Web",
            ui_nodes=nodes,
            ui_node_count=len(nodes),
        )
        state = graph.observe(obs)
        nxt = graph.get_next_action()
        self.assertIsNotNone(nxt)
        self.assertEqual(nxt["_detection_source"], "visual_grounding")
        self.assertEqual(nxt["x"], 200)
        self.assertEqual(nxt["y"], 400)

        device_taps: List[tuple] = []

        def fake_tap(x, y):
            device_taps.append((x, y))
            return ToolResult(success=True, tool="tap", data={"x": x, "y": y})

        result = fake_tap(nxt["x"], nxt["y"])
        self.assertTrue(result.success)
        self.assertEqual(device_taps, [(200, 400)])


class TestFailedExecutionBounded(unittest.TestCase):
    def test_three_failures_then_resolved_failed_no_loop(self):
        graph = ExplorationGraph(package_name="com.unknown.app")
        from sudarshan_core.engines.agentic.perception import Observation
        obs = Observation(
            activity="com.unknown.app/.A",
            ui_nodes=[_node("n1", "Affirm", role=SemanticRole.ACCEPT.value)],
            ui_node_count=1,
        )
        state = graph.observe(obs)
        nxt = graph.get_next_action()
        dispatcher = ActionDispatcher()
        attempts = []
        current = dict(nxt)
        for i in range(10):
            attempts.append(i + 1)
            graph.record_action(
                state.state_id, state.state_id,
                current.get("tool", "tap"), nxt["text"],
                success=False, verified=False,
                dispatched=True, executed=False,
                attempts=i + 1, action_id=nxt["_action_id"],
            )
            retry = dispatcher.retry_payload(nxt, i + 1)
            if retry is None:
                break
            current = retry
        self.assertEqual(len(attempts), MAX_EXECUTION_ATTEMPTS)
        item = state.actionable_elements[0]
        self.assertTrue(item.failed)
        self.assertFalse(graph.has_unexplored_work() and not item.failed)
        nxt2 = graph.get_next_action(state_id=state.state_id)
        # Must not keep selecting the same failed control.
        if nxt2 is not None:
            self.assertNotEqual(nxt2.get("_action_id"), nxt["_action_id"])


class TestCoordinateTransform(unittest.TestCase):
    def test_screenshot_pixels_scale_to_device(self):
        x, y = screenshot_coords_to_device(
            540, 960,
            image_width=1080, image_height=1920,
            device_width=1080, device_height=2400,
        )
        self.assertEqual(x, 540)
        self.assertEqual(y, 1200)

    def test_identity_when_sizes_match(self):
        x, y = screenshot_coords_to_device(
            10, 20,
            image_width=1080, image_height=2400,
            device_width=1080, device_height=2400,
        )
        self.assertEqual((x, y), (10, 20))


class TestParentClickableRecovery(unittest.TestCase):
    def test_labeled_child_targets_clickable_parent_bounds(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node class="android.widget.FrameLayout" clickable="true"
        bounds="[100,1400][980,1700]">
    <node class="android.widget.TextView" text="Affirm" clickable="false"
          bounds="[400,1500][680,1600]"/>
  </node>
</hierarchy>"""
        pipeline = PerceptionPipeline(device_serial="s", package_name="p")
        nodes = pipeline._parse_ui_nodes(xml)
        labels = [n.text for n in nodes]
        self.assertIn("Affirm", labels)
        cta = next(n for n in nodes if n.text == "Affirm")
        self.assertTrue(cta.is_clickable)
        self.assertEqual(cta.detection_source, "clickable_parent_recovery")
        self.assertEqual(cta.bounds, "[100,1400][980,1700]")
        self.assertEqual(cta.center_x, (100 + 980) // 2)
        self.assertEqual(cta.center_y, (1400 + 1700) // 2)


class TestDispatcherRetryLadder(unittest.TestCase):
    """
    The ladder's contract, updated for the strategy-based rungs.

    The previous version of this test asserted the OLD three-rung shape:
    ``tap`` at attempt 1, ``tap`` again at attempt 2, then None. That shape was
    the defect, not the contract - all three rungs resolved the element the same
    way, so a control that could not be found by text was not found by tapping
    the coordinates the text lookup produced either, and the third attempt
    repeated the second exactly.

    What is asserted now is the property the old test was reaching for and could
    not express: each rung must resolve the element by a DIFFERENT means, and
    the ladder must still be bounded. The specific tool names are no longer
    pinned, because which rungs an action can offer depends on which identities
    it carries - and pinning them is what made the old ladder impossible to
    extend without editing a test that had no opinion about the behaviour.
    """

    def test_each_rung_resolves_the_element_differently(self):
        dispatcher = ActionDispatcher()
        action = {"tool": "click_text", "text": "Affirm", "x": 10, "y": 20,
                  "_bounds": "[100,1400][980,1700]"}

        strategies, tried, attempt = [], [], 0
        while True:
            payload = dispatcher.retry_payload(action, attempt, tried=tried)
            if payload is None:
                break
            attempt += 1
            tried = payload["_strategies_tried"]
            strategies.append(payload["_pipeline_debug"]["retry_strategy"])

        self.assertGreater(len(strategies), 1, "the ladder must have rungs")
        self.assertEqual(
            len(strategies), len(set(strategies)),
            f"a rung was repeated: {strategies}",
        )

    def test_the_ladder_terminates(self):
        dispatcher = ActionDispatcher()
        action = {"tool": "click_text", "text": "Affirm", "x": 10, "y": 20}

        tried, attempt = [], 0
        while attempt < 50:
            payload = dispatcher.retry_payload(action, attempt, tried=tried)
            if payload is None:
                return
            attempt += 1
            tried = payload["_strategies_tried"]
        self.fail("retry_payload never returned None")


if __name__ == "__main__":
    unittest.main()
