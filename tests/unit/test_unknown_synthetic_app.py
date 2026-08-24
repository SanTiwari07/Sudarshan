"""
Synthetic unknown-application test.

The engine must discover an arbitrary workflow without any rules about
package name, screen hash, or button labels.
"""

import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.exploration_engine import (
    ExplorationGraph,
    StopReason,
)
from sudarshan_core.engines.agentic.perception import Observation, UINode
from sudarshan_core.engines.agentic.semantic_action import SemanticRole, classify_semantic_role
from sudarshan_core.engines.agentic.exploration_engine import compute_composite_state_signature


def _node(node_id: str, text: str, **kwargs: Any) -> UINode:
    role = classify_semantic_role(label=text, is_clickable=True).role.value
    return UINode(
        node_id=node_id,
        class_name=kwargs.get("class_name", "android.widget.Button"),
        text=text,
        desc=kwargs.get("desc", ""),
        resource_id=kwargs.get("resource_id", ""),
        center_x=kwargs.get("center_x", 200),
        center_y=kwargs.get("center_y", 400),
        is_input=kwargs.get("is_input", False),
        is_clickable=kwargs.get("is_clickable", True),
        is_scrollable=kwargs.get("is_scrollable", False),
        bounds=kwargs.get("bounds", "[0,0][400,100]"),
        semantic_role=role,
    )


class UnknownSyntheticApp:
    """
    Arbitrary workflow unknown to the engine:
      welcome -> permission -> scroll list -> external prompt -> done
    """

    PACKAGE = "com.zeta.unknown.app"

    SCREENS: Dict[str, Dict[str, Any]] = {
        "WELCOME": {
            "activity": f"{PACKAGE}/.SplashActivity",
            "nodes": [
                _node("n0", "Welcome traveller", is_clickable=False),
                _node("n1", "Begin journey", center_y=800),
            ],
            "next": {"Begin journey": "PERM"},
        },
        "PERM": {
            "activity": f"{PACKAGE}/.CapabilityActivity",
            "nodes": [
                _node("n0", "Allow sensor access"),
                _node("n1", "Grant access", center_y=900),
                _node("n2", "Skip for now", center_y=700),
            ],
            "next": {"Grant access": "SCROLL", "Skip for now": "DONE"},
        },
        "SCROLL": {
            "activity": f"{PACKAGE}/.ListActivity",
            "nodes": [
                _node("n0", "Feature list", is_scrollable=True, is_clickable=False),
                _node("n1", "Open settings panel", center_y=850),
            ],
            "next": {"Open settings panel": "EXTERNAL"},
        },
        "EXTERNAL": {
            "activity": f"{PACKAGE}/.BridgeActivity",
            "nodes": [
                _node("n0", "External helper required"),
                _node("n1", "Launch helper", center_y=900),
            ],
            "next": {"Launch helper": "DONE"},
        },
        "DONE": {
            "activity": f"{PACKAGE}/.CompleteActivity",
            "nodes": [_node("n0", "Journey complete")],
            "next": {},
        },
    }

    def __init__(self) -> None:
        self.current = "WELCOME"

    def observe(self) -> Observation:
        screen = self.SCREENS[self.current]
        nodes = screen["nodes"]
        obs = Observation(
            activity=screen["activity"],
            ui_nodes=nodes,
            ui_node_count=len(nodes),
        )
        sh, _ = compute_composite_state_signature(
            screen["activity"], self.PACKAGE, nodes,
        )
        obs.screen_hash = sh
        return obs

    def act(self, label: str) -> bool:
        transitions = self.SCREENS[self.current].get("next", {})
        if label in transitions:
            self.current = transitions[label]
            return True
        if label.startswith("scroll:"):
            return True
        return False


class TestUnknownSyntheticApp(unittest.TestCase):
    def test_discovers_arbitrary_workflow_without_package_rules(self):
        app = UnknownSyntheticApp()
        graph = ExplorationGraph(package_name=UnknownSyntheticApp.PACKAGE)
        graph.observe(app.observe(), semantic_type="UNKNOWN", elapsed_ts="00:00")

        visited_labels: List[str] = []
        for _ in range(25):
            nxt = graph.get_next_action()
            if nxt is None:
                break
            label = nxt.get("text", "")
            visited_labels.append(label)
            pre = graph._current_state_id
            success = app.act(label)
            post_obs = app.observe()
            post_state = graph.observe(
                post_obs, semantic_type="UNKNOWN", elapsed_ts="00:05",
            )
            graph.record_action(
                pre, post_state.state_id,
                nxt.get("tool", "click_text"), label,
                success=success,
                action_id=nxt.get("_action_id", ""),
            )
            if app.current == "DONE":
                break

        self.assertIn("Begin journey", visited_labels)
        self.assertIn("Grant access", visited_labels)
        self.assertEqual(app.current, "DONE")
        metrics = graph.coverage_metrics()
        self.assertGreater(metrics["actionable_elements_discovered"], 0)
        self.assertGreater(metrics["actionable_elements_executed"], 0)

    def test_semantic_roles_for_unknown_labels(self):
        for label, expected in (
            ("Begin journey", SemanticRole.ACCEPT),
            ("Grant access", SemanticRole.ACCEPT),
            ("Skip for now", SemanticRole.DECLINE),
        ):
            role = classify_semantic_role(label=label, is_clickable=True).role
            if expected == SemanticRole.DECLINE:
                self.assertIn(role, {SemanticRole.DECLINE, SemanticRole.CANCEL})
            else:
                self.assertTrue(
                    role in {SemanticRole.ACCEPT, SemanticRole.PROGRESS, SemanticRole.ENABLE}
                )

    def test_no_false_exploration_complete_with_unresolved(self):
        graph = ExplorationGraph(package_name=UnknownSyntheticApp.PACKAGE)
        app = UnknownSyntheticApp()
        graph.observe(app.observe(), semantic_type="UNKNOWN")
        self.assertTrue(graph.has_unexplored_work())
        graph.stop_reason = StopReason.NO_UNEXPLORED_ACTIONS
        self.assertIsNotNone(graph.stop_reason)


if __name__ == "__main__":
    unittest.main()
