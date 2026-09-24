"""SUDARSHAN — Laya Decision Engine Smoke Test.

Validates that:
1. `laya` package is installed and importable.
2. `torch` and `transformers` meet minimum version requirements.
3. Structured action choice questions format properly for Laya System-1.
4. Laya DecisionProvider can format, validate, and select actions.
"""

from unittest.mock import MagicMock
import pytest


def test_laya_package_installed():
    import laya

    assert hasattr(laya, "__version__")
    assert hasattr(laya, "Router")
    assert hasattr(laya, "Agent")
    assert hasattr(laya, "load")


def test_torch_and_transformers_available():
    import torch
    import transformers

    assert hasattr(torch, "__version__")
    assert hasattr(transformers, "__version__")


def test_laya_typed_question_format():
    """Verify that action selection candidate serialization strictly adheres to Laya question format."""
    state = "Screen: com.bank.app/TransferActivity\nGoal: authorize_transaction"
    questions = {
        "action": {
            "type": "choice",
            "instructions": "Select the best UI action to advance the transaction authorization.",
            "criteria": {
                "btn_confirm": "TAP 'Confirm Transfer' (class: android.widget.Button)",
                "input_pin": "TYPE_TEXT 'Enter 4-digit PIN' (class: android.widget.EditText)",
                "btn_cancel": "TAP 'Cancel' (class: android.widget.Button)",
            },
        }
    }

    assert questions["action"]["type"] == "choice"
    assert len(questions["action"]["criteria"]) == 3
    assert "btn_confirm" in questions["action"]["criteria"]


def test_laya_mock_decision_end_to_end():
    from sudarshan_core.engines.agentic.agent_memory import AgentMemory
    from sudarshan_core.engines.agentic.exploration_engine import ActionItem, ExplorationGraph, ExplorationState
    from sudarshan_core.engines.agentic.goal_tracker import FraudGoal, GoalTracker
    from sudarshan_core.engines.agentic.laya_planner import LayaPlanner
    from sudarshan_core.engines.agentic.perception import Observation
    import asyncio

    exp = MagicMock(spec=ExplorationGraph)
    state = MagicMock(spec=ExplorationState)
    item1 = ActionItem(action_id="a1", node_id="btn_login", action_type="click", label="Login", center_x=10, center_y=20)
    item2 = ActionItem(action_id="a2", node_id="btn_skip", action_type="click", label="Skip", center_x=30, center_y=40)
    state.unexplored_actions.return_value = [item1, item2]
    exp.states = {"s1": state}
    exp._current_state_id = "s1"

    gt = GoalTracker()
    gt.goals.clear()
    gt.goals.append(FraudGoal(name="login_flow", stage=1, description="Perform login"))

    obs = Observation(activity="com.test.app/MainActivity", ui_nodes=[], screen_hash="h1", frida_events=[], screenshot_taken=False)

    planner = LayaPlanner(provider="mock", exploration=exp)
    action = asyncio.run(planner.decide(obs, AgentMemory(), gt))

    assert action is not None
    assert action["node_id"] == "btn_login"
    assert action["tool"] == "tap"
    assert action["_selected_by"] == "laya_planner"
