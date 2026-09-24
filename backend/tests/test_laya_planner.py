import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.exploration_engine import ActionItem, ExplorationGraph, ExplorationState
from sudarshan_core.engines.agentic.goal_tracker import FraudGoal, GoalTracker
from sudarshan_core.engines.agentic.laya_planner import LayaPlanner
from sudarshan_core.engines.agentic.perception import Observation


@pytest.fixture
def memory():
    return AgentMemory()


@pytest.fixture
def goals():
    gt = GoalTracker()
    gt.goals.clear()
    gt.goals.append(FraudGoal(name="login_flow", stage=1, description="Navigate login screen"))
    return gt


@pytest.fixture
def obs():
    return Observation(
        activity="com.example.bank/LoginActivity",
        ui_nodes=[],
        screen_hash="hash_laya_123",
        frida_events=[],
        screenshot_taken=False,
    )


@pytest.fixture
def mock_exploration():
    exp = MagicMock(spec=ExplorationGraph)
    exp._current_state_id = "state_login"

    state = MagicMock(spec=ExplorationState)
    item1 = ActionItem(action_id="act_btn", node_id="btn_submit", action_type="click", label="Sign In", center_x=100, center_y=200)
    item2 = ActionItem(action_id="act_input", node_id="input_user", action_type="input", label="Username", center_x=100, center_y=150, field_kind="username")
    item3 = ActionItem(action_id="act_failed", node_id="btn_broken", action_type="click", label="Dead Button", center_x=50, center_y=50)
    item3.failed = True

    state.unexplored_actions.return_value = [item1, item2, item3]
    exp.states = {"state_login": state}
    return exp


def create_mock_client(json_response=None, raise_exc=None):
    mock_resp = MagicMock()
    if raise_exc:
        mock_resp.raise_for_status.side_effect = raise_exc
    else:
        mock_resp.json.return_value = json_response or {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_resp
    mock_client.__aenter__.return_value = mock_client
    return mock_client


@patch("sudarshan_core.engines.agentic.laya_planner.httpx.AsyncClient")
def test_laya_planner_valid_choice_tap(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "model": "convaiinnovations/laya-typed-decisions",
        "answers": {"action": {"choice": "btn_submit", "confidence": 0.94}},
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)

    planner = LayaPlanner(device_serial="dev1", package_name="com.example.bank", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))

    assert action is not None
    assert action["tool"] == "tap"
    assert action["node_id"] == "btn_submit"
    assert action["_selected_by"] == "laya_planner"
    assert action["_confidence"] == 0.94


@patch("sudarshan_core.engines.agentic.laya_planner.httpx.AsyncClient")
def test_laya_planner_valid_choice_input(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "model": "convaiinnovations/laya-typed-decisions",
        "answers": {"action": {"choice": "input_user", "confidence": 0.88}},
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)

    planner = LayaPlanner(device_serial="dev1", package_name="com.example.bank", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))

    assert action is not None
    assert action["tool"] == "type_text"
    assert action["node_id"] == "input_user"
    assert action.get("field_hint") == "username"
    assert action["_selected_by"] == "laya_planner"


@patch("sudarshan_core.engines.agentic.laya_planner.httpx.AsyncClient")
def test_laya_planner_confidence_threshold_rejection(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "answers": {"action": {"choice": "btn_submit", "confidence": 0.45}},
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)

    planner = LayaPlanner(
        confidence_threshold=0.70,
        device_serial="dev1",
        package_name="pkg",
        exploration=mock_exploration,
    )
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None


@patch("sudarshan_core.engines.agentic.laya_planner.httpx.AsyncClient")
def test_laya_planner_hallucinated_choice(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "answers": {"action": {"choice": "non_existent_button", "confidence": 0.99}},
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)

    planner = LayaPlanner(device_serial="dev1", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None


@patch("sudarshan_core.engines.agentic.laya_planner.httpx.AsyncClient")
def test_laya_planner_timeout_resilience(mock_client_class, obs, memory, goals, mock_exploration):
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.TimeoutException("Connection timed out")
    mock_client.__aenter__.return_value = mock_client
    mock_client_class.return_value = mock_client

    planner = LayaPlanner(device_serial="dev1", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None


def test_laya_planner_mock_mode(obs, memory, goals, mock_exploration):
    planner = LayaPlanner(
        provider="mock",
        device_serial="dev1",
        package_name="pkg",
        exploration=mock_exploration,
    )
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is not None
    # Sign In should be selected because goal contains "login"
    assert action["node_id"] == "btn_submit"
    assert action["_selected_by"] == "laya_planner"


def test_laya_planner_serialization(obs, memory, goals, mock_exploration):
    planner = LayaPlanner(exploration=mock_exploration)
    candidates = mock_exploration.states["state_login"].unexplored_actions()
    payload = planner._serialize_candidates(obs, goals, candidates)

    assert payload["model"] == "convaiinnovations/laya-typed-decisions"
    assert "com.example.bank/LoginActivity" in payload["state"]
    assert "btn_submit" in payload["questions"]["action"]["criteria"]
    assert "input_user" in payload["questions"]["action"]["criteria"]
    assert payload["questions"]["action"]["type"] == "choice"
