import pytest
import asyncio
import httpx
from unittest.mock import MagicMock, AsyncMock, patch

from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, ExplorationState, ActionItem
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker, FraudGoal, GoalStatus

@pytest.fixture
def memory():
    return AgentMemory()

@pytest.fixture
def goals():
    gt = GoalTracker()
    gt.goals.clear()
    gt.goals.append(FraudGoal(name="test_goal", stage=1, description="Test Goal"))
    return gt

@pytest.fixture
def obs():
    return Observation(
        activity="com.test/MainActivity",
        ui_nodes=[],
        screen_hash="hash123",
        frida_events=[],
        screenshot_taken=False
    )

@pytest.fixture
def mock_exploration():
    exp = MagicMock(spec=ExplorationGraph)
    exp._current_state_id = "state_1"
    
    state = MagicMock(spec=ExplorationState)
    item1 = ActionItem(action_id="a1", node_id="n1", action_type="click", label="Button 1", center_x=10, center_y=20)
    item2 = ActionItem(action_id="a2", node_id="n2", action_type="input", label="Input 1", center_x=30, center_y=40, field_kind="email")
    item3 = ActionItem(action_id="a3", node_id="n3", action_type="tap", label="Failed Button", center_x=50, center_y=60)
    item3.failed = True
    
    state.unexplored_actions.return_value = [item1, item2, item3]
    exp.states = {"state_1": state}
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

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_valid_choice(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "model": "jev-latest",
        "answers": {"action": {"choice": "n2", "confidence": 0.95}}
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    
    assert action is not None
    assert action["tool"] == "type_text"
    assert action["node_id"] == "n2"
    assert action["x"] == 30
    assert action["y"] == 40
    assert action.get("field_hint") == "email"
    assert action["_selected_by"] == "jev_planner"

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_valid_choice_click(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "model": "jev-latest",
        "answers": {"action": {"choice": "n1", "confidence": 0.99}}
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    
    assert action is not None
    assert action["tool"] == "tap"
    assert action["node_id"] == "n1"
    assert action["_selected_by"] == "jev_planner"

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_invalid_choice(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "answers": {"action": {"choice": "hallucinated_123"}}
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_failed_candidate(mock_client_class, obs, memory, goals, mock_exploration):
    json_data = {
        "answers": {"action": {"choice": "n3"}}
    }
    mock_client_class.return_value = create_mock_client(json_response=json_data)
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_http_400(mock_client_class, obs, memory, goals, mock_exploration):
    mock_exc = httpx.HTTPStatusError("400 Bad Request", request=MagicMock(), response=MagicMock(status_code=400, text="Bad Req"))
    mock_client_class.return_value = create_mock_client(raise_exc=mock_exc)
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None

@patch("sudarshan_core.engines.agentic.jev_planner.httpx.AsyncClient")
def test_jev_planner_timeout(mock_client_class, obs, memory, goals, mock_exploration):
    mock_client = AsyncMock()
    mock_client.post.side_effect = httpx.TimeoutException("Timeout")
    mock_client.__aenter__.return_value = mock_client
    mock_client_class.return_value = mock_client
    
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None

def test_jev_planner_serialization(obs, memory, goals, mock_exploration):
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    candidates = mock_exploration.states["state_1"].unexplored_actions()
    payload = planner._serialize_candidates(obs, goals, candidates)
    
    assert payload["model"] == "jev-latest"
    assert "Goal: test_goal" in payload["state"]
    assert "com.test/MainActivity" in payload["state"]
    
    criteria = payload["questions"]["action"]["criteria"]
    assert len(criteria) == 3
    assert list(criteria.keys()) == ["n1", "n2", "n3"]

def test_jev_planner_no_graph(obs, memory, goals):
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=None)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None

def test_jev_planner_no_unexplored(obs, memory, goals, mock_exploration):
    mock_exploration.states["state_1"].unexplored_actions.return_value = []
    planner = JevPlanner(api_key="test", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None
