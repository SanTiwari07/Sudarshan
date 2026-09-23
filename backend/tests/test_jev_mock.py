import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.hybrid_planner import HybridPlanner
from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, ActionItem

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
def goals():
    tracker = GoalTracker()
    goal_mock = MagicMock()
    goal_mock.name = "Login to Account"
    tracker.get_next_incomplete_goal = MagicMock(return_value=goal_mock)
    tracker.next_priority_goal = MagicMock(return_value=goal_mock)
    return tracker

@pytest.fixture
def memory():
    return AgentMemory()

@pytest.fixture
def candidates():
    return [
        ActionItem(action_id="a1", node_id="n1", action_type="tap", label="Cancel", is_clickable=True),
        ActionItem(action_id="a2", node_id="n2", action_type="type_text", label="Username", is_input=True),
        ActionItem(action_id="a3", node_id="n3", action_type="tap", label="Login", is_clickable=True)
    ]

@pytest.fixture
def mock_exploration(candidates):
    exp = MagicMock(spec=ExplorationGraph)
    exp._current_state_id = "state_1"
    state = MagicMock()
    state.unexplored_actions = MagicMock(return_value=candidates)
    exp.states = {"state_1": state}
    return exp

def test_mock_valid_candidate_selection_input(obs, memory, goals, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is not None
    # Goal is "Login to Account" which has "login" so it prefers input fields
    assert action["node_id"] == "n2"
    assert planner.last_failure_reason == "JEV_SUCCESS"

def test_mock_valid_candidate_selection_button(obs, memory, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    tracker = GoalTracker()
    goal_mock = MagicMock()
    goal_mock.name = "Find Settings"
    tracker.next_priority_goal = MagicMock(return_value=goal_mock)
    
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    action = asyncio.run(planner.decide(obs, memory, tracker))
    assert action is not None
    # Navigates to first clickable
    assert action["node_id"] == "n1"

def test_mock_empty_candidate_list(obs, memory, goals, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    mock_exploration.states["state_1"].unexplored_actions.return_value = []
    
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None
    assert planner.last_failure_reason == "JEV_NO_CANDIDATES"

def test_mock_invalid_candidate_returned(obs, memory, goals, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    # Force _invoke_mock to return a hallucinated ID
    original_invoke = planner._invoke_mock
    async def fake_invoke(*args, **kwargs):
        return {"selected_id": "hallucinated_id", "confidence": 0.9}
    planner._invoke_mock = fake_invoke
    
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None
    assert planner.last_failure_reason == "JEV_INVALID_CHOICE"

def test_mock_confidence_below_threshold(obs, memory, goals, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    # Force low confidence
    async def fake_invoke(*args, **kwargs):
        return {"selected_id": "n1", "confidence": 0.4}
    planner._invoke_mock = fake_invoke
    
    action = asyncio.run(planner.decide(obs, memory, goals))
    # It still returns the action (HybridPlanner handles the threshold)
    assert action is not None
    assert planner.last_confidence == 0.4
    assert planner.last_failure_reason == "JEV_SUCCESS"

def test_mock_candidate_validation_failure(obs, memory, goals, mock_exploration, candidates, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    candidates[0].failed = True # Make it stale
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    async def fake_invoke(*args, **kwargs):
        return {"selected_id": "n1", "confidence": 0.9}
    planner._invoke_mock = fake_invoke
    
    action = asyncio.run(planner.decide(obs, memory, goals))
    assert action is None
    assert planner.last_failure_reason == "JEV_STALE_CHOICE"

def test_mock_deterministic_repeated_execution(obs, memory, goals, mock_exploration, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    action1 = asyncio.run(planner.decide(obs, memory, goals))
    action2 = asyncio.run(planner.decide(obs, memory, goals))
    assert action1 == action2
