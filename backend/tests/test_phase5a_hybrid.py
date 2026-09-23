import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from sudarshan_core.engines.agentic_explorer import AgenticExplorer
from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.hybrid_planner import HybridPlanner
from sudarshan_core.engines.agentic.planner import AgentPlanner
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, ActionItem
from sudarshan_core.engines.agentic.action_dispatch import ActionDispatcher
from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker

@pytest.fixture
def mock_exploration():
    exp = MagicMock(spec=ExplorationGraph)
    exp._current_state_id = "state_1"
    
    cand1 = ActionItem(action_id="a1", node_id="n1", action_type="tap", label="Btn1", is_clickable=True)
    cand1.center_x, cand1.center_y = 10, 10
    cand2 = ActionItem(action_id="a2", node_id="n2", action_type="input", label="Input1", is_input=True)
    cand2.center_x, cand2.center_y = 20, 20
    
    state = MagicMock()
    state.unexplored_actions = MagicMock(return_value=[cand1, cand2])
    exp.states = {"state_1": state}
    exp.get_next_action = MagicMock(return_value=None)
    return exp

@pytest.fixture
def mock_explorer(monkeypatch, mock_exploration):
    monkeypatch.setenv("SUDARSHAN_PLANNER_MODE", "hybrid")
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    
    explorer = AgenticExplorer(device_serial="dev", package_name="pkg", adb_path="adb")
    explorer.exploration = mock_exploration
    
    jev = JevPlanner(api_key="mock", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    gemini = MagicMock(spec=AgentPlanner)
    
    explorer.planner = HybridPlanner(jev, gemini)
    
    explorer.dispatcher = ActionDispatcher()
    explorer.tool_executor = MagicMock()
    explorer.tool_executor.execute = MagicMock(return_value=True)
    
    explorer.verifier = MagicMock()
    ver_result = MagicMock()
    ver_result.success = True
    explorer.verifier.verify = MagicMock(return_value=ver_result)
    
    return explorer

# TEST 1 - Jev Success
def test_phase5a_jev_success(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    jev._invoke_mock = AsyncMock(return_value={"selected_id": "n1", "confidence": 0.95})
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "jev_planner"
    assert action["node_id"] == "n1"
    jev._invoke_mock.assert_called_once()
    gemini.decide.assert_not_called()

# TEST 2 - Low Confidence
def test_phase5a_jev_low_confidence(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    jev._invoke_mock = AsyncMock(return_value={"selected_id": "n1", "confidence": 0.2})
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "gemini"
    jev._invoke_mock.assert_called_once()
    gemini.decide.assert_called_once()

# TEST 3 - Jev Failure (Timeout/Exception)
def test_phase5a_jev_failure(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    async def mock_fail(*args, **kwargs):
        jev.last_failure_reason = "JEV_TIMEOUT"
        return {}
    
    jev._invoke_mock = AsyncMock(side_effect=mock_fail)
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "gemini"
    jev._invoke_mock.assert_called_once()
    gemini.decide.assert_called_once()

# TEST 4 - Invalid Jev Candidate
def test_phase5a_invalid_candidate(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    jev._invoke_mock = AsyncMock(return_value={"selected_id": "invalid_123", "confidence": 0.99})
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "gemini"
    jev._invoke_mock.assert_called_once()
    gemini.decide.assert_called_once()

# TEST 5 - Empty Candidate List
def test_phase5a_empty_candidates(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    mock_explorer.exploration.states["state_1"].unexplored_actions.return_value = []
    
    jev._invoke_mock = AsyncMock()
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "gemini"
    jev._invoke_mock.assert_not_called()
    gemini.decide.assert_called_once()

# TEST 6 - Vision Required
def test_phase5a_vision_skip(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    jev.decide = AsyncMock() # We shouldn't even call this
    gemini.decide = AsyncMock(return_value={"tool": "gemini_tool", "_selected_by": "gemini"})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=True)
    obs.vision_reason = "webview_activity"
    
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action["_selected_by"] == "gemini"
    assert not jev.decide.called
    gemini.decide.assert_called_once()

# TEST 7 - Both Planners Fail
def test_phase5a_both_fail(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    async def mock_fail(*args, **kwargs):
        jev.last_failure_reason = "JEV_TIMEOUT"
        return {}
        
    jev._invoke_mock = AsyncMock(side_effect=mock_fail)
    gemini.decide = AsyncMock(return_value=None)
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is None
    jev._invoke_mock.assert_called_once()
    gemini.decide.assert_called_once()

# TEST 10 - Execution Boundary
def test_phase5a_execution_boundary(mock_explorer):
    jev = mock_explorer.planner.jev_planner
    gemini = mock_explorer.planner.agent_planner
    
    jev._invoke_mock = AsyncMock(return_value={"selected_id": "n1", "confidence": 0.95})
    
    obs = Observation(activity="com.test/Main", ui_nodes=[], screen_hash="hash1", frida_events=[], screenshot_taken=False)
    action = asyncio.run(mock_explorer.planner.decide(obs, AgentMemory(), GoalTracker()))
    
    trace = mock_explorer.dispatcher.begin_trace(action)
    exe_action = mock_explorer.dispatcher.retry_payload(action, 1)
    res = mock_explorer.tool_executor.execute(exe_action)
    ver = mock_explorer.verifier.verify(exe_action, "s1", "s2")
    
    assert res is True
    assert ver.success is True
    assert "tool" in exe_action
