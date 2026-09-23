import pytest
import asyncio
from unittest.mock import MagicMock, patch

from sudarshan_core.engines.agentic_explorer import AgenticExplorer
from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, ActionItem
from sudarshan_core.engines.agentic.action_dispatch import ActionDispatcher

@pytest.fixture
def mock_explorer(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_PLANNER_MODE", "jev")
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    
    explorer = AgenticExplorer(device_serial="dev", package_name="pkg", adb_path="adb")
    
    # Mock ToolExecutor
    explorer.dispatcher = ActionDispatcher()
    explorer.tool_executor = MagicMock()
    explorer.tool_executor.execute = MagicMock(return_value=True)
    
    # Mock Verifier
    explorer.verifier = MagicMock()
    ver_result = MagicMock()
    ver_result.success = True
    explorer.verifier.verify = MagicMock(return_value=ver_result)
    
    return explorer

def test_mock_pipeline_integration(mock_explorer):
    # Setup mock exploration state
    mock_exploration = MagicMock(spec=ExplorationGraph)
    mock_exploration._current_state_id = "state_1"
    
    cand = ActionItem(action_id="a1", node_id="n1", action_type="tap", label="Mock Button", is_clickable=True)
    cand.center_x = 100
    cand.center_y = 200
    
    state = MagicMock()
    state.unexplored_actions = MagicMock(return_value=[cand])
    mock_exploration.states = {"state_1": state}
    mock_exploration.get_next_action = MagicMock(return_value=None)
    
    # We replace exploration with our mock
    mock_explorer.exploration = mock_exploration
    # Also recreate planner with this exploration
    mock_explorer.planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    # We can just simulate the loop steps:
    # 1. Planner decides
    action = asyncio.run(mock_explorer.planner.decide(
        MagicMock(screenshot_taken=False), mock_explorer.memory, mock_explorer.goals
    ))
    
    assert action is not None
    assert action["_selected_by"] == "jev_mock" or action["_selected_by"] == "jev_planner"
    assert action["x"] == 100
    assert action["y"] == 200
    
    # 2. Dispatcher translates
    trace = mock_explorer.dispatcher.begin_trace(action)
    exe_action = mock_explorer.dispatcher.retry_payload(action, 1)
    
    assert exe_action["tool"] == "tap" or "tool" in exe_action
    
    # 3. Executor runs
    res = mock_explorer.tool_executor.execute(exe_action)
    assert res is True
    
    # 4. Verifier verifies
    ver = mock_explorer.verifier.verify(exe_action, "state_1", "state_2")
    assert ver.success is True

def test_mock_pipeline_verification_failure(mock_explorer):
    # Setup mock exploration state
    mock_exploration = MagicMock(spec=ExplorationGraph)
    mock_exploration._current_state_id = "state_1"
    cand = ActionItem(action_id="a1", node_id="n1", action_type="tap", label="Mock Button", is_clickable=True)
    state = MagicMock()
    state.unexplored_actions = MagicMock(return_value=[cand])
    mock_exploration.states = {"state_1": state}
    mock_explorer.exploration = mock_exploration
    mock_explorer.planner = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=mock_exploration)
    
    # Force verification failure
    ver_result = MagicMock()
    ver_result.success = False
    mock_explorer.verifier.verify = MagicMock(return_value=ver_result)
    
    action = asyncio.run(mock_explorer.planner.decide(MagicMock(screenshot_taken=False), mock_explorer.memory, mock_explorer.goals))
    trace = mock_explorer.dispatcher.begin_trace(action)
    exe_action = mock_explorer.dispatcher.retry_payload(action, 1)
    ver = mock_explorer.verifier.verify(exe_action, "state_1", "state_1")
    assert ver.success is False

def test_mock_fallback_behavior(monkeypatch):
    # Test that when HybridPlanner wraps it, fallback works
    from sudarshan_core.engines.agentic.hybrid_planner import HybridPlanner
    from sudarshan_core.engines.agentic.planner import AgentPlanner
    from unittest.mock import AsyncMock
    
    # JevMock returns low confidence
    jev = JevPlanner(api_key="none", device_serial="dev", package_name="pkg", exploration=MagicMock())
    jev._invoke_mock = AsyncMock(return_value={"selected_id": "n1", "confidence": 0.2})
    
    gemini = MagicMock(spec=AgentPlanner)
    gemini.decide = AsyncMock(return_value={"tool": "type_text", "_selected_by": "gemini"})
    
    hybrid = HybridPlanner(jev, gemini)
    
    monkeypatch.setenv("SUDARSHAN_JEV_PROVIDER", "mock")
    jev.provider = "mock"
    
    action = asyncio.run(hybrid.decide(MagicMock(screenshot_taken=False), MagicMock(), MagicMock()))
    assert action["_selected_by"] == "gemini"
    assert jev._invoke_mock.called
    assert gemini.decide.called
