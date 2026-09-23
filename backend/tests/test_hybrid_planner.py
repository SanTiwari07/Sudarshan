import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from sudarshan_core.engines.agentic.hybrid_planner import HybridPlanner
from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.planner import AgentPlanner
from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker

@pytest.fixture
def mock_jev():
    planner = MagicMock(spec=JevPlanner)
    planner.last_failure_reason = ""
    planner.last_confidence = 0.0
    planner.last_latency_ms = 0.0
    return planner

@pytest.fixture
def mock_gemini():
    planner = MagicMock(spec=AgentPlanner)
    return planner

@pytest.fixture
def obs():
    return Observation(
        activity="com.test/MainActivity",
        ui_nodes=[],
        screen_hash="hash123",
        frida_events=[],
        screenshot_taken=False
    )

def test_hybrid_jev_success(mock_jev, mock_gemini, obs):
    mock_jev.decide = AsyncMock(return_value={"tool": "tap", "node_id": "n2"})
    mock_jev.last_failure_reason = "JEV_SUCCESS"
    mock_jev.last_confidence = 0.9
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is not None
    assert action["tool"] == "tap"
    mock_jev.decide.assert_called_once()
    mock_gemini.decide.assert_not_called()

def test_hybrid_jev_low_confidence(mock_jev, mock_gemini, obs):
    mock_jev.decide = AsyncMock(return_value={"tool": "tap", "node_id": "n2"})
    mock_jev.last_failure_reason = "JEV_SUCCESS"
    mock_jev.last_confidence = 0.5 # Below 0.7 threshold
    
    mock_gemini.decide = AsyncMock(return_value={"tool": "type_text"})
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is not None
    assert action["tool"] == "type_text"
    mock_jev.decide.assert_called_once()
    mock_gemini.decide.assert_called_once()

def test_hybrid_jev_failure_gemini_success(mock_jev, mock_gemini, obs):
    mock_jev.decide = AsyncMock(return_value=None)
    mock_jev.last_failure_reason = "JEV_TIMEOUT"
    
    mock_gemini.decide = AsyncMock(return_value={"tool": "type_text"})
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is not None
    assert action["tool"] == "type_text"
    mock_jev.decide.assert_called_once()
    mock_gemini.decide.assert_called_once()

def test_hybrid_vision_required(mock_jev, mock_gemini, obs):
    obs.screenshot_taken = True
    obs.vision_reason = "webview_activity"
    
    mock_gemini.decide = AsyncMock(return_value={"tool": "scroll"})
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is not None
    assert action["tool"] == "scroll"
    mock_jev.decide.assert_not_called()
    mock_gemini.decide.assert_called_once()

def test_hybrid_vision_not_required_but_screenshot_taken(mock_jev, mock_gemini, obs):
    obs.screenshot_taken = True
    obs.vision_reason = "frida_event_fraud_category" # Standard hook trigger, UI is fine
    
    mock_jev.decide = AsyncMock(return_value={"tool": "tap", "node_id": "n1"})
    mock_jev.last_failure_reason = "JEV_SUCCESS"
    mock_jev.last_confidence = 0.95
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is not None
    assert action["tool"] == "tap"
    mock_jev.decide.assert_called_once()
    mock_gemini.decide.assert_not_called()

def test_hybrid_both_planners_fail(mock_jev, mock_gemini, obs):
    mock_jev.decide = AsyncMock(return_value=None)
    mock_jev.last_failure_reason = "JEV_TIMEOUT"
    
    mock_gemini.decide = AsyncMock(return_value=None)
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    
    action = asyncio.run(planner.decide(obs, AgentMemory(), GoalTracker()))
    
    assert action is None
    mock_jev.decide.assert_called_once()
    mock_gemini.decide.assert_called_once()

def test_hybrid_invalidate_cache(mock_jev, mock_gemini):
    mock_jev.invalidate_cache_for_screen = MagicMock()
    mock_gemini.invalidate_cache_for_screen = MagicMock()
    
    planner = HybridPlanner(mock_jev, mock_gemini)
    planner.invalidate_cache_for_screen("hash123")
    
    mock_jev.invalidate_cache_for_screen.assert_called_once_with("hash123")
    mock_gemini.invalidate_cache_for_screen.assert_called_once_with("hash123")

