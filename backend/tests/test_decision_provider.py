import asyncio
from unittest.mock import AsyncMock, MagicMock
import pytest

from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.decision_provider import (
    CascadingDecisionProvider,
    GeminiDecisionProvider,
    JevDecisionProvider,
    LayaDecisionProvider,
    RuleDecisionProvider,
    create_decision_provider,
)
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
from sudarshan_core.engines.agentic.perception import Observation, UINode


@pytest.fixture
def memory():
    return AgentMemory()


@pytest.fixture
def goals():
    return GoalTracker()


@pytest.fixture
def text_obs():
    node = UINode(
        node_id="n1",
        class_name="android.widget.Button",
        text="Continue",
        desc="",
        resource_id="btn_continue",
        center_x=50,
        center_y=25,
        is_input=False,
        is_clickable=True,
        is_scrollable=False,
        bounds="[0,0][100,50]",
    )
    return Observation(
        activity="com.test/MainActivity",
        ui_nodes=[node],
        screen_hash="hash_text",
        frida_events=[],
        screenshot_taken=False,
    )


@pytest.fixture
def webview_obs():
    return Observation(
        activity="com.test/WebViewActivity",
        ui_nodes=[],
        screen_hash="hash_webview",
        frida_events=[],
        screenshot_taken=False,
    )


def test_jev_decision_provider(text_obs, memory, goals):
    mock_jev = AsyncMock()
    mock_jev.decide.return_value = {"tool": "tap", "node_id": "btn1", "_selected_by": "jev_planner"}

    provider = JevDecisionProvider(mock_jev)
    action = asyncio.run(provider.decide(text_obs, memory, goals))
    assert action is not None
    assert action["node_id"] == "btn1"
    mock_jev.decide.assert_called_once()


def test_laya_decision_provider(text_obs, memory, goals):
    mock_laya = AsyncMock()
    mock_laya.decide.return_value = {"tool": "type_text", "node_id": "field1", "_selected_by": "laya_planner"}

    provider = LayaDecisionProvider(mock_laya)
    action = asyncio.run(provider.decide(text_obs, memory, goals))
    assert action is not None
    assert action["tool"] == "type_text"
    mock_laya.decide.assert_called_once()


def test_cascading_provider_primary_success(text_obs, memory, goals):
    laya_mock = AsyncMock()
    laya_mock.decide.return_value = {"tool": "tap", "node_id": "laya_node", "_selected_by": "laya_planner"}

    gemini_mock = AsyncMock()
    gemini_mock.decide.return_value = {"tool": "tap", "node_id": "gemini_node", "_selected_by": "gemini"}

    cascade = CascadingDecisionProvider([
        ("laya", LayaDecisionProvider(laya_mock)),
        ("gemini", GeminiDecisionProvider(gemini_mock)),
    ])

    action = asyncio.run(cascade.decide(text_obs, memory, goals))
    assert action is not None
    assert action["node_id"] == "laya_node"
    gemini_mock.decide.assert_not_called()


def test_cascading_provider_fallback_to_gemini(text_obs, memory, goals):
    laya_mock = AsyncMock()
    laya_mock.decide.return_value = None  # Laya has no choice / low confidence

    gemini_mock = AsyncMock()
    gemini_mock.decide.return_value = {"tool": "tap", "node_id": "gemini_node", "_selected_by": "gemini"}

    cascade = CascadingDecisionProvider([
        ("laya", LayaDecisionProvider(laya_mock)),
        ("gemini", GeminiDecisionProvider(gemini_mock)),
    ])

    action = asyncio.run(cascade.decide(text_obs, memory, goals))
    assert action is not None
    assert action["node_id"] == "gemini_node"


def test_cascading_provider_webview_routes_to_vision(webview_obs, memory, goals):
    laya_mock = AsyncMock()
    gemini_mock = AsyncMock()
    gemini_mock.decide.return_value = {"tool": "tap", "x": 50, "y": 50, "_selected_by": "gemini_vision"}

    cascade = CascadingDecisionProvider(
        providers=[("laya", LayaDecisionProvider(laya_mock))],
        vision_provider=GeminiDecisionProvider(gemini_mock),
    )

    action = asyncio.run(cascade.decide(webview_obs, memory, goals))
    assert action is not None
    assert action["_selected_by"] == "gemini_vision"
    laya_mock.decide.assert_not_called()


def test_factory_creation():
    laya_mock = MagicMock()
    gemini_mock = MagicMock()
    jev_mock = MagicMock()

    prov_laya = create_decision_provider("laya", laya_planner=laya_mock)
    assert isinstance(prov_laya, LayaDecisionProvider)

    prov_laya_hybrid = create_decision_provider(
        "laya_hybrid",
        laya_planner=laya_mock,
        agent_planner=gemini_mock,
    )
    assert isinstance(prov_laya_hybrid, CascadingDecisionProvider)
    assert len(prov_laya_hybrid.providers) == 2

    prov_jev = create_decision_provider("jev", jev_planner=jev_mock)
    assert isinstance(prov_jev, JevDecisionProvider)
