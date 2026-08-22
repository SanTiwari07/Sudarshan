"""Fix A: fraud-relevant Frida events force Vision even when the XML parses.

An overlay drawn above the target app leaves a well-formed, well-labelled UI
tree, so the five original triggers never fire and the planner navigates blind.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.perception import (
    FRAUD_EVENT_CATEGORIES,
    Observation,
    PerceptionPipeline,
    UINode,
)


def _healthy_obs(**kw):
    """An observation the original triggers would all decline to screenshot."""
    nodes = [
        UINode(f"n{i}", "android.widget.Button", f"Label {i}", "", f"id/b{i}",
               10, 10, False, True, False, "[0,0][100,100]")
        for i in range(5)
    ]
    obs = Observation(
        activity="com.bank/com.bank.MainActivity",
        ui_nodes=nodes,
        ui_node_count=len(nodes),
        ui_xml_raw="<hierarchy><node/></hierarchy>",
    )
    for k, v in kw.items():
        setattr(obs, k, v)
    return obs


def _pipeline():
    return PerceptionPipeline(device_serial="emulator-5554", package_name="com.bank")


def test_healthy_screen_still_needs_no_screenshot():
    """Guard the baseline: without fraud events nothing changed."""
    assert _pipeline()._screenshot_needed(_healthy_obs(), False) == ""


def test_overlay_event_forces_vision_on_healthy_xml():
    obs = _healthy_obs(frida_events=[{"category": "overlay", "severity": "HIGH"}])
    reason = _pipeline()._screenshot_needed(obs, False)
    assert reason.startswith("frida_event_fraud_category")
    assert "overlay" in reason


def test_each_fraud_category_triggers_vision():
    for cat in FRAUD_EVENT_CATEGORIES:
        obs = _healthy_obs(frida_events=[{"category": cat}])
        reason = _pipeline()._screenshot_needed(obs, False)
        assert reason.startswith("frida_event_fraud_category"), cat


def test_category_matching_is_case_insensitive():
    obs = _healthy_obs(frida_events=[{"category": "OverLay"}])
    assert _pipeline()._screenshot_needed(obs, False).startswith(
        "frida_event_fraud_category"
    )


def test_unrelated_event_category_does_not_trigger():
    obs = _healthy_obs(frida_events=[{"category": "network"}, {"category": "crypto"}])
    assert _pipeline()._screenshot_needed(obs, False) == ""


def test_malformed_events_are_ignored_not_raised():
    obs = _healthy_obs(frida_events=[None, "overlay", 42, {}, {"category": None}])
    assert _pipeline()._screenshot_needed(obs, False) == ""


def test_fraud_categories_helper_dedupes_and_normalises():
    obs = _healthy_obs(frida_events=[
        {"category": "overlay"}, {"category": "OVERLAY"}, {"category": "sms"},
    ])
    assert PerceptionPipeline._fraud_event_categories(obs) == {"overlay", "sms"}


def test_original_triggers_still_fire():
    """Fix A must not displace the five pre-existing triggers."""
    p = _pipeline()
    assert p._screenshot_needed(_healthy_obs(ui_xml_raw=""), False) == "ui_xml_empty"
    assert p._screenshot_needed(_healthy_obs(), True) == "previous_action_failed"
    obs = _healthy_obs(ui_nodes=[], ui_node_count=0)
    assert "no_actionable_nodes" in p._screenshot_needed(obs, False)
