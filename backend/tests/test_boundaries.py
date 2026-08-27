"""
Trust-boundary and device-property regression tests.

Two root defects:

1. `risk_engine` consumed `dynamic["bfci"]` verbatim from an untyped dict. The
   sandbox was the only writer, so isolation of the verdict rested on
   convention rather than validation - a NaN, a string or an out-of-range score
   would have propagated straight into the FRS.

2. Screen dimensions had two disagreeing sources: `tool_executor` read them
   from the environment while the planner validated against `tool_registry`'s
   hardcoded 1080x1920. On the project's 1080x2400 Pixel_6 that rejected every
   action in the bottom 480px - 20% of the screen - as Step5_OutOfBounds.
"""

import math

import pytest

from sudarshan_core.engines.agentic.device_properties import (
    FALLBACK_SCREEN_HEIGHT,
    FALLBACK_SCREEN_WIDTH,
    clear_cache,
    get_screen_size,
    parse_wm_size,
)
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags


def _score(dynamic):
    return calculate_risk_score(
        StaticAnalysisFlags(has_sms_read_write=True),
        ai_confidence=1.0,
        dynamic_result=dynamic,
    )


# ─── Risk-engine boundary ─────────────────────────────────────────────────────

def test_valid_payload_is_unchanged_by_validation():
    """Validation must not shift any existing verdict."""
    result = _score({"available": True, "engine": "frida", "bfci": 61.25,
                     "bfci_components": {"sms": 50.0}})
    assert result["frs_breakdown"]["dynamic"] == 61.25


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_bfci_is_rejected(bad):
    result = _score({"available": True, "engine": "frida", "bfci": bad,
                     "bfci_components": {"sms": 50.0}})
    assert math.isfinite(result["final_risk_score"])
    assert math.isfinite(result["frs_breakdown"]["dynamic"])


@pytest.mark.parametrize("bad", ["not-a-number", None, [1, 2], {"a": 1}, object()])
def test_non_numeric_bfci_is_rejected(bad):
    result = _score({"available": True, "engine": "frida", "bfci": bad,
                     "bfci_components": {"sms": 50.0}})
    assert math.isfinite(result["final_risk_score"])


def test_out_of_range_bfci_is_clamped():
    high = _score({"available": True, "engine": "frida", "bfci": 10_000.0,
                   "bfci_components": {"sms": 50.0}})
    assert high["frs_breakdown"]["dynamic"] <= 100.0
    assert high["final_risk_score"] <= 100.0


def test_negative_bfci_cannot_reduce_the_score_below_zero():
    result = _score({"available": True, "engine": "frida", "bfci": -500.0,
                     "bfci_components": {"sms": 50.0}})
    assert result["final_risk_score"] >= 0.0


def test_malformed_components_container_is_survivable():
    for components in ("string", 42, None, ["list"]):
        result = _score({"available": True, "engine": "frida",
                         "bfci": 50.0, "bfci_components": components})
        assert math.isfinite(result["final_risk_score"])


def test_malformed_component_values_are_rejected():
    result = _score({
        "available": True, "engine": "frida", "bfci": 0,
        "bfci_components": {"sms": float("nan"), "overlay": "abc", "banking": 50.0},
    })
    assert math.isfinite(result["frs_breakdown"]["dynamic"])


def test_missing_dynamic_section_uses_static_branch():
    result = _score(None)
    assert result["frs_breakdown"]["formula_used"] == "static_only_frs"


def test_malformed_evidence_type_is_survivable():
    result = _score({"available": True, "engine": "frida", "bfci": 50.0,
                     "bfci_components": {"sms": 50.0}, "bfci_evidence": "not-a-list"})
    assert isinstance(result["evidence"], list)


def test_boundary_values_zero_and_hundred_pass_through():
    zero = _score({"available": True, "engine": "frida", "bfci": 0.0,
                   "bfci_components": {"sms": 0.0}})
    full = _score({"available": True, "engine": "frida", "bfci": 100.0,
                   "bfci_components": {"sms": 100.0}})
    assert zero["frs_breakdown"]["dynamic"] == 0.0
    assert full["frs_breakdown"]["dynamic"] == 100.0


# ─── Device properties ────────────────────────────────────────────────────────

def test_parse_portrait():
    assert parse_wm_size("Physical size: 1080x2400") == (1080, 2400)


def test_parse_landscape():
    assert parse_wm_size("Physical size: 2400x1080") == (2400, 1080)


def test_override_size_wins_over_physical():
    """What the display actually renders at is the override, when present."""
    out = "Physical size: 1440x3120\nOverride size: 1080x2340"
    assert parse_wm_size(out) == (1080, 2340)


def test_parse_foldable_large_inner_display():
    assert parse_wm_size("Physical size: 1812x2176") == (1812, 2176)


@pytest.mark.parametrize(
    "text", ["", "wm: command not found", "Physical size: garbage", None]
)
def test_unparseable_output_returns_none(text):
    assert parse_wm_size(text or "") is None


def test_implausible_dimensions_are_rejected():
    assert parse_wm_size("Physical size: 1x1") is None
    assert parse_wm_size("Physical size: 999999x999999") is None


def test_env_override_takes_priority(monkeypatch):
    clear_cache()
    monkeypatch.setenv("SUDARSHAN_SCREEN_WIDTH", "1440")
    monkeypatch.setenv("SUDARSHAN_SCREEN_HEIGHT", "3120")
    assert get_screen_size(adb_path="definitely-not-a-real-binary") == (1440, 3120)


def test_invalid_env_override_is_ignored(monkeypatch):
    """
    A non-numeric override must be ignored rather than crashing or being
    half-applied.

    The device query is stubbed out rather than defeated with a bogus
    adb_path. `get_screen_size` routes every query through
    `get_sandbox_provider()` - the policy-enforcing choke point - and does not
    use `adb_path` at all, so on a machine with an emulator attached the bogus
    path did not prevent a real `wm size`, and the assertion compared the
    fallback against that device's true resolution (1080x2400 here). The test
    passed only where no device was connected.

    What is under test is the override handling, so the device answer is made
    deterministic instead of being left to whatever hardware is plugged in.
    """
    import sudarshan_core.engines.agentic.device_properties as dp

    clear_cache()
    monkeypatch.setenv("SUDARSHAN_SCREEN_WIDTH", "not-a-number")
    monkeypatch.setenv("SUDARSHAN_SCREEN_HEIGHT", "3120")

    class _NoDevice:
        def adb(self, *a, **k):
            return False, ""

    monkeypatch.setattr(dp, "get_sandbox_provider", lambda: _NoDevice(), raising=False)
    monkeypatch.setattr(
        "sudarshan_core.sandbox.get_sandbox_provider", lambda: _NoDevice(),
    )

    assert get_screen_size() == (FALLBACK_SCREEN_WIDTH, FALLBACK_SCREEN_HEIGHT)


def test_falls_back_when_adb_unavailable(monkeypatch):
    """`wm size` unavailable → fallback, never an exception."""
    clear_cache()
    monkeypatch.delenv("SUDARSHAN_SCREEN_WIDTH", raising=False)
    monkeypatch.delenv("SUDARSHAN_SCREEN_HEIGHT", raising=False)
    size = get_screen_size(adb_path="definitely-not-a-real-binary", device_serial="nope")
    assert size == (FALLBACK_SCREEN_WIDTH, FALLBACK_SCREEN_HEIGHT)


def test_validator_and_executor_agree(monkeypatch):
    """
    The exact coupling defect: planner and executor must never disagree about
    how tall the screen is.
    """
    clear_cache()
    monkeypatch.setenv("SUDARSHAN_SCREEN_WIDTH", "1080")
    monkeypatch.setenv("SUDARSHAN_SCREEN_HEIGHT", "2400")

    from sudarshan_core.engines.agentic.planner import AgentPlanner
    from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

    planner = AgentPlanner(api_key=None, device_serial="s", package_name="p")
    executor = ToolExecutor(device_serial="s", package_name="p")
    assert planner._screen_bounds() == executor.screen_size == (1080, 2400)


def test_tall_screen_coordinates_are_accepted(monkeypatch):
    """
    Regression: y=2000 on a 1080x2400 device was rejected as out-of-bounds
    because validation used a hardcoded 1920 height.
    """
    clear_cache()
    monkeypatch.setenv("SUDARSHAN_SCREEN_WIDTH", "1080")
    monkeypatch.setenv("SUDARSHAN_SCREEN_HEIGHT", "2400")

    import json as _json

    from sudarshan_core.engines.agentic.perception import Observation
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    planner = AgentPlanner(api_key=None, device_serial="s", package_name="p")
    action = _json.dumps({
        "tool": "tap", "x": 540, "y": 2000,
        "goal": "Login Flow", "reasoning": "bottom-of-screen button",
        "confidence": 0.9,
    })
    validated, error = planner._validate_action(action, Observation())
    assert validated is not None, f"rejected a reachable coordinate: {error}"
    assert validated["y"] == 2000


def test_coordinate_beyond_real_screen_is_still_rejected(monkeypatch):
    clear_cache()
    monkeypatch.setenv("SUDARSHAN_SCREEN_WIDTH", "1080")
    monkeypatch.setenv("SUDARSHAN_SCREEN_HEIGHT", "2400")

    import json as _json

    from sudarshan_core.engines.agentic.perception import Observation
    from sudarshan_core.engines.agentic.planner import AgentPlanner

    planner = AgentPlanner(api_key=None, device_serial="s", package_name="p")
    action = _json.dumps({
        "tool": "tap", "x": 540, "y": 99_999,
        "goal": "g", "reasoning": "r", "confidence": 0.9,
    })
    validated, error = planner._validate_action(action, Observation())
    assert validated is None
    assert "OutOfBounds" in error
