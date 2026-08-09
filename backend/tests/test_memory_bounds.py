"""
Regression tests for AgentMemory capacity limits.

Root defect: five collections grew without bound for the lifetime of an
analysis - `visited_screens`, `_screen_action_counts` (both the dict AND each
inner list), `network_events`, `failed_actions` and `_frida_event_counts`.
The analysed application decides how many unique screens and URLs exist, so
these were attacker-influenced and could be driven to exhaust memory.

`network_events` additionally used an O(n) `not in list` scan per event, which
degraded quadratically as the list grew.
"""

import time

import pytest

from sudarshan_core.engines.agentic.agent_memory import (
    MAX_ACTIONS_TRACKED_PER_SCREEN,
    MAX_FAILED_ACTIONS,
    MAX_NETWORK_EVENTS,
    MAX_SCREENS_WITH_ACTION_COUNTS,
    MAX_VISITED_SCREENS,
    AgentMemory,
)


@pytest.fixture
def memory():
    return AgentMemory()


def _net_events(n, prefix="http://c2-"):
    return [
        {"category": "network", "data": {"url": f"{prefix}{i}.example"}}
        for i in range(n)
    ]


# ─── visited_screens ──────────────────────────────────────────────────────────

def test_visited_screens_is_bounded(memory):
    for i in range(MAX_VISITED_SCREENS * 2):
        memory.register_screen(f"screen{i}", "com.x/.A")
    assert len(memory.visited_screens) <= MAX_VISITED_SCREENS


def test_total_screens_seen_survives_eviction(memory):
    """Eviction must not corrupt coverage metrics."""
    total = MAX_VISITED_SCREENS * 2
    for i in range(total):
        memory.register_screen(f"screen{i}", "com.x/.A")
    assert memory._total_screens_seen == total


def test_revisiting_a_screen_protects_it_from_eviction(memory):
    memory.register_screen("keepme", "com.x/.A")
    for i in range(MAX_VISITED_SCREENS - 1):
        memory.register_screen(f"s{i}", "com.x/.A")
        memory.register_screen("keepme", "com.x/.A")     # refresh recency
    memory.register_screen("overflow", "com.x/.A")
    assert "keepme" in memory.visited_screens


def test_register_screen_still_reports_new_vs_seen(memory):
    assert memory.register_screen("a", "com.x/.A") is True
    assert memory.register_screen("a", "com.x/.A") is False


# ─── _screen_action_counts ────────────────────────────────────────────────────

def test_screen_action_dict_is_bounded(memory):
    for i in range(MAX_SCREENS_WITH_ACTION_COUNTS * 2):
        memory.register_screen(f"screen{i}", "com.x/.A")
        memory.record_action(tool="tap", target="b", goal_name="g",
                             reasoning="r", success=True)
    assert len(memory._screen_action_counts) <= MAX_SCREENS_WITH_ACTION_COUNTS


def test_per_screen_action_list_is_bounded(memory):
    memory.register_screen("one_screen", "com.x/.A")
    for _ in range(MAX_ACTIONS_TRACKED_PER_SCREEN * 5):
        memory.record_action(tool="tap", target="b", goal_name="g",
                             reasoning="r", success=True)
    assert len(memory._screen_action_counts["one_screen"]) <= MAX_ACTIONS_TRACKED_PER_SCREEN


def test_loop_detection_still_works_after_bounding(memory):
    """Bounding must not break the behaviour the collection exists for."""
    from sudarshan_core.engines.agentic.agent_memory import MAX_ACTIONS_PER_SCREEN
    memory.register_screen("s", "com.x/.A")
    for _ in range(MAX_ACTIONS_PER_SCREEN):
        memory.record_action(tool="tap", target="btn", goal_name="g",
                             reasoning="r", success=True)
    assert memory.is_action_loop("tap", "btn") is True


# ─── network_events ───────────────────────────────────────────────────────────

def test_network_events_are_bounded(memory):
    memory.record_frida_events(_net_events(MAX_NETWORK_EVENTS * 2), goal_name="Network / C2")
    assert len(memory.network_events) <= MAX_NETWORK_EVENTS


def test_network_events_deduplicate(memory):
    dupes = [{"category": "network", "data": {"url": "http://same.example"}}] * 50
    memory.record_frida_events(dupes, goal_name="Network / C2")
    assert memory.network_events.count("http://same.example") == 1


def test_network_set_and_list_never_disagree(memory):
    """After eviction the O(1) index must not retain dropped URLs."""
    memory.record_frida_events(_net_events(MAX_NETWORK_EVENTS * 2), goal_name="Network / C2")
    assert set(memory.network_events) == memory._network_seen


def test_evicted_url_can_be_recorded_again(memory):
    """Consequence of keeping set and list in sync - not a leak."""
    memory.record_frida_events(
        [{"category": "network", "data": {"url": "http://first.example"}}],
        goal_name="Network / C2",
    )
    memory.record_frida_events(_net_events(MAX_NETWORK_EVENTS + 10), goal_name="Network / C2")
    assert "http://first.example" not in memory._network_seen


@pytest.mark.parametrize("count", [100_000])
def test_hundred_thousand_network_events_stay_bounded_and_fast(memory, count):
    """
    §4 matrix: 100k events including duplicates. Guards both the capacity limit
    and the O(1) dedupe - the previous O(n) scan made this quadratic.
    """
    events = _net_events(count // 2) * 2          # every URL appears twice
    start = time.monotonic()
    memory.record_frida_events(events, goal_name="Network / C2")
    elapsed = time.monotonic() - start

    assert len(memory.network_events) <= MAX_NETWORK_EVENTS
    assert set(memory.network_events) == memory._network_seen
    # Generous ceiling: the point is to catch quadratic regression, not to
    # benchmark the machine.
    assert elapsed < 30.0, f"dedupe took {elapsed:.1f}s - suspect O(n) scan regression"


# ─── failed_actions ───────────────────────────────────────────────────────────

def test_failed_actions_are_bounded(memory):
    memory.register_screen("s", "com.x/.A")
    for i in range(MAX_FAILED_ACTIONS * 3):
        memory.record_action(tool="tap", target=f"b{i}", goal_name="g",
                             reasoning="r", success=False, error="boom")
    assert len(memory.failed_actions) <= MAX_FAILED_ACTIONS


def test_most_recent_failures_are_the_ones_retained(memory):
    memory.register_screen("s", "com.x/.A")
    for i in range(MAX_FAILED_ACTIONS * 2):
        memory.record_action(tool="tap", target=f"b{i}", goal_name="g",
                             reasoning="r", success=False, error=f"err{i}")
    targets = [f["target"] for f in memory.failed_actions]
    assert targets[-1] == f"b{MAX_FAILED_ACTIONS * 2 - 1}"


# ─── Credential safety must survive the refactor ──────────────────────────────

def test_credential_values_never_stored(memory):
    from sudarshan_core.engines.agentic.tool_executor import FORM_VALUES
    memory.register_screen("s", "com.x/.A")
    memory.record_action(tool="type_text", target="pwd", goal_name="Login Flow",
                         reasoning="r", success=True, credential_key="password")
    context = memory.build_prompt_context()
    for value in FORM_VALUES.values():
        assert value not in context
