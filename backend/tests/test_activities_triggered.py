"""
Regression tests for Task 4:
  activities_triggered must reflect activities actually observed during the
  session, NOT [package_name] (which was a hardcoded fabrication).

  _collect_observed_activities() must:
    - Extract real activity names from session.reports["agent_memory"]["visited_screens"]
    - Fall back to EventBus activity events in attack_timeline
    - Return [] (empty list) when no explorer ran - NEVER [package_name]
    - Be idempotent and never raise on malformed/missing data
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest


# ── import the helper under test ──────────────────────────────────────────────

from sudarshan_core.engines.frida_sandbox import _collect_observed_activities


PACKAGE = "com.example.bankbot"


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_session(reports: Dict[str, Any] = None) -> MagicMock:
    session = MagicMock()
    session.reports = reports or {}
    session.package_name = PACKAGE
    return session


# ── Test 1: real activities extracted from explorer memory ────────────────────

def test_extracts_activities_from_agent_memory():
    """
    When session.reports contains agent_memory with visited_screens that have
    activity keys, _collect_observed_activities must return those activities,
    not [package_name].
    """
    real_activities = [
        "com.example.bankbot.MainActivity",
        "com.example.bankbot.LoginActivity",
    ]
    reports = {
        "agent_memory": {
            "visited_screens": {
                "hash_abc": {"activity": real_activities[0], "iteration": 1},
                "hash_def": {"activity": real_activities[1], "iteration": 2},
            }
        }
    }

    session = _make_session(reports)
    result = _collect_observed_activities(session)

    assert set(result) == set(real_activities), (
        f"Expected {real_activities}, got {result}. "
        "activities_triggered must reflect actual observed activities."
    )
    assert PACKAGE not in result, (
        "activities_triggered must not contain the bare package name "
        " - that was the fabricated placeholder."
    )


# ── Test 2: empty list returned when no explorer ran ─────────────────────────

def test_returns_empty_when_no_explorer():
    """
    When session.reports is empty (no explorer ran), _collect_observed_activities
    must return [] - not [package_name], which was the old fabrication.
    """
    session = _make_session(reports={})
    result = _collect_observed_activities(session)

    assert result == [], (
        f"Expected [], got {result}. "
        "No fabricated placeholder allowed when no explorer ran."
    )
    assert PACKAGE not in result


# ── Test 3: returns empty list when agent_memory is missing ───────────────────

def test_returns_empty_when_agent_memory_missing():
    """
    Missing agent_memory key must degrade to [] gracefully.
    """
    session = _make_session(reports={"exploration_summary": {"screens_visited": 3}})
    result = _collect_observed_activities(session)
    assert result == []


# ── Test 4: falls back to attack_timeline when visited_screens is empty ────────

def test_falls_back_to_attack_timeline():
    """
    When visited_screens is empty but attack_timeline contains activity events,
    those activities should be returned.
    """
    fallback_act = "com.example.bankbot.OverlayService"
    reports = {
        "agent_memory": {
            "visited_screens": {}  # empty
        },
        "attack_timeline": [
            {
                "category": "activity",
                "data": {"activity": fallback_act},
            },
            {
                "category": "network",
                "data": {"url": "http://evil.ru"},
            },
        ],
    }

    session = _make_session(reports)
    result = _collect_observed_activities(session)

    assert fallback_act in result, (
        f"Expected activity '{fallback_act}' from attack_timeline, got {result}"
    )


# ── Test 5: handles malformed/None reports gracefully ─────────────────────────

@pytest.mark.parametrize("bad_reports", [
    None,
    {},
    {"agent_memory": None},
    {"agent_memory": {"visited_screens": None}},
    {"agent_memory": {"visited_screens": "not_a_dict"}},
    {"agent_memory": {"visited_screens": 42}},
])
def test_never_raises_on_malformed_data(bad_reports):
    """
    _collect_observed_activities must never raise, regardless of what is in
    session.reports. Attackers control APK content → analysis must be a total
    function.
    """
    session = MagicMock()
    session.reports = bad_reports
    session.package_name = PACKAGE

    # Must not raise
    result = _collect_observed_activities(session)
    assert isinstance(result, list)


# ── Test 6: result is never [package_name] ────────────────────────────────────

def test_result_is_never_package_name_alone():
    """
    Under no circumstances should the result be exactly [package_name].
    That was the specific fabrication that was being fixed.
    """
    # Try every plausible edge case
    for bad_reports in [{}, None, {"agent_memory": {}}]:
        session = MagicMock()
        session.reports = bad_reports
        session.package_name = PACKAGE

        result = _collect_observed_activities(session)
        assert result != [PACKAGE], (
            f"result == ['{PACKAGE}'] - this is the fabricated placeholder that "
            "must never be returned by _collect_observed_activities."
        )


# ── Test 7: deduplication ─────────────────────────────────────────────────────

def test_deduplicates_activities():
    """
    The same activity seen on multiple screens must appear only once.
    """
    act = "com.example.bankbot.MainActivity"
    reports = {
        "agent_memory": {
            "visited_screens": {
                "hash_a": {"activity": act},
                "hash_b": {"activity": act},  # same activity, different screen hash
                "hash_c": {"activity": "com.example.bankbot.Other"},
            }
        }
    }

    session = _make_session(reports)
    result = _collect_observed_activities(session)

    assert result.count(act) == 1, (
        f"'{act}' appears {result.count(act)} times, expected 1. "
        "activities_triggered must be deduplicated."
    )
