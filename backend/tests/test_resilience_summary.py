"""Resilience banner rows: measured facts first, and no invented harness actions.

The rows these produce are read by an analyst as "here is what the sandbox did
to the device". The previous implementation inferred them from the *sample's*
telemetry, so a run in which no clock was ever touched still announced
"Fast-forwarded time (+24h)". These tests pin the distinction: a claim about
the harness may only come from a record of the harness acting.
"""

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from app.services.resilience_summary import build_resilience_actions  # noqa: E402


def _sequence(**overrides):
    """A recorded anti-evasion sequence, as the sandbox writes it."""
    base = {
        "verdict": "NO_CHANGES_OBSERVED",
        "steps": [
            {
                "key": "warp_6h",
                "ok": True,
                "data": {"time_warp": {"observed_shift_hours": 6.0, "jobs_forced": ["12"]}},
            },
            {
                "key": "warp_24h",
                "ok": True,
                "data": {"time_warp": {"observed_shift_hours": 18.0, "jobs_forced": []}},
            },
            {"key": "battery", "ok": True, "data": {"observed_level": 50}},
            {"key": "contacts", "ok": True, "data": {"inserted": 12}},
            {"key": "calls", "ok": True, "data": {"inserted": 10}},
            {"key": "sms", "ok": True, "data": {"inserted": 4}},
            {"key": "photos", "ok": True, "data": {"inserted": 3}},
        ],
    }
    base.update(overrides)
    return base


def _rows_by_type(rows):
    return {r["type"]: r for r in rows}


def test_measured_rows_carry_the_observed_numbers():
    rows = _rows_by_type(build_resilience_actions({"anti_evasion": _sequence()}, {}))
    warp = rows["time_warp"]["result_summary"]
    assert "+24.0h" in warp and "2 shift(s)" in warp and "1 scheduled job(s)" in warp

    persona = rows["persona_seeding"]["result_summary"]
    assert "12 synthetic contact(s)" in persona and "4 bank SMS" in persona
    assert "10 call-log entry(ies)" in persona and "3 photo(s)" in persona


def test_a_refused_warp_is_reported_as_refused():
    """The device said no. The banner must not say we advanced anything."""
    refused = _sequence(
        steps=[
            {
                "key": "warp_6h",
                "ok": False,
                "data": {"time_warp": {"observed_shift_hours": 0.0, "jobs_forced": []}},
            }
        ]
    )
    rows = _rows_by_type(build_resilience_actions({"anti_evasion": refused}, {}))
    assert "refused" in rows["time_warp"]["result_summary"]
    assert "Advanced" not in rows["time_warp"]["result_summary"]


def test_a_device_that_was_already_seeded_still_reports_what_it_holds():
    already = _sequence(
        steps=[{"key": "contacts", "ok": True, "data": {"inserted": 0, "already_present": 12}}]
    )
    rows = _rows_by_type(build_resilience_actions({"anti_evasion": already}, {}))
    assert "12 synthetic contact(s)" in rows["persona_seeding"]["result_summary"]


def test_legacy_cases_describe_observations_not_harness_actions():
    """
    A case analysed before the sequence existed has no record of a time warp,
    because none happened. The row may only describe what was seen.
    """
    legacy = {
        "anti_analysis_events": [{"hook": "System.currentTimeMillis"}],
        "api_calls": ["content://contacts/phones"],
    }
    rows = _rows_by_type(build_resilience_actions(legacy, {}))
    summaries = " ".join(r["result_summary"] for r in rows.values())
    assert "Fast-forwarded" not in summaries
    assert "Injected synthetic" not in summaries
    assert "observed" in rows["time_warp"]["result_summary"]
    assert "queried the contacts" in rows["persona_seeding"]["result_summary"]


def test_permission_row_counts_real_grants():
    rows = _rows_by_type(
        build_resilience_actions(
            {"anti_evasion": _sequence(), "pregranted_permissions": ["A", "B", "C"]}, {}
        )
    )
    assert "3 declared runtime permission(s) granted" in rows["permission_grants"]["result_summary"]


def test_permission_row_without_grants_describes_the_manifest_only():
    rows = _rows_by_type(
        build_resilience_actions({"api_calls": []}, {"has_accessibility_abuse": True})
    )
    summary = rows["permission_grants"]["result_summary"]
    assert "declares" in summary
    assert "Auto-granted" not in summary


def test_nothing_to_say_produces_no_rows():
    assert build_resilience_actions({"api_calls": [], "anti_analysis_events": []}, {}) == []
    assert build_resilience_actions(None, {}) == []
