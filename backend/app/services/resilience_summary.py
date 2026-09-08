"""Resilience banner rows for the fraud card.

Three routes need the same three-line summary of what the sandbox did *to* the
device - the upload response, the stored-case reader and the report reader -
and each had its own copy of the logic. The copies inferred harness actions
from the sample's telemetry: any anti-analysis event mentioning "time" produced
"Fast-forwarded time (+24h) and intercepted dormant time-delayed payloads",
whether or not a clock had ever been touched. That is a claim about the
harness, drawn from evidence about the sample, and on a run with no time warp
it was simply false.

The sandbox now records what it actually did (``dynamic_result.anti_evasion``,
written mid-session by :mod:`sudarshan_core.engines.anti_evasion`), so the rows
are built from measurements: the observed clock shift, the rows the providers
accepted, and the before/after delta. The inference path remains for cases
analysed before that existed, reworded to describe what was *observed* rather
than what we would like to claim we did.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

#: Row types the fraud card knows how to render (it maps each to an icon).
TYPE_TIME_WARP = "time_warp"
TYPE_PERSONA = "persona_seeding"
TYPE_PERMISSIONS = "permission_grants"


def _step(steps: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
    for step in steps:
        if step.get("key") == key:
            return step
    return None


def _measured_rows(anti_evasion: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Rows describing the sequence the sandbox actually ran."""
    rows: List[Dict[str, Any]] = []
    steps = [s for s in anti_evasion.get("steps") or [] if isinstance(s, dict)]

    warps = [s for s in steps if str(s.get("key", "")).startswith("warp_")]
    if warps:
        shift = 0.0
        jobs = 0
        for step in warps:
            warp = (step.get("data") or {}).get("time_warp") or {}
            shift += float(warp.get("observed_shift_hours") or 0.0)
            jobs += len(warp.get("jobs_forced") or [])
        applied = [s for s in warps if s.get("ok")]
        if applied:
            summary = f"Advanced the device clock {shift:+.1f}h across {len(applied)} shift(s)"
            summary += f", forcing {jobs} scheduled job(s)" if jobs else ", and cycled Doze"
            summary += " to release deferred background work."
        else:
            summary = (
                "The device refused every clock change, so dormancy timers were "
                "not defeated on this run."
            )
        rows.append({"type": TYPE_TIME_WARP, "title": "Time-Warping", "result_summary": summary})

    # Each provider reports rows it wrote and rows the device already held; the
    # analyst cares that the device *carries* them, not which run put them there.
    held = {}
    for key in ("contacts", "calls", "sms", "photos"):
        data = (_step(steps, key) or {}).get("data") or {}
        held[key] = int(data.get("inserted") or 0) or int(data.get("already_present") or 0)

    if any(_step(steps, key) for key in ("contacts", "calls", "sms", "photos")):
        if any(held.values()):
            summary = (
                f"Device carries {held['contacts']} synthetic contact(s), "
                f"{held['calls']} call-log entry(ies), {held['sms']} bank SMS and "
                f"{held['photos']} photo(s), clearing the empty-device checks "
                "evasive families run before unpacking."
            )
        else:
            summary = (
                "The device refused every history write, so emptiness checks "
                "were not cleared on this run."
            )
        rows.append({"type": TYPE_PERSONA, "title": "Persona Seeding", "result_summary": summary})

    return rows


def _observed_rows(dynamic: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Fallback for cases analysed before the sequence was measured.

    Each row describes what was seen in the sample's telemetry. It deliberately
    does not claim the harness performed an action: nothing in a stored case
    from before this feature records that it did.
    """
    rows: List[Dict[str, Any]] = []

    anti_events = dynamic.get("anti_analysis_events") or []
    time_events = [
        e for e in anti_events if "time" in str(e).lower() or "alarm" in str(e).lower()
    ]
    if time_events:
        rows.append(
            {
                "type": TYPE_TIME_WARP,
                "title": "Dormancy checks observed",
                "result_summary": (
                    f"{len(time_events)} time- or alarm-related anti-analysis event(s) "
                    "observed - the sample inspected the clock or scheduled deferred work."
                ),
            }
        )

    api_calls = dynamic.get("api_calls") or []
    if any(
        "content://contacts" in str(a).lower() or "content://sms" in str(a).lower()
        for a in api_calls
    ):
        rows.append(
            {
                "type": TYPE_PERSONA,
                "title": "Device-history access observed",
                "result_summary": (
                    "The sample queried the contacts or SMS providers - the emptiness "
                    "check evasion-first families run before unpacking."
                ),
            }
        )
    return rows


def build_resilience_actions(
    dynamic: Optional[Dict[str, Any]],
    static_flags: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Banner rows for one case. Empty when there is nothing truthful to say."""
    if not isinstance(dynamic, dict):
        return []

    anti_evasion = dynamic.get("anti_evasion")
    rows = (
        _measured_rows(anti_evasion)
        if isinstance(anti_evasion, dict) and anti_evasion
        else _observed_rows(dynamic)
    )

    flags = static_flags if isinstance(static_flags, dict) else {}
    granted = dynamic.get("pregranted_permissions") or []
    if granted:
        rows.append(
            {
                "type": TYPE_PERMISSIONS,
                "title": "Permission Grants",
                "result_summary": (
                    f"{len(granted)} declared runtime permission(s) granted before launch so "
                    "the payload was not blocked by an unanswered consent dialog."
                ),
            }
        )
    elif flags.get("has_system_alert_window") or flags.get("has_accessibility_abuse"):
        rows.append(
            {
                "type": TYPE_PERMISSIONS,
                "title": "High-risk capability declared",
                "result_summary": (
                    "The sample declares overlay and/or accessibility capability - the two "
                    "permissions Android banking trojans need before any payload runs."
                ),
            }
        )
    return rows
