"""
Sandbox preconditions in the reconstructed workflow.

§24's own example chain is:

    Accessibility Enabled -> OTP Screen -> SMS Interception -> Network POST

Its first link could never form. The reconstructor was fed only Frida hook
events, and "Accessibility Enabled" is a capability the SANDBOX grants, not a
hook the app calls - so a run where we enabled accessibility and the sample then
intercepted SMS showed the interception with no account of what made it
reachable.

The load-bearing constraint is the other direction: a capability we granted
ourselves must never make a benign run look fraudulent. `fraud_sequence_detected`
fires when any stage matches, so preconditions are structurally excluded from
detection and from chain confidence rather than merely labelled.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.workflow_reconstructor import (  # noqa: E402
    WorkflowReconstructor,
    investigation_records,
)

P = "android.permission."
SMS_EVENT = {
    "id": "e1", "category": "sms",
    "hook": "SmsMessage.getMessageBody", "timestamp_ms": 5000,
}


def _reconstruct(records):
    return WorkflowReconstructor().reconstruct(records)


# ── preconditions alone are not a fraud sequence ─────────────────────────────

def test_a_sandbox_grant_alone_is_not_a_fraud_sequence():
    """The false positive this design exists to prevent."""
    workflow = _reconstruct(investigation_records(accessibility_enabled=True))
    assert workflow.fraud_sequence_detected is False
    assert workflow.sequence_label == "PRECONDITIONS_ONLY"
    assert workflow.chain_confidence == 0.0


def test_precondition_stages_still_appear_in_the_chain():
    """They explain what made later behaviour reachable, so they are shown."""
    workflow = _reconstruct(investigation_records(
        accessibility_enabled=True, granted_permissions=[P + "CAMERA"],
    ))
    labels = {s.label for s in workflow.stages}
    assert "Accessibility Enabled by Sandbox" in labels
    assert "Runtime Permissions Granted by Sandbox" in labels


def test_every_precondition_stage_is_flagged_as_one():
    workflow = _reconstruct(investigation_records(
        accessibility_enabled=True, overlay_granted=True,
        granted_permissions=[P + "CAMERA"],
    ))
    assert all(s.is_precondition for s in workflow.stages)


def test_precondition_descriptions_say_they_are_harness_actions():
    """An analyst must not read a granted capability as app behaviour."""
    workflow = _reconstruct(investigation_records(accessibility_enabled=True))
    assert "harness action" in workflow.stages[0].description.lower()


# ── real behaviour still detected, now with context ──────────────────────────

def test_behaviour_alongside_a_precondition_is_still_detected():
    workflow = _reconstruct(
        investigation_records(accessibility_enabled=True) + [SMS_EVENT]
    )
    assert workflow.fraud_sequence_detected is True
    assert workflow.sequence_label != "PRECONDITIONS_ONLY"


def test_chain_confidence_ignores_preconditions():
    """
    Preconditions carry confidence 1.0 - they are verified facts about the
    device. Averaging them in would inflate every chain toward certainty.
    """
    with_pre = _reconstruct(
        investigation_records(accessibility_enabled=True) + [SMS_EVENT]
    )
    behaviour_only = _reconstruct([SMS_EVENT])
    assert with_pre.chain_confidence == behaviour_only.chain_confidence


def test_the_chain_shows_the_precondition_and_the_behaviour_together():
    workflow = _reconstruct(
        investigation_records(accessibility_enabled=True) + [SMS_EVENT]
    )
    kinds = {s.is_precondition for s in workflow.stages}
    assert kinds == {True, False}


# ── existing behaviour preserved ─────────────────────────────────────────────

def test_hook_only_reconstruction_is_unchanged():
    workflow = _reconstruct([SMS_EVENT])
    assert workflow.fraud_sequence_detected is True
    assert workflow.stages[0].is_precondition is False


def test_no_records_still_yields_an_empty_workflow():
    workflow = _reconstruct([])
    assert workflow.fraud_sequence_detected is False
    assert workflow.stages == []


def test_stages_remain_serialisable_with_the_new_field():
    import json

    workflow = _reconstruct(investigation_records(accessibility_enabled=True))
    data = json.loads(json.dumps(workflow.to_dict()))
    assert data["stages"][0]["is_precondition"] is True


# ── record construction ──────────────────────────────────────────────────────

def test_records_use_the_existing_schema():
    """§23: no second event schema."""
    for record in investigation_records(accessibility_enabled=True):
        assert {"id", "category", "hook", "timestamp_ms"} <= set(record)


def test_nothing_verified_yields_no_records():
    assert investigation_records() == []


def test_each_granted_permission_becomes_a_record():
    records = investigation_records(
        granted_permissions=[P + "CAMERA", P + "READ_SMS"]
    )
    assert len(records) == 2


def test_record_ids_are_unique():
    records = investigation_records(
        accessibility_enabled=True, overlay_granted=True,
        granted_permissions=[P + "CAMERA", P + "READ_SMS"],
    )
    assert len({r["id"] for r in records}) == len(records)


def test_timestamps_preserve_the_order_they_were_established_in():
    records = investigation_records(
        accessibility_enabled=True, overlay_granted=True, base_timestamp_ms=1000,
    )
    assert [r["timestamp_ms"] for r in records] == sorted(
        r["timestamp_ms"] for r in records
    )


def test_crashes_are_carried_but_are_not_preconditions():
    records = investigation_records(
        crash_findings=[{"crash_type": "CRASH_ON_LAUNCH", "summary": "died early",
                         "severity": "LOW"}]
    )
    assert records[0]["category"] == "app_telemetry"
    assert _reconstruct(records).stages == []


def test_malformed_crash_findings_are_skipped():
    assert investigation_records(crash_findings=["not a dict", None]) == []


# ── the sandbox helper ───────────────────────────────────────────────────────

def test_the_sandbox_builds_records_from_verified_grants_only():
    from sudarshan_core.engines.frida_sandbox import _build_investigation_records

    class _Session:
        reports = {"permissions": {"records": [
            {"permission": P + "BIND_ACCESSIBILITY_SERVICE", "granted": True},
            {"permission": P + "READ_SMS", "granted": False},
        ]}}

    records = _build_investigation_records(_Session())
    hooks = {r["hook"] for r in records}
    assert "sandbox.grant.accessibility" in hooks
    # The unverified grant contributes nothing.
    assert not any(P + "READ_SMS" in r["description"] for r in records)


def test_the_sandbox_helper_tolerates_a_missing_report():
    from sudarshan_core.engines.frida_sandbox import _build_investigation_records

    class _Empty:
        reports = None

    assert _build_investigation_records(_Empty()) == []


def test_the_sandbox_helper_tolerates_a_non_dict_report():
    from sudarshan_core.engines.frida_sandbox import _build_investigation_records

    class _Odd:
        reports = "unexpected"

    assert _build_investigation_records(_Odd()) == []
