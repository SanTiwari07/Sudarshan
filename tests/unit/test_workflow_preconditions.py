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


# ── the rule table must speak the agent's vocabulary ─────────────────────────

import re  # noqa: E402

_JS = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.js"

#: Hooks the ENGINE synthesises rather than the Frida agent emitting them.
#: Named so they cannot be mistaken for observed API calls.
_SYNTHETIC_HOOKS = frozenset({
    "launcher.component_unresolvable",   # inferred from a refused relaunch
    "process_crash",                     # from the crash classifier
})


def _emittable_hooks():
    js = _JS.read_text(encoding="utf-8", errors="replace")
    return (
        set(re.findall(r"hook:\s*'([^']+)'", js))
        | set(re.findall(r'hook:\s*"([^"]+)"', js))
        | _SYNTHETIC_HOOKS
    )


def test_every_rule_trigger_is_a_hook_something_actually_emits():
    """
    The defect this guards against, measured on Cerberus: 0 of 103 evidence
    records matched any stage, because 9 of 25 triggers named hooks the agent
    never emits. The device-admin rule listened for
    DevicePolicyManager.setActiveAdmin while the sample fired
    DevicePolicyManager.isAdminActive 47 times.

    A rule that cannot fire is worse than a missing rule: it looks like coverage.
    """
    from sudarshan_core.engines.workflow_reconstructor import _STAGE_RULES

    emittable = _emittable_hooks()
    dead = [
        (rule.label, hook)
        for rule in _STAGE_RULES
        if not rule.is_precondition
        for hook in rule.trigger_hooks
        if hook not in emittable
    ]
    assert not dead, f"rules trigger on hooks nothing emits: {dead}"


def test_every_behavioural_rule_has_at_least_one_trigger():
    from sudarshan_core.engines.workflow_reconstructor import _STAGE_RULES

    for rule in _STAGE_RULES:
        assert rule.trigger_hooks, f"{rule.label} can never fire"


def test_the_accessibility_rule_does_not_trigger_on_every_app():
    """
    sendAccessibilityEvent is emitted by any app whose UI changes - both benign
    corpus samples fired it. Using it here would detect "app has a UI".
    """
    from sudarshan_core.engines.workflow_reconstructor import _STAGE_RULES

    for rule in _STAGE_RULES:
        assert "AccessibilityManager.sendAccessibilityEvent" not in rule.trigger_hooks


def test_the_device_admin_rule_listens_for_what_cerberus_fired():
    from sudarshan_core.engines.workflow_reconstructor import _STAGE_RULES

    persistence = [r for r in _STAGE_RULES if r.category == "persistence"]
    triggers = {h for r in persistence for h in r.trigger_hooks}
    assert "DevicePolicyManager.isAdminActive" in triggers


def test_self_hiding_produces_a_behavioural_stage():
    """Removing your own launcher icon is the app's doing, not the harness's."""
    from sudarshan_core.engines.workflow_reconstructor import WorkflowReconstructor

    workflow = WorkflowReconstructor().reconstruct([{
        "id": "e1", "category": "persistence",
        "hook": "launcher.component_unresolvable", "timestamp_ms": 1000,
    }])
    assert workflow.fraud_sequence_detected is True
    assert workflow.stages[0].is_precondition is False
    assert "Launcher Icon Removal" == workflow.stages[0].label


def test_the_synthetic_hook_name_does_not_impersonate_an_api_call():
    """
    It was named PackageManager.setComponentEnabledSetting, which reads as a
    hooked call. The agent does not hook that API; the finding is inferred from
    Android refusing the relaunch.
    """
    js = _JS.read_text(encoding="utf-8", errors="replace")
    assert "setComponentEnabledSetting" not in js

    from sudarshan_core.engines import agentic_explorer

    source = Path(agentic_explorer.__file__).read_text(encoding="utf-8", errors="replace")
    assert "launcher.component_unresolvable" in source
    assert '"hook": "PackageManager.setComponentEnabledSetting"' not in source
