"""
Canonical behaviours: the contract, and the bug that motivated them.

Two things are pinned here.

**The taxonomy must describe the agent that exists.** Goals used to match raw
hook names, and four `test_goal_hook_contract` tests have been red at baseline
because those names had drifted away from what the compiled agent emits - so
those stages were unreachable by construction and no runtime evidence could
move them. Moving to behaviours only helps if the behaviour table cannot drift
the same way, which is what `test_every_declared_hook_is_emitted_by_the_agent`
enforces.

**Volume must never become confidence.** The engine's failure mode in the other
direction is a chatty application whose ordinary lifecycle chatter completes a
fraud goal. Every promotion rule below is asserted explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sudarshan_core.engines.behavior_taxonomy import (
    BEHAVIOR_RULES,
    Behavior,
    BehaviorWeight,
    EvidenceStrength,
    all_declared_hooks,
    classify_events,
    evaluate_behaviour_evidence,
)
from sudarshan_core.engines.runtime_event import normalize_event, normalize_events

_AGENT_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.js"
)


def _event(category: str, hook: str, **extra):
    raw = {"category": category, "severity": "HIGH", "timestamp": 1,
           "data": {"hook": hook, **extra}}
    return normalize_event(raw)


# ─── The taxonomy describes the agent that actually exists ───────────────────

@pytest.mark.skipif(not _AGENT_SOURCE.exists(), reason="agent source not present")
def test_every_declared_hook_is_emitted_by_the_agent():
    """
    No behaviour may depend on a hook name the agent does not emit.

    This is the guard the goal graph never had. A hook that exists only in a
    declaration is a stage that can never complete, and the failure is silent:
    the run looks like a sample that did nothing.
    """
    source = _AGENT_SOURCE.read_text(encoding="utf-8", errors="replace")
    missing = sorted(h for h in all_declared_hooks() if h not in source)
    assert not missing, (
        f"behaviour rules reference hook names the agent does not emit: {missing}"
    )


def test_every_behavior_enum_member_has_at_least_one_rule():
    """A behaviour with no rule is unreachable, which is the same defect class."""
    covered = {rule.behavior for rule in BEHAVIOR_RULES}
    orphans = sorted(b.value for b in Behavior if b not in covered)
    assert not orphans, f"behaviours with no detection rule: {orphans}"


# ─── Category gating ─────────────────────────────────────────────────────────

def test_the_same_hook_under_a_different_category_is_a_different_behavior():
    """
    The agent routes one hook name to a scored or unscored category depending
    on what it saw. `WindowManager.updateViewLayout` is an overlay manipulation
    under `overlay` and ordinary window bookkeeping under `app_telemetry`.
    """
    as_overlay = classify_events([_event("overlay", "WindowManager.updateViewLayout")])
    as_telemetry = classify_events(
        [_event("app_telemetry", "WindowManager.updateViewLayout")]
    )
    assert Behavior.OVERLAY_WINDOW_MANIPULATED in as_overlay
    assert Behavior.OVERLAY_WINDOW_MANIPULATED not in as_telemetry


def test_the_agents_own_liveness_probe_cannot_become_a_c2_request():
    """`URL.openConnection` under `smoke` is the agent probing, not the sample."""
    observed = classify_events([_event("smoke", "URL.openConnection")])
    assert Behavior.HTTP_REQUEST not in observed


def test_harness_attributed_events_are_never_classified():
    observed = classify_events(
        normalize_events([{
            "category": "harness_action",
            "data": {"hook": "sandbox.build_fields_spoofed"},
        }])
    )
    assert observed == {}


# ─── Evidence thresholds ─────────────────────────────────────────────────────

def test_one_decisive_behavior_is_conclusive():
    observed = classify_events([_event("sms", "SmsMessage.getMessageBody")])
    verdict = evaluate_behaviour_evidence(observed, [Behavior.SMS_READ])
    assert verdict.strength is EvidenceStrength.CONCLUSIVE


def test_one_strong_behavior_alone_is_only_moderate():
    """
    A single characteristic observation is a real finding and not a proof.
    An HTTP request is not a C2 channel until something corroborates it.
    """
    observed = classify_events([_event("network", "OkHttp.RealCall.execute")])
    verdict = evaluate_behaviour_evidence(observed, [Behavior.HTTP_REQUEST])
    assert verdict.strength is EvidenceStrength.MODERATE


def test_two_independent_strong_behaviors_are_conclusive():
    observed = classify_events([
        _event("network", "OkHttp.RealCall.execute"),
        _event("network", "SSL_write"),
    ])
    verdict = evaluate_behaviour_evidence(
        observed, [Behavior.HTTP_REQUEST, Behavior.TLS_PAYLOAD_CAPTURE],
    )
    assert verdict.strength is EvidenceStrength.CONCLUSIVE


def test_volume_never_promotes_ubiquitous_behaviour():
    """
    Fifty lifecycle callbacks are still fifty lifecycle callbacks. A chatty
    application must not be able to buy its way to a completed fraud goal.
    """
    observed = classify_events(
        [_event("smoke", "Activity.onResume") for _ in range(50)]
    )
    verdict = evaluate_behaviour_evidence(observed, [Behavior.APP_LIFECYCLE])
    assert verdict.strength is EvidenceStrength.WEAK
    assert observed[Behavior.APP_LIFECYCLE].count == 50


def test_supporting_evidence_alone_is_never_conclusive():
    """
    Checking whether you are a device admin is a query any app may make. It is
    not the exercise of device-admin power, and must not complete persistence.
    """
    observed = classify_events(
        [_event("persistence", "DevicePolicyManager.isAdminActive")]
    )
    verdict = evaluate_behaviour_evidence(
        observed,
        [Behavior.SCHEDULED_EXECUTION, Behavior.DEVICE_ADMIN_ABUSE],
        [Behavior.DEVICE_ADMIN_QUERY],
    )
    assert verdict.strength is not EvidenceStrength.CONCLUSIVE


def test_a_weight_override_only_applies_to_the_goal_that_declares_it():
    """
    Weight is a property of the (behaviour, claim) pair. Lifecycle callbacks
    are ubiquitous evidence of code loading and decisive evidence that the
    application launched and ran its own code.
    """
    observed = classify_events([_event("smoke", "Activity.onCreate")])

    without = evaluate_behaviour_evidence(observed, [Behavior.APP_LIFECYCLE])
    with_override = evaluate_behaviour_evidence(
        observed, [Behavior.APP_LIFECYCLE],
        weight_overrides={Behavior.APP_LIFECYCLE: BehaviorWeight.DECISIVE},
    )
    assert without.strength is EvidenceStrength.WEAK
    assert with_override.strength is EvidenceStrength.CONCLUSIVE


def test_no_observations_is_none_not_weak():
    verdict = evaluate_behaviour_evidence({}, [Behavior.SMS_READ])
    assert verdict.strength is EvidenceStrength.NONE


# ─── Normalization preserves the raw event ───────────────────────────────────

def test_normalization_never_destroys_the_raw_event():
    raw = {"category": "code_execution", "severity": "CRITICAL", "timestamp": 99,
           "data": {"hook": "ProcessBuilder.start", "class_name": "ProcessBuilder"},
           "some_future_field": "kept"}
    event = normalize_event(raw)
    assert event is not None
    assert event.raw is raw
    assert event.to_dict()["raw"]["some_future_field"] == "kept"


def test_a_bare_native_hook_is_qualified_from_its_class():
    """
    The agent emits some hooks already qualified (`WindowManager.addView`) and
    some as a bare method plus a class (`execve` + `libc`). Matching on the raw
    name alone missed half of them.
    """
    event = normalize_event(
        {"category": "code_execution",
         "data": {"hook": "execve", "class_name": "libc"}}
    )
    assert event is not None
    assert event.qualified_hook == "libc.execve"
    assert event.matches_hook("libc.execve")


def test_hook_matching_is_anchored_and_does_not_match_a_prefix():
    """`exec` must not match `execve`, or every behaviour bleeds into another."""
    event = normalize_event(
        {"category": "code_execution", "data": {"hook": "libc.execve"}}
    )
    assert event is not None
    assert event.matches_hook("execve")
    assert not event.matches_hook("Runtime.exec")


def test_a_subclass_qualified_accessibility_hook_still_matches():
    """
    The agent qualifies this one at emit time with the subclass it found on the
    device, which no declaration can know in advance.
    """
    event = normalize_event({
        "category": "accessibility",
        "data": {"hook": "com.evil.pkg.MyService.onAccessibilityEvent"},
    })
    assert event is not None
    observed = classify_events([event])
    assert Behavior.ACCESSIBILITY_SERVICE_ACTIVE in observed
