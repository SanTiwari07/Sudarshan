"""
Evasion must be attributed to the sample, never to the harness.

The defect this guards against, measured on the stored corpus:

The Frida agent spoofs emulator-identifying Build fields at attach time to
conceal the sandbox. That is something WE do, unconditionally, on every
emulator run - and it emitted an event under `anti_analysis`.

`dynamic_exclusion_reason()` reads any anti_analysis event as proof the SAMPLE
resisted observation and returns EVASION_ONLY. All ten stored runs carried
exactly one anti_analysis event, the same one, for benign apps and banking
trojans alike. Four of them were labelled EVASION_ONLY on the strength of the
sandbox's own countermeasure.

A constant that does not vary with the sample cannot be evidence about the
sample. These tests pin the split, and pin that a real evader is still caught.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.risk_engine import (  # noqa: E402
    dynamic_exclusion_reason,
    sample_attributable_evasion,
)

_HOOKS_DIR = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"

#: The harness action as the agent emitted it BEFORE the split. Ten stored runs
#: still carry this shape, so it must keep being recognised.
LEGACY_HARNESS_EVENT = {
    "category": "anti_analysis",
    "hook": "Build.<static fields>",
    "severity": "HIGH",
    "description": "Emulator-identifying Build fields replaced: MODEL=\"sdk_gphone\"",
}

#: A genuine evasion attempt by the sample.
SAMPLE_EVENT = {
    "category": "anti_analysis",
    "hook": "Debug.isDebuggerConnected",
    "severity": "HIGH",
    "description": "App probed for debugger connection",
}


def _run(events, **kw):
    """A dynamic result that reached the evasion branch: ran, saw nothing."""
    base = {
        "available": True,
        "dynamic_status": "EVENTS_CAPTURED",
        "bfci": 0.0,
        "anti_analysis_events": events,
        # Deliberately NO observed behaviour: any entry in
        # _OBSERVED_BEHAVIOR_FIELDS makes the run "conclusive", which returns
        # before the evasion branch these tests are about.
        "frida_events": {},
        "ui_hierarchy_xml": "<hierarchy/>",
    }
    base.update(kw)
    return base


# ── attribution ──────────────────────────────────────────────────────────────

def test_the_harness_build_spoof_is_not_sample_evasion():
    assert sample_attributable_evasion([LEGACY_HARNESS_EVENT]) == []


def test_a_real_probe_by_the_sample_is_sample_evasion():
    assert len(sample_attributable_evasion([SAMPLE_EVENT])) == 1


def test_an_explicit_harness_actor_is_recognised():
    assert sample_attributable_evasion([
        {"hook": "something.new", "actor": "harness"},
    ]) == []


def test_the_harness_action_category_is_recognised():
    assert sample_attributable_evasion([
        {"hook": "something.new", "category": "harness_action"},
    ]) == []


def test_attribution_is_read_from_nested_data_too():
    """Events arrive both flattened and wrapped in `data` depending on path."""
    assert sample_attributable_evasion([
        {"data": {"hook": "sandbox.build_fields_spoofed", "actor": "harness"}},
    ]) == []


def test_the_new_hook_name_is_recognised_as_harness():
    assert sample_attributable_evasion([
        {"category": "anti_analysis", "hook": "sandbox.build_fields_spoofed"},
    ]) == []


def test_a_mixed_run_keeps_only_the_sample_events():
    kept = sample_attributable_evasion([LEGACY_HARNESS_EVENT, SAMPLE_EVENT])
    assert [e["hook"] for e in kept] == ["Debug.isDebuggerConnected"]


def test_malformed_entries_do_not_crash_attribution():
    """
    Unparseable entries are KEPT, not discarded. We can only claim an event is
    ours when we can read it; assuming otherwise would let a malformed sample
    event silently drop out of the evasion count.
    """
    assert sample_attributable_evasion([None, 5, "text", {}]) == [None, 5, "text", {}]
    assert sample_attributable_evasion(None) == []


# ── the decision this feeds ──────────────────────────────────────────────────

def test_a_run_with_only_the_harness_event_is_not_called_evasion():
    """
    The exact stored shape of Cerberus, Hydra, Anubis and com.half.powder:
    one anti_analysis event, and it is ours.
    """
    assert dynamic_exclusion_reason(_run([LEGACY_HARNESS_EVENT])) == "NO_BEHAVIOR_OBSERVED"


def test_a_run_with_real_sample_evasion_is_still_called_evasion():
    """com.sina.weibo carried two genuine probes. It must stay EVASION_ONLY."""
    assert dynamic_exclusion_reason(
        _run([LEGACY_HARNESS_EVENT, SAMPLE_EVENT])
    ) == "EVASION_ONLY"


def test_the_axis_is_excluded_either_way():
    """
    Correcting the reason must not accidentally SCORE a run that observed
    nothing. A 0.0 dynamic axis at weight 0.35 would read as "we looked and
    it was clean", which is the opposite of what happened.
    """
    for events in ([LEGACY_HARNESS_EVENT], [LEGACY_HARNESS_EVENT, SAMPLE_EVENT]):
        assert dynamic_exclusion_reason(_run(events)) is not None


def test_a_conclusive_run_is_still_scoreable():
    """The harness event must not block a run that DID observe behaviour."""
    assert dynamic_exclusion_reason(
        _run([LEGACY_HARNESS_EVENT], bfci=27.74)
    ) is None


# ── the agent must not re-file it under anti_analysis ─────────────────────────

def test_the_agent_files_the_build_spoof_as_a_harness_action():
    js = (_HOOKS_DIR / "banking_trojan.js").read_text(encoding="utf-8", errors="replace")
    assert "emit('harness_action'" in js
    assert "sandbox.build_fields_spoofed" in js
    # The old name must be gone, or stored-run detection and live detection
    # would disagree about what the same event is called.
    assert "Build.<static fields>" not in js


def test_the_compiled_bundle_carries_the_split():
    """
    banking_trojan.bundle.js is what actually runs. Editing the source without
    `npm run build` would leave the agent still emitting the old evasion event
    while every unit test here passes.
    """
    bundle = (_HOOKS_DIR / "banking_trojan.bundle.js").read_text(
        encoding="utf-8", errors="replace"
    )
    assert "sandbox.build_fields_spoofed" in bundle
    assert "harness_action" in bundle
    assert "Build.<static fields>" not in bundle


def test_the_sandbox_registers_a_bucket_for_harness_actions():
    """
    An unregistered category falls through to `dangerous_apis`
    (frida_sandbox.py), which would file our own action as sample behaviour -
    a worse misattribution than the one being fixed.
    """
    from sudarshan_core.engines import frida_sandbox

    source = Path(frida_sandbox.__file__).read_text(encoding="utf-8", errors="replace")
    assert '"harness_action": []' in source


def test_harness_action_never_counts_as_observed_sample_behaviour():
    from sudarshan_core.engines.risk_engine import _count_observed_sample_behavior

    observed = _count_observed_sample_behavior({
        "frida_events": {"harness_action": [LEGACY_HARNESS_EVENT] * 5},
    })
    assert observed == 0
