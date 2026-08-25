"""
Ordinary application behaviour is not proof that we observed the sample.

`app_telemetry` ("activity lifecycle, keyboard, generic crypto / prefs /
windows") and `smoke` ("baseline runtime smoke-test events") are, by their own
definitions, what EVERY app produces. `_MIN_DYNAMIC_EVENTS` is 1, so a single
lifecycle event was enough to mark a run conclusive and score the fraud axis
0.0 at its 0.35 weight - the heaviest in the formula.

Measured on a live 300-second Anubis run with the current agent:

    frida_events  {harness_action: 1, smoke: 1, app_telemetry: 1}
    api_calls     ["Activity.onResume", "ContextWrapper.getSharedPreferences"]
    coverage      25%

Three ordinary events, one of them ours, scored the fraud axis as a clean zero
and cost 15 points: 34.44 (Suspicious) -> 19.38 (inside the Safe band).

The perverse incentive that removes: a dropper scored BETTER by behaving during
the window than by defeating the sandbox, because defeating it excluded the
axis while behaving scored it at zero.

This does NOT make the dynamic axis one-directional. A well-covered run that
observes benign behaviour still lowers the verdict - that property is asserted
in backend/tests/test_detection_regressions.py and must keep passing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

import sudarshan_core.engines.risk_engine as RE  # noqa: E402
from sudarshan_core.engines.risk_engine import (  # noqa: E402
    _count_observed_sample_behavior,
    dynamic_exclusion_reason,
)


def _live_anubis_shape(**kw):
    """The measured shape of a live run that observed only ordinary behaviour."""
    base = {
        "available": True,
        "dynamic_status": "EVENTS_CAPTURED",
        "bfci": 0.0,
        "anti_analysis_events": [],
        "api_calls": ["Activity.onResume", "ContextWrapper.getSharedPreferences"],
        "frida_events": {
            "harness_action": [{"hook": "sandbox.build_fields_spoofed"}],
            "smoke": [{"hook": "ContextWrapper.getSharedPreferences"}],
            "app_telemetry": [{"hook": "Activity.onResume"}],
        },
    }
    base.update(kw)
    return base


# ── the baseline buckets ─────────────────────────────────────────────────────

def test_baseline_buckets_are_not_counted_as_observation():
    assert _count_observed_sample_behavior({
        "frida_events": {"app_telemetry": [{"hook": "a"}] * 5,
                         "smoke": [{"hook": "b"}] * 5},
    }) == 0


def test_a_fraud_category_bucket_is_still_counted():
    assert _count_observed_sample_behavior({
        "frida_events": {"sms": [{"hook": "SmsMessage.getMessageBody"}]},
    }) == 1


def test_the_baseline_set_matches_the_sandbox_definitions():
    """
    These two names must exist as buckets in the sandbox, or the filter is
    silently inert.
    """
    from sudarshan_core.engines import frida_sandbox

    source = Path(frida_sandbox.__file__).read_text(encoding="utf-8", errors="replace")
    for name in RE._BASELINE_EVIDENCE_CATEGORIES:
        assert f'"{name.lower()}": []' in source


def test_baseline_categories_are_not_scored_by_bfci():
    """
    Discounting a category that BFCI weighs would blind the fraud axis. These
    must be unscored by construction.
    """
    from sudarshan_core.engines.bfci_scorer import BFCI_WEIGHTS

    for name in RE._BASELINE_EVIDENCE_CATEGORIES:
        assert name.lower() not in BFCI_WEIGHTS


# ── the uncategorised duplicate ──────────────────────────────────────────────

def test_the_same_event_is_not_counted_twice_through_api_calls():
    """
    api_calls is a flattened, uncategorised projection of the same hooks. The
    bucket filter skipped them and api_calls let them straight back in.
    """
    assert _count_observed_sample_behavior(_live_anubis_shape()) == 0


def test_an_api_call_with_no_matching_baseline_event_is_still_counted():
    """
    Subtraction is by exact hook name, so a genuine API call that never
    appeared in a baseline bucket must survive.
    """
    run = _live_anubis_shape()
    run["api_calls"] = run["api_calls"] + ["SmsManager.sendTextMessage"]
    assert _count_observed_sample_behavior(run) == 1


def test_a_well_covered_run_with_no_buckets_is_unaffected():
    """
    The documented property this must not break: a run that exercised the app
    is still observation, and still able to lower a verdict.
    """
    covered = {
        "available": True,
        "api_calls": ["Activity.onCreate", "View.onClick"],
        "activities_triggered": ["MainActivity", "SettingsActivity"],
        "network_logs": ["GET https://api.example/config"],
    }
    assert _count_observed_sample_behavior(covered) == 5
    assert dynamic_exclusion_reason(dict(covered, bfci=0.0)) is None


# ── the decision and the score ───────────────────────────────────────────────

def test_a_run_of_only_ordinary_behaviour_excludes_the_axis():
    assert dynamic_exclusion_reason(_live_anubis_shape()) is not None


def test_excluding_beats_scoring_a_zero_for_the_same_run():
    """
    The regression: a sample lost points for being successfully analysed.
    """
    flags = {"has_concealed_payload": True, "obfuscation_score": 0.8,
             "hardcoded_urls_ips": ["a.test", "b.test"]}
    dyn = _live_anubis_shape()

    after = RE.calculate_risk_score(flags, dynamic_result=dyn)["final_risk_score"]

    original = RE._BASELINE_EVIDENCE_CATEGORIES
    RE._BASELINE_EVIDENCE_CATEGORIES = frozenset()   # old behaviour
    try:
        before = RE.calculate_risk_score(flags, dynamic_result=dyn)["final_risk_score"]
    finally:
        RE._BASELINE_EVIDENCE_CATEGORIES = original

    assert after > before


def test_malformed_shapes_do_not_break_counting():
    assert _count_observed_sample_behavior({"api_calls": None}) == 0
    assert _count_observed_sample_behavior({"frida_events": {"smoke": None}}) == 0
    assert _count_observed_sample_behavior(
        {"api_calls": [None, 5], "frida_events": {"app_telemetry": ["junk"]}}
    ) == 2


# ── the flushed-evidence path ────────────────────────────────────────────────

def test_baseline_evidence_records_do_not_make_a_run_conclusive():
    """
    Evidence records carry their own category. `evidence_record_count` is a
    bare total that already had to be filtered for harness bookkeeping; the
    same reasoning applies to ordinary-behaviour records.
    """
    from sudarshan_core.engines.risk_engine import _count_behavioural_evidence_records

    records = [
        {"category": "app_telemetry", "hook": "Activity.onResume"},
        {"category": "smoke", "hook": "ContextWrapper.getSharedPreferences"},
        {"category": "harness_action", "hook": "sandbox.build_fields_spoofed"},
        {"category": "anti_analysis", "hook": "Debug.isDebuggerConnected"},
    ]
    assert _count_behavioural_evidence_records({"evidence": records}) == 0


def test_a_real_behavioural_record_still_counts():
    from sudarshan_core.engines.risk_engine import _count_behavioural_evidence_records

    records = [
        {"category": "app_telemetry", "hook": "Activity.onResume"},
        {"category": "sms", "hook": "SmsMessage.getMessageBody"},
    ]
    assert _count_behavioural_evidence_records({"evidence": records}) == 1


def test_the_three_discount_sets_are_disjoint():
    """
    A category in two sets would be a sign the taxonomy has drifted; each
    describes a different reason for not counting.
    """
    sets = (RE._EVASION_EVIDENCE_CATEGORIES,
            RE._HARNESS_EVIDENCE_CATEGORIES,
            RE._BASELINE_EVIDENCE_CATEGORIES)
    for i, a in enumerate(sets):
        for b in sets[i + 1:]:
            assert not (a & b)
