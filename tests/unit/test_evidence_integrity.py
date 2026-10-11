"""
EvidenceStore identity, de-duplication, provenance and synthetic-event
isolation; BFCI reproducibility and attribution. Pure in-process tests.
"""

from __future__ import annotations

import copy

import pytest

from sudarshan_core.engines.bfci_scorer import (
    BFCI_WEIGHTS,
    calculate_bfci_v2,
    detect_fraud_sequences,
    explain_bfci,
)
from sudarshan_core.engines.event_bus import RuntimeEventBus
from sudarshan_core.engines.evidence_store import EvidenceStore
from sudarshan_core.engines.runtime_event import event_fingerprint


def _java(eid="ev_1", hook="SmsManager.sendTextMessage", category="sms", ts=1_700_000_000_000):
    return {
        "event_type": "FRIDA_EVENT", "event_id": eid, "timestamp": ts, "category": category,
        "hook": hook, "source": "frida", "pid": 10, "thread": 11,
        "data": {"hook": hook, "description": f"{hook} called"},
    }


def _native(ts=1_700_000_000_000, port=443):
    return {
        "event_type": "FRIDA_EVENT", "event_id": f"native_ev_{ts}", "timestamp": ts,
        "category": "network", "source": "native", "hook": "libc.connect",
        "ioc": f"10.0.0.1:{port}", "data": {"hook": "libc.connect", "url": f"10.0.0.1:{port}"},
    }


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(package_name="com.example", case_id="case-1", db_path=tmp_path / "e.db")
    return s


# ── EvidenceStore ─────────────────────────────────────────────────────────────

def test_redelivered_event_is_one_record(store):
    ev = _java()
    store._on_event(copy.deepcopy(ev))
    second = copy.deepcopy(ev)
    store._on_event(second)
    assert store.count() == 1
    assert store.metrics()["duplicates"] == 1
    # The duplicate is pointed at the record that already holds it.
    assert second["evidence_record_id"] == store.get_all()[0].id


def test_distinct_native_events_sharing_an_event_id_are_kept(store):
    store._on_event(_native(port=443))
    store._on_event(_native(port=8080))      # same ms -> same native event_id
    assert store.count() == 2


def test_evidence_key_is_stable_across_stores_and_delivery_wrappers(tmp_path):
    a = EvidenceStore(case_id="c", db_path=tmp_path / "a.db")
    b = EvidenceStore(case_id="c", db_path=tmp_path / "b.db")
    a._on_event(_java())
    wrapped = _java()
    wrapped["type"] = "FRIDA_EVENT"
    wrapped["evidence_record_id"] = "something-the-host-added"
    b._on_event(wrapped)
    assert a.get_all()[0].evidence_key == b.get_all()[0].evidence_key
    raw = _java()
    raw["event_type"] = "FRIDA_HOOK"          # as the agent emits it
    assert event_fingerprint(raw) == a.get_all()[0].evidence_key


def test_provenance_distinguishes_sources(store):
    store._on_event(_java())
    store._on_event(_native())
    harness = _java(eid="ev_h", hook="Build.<static fields>", category="harness_action")
    store._on_event(harness)
    by_api = {r.api: r.provenance for r in store.get_all()}
    assert by_api["SmsManager.sendTextMessage"]["source"] == "frida_java"
    assert by_api["libc.connect"]["source"] == "frida_native"
    assert by_api["Build.<static fields>"]["source"] == "harness"
    for p in by_api.values():
        assert p["analysis_kind"] == "dynamic" and p["case_id"] == "case-1"


def test_synthetic_events_never_enter_real_evidence(store):
    ev = _java()
    ev["synthetic"] = True
    store._on_event(ev)
    assert store.count() == 0
    assert store.metrics()["rejected_synthetic"] == 1


def test_synthetic_events_allowed_only_in_test_store(tmp_path):
    s = EvidenceStore(db_path=tmp_path / "t.db", allow_synthetic=True)
    ev = _java()
    ev["data"]["synthetic"] = True
    s._on_event(ev)
    assert s.count() == 1 and s.get_all()[0].provenance["synthetic"] is True


def test_malformed_event_does_not_burn_finding_id(store):
    store._on_event({"event_type": "FRIDA_EVENT", "category": "sms", "data": None,
                     "timestamp": "not-a-number", "hook": "X.y"})
    store._on_event(_java(eid="ev_2"))
    ids = [r.finding_id for r in store.get_all()]
    assert ids == ["EVID-001", "EVID-002"]


def test_top_level_hook_resolved(store):
    store._on_event({"event_type": "FRIDA_EVENT", "category": "sms", "hook": "SmsManager.sendTextMessage",
                     "timestamp": 1, "data": {}})
    rec = store.get_all()[0]
    assert rec.api == "SmsManager.sendTextMessage"
    assert rec.mitre_technique_id == "T1582"


def test_recovery_does_not_duplicate_by_key(tmp_path):
    db = tmp_path / "r.db"
    s1 = EvidenceStore(case_id="c", db_path=db)
    s1._on_event(_java())
    s2 = EvidenceStore(case_id="c", db_path=db)
    s2._on_event(_java())
    assert s2.recover_records() == 0
    assert s2.count() == 1


def test_bus_to_store_integration_with_duplicates(tmp_path):
    bus = RuntimeEventBus()
    s = EvidenceStore(event_bus=bus, db_path=tmp_path / "i.db")
    for _ in range(3):
        bus.publish(_java())
    bus.publish(_java(eid="ev_2"))
    assert bus.drain(5.0)
    assert s.count() == 2
    assert s.metrics()["duplicates"] == 2
    bus.close()


# ── BFCI ──────────────────────────────────────────────────────────────────────

def test_duplicate_events_do_not_inflate_bfci():
    once = {"sms": [_java()], "network": [_native()]}
    twice = {"sms": [_java(), _java()], "network": [_native(), _native(), _native()]}
    assert calculate_bfci_v2(once)[0] == calculate_bfci_v2(twice)[0]
    exp = explain_bfci(twice)
    assert exp["contributions"]["sms"]["duplicates_ignored"] == 1
    assert exp["contributions"]["network"]["duplicates_ignored"] == 2


def test_distinct_events_still_raise_volume_score():
    one = calculate_bfci_v2({"sms": [_java("a")]})[1]["sms"]
    two = calculate_bfci_v2({"sms": [_java("a"), _java("b")]})[1]["sms"]
    assert two > one


def test_empty_and_none_evidence_score_zero():
    for ev in (None, {}, {k: [] for k in BFCI_WEIGHTS}):
        bfci, comps, evidence, seqs = calculate_bfci_v2(ev)
        assert bfci == 0.0 and not evidence and not seqs
        assert all(v == 0.0 for v in comps.values())
    exp = explain_bfci(None)
    assert exp["bfci"] == 0.0
    assert all(c["evidence_refs"] == [] for c in exp["contributions"].values())


def test_unstamped_events_cannot_establish_a_sequence():
    """Regression: missing timestamps were scored as t=0, all inside one window."""
    events = {"accessibility": [{"hook": "a"}], "sms": [{"hook": "s"}], "network": [{"hook": "n"}]}
    assert detect_fraud_sequences(events) == []
    bfci, comps, _, seqs = calculate_bfci_v2(events)
    assert seqs == []
    assert bfci == round(sum(BFCI_WEIGHTS[k] * v for k, v in comps.items()), 2)


def test_sequence_cites_supporting_events():
    events = {
        "accessibility": [_java("a1", "AccessibilityService.onAccessibilityEvent", "accessibility", 10_000)],
        "sms": [_java("s1", ts=15_000)],
        "network": [_native(ts=20_000)],
    }
    exp = explain_bfci(events)
    seq = {s["label"]: s for s in exp["sequences"]}
    assert "OTP_THEFT_CHAIN" in seq
    cited = set(seq["OTP_THEFT_CHAIN"]["evidence_refs"])
    all_refs = {r for c in exp["contributions"].values() for r in c["evidence_refs"]}
    assert cited and cited <= all_refs


def test_every_contribution_has_reason_and_refs_and_sums_to_raw():
    events = {
        "code_execution": [_java("x1", "ProcessBuilder.start", "code_execution")],
        "sms": [_java("s1")],
    }
    exp = explain_bfci(events)
    for cat, c in exp["contributions"].items():
        assert c["reason"]
        if c["contribution"] > 0:
            assert len(c["evidence_refs"]) == c["event_count"] > 0
    assert exp["raw_bfci"] == pytest.approx(
        sum(c["contribution"] for c in exp["contributions"].values()), abs=0.01)
    # code_execution's contribution used to have no evidence string at all.
    assert any("[X]" in line for line in calculate_bfci_v2(events)[2])


def test_scoring_is_reproducible_and_order_independent():
    events = {"sms": [_java("a"), _java("b")], "network": [_native(port=1), _native(port=2)]}
    reversed_events = {k: list(reversed(v)) for k, v in reversed(list(events.items()))}
    runs = [explain_bfci(copy.deepcopy(events)) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]
    assert calculate_bfci_v2(reversed_events)[0] == runs[0]["bfci"]
    assert explain_bfci(events)["ruleset_version"]


def test_conflicting_findings_scored_from_observed_evidence_only():
    """Harness/unscored categories never move the score; scored ones do."""
    base = {"sms": [_java("s1")]}
    noisy = {**base, "harness_action": [_java("h", "Build.<static fields>", "harness_action")],
             "anti_analysis": [_java("aa", "Debug.isDebuggerConnected", "anti_analysis")],
             "dangerous_apis": [_java("d", "DexClassLoader.<init>", "dangerous_apis")]}
    assert calculate_bfci_v2(base)[0] == calculate_bfci_v2(noisy)[0]
