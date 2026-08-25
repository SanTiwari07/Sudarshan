"""
Secondary payload tracking (§19, §20).

The graph already exposed record_secondary_apk(), but nothing in production
called it - only tests did. A dropper could fetch a payload, write it to
storage and ask Android to install it, and the run reported nothing.

The load-bearing property here is the status ladder. "Installation was
requested" and "malware was installed" are different claims, and a report that
conflates them overstates the evidence in exactly the way §34 forbids. These
tests pin every rung, and pin that nothing skips one.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.secondary_payload import (  # noqa: E402
    HOOK_APK_WRITE,
    HOOK_DOWNLOAD_ENQUEUE,
    HOOK_INSTALL_REQUEST,
    PayloadStatus,
    SecondaryPayload,
    SecondaryPayloadTracker,
    extract_apk_path,
    sha256_file,
)

APK = "/data/data/com.evil.app/files/payload.apk"


def _event(hook: str, **data):
    base = {"id": "e1", "timestamp_ms": 1000, "hook": hook}
    base.update(data)
    return base


# ── path extraction ──────────────────────────────────────────────────────────

def test_an_apk_path_is_recovered_from_the_path_field():
    assert extract_apk_path({"path": APK}) == APK


def test_an_apk_path_is_recovered_from_a_description():
    event = {"description": f"Application wrote an APK to storage: {APK}"}
    assert extract_apk_path(event) == APK


def test_a_non_apk_path_is_not_treated_as_a_payload():
    assert extract_apk_path({"path": "/data/data/com.evil.app/files/cache.db"}) == ""


def test_an_event_naming_no_path_yields_nothing():
    assert extract_apk_path({"description": "queued a download"}) == ""


# ── detection ────────────────────────────────────────────────────────────────

def test_an_apk_write_is_detected():
    tracker = SecondaryPayloadTracker("com.evil.app")
    payload = tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    assert payload is not None
    assert payload.status == PayloadStatus.DETECTED.value
    assert payload.filename == "payload.apk"
    assert payload.parent_package == "com.evil.app"


def test_unrelated_hooks_are_ignored():
    tracker = SecondaryPayloadTracker("com.evil.app")
    assert tracker.observe_event(_event("SmsManager.sendTextMessage")) is None
    assert tracker.payloads == []


def test_a_queued_download_with_no_file_does_not_invent_an_artifact():
    """
    DownloadManager.enqueue cannot read its own destination URI. Recording a
    payload from it would mean reporting a file we never saw.
    """
    tracker = SecondaryPayloadTracker("com.evil.app")
    assert tracker.observe_event(_event(HOOK_DOWNLOAD_ENQUEUE)) is None
    assert tracker.payloads == []


def test_the_same_apk_seen_twice_is_one_payload():
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    assert len(tracker.payloads) == 1


def test_hook_data_nested_under_data_is_read():
    tracker = SecondaryPayloadTracker("com.evil.app")
    payload = tracker.observe_event(
        {"id": "e1", "data": {"hook": HOOK_APK_WRITE, "path": APK}}
    )
    assert payload is not None


def test_the_payload_budget_is_bounded():
    tracker = SecondaryPayloadTracker("com.evil.app", max_payloads=2)
    for i in range(5):
        tracker.observe_event(_event(HOOK_APK_WRITE, path=f"/data/p{i}.apk"))
    assert len(tracker.payloads) == 2
    assert tracker.dropped_over_budget == 3


# ── the status ladder: the distinction §34 depends on ────────────────────────

def test_install_requested_is_not_install_confirmed():
    """The single most overstateable claim in the whole pipeline."""
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    payload = tracker.observe_event(_event(HOOK_INSTALL_REQUEST, path=APK))

    assert payload.install_requested is True
    assert payload.install_confirmed is False
    assert payload.status == PayloadStatus.INSTALL_REQUESTED.value


def test_installation_is_confirmed_only_by_package_presence():
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    payload = tracker.payloads[0]
    payload.package_name = "com.evil.child"

    assert tracker.confirm_installed("com.other.app") is None
    assert payload.install_confirmed is False

    confirmed = tracker.confirm_installed("com.evil.child")
    assert confirmed is payload
    assert payload.install_confirmed is True
    assert payload.status == PayloadStatus.INSTALLED.value


def test_status_never_moves_backwards():
    payload = SecondaryPayload(device_path=APK)
    payload.promote(PayloadStatus.INSTALL_REQUESTED.value)
    payload.promote(PayloadStatus.DETECTED.value)
    assert payload.status == PayloadStatus.INSTALL_REQUESTED.value


def test_a_blocked_payload_cannot_be_promoted_later():
    """Policy refused to preserve it, so it must never read as analyzed."""
    payload = SecondaryPayload(device_path=APK)
    payload.blocked_by_policy = True
    payload.status = PayloadStatus.BLOCKED.value
    payload.promote(PayloadStatus.ANALYZED.value)
    assert payload.status == PayloadStatus.BLOCKED.value


# ── preservation and hashing ─────────────────────────────────────────────────

class _FakeAdb:
    """Stands in for the sandbox provider's adb callable."""

    def __init__(self, size: int, content: bytes = b"child-apk-bytes"):
        self.size = size
        self.content = content
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if "stat" in args:
            return (True, f"{self.size}\n")
        if "pull" in args:
            Path(args[-1]).write_bytes(self.content)
            return (True, "1 file pulled")
        return (True, "")


def test_a_preserved_payload_is_hashed(tmp_path):
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    payload = tracker.payloads[0]
    adb = _FakeAdb(size=15)

    tracker.preserve(payload, tmp_path, adb, device_serial="emulator-5554")

    assert payload.status == PayloadStatus.HASHED.value
    assert payload.sha256 == hashlib.sha256(b"child-apk-bytes").hexdigest()
    assert payload.size_bytes == 15
    assert Path(payload.local_path).exists()


def test_an_oversized_payload_is_blocked_rather_than_pulled(tmp_path):
    """A sample can point at an arbitrarily large file; pulling it is the DoS."""
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    payload = tracker.payloads[0]
    adb = _FakeAdb(size=999)

    tracker.preserve(payload, tmp_path, adb, max_bytes=100)

    assert payload.blocked_by_policy is True
    assert payload.status == PayloadStatus.BLOCKED.value
    assert payload.sha256 == ""
    assert not any("pull" in c for c in adb.calls)


def test_a_failed_pull_does_not_fabricate_a_hash(tmp_path):
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    payload = tracker.payloads[0]

    def broken_adb(*args, **kwargs):
        if "stat" in args:
            return (True, "15\n")
        raise RuntimeError("device offline")

    tracker.preserve(payload, tmp_path, broken_adb)

    assert payload.sha256 == ""
    assert payload.status == PayloadStatus.DOWNLOADED.value
    assert any("Pull failed" in n for n in payload.notes)


def test_preserving_never_installs_anything(tmp_path):
    """The investigator observes; only the victim taps Install."""
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    adb = _FakeAdb(size=15)
    tracker.preserve(tracker.payloads[0], tmp_path, adb)

    # Assert on the adb subcommands themselves. Matching a substring across
    # the joined argv would also match the tmp_path, which pytest names after
    # this very test.
    subcommands = {
        str(arg) for call in adb.calls for arg in call
        if str(arg) in {"install", "install-multiple", "rm", "uninstall", "shell"}
        or str(arg).startswith("install")
    }
    assert "install" not in subcommands
    assert "install-multiple" not in subcommands
    assert "uninstall" not in subcommands
    assert "rm" not in subcommands


def test_sha256_file_matches_hashlib(tmp_path):
    target = tmp_path / "x.apk"
    target.write_bytes(b"abc" * 1000)
    assert sha256_file(target) == hashlib.sha256(b"abc" * 1000).hexdigest()


# ── parent-child relationship (§20) ──────────────────────────────────────────

def test_the_parent_child_relationship_is_recorded():
    tracker = SecondaryPayloadTracker("com.evil.parent")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    record = tracker.to_records()[0]
    assert record["parent_package"] == "com.evil.parent"
    assert record["filename"] == "payload.apk"


def test_records_keep_requested_and_confirmed_as_separate_fields():
    """A report must state the distinction without inferring it from an enum."""
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    tracker.observe_event(_event(HOOK_INSTALL_REQUEST, path=APK))
    record = tracker.to_records()[0]
    assert record["install_requested"] is True
    assert record["install_confirmed"] is False


def test_the_summary_counts_what_actually_happened():
    tracker = SecondaryPayloadTracker("com.evil.app")
    tracker.observe_event(_event(HOOK_APK_WRITE, path=APK))
    tracker.observe_event(_event(HOOK_INSTALL_REQUEST, path=APK))
    summary = tracker.summary()
    assert summary["count"] == 1
    assert summary["install_requested"] == 1
    assert summary["install_confirmed"] == 0
    assert summary["hashed"] == 0


# ── the hooks must be real ───────────────────────────────────────────────────

_HOOKS_DIR = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"


def test_every_hook_this_module_listens_for_is_emitted_by_the_agent():
    """
    The defect this guards against is the one that made the whole feature
    dead: an API with no producer. If a hook name here drifts from the Frida
    agent, detection silently stops.
    """
    js = (_HOOKS_DIR / "banking_trojan.js").read_text(
        encoding="utf-8", errors="replace"
    )
    for hook in (HOOK_APK_WRITE, HOOK_DOWNLOAD_ENQUEUE, HOOK_INSTALL_REQUEST):
        assert f"'{hook}'" in js, f"{hook} is not emitted by the Frida agent"


def test_the_compiled_bundle_is_not_stale():
    """
    banking_trojan.bundle.js is what actually runs - on Frida 17 the Java
    global was removed, so the agent MUST be compiled with frida-java-bridge
    linked in. Editing the source without running `npm run build` leaves the
    new hooks out of the artifact that ships, and the feature is dead on a real
    device while every unit test still passes.

    Rebuild with:  cd shared/sudarshan_core/engines/frida_hooks && npm run build
    """
    bundle = _HOOKS_DIR / "banking_trojan.bundle.js"
    assert bundle.exists(), "compiled Frida agent is missing"
    compiled = bundle.read_text(encoding="utf-8", errors="replace")

    for hook in (HOOK_APK_WRITE, HOOK_DOWNLOAD_ENQUEUE, HOOK_INSTALL_REQUEST):
        assert hook in compiled, (
            f"{hook} is in banking_trojan.js but not in the compiled bundle - "
            f"run `npm run build` in {_HOOKS_DIR.name}/"
        )
