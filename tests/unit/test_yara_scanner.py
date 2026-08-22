"""
Tests for the YARA scanner and the shipped ruleset.

Two things are covered, and they fail for different reasons:

* the scanner plumbing, which was broken in two ways that both presented as
  "YARA ran and found nothing" rather than as an error, and
* the ruleset, which must compile and must not fire on strings taken from
  ordinary apps.

No corpus is required - the malware samples are gitignored, so these build the
inputs they need. scripts/validate_yara_rules.py is the counterpart that
measures the rules against the real 17-sample corpus.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

yara = pytest.importorskip("yara", reason="yara-python not installed")

from sudarshan_core.engines.yara_scanner import (  # noqa: E402
    YARAScanner,
    matched_strings,
)

RULES_DIR = _ROOT / "shared" / "sudarshan_core" / "engines" / "yara_rules"


# ── matched_strings: the API break that swallowed every match ─────────────────

def test_extracts_matched_data_from_the_modern_api():
    """
    yara-python >= 4.3 returns StringMatch objects.

    The scanner used to do `s[2].decode()`, which raises
    "TypeError: 'yara.StringMatch' object is not subscriptable" - and both call
    sites caught Exception, so every match became a logged scan failure.
    """
    rules = yara.compile(source='rule r { strings: $a = "needle" condition: $a }')
    match = rules.match(data=b"hay needle hay")[0]
    assert matched_strings(match) == ["needle"]


def test_multiple_distinct_matches_are_deduped_and_sorted():
    rules = yara.compile(
        source='rule r { strings: $a = "alpha" $b = "beta" condition: any of them }'
    )
    match = rules.match(data=b"beta alpha beta alpha")[0]
    assert matched_strings(match) == ["alpha", "beta"]


def test_the_legacy_tuple_api_is_still_accepted():
    """yara-python < 4.3 returned (offset, identifier, data) tuples."""
    class LegacyMatch:
        strings = [(0, "$a", b"needle")]

    assert matched_strings(LegacyMatch()) == ["needle"]


def test_a_match_with_no_strings_yields_an_empty_list():
    class Empty:
        strings = []

    assert matched_strings(Empty()) == []


def test_an_unrecognised_entry_shape_is_skipped_not_raised():
    class Weird:
        strings = [object()]

    assert matched_strings(Weird()) == []


def test_undecodable_bytes_do_not_raise():
    class Binary:
        class _Inst:
            matched_data = b"\xff\xfe\x00bad"
        strings = [type("S", (), {"instances": [_Inst()]})()]

    assert len(matched_strings(Binary())) == 1


# ── rules directory loading ──────────────────────────────────────────────────

def test_the_shipped_rules_directory_exists_and_is_not_empty():
    """
    The engine gates on this directory; it was absent entirely, so YARA was a
    silent no-op in every run.
    """
    assert RULES_DIR.is_dir()
    assert list(RULES_DIR.glob("*.yar")), "no rulesets shipped"


def test_the_shipped_rules_compile():
    """A syntax error in one file compiles nothing at all."""
    filepaths = {f.name: str(f) for f in sorted(RULES_DIR.glob("*.yar"))}
    yara.compile(filepaths=filepaths)   # raises yara.SyntaxError on failure


def test_scanner_loads_the_shipped_rules():
    scanner = YARAScanner(rules_dir=RULES_DIR)
    assert scanner.yara_available is True
    assert scanner.rules is not None


def test_dot_yara_files_are_loaded_too(tmp_path):
    """
    frida_sandbox gates on `*.yar*` and its warning names ".yar/.yara", but the
    scanner used to glob "*.yar" only - so a .yara-only directory reported
    "rules loaded" and then matched nothing.
    """
    (tmp_path / "r.yara").write_text('rule only_yara { strings: $a = "zzq" condition: $a }')
    scanner = YARAScanner(rules_dir=tmp_path)
    assert scanner.rules is not None
    assert scanner.scan_strings(["zzq"]) is True
    assert scanner.matches[0]["rule_name"] == "only_yara"


def test_a_directory_with_no_rules_leaves_the_scanner_inert(tmp_path):
    scanner = YARAScanner(rules_dir=tmp_path)
    assert scanner.rules is None
    assert scanner.scan_strings(["anything"]) is False


def test_a_broken_ruleset_disables_scanning_rather_than_raising(tmp_path):
    (tmp_path / "bad.yar").write_text("rule broken { this is not yara }")
    scanner = YARAScanner(rules_dir=tmp_path)
    assert scanner.rules is None


# ── end-to-end matching through the scanner ──────────────────────────────────

def _scan(strings):
    scanner = YARAScanner(rules_dir=RULES_DIR)
    scanner.scan_strings(strings)
    return {m["rule_name"] for m in scanner.matches}


def test_accessibility_abuse_needs_both_halves():
    """Binding the service is not abuse; driving the UI with it is."""
    assert _scan(["onAccessibilityEvent"]) == set()
    assert _scan(["performGlobalAction"]) == set()
    assert "android_accessibility_abuse_runtime" in _scan(
        ["onAccessibilityEvent", "performGlobalAction"]
    )


def test_sms_interception_needs_receipt_and_reading():
    assert _scan(["SmsMessage"]) == set()
    assert "android_sms_otp_interception" in _scan(["createFromPdu", "getMessageBody"])


def test_overlay_rule_requires_injection_targets_not_just_an_overlay():
    """
    A floating window is not phishing. Pairing the overlay constant with
    foreground-app polling flagged NewPipe and VLC, so the rule now requires the
    operator-supplied injection vocabulary.
    """
    assert _scan(["TYPE_APPLICATION_OVERLAY", "getRunningAppProcesses"]) == set()
    assert "android_overlay_credential_phishing" in _scan(
        ["TYPE_APPLICATION_OVERLAY", "startInject"]
    )


def test_in_memory_dex_loading_fires_alone_but_plain_dexclassloader_does_not():
    """DexClassLoader plus a Cipher constant flagged Amaze, VLC and InsecureBankv2."""
    assert _scan(["DexClassLoader", "javax.crypto.Cipher"]) == set()
    assert "android_in_memory_dex_payload" in _scan(["InMemoryDexClassLoader"])


def test_device_admin_needs_an_abuse_or_persistence_verb():
    assert _scan(["DeviceAdminReceiver"]) == set()
    assert "android_device_admin_persistence" in _scan(
        ["DeviceAdminReceiver", "resetPassword"]
    )


def test_locknow_alone_no_longer_implies_persistence():
    """VLC carries lockNow, so it was removed from the abuse group."""
    assert _scan(["DeviceAdminReceiver", "lockNow"]) == set()


def test_c2_channel_needs_two_verbs_or_a_verb_plus_identity():
    assert _scan(["startInject"]) == set()
    assert "android_bot_command_channel" in _scan(["startInject", "grab_cc"])
    assert "android_bot_command_channel" in _scan(["startInject", "bot_id"])


@pytest.mark.parametrize("benign", [
    # Framework and plugin vocabulary from the benign controls. The first draft
    # of the ruleset fired on all of these.
    ["AccessibilityNodeInfo", "ACTION_ACCESSIBILITY_FOCUS", "AccessibilityServiceInfo"],
    ["DexClassLoader", "SecretKeySpec", "AES/CBC/PKCS5Padding"],
    ["TYPE_APPLICATION_OVERLAY", "getRunningTasks", "UsageStatsManager"],
    ["ro.kernel.qemu", "test-keys", "Superuser.apk", "de.robv.android.xposed"],
    ["SmsMessage", "addView", "getInstalledApplications", "lockNow"],
])
def test_ordinary_app_vocabulary_does_not_fire_any_rule(benign):
    assert _scan(benign) == set()


# ── match plumbing ───────────────────────────────────────────────────────────

def test_a_match_is_published_to_the_event_bus():
    published = []

    class Bus:
        def publish(self, event):
            published.append(event)

    scanner = YARAScanner(rules_dir=RULES_DIR, event_bus=Bus())
    scanner.scan_strings(["InMemoryDexClassLoader"])
    assert published
    assert published[0]["category"] == "yara_match"
    assert published[0]["severity"] == "HIGH"
    assert published[0]["data"]["strings"] == ["InMemoryDexClassLoader"]


def test_flush_writes_matches_and_reports_the_count(tmp_path):
    scanner = YARAScanner(rules_dir=RULES_DIR)
    scanner.scan_strings(["InMemoryDexClassLoader"])
    out = tmp_path / "yara_results.json"
    assert scanner.flush(out) == 1
    assert "InMemoryDexClassLoader" in out.read_text(encoding="utf-8")


def test_flush_with_no_matches_writes_nothing_and_returns_zero(tmp_path):
    scanner = YARAScanner(rules_dir=RULES_DIR)
    out = tmp_path / "yara_results.json"
    assert scanner.flush(out) == 0
    assert not out.exists()


def test_scanning_a_missing_file_is_false_not_an_exception(tmp_path):
    scanner = YARAScanner(rules_dir=RULES_DIR)
    assert scanner.scan_file(tmp_path / "nope.apk") is False


def test_empty_string_list_is_rejected():
    assert YARAScanner(rules_dir=RULES_DIR).scan_strings([]) is False
