"""
Tests for the VirusTotal cross-check harness.

No network: every lookup goes through a fake client, so the suite passes on a
machine with no VT key and asserts on the parsing and bucketing rules rather
than on whatever VT happens to say about a sample today.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.validation.virustotal_crosscheck import (  # noqa: E402
    BENIGN,
    ERROR,
    LOW_DETECTION,
    MALWARE,
    NOT_FOUND,
    VT_MALICIOUS_VENDOR_THRESHOLD,
    CrossCheckRow,
    CrossCheckSummary,
    VTResult,
    classify_vt,
    lookup_hash,
    lookup_many,
    rate_limit_per_min,
    sudarshan_verdict,
    vt_api_key,
)

SHA = "a" * 64


class _Response:
    def __init__(self, status_code: int, payload=None, raises: bool = False):
        self.status_code = status_code
        self._payload = payload
        self._raises = raises

    def json(self):
        if self._raises:
            raise ValueError("not json")
        return self._payload


class _Client:
    """Returns a queued response per call; records the headers it was given."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = []

    async def get(self, url, headers=None):
        self.calls.append((url, headers))
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _vt_payload(malicious=0, suspicious=0, undetected=0, harmless=0, label=None, results=None):
    attrs = {
        "last_analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "timeout": 3,             # must not reach the denominator
            "type-unsupported": 5,    # must not reach the denominator
        },
        "last_analysis_results": results or {},
    }
    if label is not None:
        attrs["popular_threat_classification"] = {"suggested_threat_label": label}
    return {"data": {"attributes": attrs}}


# ── classify_vt ───────────────────────────────────────────────────────────────

def test_threshold_vendors_is_malware():
    assert classify_vt(VT_MALICIOUS_VENDOR_THRESHOLD, 70) == MALWARE


def test_one_vendor_short_of_threshold_is_low_detection_not_benign():
    """A 4/70 hit is ambiguous; bucketing it as benign would hide it."""
    assert classify_vt(VT_MALICIOUS_VENDOR_THRESHOLD - 1, 70) == LOW_DETECTION


def test_zero_detections_is_benign():
    assert classify_vt(0, 70) == BENIGN


def test_no_completed_analyses_is_not_found_not_benign():
    """A record with an empty stats block is "no opinion", not a clean scan."""
    assert classify_vt(0, 0) == NOT_FOUND


# ── sudarshan_verdict ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("band", ["Suspicious", "High Risk", "Critical"])
def test_every_non_safe_band_counts_as_malware(band):
    assert sudarshan_verdict(band) == MALWARE


@pytest.mark.parametrize("band", ["Safe", "", None, "Unknown"])
def test_safe_and_unrecognised_bands_count_as_benign(band):
    assert sudarshan_verdict(band) == BENIGN


# ── lookup_hash ───────────────────────────────────────────────────────────────

def test_parses_a_malicious_response():
    client = _Client(_Response(200, _vt_payload(
        malicious=30, undetected=40, label="trojan.anubis/banker",
        results={"VendorA": {"category": "malicious"},
                 "VendorB": {"category": "malicious"},
                 "VendorC": {"category": "undetected"}},
    )))
    r = asyncio.run(lookup_hash(SHA, "key", client))
    assert r.verdict == MALWARE
    assert r.malicious == 30
    assert r.total == 70          # timeout / type-unsupported excluded
    assert r.family == "trojan.anubis/banker"
    assert r.vendors == ["VendorA", "VendorB"]
    assert r.ratio_text == "30/70"


def test_sends_the_api_key_header():
    client = _Client(_Response(200, _vt_payload(undetected=70)))
    asyncio.run(lookup_hash(SHA, "secret-key", client))
    _url, headers = client.calls[0]
    assert headers == {"x-apikey": "secret-key"}


def test_404_is_not_found():
    r = asyncio.run(lookup_hash(SHA, "key", _Client(_Response(404))))
    assert r.verdict == NOT_FOUND


def test_429_is_reported_as_rate_limited_error():
    r = asyncio.run(lookup_hash(SHA, "key", _Client(_Response(429))))
    assert r.verdict == ERROR
    assert "429" in r.detail


def test_transport_failure_becomes_an_error_row_not_an_exception():
    r = asyncio.run(lookup_hash(SHA, "key", _Client(RuntimeError("boom"))))
    assert r.verdict == ERROR
    assert "RuntimeError" in r.detail


def test_unparseable_body_becomes_an_error_row():
    r = asyncio.run(lookup_hash(SHA, "key", _Client(_Response(200, raises=True))))
    assert r.verdict == ERROR


def test_missing_threat_label_yields_no_family():
    """Absence of a VT classification must never be filled in from elsewhere."""
    client = _Client(_Response(200, _vt_payload(malicious=9, undetected=61)))
    assert asyncio.run(lookup_hash(SHA, "key", client)).family == ""


# ── lookup_many ───────────────────────────────────────────────────────────────

def test_lookup_many_returns_one_row_per_hash_and_does_not_sleep_for_one():
    client = _Client(_Response(200, _vt_payload(undetected=70)))
    out = asyncio.run(lookup_many([SHA], "key", per_min=1, client=client))
    assert set(out) == {SHA}          # a 60s sleep here would hang the suite


def test_lookup_many_keeps_going_after_a_failed_lookup():
    other = "b" * 64
    client = _Client(RuntimeError("down"), _Response(200, _vt_payload(malicious=40, undetected=30)))
    out = asyncio.run(lookup_many([SHA, other], "key", per_min=6000, client=client))
    assert out[SHA].verdict == ERROR
    assert out[other].verdict == MALWARE


# ── summary ───────────────────────────────────────────────────────────────────

def _row(name, label, band, vt_verdict, malicious=0, total=70):
    return CrossCheckRow(
        name=name, sha256=SHA, corpus_label=label, sudarshan_band=band,
        sudarshan_frs=0.0, sudarshan_family="",
        vt=VTResult(SHA, vt_verdict, malicious=malicious, total=total),
    )


def test_confusion_matrix_counts_each_quadrant():
    summary = CrossCheckSummary([
        _row("mal", "malware", "High Risk", MALWARE, 40),
        _row("ben", "benign", "Safe", BENIGN),
        _row("fp", "benign", "Suspicious", BENIGN),
        _row("miss", "malware", "Safe", MALWARE, 40),
    ])
    assert summary.confusion() == {
        "both_malware": 1,
        "both_benign": 1,
        "sudarshan_only_malware": 1,
        "vt_only_malware": 1,
    }
    assert summary.agreement_rate == 0.5


def test_non_comparable_rows_are_excluded_not_scored():
    """NOT_FOUND / LOW_DETECTION must not inflate or deflate agreement."""
    summary = CrossCheckSummary([
        _row("known", "malware", "High Risk", MALWARE, 40),
        _row("unknown", "malware", "Safe", NOT_FOUND),
        _row("ambiguous", "benign", "Safe", LOW_DETECTION, 2),
        _row("dead", "benign", "Safe", ERROR),
    ])
    assert len(summary.comparable_rows) == 1
    assert len(summary.excluded) == 3
    assert summary.agreement_rate == 1.0
    assert sum(summary.confusion().values()) == 1


def test_agreement_rate_is_none_when_nothing_was_comparable():
    """An all-unknown corpus must not report a perfect score."""
    summary = CrossCheckSummary([_row("u", "malware", "Safe", NOT_FOUND)])
    assert summary.agreement_rate is None


def test_disagreements_lists_only_comparable_mismatches():
    summary = CrossCheckSummary([
        _row("fp", "benign", "Critical", BENIGN),
        _row("unknown", "malware", "Safe", NOT_FOUND),
    ])
    assert [r.name for r in summary.disagreements] == ["fp"]


# ── configuration ─────────────────────────────────────────────────────────────

def test_api_key_prefers_explicit_then_env(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "  from-env  ")
    assert vt_api_key("explicit") == "explicit"
    assert vt_api_key() == "from-env"


def test_api_key_is_empty_when_unset(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert vt_api_key() == ""


@pytest.mark.parametrize("raw,expected", [("10", 10), ("", 4), ("nonsense", 4), ("0", 1), ("-5", 1)])
def test_rate_limit_falls_back_and_never_reaches_zero(monkeypatch, raw, expected):
    monkeypatch.setenv("VIRUSTOTAL_RATE_LIMIT_PER_MIN", raw)
    assert rate_limit_per_min() == expected
