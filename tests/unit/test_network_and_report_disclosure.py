"""
Network evidence attribution and report/API disclosure.

Pure in-process: NetworkCapture, the PDF builder (real ReportLab output, text
extracted with pypdf) and the API response model. No device, no mocks of the
units under test.
"""

from __future__ import annotations

import io
import json
import time
from datetime import datetime, timezone

import pytest

from sudarshan_core.engines.network_capture import NetworkCapture
from sudarshan_core.engines.pdf_generator import build_pdf_report, telemetry_metadata_rows


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _har(tmp_path, entries):
    p = tmp_path / "shared.har"
    p.write_text(json.dumps({"log": {"entries": entries}}), encoding="utf-8")
    return str(p)


def _entry(url, started, method="GET", headers=None):
    return {"startedDateTime": started, "request": {"method": method, "url": url, "headers": headers or []},
            "response": {"status": 200, "bodySize": 10}}


# ── NetworkCapture ────────────────────────────────────────────────────────────

def test_session_bound_capture_ignores_other_analyses_har_entries(tmp_path):
    start = time.time()
    nc = NetworkCapture(session_started_at=start)
    har = _har(tmp_path, [
        _entry("https://previous-sample.example/c2", _iso(start - 3600)),   # earlier analysis
        _entry("https://this-sample.example/c2", _iso(start + 1)),
        {"request": {"method": "GET", "url": "https://undated.example/"}, "response": {}},
    ])
    nc.ingest_mitmproxy_har(har)
    urls = {f["url"] for f in nc.flows}
    assert urls == {"https://this-sample.example/c2"}
    rep = nc.collection_report()
    assert rep["har_entries_out_of_window"] == 1
    assert rep["har_entries_undated"] == 1
    assert rep["encrypted_traffic_inspected"] is True
    assert any("not attributed" in line for line in rep["limitations"])


def test_unbound_capture_keeps_legacy_behaviour(tmp_path):
    nc = NetworkCapture()
    nc.ingest_mitmproxy_har(_har(tmp_path, [_entry("https://a.example/", "2020-01-01T00:00:00Z")]))
    assert len(nc.flows) == 1


def test_native_connect_is_not_labelled_http_get():
    nc = NetworkCapture()
    ev = {"category": "network", "timestamp": 1000, "hook": "libc.connect",
          "data": {"hook": "libc.connect", "ip": "10.0.0.2", "port": 4444, "url": "10.0.0.2:4444"}}
    nc._on_event(ev)
    nc._on_event(dict(ev, timestamp=2000))
    assert len(nc.flows) == 1
    f = nc.flows[0]
    assert f["method"] == "TCP_CONNECT"
    assert (f["ip"], f["port"]) == ("10.0.0.2", 4444)
    assert f["observation_count"] == 2 and f["first_seen"] == 1000 and f["last_seen"] == 2000
    assert f["payload_inspected"] is False


def test_null_data_does_not_raise():
    NetworkCapture()._on_event({"category": "network", "data": None})


def test_credentials_in_har_headers_are_redacted(tmp_path):
    nc = NetworkCapture()
    nc.ingest_mitmproxy_har(_har(tmp_path, [_entry(
        "https://bank.example/api", "2020-01-01T00:00:00Z",
        headers=[{"name": "Authorization", "value": "Bearer secret"},
                 {"name": "Cookie", "value": "sid=abc"},
                 {"name": "User-Agent", "value": "Trojan/1"}])]))
    h = nc.flows[0]["headers"]
    assert h["Authorization"] == "[REDACTED]" and h["Cookie"] == "[REDACTED]"
    assert h["User-Agent"] == "Trojan/1"
    assert "secret" not in json.dumps(nc.flows)


def test_no_har_discloses_no_tls_inspection(monkeypatch):
    import sudarshan_core.engines.network_capture as ncm
    monkeypatch.setattr(ncm, "MITMPROXY_HAR_PATH", "")
    rep = NetworkCapture(session_started_at=time.time()).collection_report()
    assert rep["encrypted_traffic_inspected"] is False
    assert any("NOT inspected" in line for line in rep["limitations"])


# ── Report rows ───────────────────────────────────────────────────────────────

def test_report_rows_never_invent_values_for_old_cases():
    rows = dict(telemetry_metadata_rows({}, {}))
    assert "Not recorded" in rows["Telemetry diagnostics"]
    assert rows["Encrypted traffic inspected"] == "Not recorded"


def test_report_rows_state_recorded_facts():
    tele = {
        "classification": "NO_TELEMETRY_OBSERVED", "explanation": "lost",
        "agent": {"canary_received": True, "java_bridge_failed": False,
                  "diagnostics": ["java_bridge_ready", "deoptimizeEverything_skipped_api34_plus"]},
        "hooks": {"installed": 77, "exercised": 0, "errors": 2},
        "events": {"received": 0, "published": 0},
        "session": {"attached_at_window_end": False, "detach_reason": "process-terminated"},
        "evidence_store": {"accepted": 0, "duplicates": 0},
    }
    rows = dict(telemetry_metadata_rows(tele, {"encrypted_traffic_inspected": False}))
    assert rows["Agent load canary"] == "Received"
    assert rows["Java.deoptimizeEverything()"].startswith("Skipped")
    assert rows["Session end"] == "Detached early: process-terminated"
    assert rows["Encrypted traffic inspected"].startswith("No")


def _minimal_case(dynamic_result):
    return {
        "case_id": "SDN-T-1", "sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32,
        "package_name": "com.example.benign", "app_name": "Benign", "analysis_mode": "androguard",
        "analysis_status": "COMPLETED", "created_at": "2026-10-01 00:00:00 UTC",
        "base_score": 10.0, "ai_confidence_multiplier": 1.0, "final_risk_score": 10.0,
        "risk_band": "Safe", "recommended_action": "None.",
        "frs_breakdown": {"stei": 10.0, "dynamic": 5.0, "dynamic_ran": True, "dynamic_conclusive": True},
        "dynamic_result": dynamic_result,
    }


def _pdf_text(case_data) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(build_pdf_report(case_data)))
    return "\n".join(p.extract_text() or "" for p in reader.pages)


def test_pdf_no_longer_prints_fabricated_sandbox_metadata():
    text = _pdf_text(_minimal_case({
        "available": True, "dynamic_status": "EVENTS_CAPTURED", "bfci": 5.0,
        "telemetry_diagnostics": {
            "classification": "RUNTIME_EVENTS_RECEIVED", "explanation": "ok",
            "agent": {"canary_received": True, "diagnostics": ["java_bridge_ready", "deoptimizeEverything_skipped_api34_plus"]},
            "hooks": {"installed": 3, "exercised": 1, "errors": 0},
            "events": {"received": 2, "published": 2},
            "session": {"attached_at_window_end": True},
            "evidence_store": {"accepted": 2, "duplicates": 0},
        },
        "network_collection": {"encrypted_traffic_inspected": False},
    }))
    assert "T+0.4s" not in text
    assert "interpreter mode forced" not in text
    assert "no redundant navigation loops" not in text
    assert "RUNTIME_EVENTS_RECEIVED" in text
    assert "Skipped by the agent" in text


# ── API model ─────────────────────────────────────────────────────────────────

def test_api_model_carries_error_and_diagnostics():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))
    from app.routes.upload import _build_dynamic_analysis_model

    dyn = {
        "available": False, "runtime_attempted": True, "dynamic_status": "FRIDA_ATTACH_FAILED",
        "error": "PermissionDeniedError: unable to access process",
        "telemetry_diagnostics": {"classification": "FRIDA_ATTACH_FAILED"},
        "network_collection": {"encrypted_traffic_inspected": False},
        "network_flows": [{"url": "10.0.0.1:443"}, "junk"],
        "bfci_explanation": {"bfci": 0.0},
        "network_logs_total": 0,
    }
    m = _build_dynamic_analysis_model(dyn).model_dump()
    assert m["error"].startswith("PermissionDeniedError")
    assert m["runtime_attempted"] is True
    assert m["telemetry_diagnostics"]["classification"] == "FRIDA_ATTACH_FAILED"
    assert m["network_flows"] == [{"url": "10.0.0.1:443"}]
    assert m["network_collection"]["encrypted_traffic_inspected"] is False
