#!/usr/bin/env python3
"""
Sudarshan Platform Integration Tests
======================================
Production integration tests that verify the complete pipeline
using real APKs (never mock data).

Tests:
  1. MobSF API (upload → scan → report → scorecard)
  2. Androguard (static analysis)
  3. APKTool (manifest decompilation)
  4. JADX (Java source analysis)
  5. Risk Engine (STEI/BFCI/FRS scoring)
  6. Backend API (upload endpoint, auth)
  7. Dashboard API (cases, reports)
  8. Dynamic Analysis (ADB + Frida - skipped if no emulator)
  9. Evidence Store
  10. Workflow Reconstructor

Usage:
    python tests/integration/test_pipeline.py
    python tests/integration/test_pipeline.py --skip-dynamic   # skip Frida
    python tests/integration/test_pipeline.py --apk path/to/test.apk
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import requests

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "shared"))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    import loguru
    loguru.logger.disable("androguard")
except ImportError:
    pass

MOBSF_HOST = os.getenv("MOBSF_HOST_EXTERNAL", "http://localhost:8008")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "sudarshan_mobsf_api_key_2026")
BACKEND_HOST = os.getenv("BACKEND_HOST", "http://localhost:8000")

ROOT = Path(__file__).parent.parent.parent

# Resolved, not hardcoded. The corpus is gitignored and currently nested at
# `test apk/test apk/`, so the previous literal path resolved to a file that
# does not exist - and the resulting skip looked like "no sample available"
# rather than "the path is wrong".
from sudarshan_core.validation.labelled_corpus import resolve_sample  # noqa: E402

_SAMPLE = resolve_sample("Vulnerable/InsecureBankv2.apk")
TEST_APK = str(_SAMPLE) if _SAMPLE else ""

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0


# ─── Pytest Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def apk_path() -> str:
    """Fixture supplying path to a test APK."""
    candidates = [
        TEST_APK,
        str(ROOT / "backend" / "test_sample.apk"),
        str(ROOT / "backend" / "UnCrackable-Level1.apk"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    pytest.skip("No valid test APK found on disk")


@pytest.fixture(scope="module")
def androguard_result(apk_path: str):
    """Fixture supplying Androguard analysis output."""
    from sudarshan_core.analyzers.apk_analyzer import analyze_apk
    return analyze_apk(apk_path)


def _assert(condition: bool, test_name: str, detail: str = "", fatal: bool = False):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        print(f"  ✅ PASS: {test_name}")
        if detail:
            print(f"     {detail}")
        PASS_COUNT += 1
        return True
    else:
        print(f"  ❌ FAIL: {test_name}")
        if detail:
            print(f"     {detail}")
        FAIL_COUNT += 1
        if fatal:
            print(f"\n[FATAL] Cannot continue without: {test_name}")
            assert False, f"Fatal test failure: {test_name} ({detail})"
        assert False, f"Test failed: {test_name} ({detail})"
        return False


def _skip(test_name: str, reason: str):
    global SKIP_COUNT
    print(f"  ⏭  SKIP: {test_name} ({reason})")
    SKIP_COUNT += 1


# ─── Test Groups ───────────────────────────────────────────────────────────────

def test_mobsf(apk_path: str):
    """Test MobSF API completely."""
    print("\n[TEST GROUP] MobSF Static Analysis API")

    headers = {"Authorization": MOBSF_API_KEY}

    # Check if MobSF is running
    try:
        r = requests.get(f"{MOBSF_HOST}/", headers=headers, timeout=2)
        if r.status_code != 200:
            pytest.skip(f"MobSF not running at {MOBSF_HOST}")
    except Exception:
        pytest.skip(f"MobSF host unreachable at {MOBSF_HOST}")

    # Upload
    with open(apk_path, "rb") as f:
        r = requests.post(
            f"{MOBSF_HOST}/api/v1/upload",
            headers=headers,
            files={"file": (Path(apk_path).name, f, "application/octet-stream")},
            timeout=120,
        )
    _assert(r.status_code == 200, "MobSF upload", f"HTTP {r.status_code}", fatal=True)
    data = r.json()
    scan_hash = data.get("hash")
    _assert(bool(scan_hash), "MobSF upload returns scan_hash", f"hash={scan_hash}", fatal=True)

    # Scan
    r = requests.post(
        f"{MOBSF_HOST}/api/v1/scan",
        headers=headers,
        data={"hash": scan_hash, "re_scan": 0},
        timeout=300,
    )
    _assert(r.status_code == 200, "MobSF static scan triggered", f"HTTP {r.status_code}")

    time.sleep(10)

    # JSON Report
    r = requests.post(
        f"{MOBSF_HOST}/api/v1/report_json",
        headers=headers,
        data={"hash": scan_hash},
        timeout=60,
    )
    _assert(r.status_code == 200, "MobSF JSON report", f"HTTP {r.status_code}", fatal=True)
    report = r.json()
    _assert("package_name" in report, "Report has package_name", report.get("package_name"))
    _assert("permissions" in report, "Report has permissions", f"{len(report.get('permissions', {}))} permissions")
    _assert("activities" in report, "Report has activities", f"{len(report.get('activities', []))} activities")
    _assert("code_analysis" in report, "Report has code_analysis")
    _assert("manifest_analysis" in report, "Report has manifest_analysis")

    # Scorecard
    r = requests.post(
        f"{MOBSF_HOST}/api/v1/scorecard",
        headers=headers,
        data={"hash": scan_hash},
        timeout=30,
    )
    _assert(r.status_code == 200, "MobSF scorecard", f"HTTP {r.status_code}")
    if r.status_code == 200:
        sc = r.json()
        _assert("security_score" in sc, "Scorecard has security_score", f"score={sc.get('security_score')}")


def test_androguard(apk_path: str):
    """Test Androguard static analysis."""
    print("\n[TEST GROUP] Androguard Static Analysis")

    try:
        from sudarshan_core.analyzers.apk_analyzer import analyze_apk
        result = analyze_apk(apk_path)

        _assert(result is not None, "analyze_apk returns result", fatal=True)
        _assert(bool(result.package_name), "Package name extracted", result.package_name)
        _assert(isinstance(result.permissions, list), "Permissions is a list", f"{len(result.permissions)} permissions")
        _assert(result.flags is not None, "StaticAnalysisFlags populated")
        _assert(isinstance(result.flags.hardcoded_urls_ips, list), "hardcoded_urls_ips is list",
                f"{len(result.flags.hardcoded_urls_ips)} URLs")
        _assert(isinstance(result.flags.obfuscation_score, float), "obfuscation_score is float",
                f"{result.flags.obfuscation_score:.4f}")

    except Exception as e:
        _assert(False, "Androguard analysis", str(e), fatal=True)


def test_apktool(apk_path: str):
    """Test APKTool static analysis."""
    print("\n[TEST GROUP] APKTool Resource Decompilation")

    try:
        from sudarshan_core.engines.apktool_engine import ApktoolEngine
        engine = ApktoolEngine()

        if not engine.is_available():
            _skip("APKTool analyze", "apktool not in PATH (not installed locally - runs in container)")
            return

        result = engine.analyze(apk_path)
        _assert(result.available, "APKTool decompilation succeeded")
        _assert(bool(result.decoded_manifest_xml), "Manifest XML extracted",
                f"{len(result.decoded_manifest_xml)} chars")
        _assert("<?xml" in result.decoded_manifest_xml or "<manifest" in result.decoded_manifest_xml,
                "Valid XML manifest content")

    except Exception as e:
        _assert(False, "APKTool analysis", str(e))


def test_jadx(apk_path: str):
    """Test JADX decompilation."""
    print("\n[TEST GROUP] JADX Java Decompilation")

    try:
        from sudarshan_core.engines.jadx_engine import JadxEngine
        engine = JadxEngine()

        if not engine.is_available():
            _skip("JADX analyze", "jadx not in PATH (not installed locally - runs in container)")
            return

        result = engine.analyze(apk_path)
        _assert(result.available, "JADX decompilation succeeded")
        _assert(result.decompiled_class_count > 0, "Classes decompiled",
                f"{result.decompiled_class_count} classes")

    except Exception as e:
        _assert(False, "JADX analysis", str(e))


def test_risk_engine(androguard_result, dynamic_result=None):
    """Test Risk Engine scoring."""
    print("\n[TEST GROUP] Risk Engine (STEI + FRS Scoring)")

    try:
        from sudarshan_core.engines.risk_engine import calculate_risk_score
        flags = androguard_result.flags

        result = calculate_risk_score(
            flags=flags,
            dynamic_result=dynamic_result,
            correlation_result={"available": False},
            all_permissions=androguard_result.permissions,
        )

        _assert(result is not None, "Risk engine returns result", fatal=True)
        _assert("final_risk_score" in result, "Has final_risk_score", f"{result.get('final_risk_score'):.1f}")
        _assert("risk_band" in result, "Has risk_band", result.get("risk_band"))
        _assert("base_score" in result, "Has base_score", f"{result.get('base_score'):.1f}")
        _assert("frs_breakdown" in result, "Has frs_breakdown")
        _assert(0 <= result["final_risk_score"] <= 100, "Score in [0, 100]")
        _assert(result["risk_band"] in ("Safe", "Suspicious", "Malicious", "Critical"), "Valid risk band")

    except Exception as e:
        _assert(False, "Risk engine scoring", str(e), fatal=True)


def test_workflow_reconstructor():
    """Test Workflow Reconstructor."""
    print("\n[TEST GROUP] Fraud Workflow Reconstructor")

    try:
        from sudarshan_core.engines.workflow_reconstructor import WorkflowReconstructor

        reconstructor = WorkflowReconstructor()

        # Simulate an OTP theft chain: accessibility → sms → network
        records = [
            {"id": "e1", "category": "accessibility", "hook": "AccessibilityNodeInfo.getText",
             "timestamp_ms": 1000, "severity": "HIGH", "description": "Screen content scraped"},
            {"id": "e2", "category": "sms", "hook": "SmsMessage.getMessageBody",
             "timestamp_ms": 2000, "severity": "CRITICAL", "description": "SMS intercepted"},
            {"id": "e3", "category": "network", "hook": "OkHttp.RealCall.execute",
             "timestamp_ms": 3000, "severity": "HIGH", "description": "HTTP POST to C2 server"},
        ]

        workflow = reconstructor.reconstruct(records)
        _assert(workflow is not None, "Reconstructor returns result", fatal=True)

        wf_dict = workflow.to_dict()
        _assert("stages" in wf_dict, "Has stages field")
        _assert("fraud_sequence_detected" in wf_dict, "Has fraud_sequence_detected")
        _assert("sequence_label" in wf_dict, "Has sequence_label", wf_dict.get("sequence_label"))
        _assert("chain_confidence" in wf_dict, "Has chain_confidence", f"{wf_dict.get('chain_confidence'):.2f}")

    except Exception as e:
        _assert(False, "Workflow reconstructor", str(e))


def test_bfci_scorer():
    """Test BFCI scoring algorithm."""
    print("\n[TEST GROUP] BFCI v2 Scorer")

    try:
        from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2

        # Simulate events from a banking trojan
        events = {
            "accessibility": [
                {"data": {"hook": "AccessibilityService.onAccessibilityEvent"}, "timestamp": 1000},
                {"data": {"hook": "AccessibilityService.performGlobalAction"}, "timestamp": 1500},
                {"data": {"hook": "AccessibilityService.onServiceConnected"}, "timestamp": 500},
            ],
            "sms": [
                {"data": {"hook": "SmsManager.sendTextMessage"}, "timestamp": 2000},
                {"data": {"hook": "SmsMessage.getMessageBody"}, "timestamp": 2100},
            ],
            "overlay": [
                {"data": {"hook": "WindowManager.addView"}, "timestamp": 3000},
            ],
            "banking": [],
            "network": [
                {"data": {"hook": "OkHttpClient.execute"}, "timestamp": 4000},
            ],
            "persistence": [],
        }

        bfci, components, evidence, sequences = calculate_bfci_v2(events)

        _assert(bfci > 0, "BFCI score > 0", f"BFCI={bfci:.1f}")
        _assert(bfci <= 100, "BFCI score <= 100")
        _assert(isinstance(components, dict), "BFCI components is dict")
        _assert(isinstance(evidence, list), "BFCI evidence is list")
        _assert(components.get("accessibility", 0) > 0, "Accessibility component scored")
        _assert(components.get("sms", 0) > 0, "SMS component scored")

        print(f"     BFCI={bfci:.1f}, accessibility={components.get('accessibility', 0):.1f}, sms={components.get('sms', 0):.1f}")
        print(f"     Detected sequences: {sequences}")

    except Exception as e:
        _assert(False, "BFCI v2 scorer", str(e))


def test_backend_api(apk_path: str):
    """Test Backend API endpoints."""
    print("\n[TEST GROUP] Backend API")

    # Health check
    try:
        r = requests.get(f"{BACKEND_HOST}/health", timeout=2)
        if r.status_code != 200:
            pytest.skip(f"Backend API not running at {BACKEND_HOST}")
    except Exception:
        pytest.skip(f"Backend host unreachable at {BACKEND_HOST}")

    # Login
    try:
        r = requests.post(
            f"{BACKEND_HOST}/api/v1/token",
            data={"username": "admin", "password": os.getenv("ADMIN_PASSWORD", "admin")},
            timeout=10,
        )
        if r.status_code == 200:
            token = r.json().get("access_token")
            _assert(bool(token), "Backend auth (JWT)", f"token={token[:20]}...")
        else:
            _skip("Backend auth", f"HTTP {r.status_code} - may need ADMIN_PASSWORD env var")
            token = None
    except Exception as e:
        _assert(False, "Backend auth", str(e))
        token = None

    # Upload endpoint (without auth - should get 401)
    try:
        with open(apk_path, "rb") as f:
            r = requests.post(
                f"{BACKEND_HOST}/api/v1/analyze",
                files={"file": ("test.apk", f, "application/octet-stream")},
                timeout=10,
            )
        _assert(r.status_code in (401, 403, 422), "Unauthenticated upload rejected",
                f"HTTP {r.status_code} (correct - not unauthorized to bypass auth)")
    except Exception as e:
        _assert(False, "Unauthenticated upload check", str(e))


def test_dynamic_analysis(apk_path: str):
    """Test dynamic analysis pipeline (Frida + ADB)."""
    print("\n[TEST GROUP] Dynamic Analysis (Frida + ADB)")

    import asyncio
    try:
        from sudarshan_core.engines.frida_sandbox import get_sandbox_status, get_connected_emulators

        status = get_sandbox_status()
        _assert(status["frida_available"], "Frida Python available", f"v{status.get('frida_version')}")
        _assert(status["adb_found"], "ADB found", status.get("adb_path"))
        _assert(status["hooks_script_present"], "Frida hooks script present",
                status.get("hooks_script_path"))

        emulators = get_connected_emulators()
        if not emulators:
            _skip("ADB emulator connected", "No emulator - start an AVD")
            _skip("APK install", "No emulator")
            _skip("App launch", "No emulator")
            _skip("Frida attach", "No emulator")
            _skip("Hook events", "No emulator")
            _skip("Evidence store population", "No emulator")
            return

        _assert(True, "ADB emulator connected", f"Devices: {emulators}")
        device = emulators[0]

        # Run full Frida analysis
        from sudarshan_core.engines.frida_sandbox import run_frida_analysis

        async def _run():
            return await run_frida_analysis(apk_path=apk_path)

        result = asyncio.run(_run())

        _assert(result is not None, "run_frida_analysis returns result", fatal=True)
        _assert("available" in result, "Result has 'available' field")
        _assert("engine" in result, "Result has 'engine' field", result.get("engine"))
        _assert("dynamic_status" in result, "Result has 'dynamic_status'", result.get("dynamic_status"))
        _assert("bfci" in result, "Result has 'bfci'", f"BFCI={result.get('bfci'):.1f}")
        _assert("bfci_components" in result, "Result has 'bfci_components'")

        if result.get("available"):
            _assert(result.get("canary_received"), "Frida canary received (hooks loaded)")
            # Any declared status is a valid, honest outcome - e.g. a legacy
            # sample whose spawn-gated launch falls back reports
            # INSTRUMENTED_TOO_LATE. What must never happen is an inconclusive
            # run being scored as a clean dynamic axis.
            from sudarshan_core.engines.frida_sandbox import DynamicAnalysisStatus
            from sudarshan_core.engines.risk_engine import (
                _INCONCLUSIVE_STATUSES, dynamic_exclusion_reason,
            )
            status = result.get("dynamic_status")
            _assert(status in {s.value for s in DynamicAnalysisStatus} | {"NO_BEHAVIOR_OBSERVED"},
                    "Dynamic status is valid", status)
            if status in _INCONCLUSIVE_STATUSES:
                _assert(dynamic_exclusion_reason(result) is not None,
                        "Inconclusive run is excluded from scoring", status)

    except Exception as e:
        _assert(False, "Dynamic analysis pipeline", str(e))


def test_evidence_store():
    """Test Evidence Store with synthetic events."""
    print("\n[TEST GROUP] Evidence Store")

    try:
        from sudarshan_core.engines.event_bus import RuntimeEventBus
        from sudarshan_core.engines.evidence_store import EvidenceStore

        bus = RuntimeEventBus()
        store = EvidenceStore(event_bus=bus, package_name="com.test.app", analysis_stage="test")

        # Publish test events
        events = [
            {
                "category": "accessibility",
                "timestamp": 1000,
                "data": {
                    "hook": "AccessibilityService.onAccessibilityEvent",
                    "severity": "HIGH",
                    "description": "Screen content scraped",
                    "args": ["event_type=32"],
                    "return_value": "void",
                    "thread_id": 1,
                    "stack_trace": [],
                },
            },
            {
                "category": "sms",
                "timestamp": 2000,
                "data": {
                    "hook": "SmsManager.sendTextMessage",
                    "severity": "CRITICAL",
                    "description": "SMS sent",
                    "args": ["+919999999999", "null", "Test OTP 1234", "null", "null"],
                    "return_value": "void",
                    "thread_id": 2,
                    "stack_trace": [],
                },
            },
        ]

        for event in events:
            bus.publish(event)

        import time
        time.sleep(0.1)  # let bus process

        _assert(True, "EvidenceStore initialized")

        # Flush to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        n = store.flush(path)
        _assert(isinstance(n, int), "EvidenceStore flush returns count", f"{n} records")

        if path.exists():
            data = json.loads(path.read_text())
            _assert(isinstance(data, (list, dict)), "Flush output is valid JSON")
            path.unlink()

    except Exception as e:
        _assert(False, "Evidence Store", str(e))


def test_threat_correlator():
    """Test Threat Correlator (graceful no-keys mode)."""
    print("\n[TEST GROUP] Threat Correlator")

    try:
        import asyncio
        from sudarshan_core.services.threat_correlator import correlate

        async def _run():
            return await correlate(
                sha256="b18af2a0e44d76348c9065cb1c7ad68028a3c00a9698f2c6daa1e0a7c3f9f1e2",
                urls=["https://malicious-example.com/payload"],
                package_name="com.test.malware",
            )

        result = asyncio.run(_run())
        _assert(result is not None, "Correlator returns result", fatal=True)
        _assert("available" in result, "Result has 'available' field")
        _assert("threat_score" in result, "Result has threat_score", f"{result.get('threat_score'):.1f}")

        if not result.get("available"):
            print("     (No threat intel API keys configured - graceful degradation ✅)")

    except Exception as e:
        _assert(False, "Threat correlator", str(e))


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", default=TEST_APK, help="APK to use for testing")
    parser.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic analysis tests")
    parser.add_argument("--skip-backend", action="store_true", help="Skip backend API tests")
    parser.add_argument("--skip-mobsf", action="store_true", help="Skip MobSF tests")
    args = parser.parse_args()

    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"[ERROR] Test APK not found: {apk_path}")
        sys.exit(1)

    print("=" * 70)
    print("SUDARSHAN - Integration Test Suite")
    print(f"APK: {apk_path}")
    print("=" * 70)

    # Core tests (always run)
    from sudarshan_core.analyzers.apk_analyzer import analyze_apk
    androguard_res = analyze_apk(apk_path)
    test_androguard(apk_path)
    test_apktool(apk_path)
    test_jadx(apk_path)
    test_bfci_scorer()
    test_workflow_reconstructor()
    test_evidence_store()
    test_threat_correlator()

    if androguard_res:
        test_risk_engine(androguard_res)

    if not args.skip_mobsf:
        test_mobsf(apk_path)

    if not args.skip_backend:
        test_backend_api(apk_path)

    if not args.skip_dynamic:
        test_dynamic_analysis(apk_path)

    # Summary
    total = PASS_COUNT + FAIL_COUNT + SKIP_COUNT
    print("\n" + "=" * 70)
    print("INTEGRATION TEST RESULTS")
    print("=" * 70)
    print(f"  Total:   {total}")
    print(f"  PASS:    {PASS_COUNT} ✅")
    print(f"  FAIL:    {FAIL_COUNT} ❌")
    print(f"  SKIP:    {SKIP_COUNT} ⏭")

    if FAIL_COUNT == 0:
        print("\n✅ ALL TESTS PASSED")
    else:
        print(f"\n❌ {FAIL_COUNT} TEST(S) FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
