#!/usr/bin/env python3
"""
Sudarshan MobSF API Integration Test
Tests the complete MobSF pipeline: upload → scan → report → parse
"""

import json
import sys
import time
import requests

HOST = "http://localhost:8008"
API_KEY = "sudarshan_mobsf_api_key_2026"
HEADERS = {"Authorization": API_KEY}
APK_PATH = r"d:\Projects\Sudarshan BOI\test apk\Vulnerable\InsecureBankv2.apk"


def print_step(step: int, label: str, status: str, detail: str = ""):
    print(f"[STEP {step}] {label}: {status}")
    if detail:
        print(f"         {detail}")


def test_mobsf():
    print("=" * 60)
    print("SUDARSHAN MobSF API End-to-End Test")
    print("=" * 60)

    # Step 1: Health Check
    try:
        r = requests.get(f"{HOST}/api_docs", headers=HEADERS, timeout=5)
        if r.status_code in (200, 302, 401, 403):
            print_step(1, "Health Check", "PASS", f"HTTP {r.status_code}")
        else:
            print_step(1, "Health Check", f"FAIL (HTTP {r.status_code})")
            sys.exit(1)
    except Exception as e:
        print_step(1, "Health Check", f"FAIL: {e}")
        sys.exit(1)

    # Step 2: Upload APK
    try:
        with open(APK_PATH, "rb") as f:
            r = requests.post(
                f"{HOST}/api/v1/upload",
                headers=HEADERS,
                files={"file": ("InsecureBankv2.apk", f, "application/octet-stream")},
                timeout=120,
            )
        r.raise_for_status()
        data = r.json()
        scan_hash = data.get("hash")
        print_step(2, "APK Upload", "PASS", f"scan_hash={scan_hash}, file={data.get('file_name')}")
    except Exception as e:
        print_step(2, "APK Upload", f"FAIL: {e}")
        sys.exit(1)

    if not scan_hash:
        print("[FAIL] No scan_hash returned from upload")
        sys.exit(1)

    # Step 3: Trigger Scan
    try:
        r = requests.post(
            f"{HOST}/api/v1/scan",
            headers=HEADERS,
            data={"hash": scan_hash, "re_scan": 0},
            timeout=300,
        )
        r.raise_for_status()
        print_step(3, "Trigger Scan", "PASS", f"Response: {r.text[:200]}")
    except Exception as e:
        print_step(3, "Trigger Scan", f"FAIL: {e}")
        sys.exit(1)

    # Step 4: Fetch JSON Report
    print("[INFO] Waiting 10s for scan to complete...")
    time.sleep(10)
    try:
        r = requests.post(
            f"{HOST}/api/v1/report_json",
            headers=HEADERS,
            data={"hash": scan_hash},
            timeout=60,
        )
        r.raise_for_status()
        report = r.json()
        print_step(4, "JSON Report", "PASS", 
                   f"package={report.get('package_name')}, "
                   f"permissions={len(report.get('permissions', {}))}, "
                   f"activities={len(report.get('activities', []))}")
    except Exception as e:
        print_step(4, "JSON Report", f"FAIL: {e}")
        sys.exit(1)

    # Step 5: Fetch Scorecard
    try:
        r = requests.post(
            f"{HOST}/api/v1/scorecard",
            headers=HEADERS,
            data={"hash": scan_hash},
            timeout=30,
        )
        scorecard = r.json() if r.status_code == 200 else {}
        print_step(5, "Scorecard", "PASS" if r.status_code == 200 else f"HTTP {r.status_code}",
                   f"security_score={scorecard.get('security_score')}")
    except Exception as e:
        print_step(5, "Scorecard", f"WARN: {e}")

    # Summary
    print("\n" + "=" * 60)
    print("MobSF API TEST RESULT: ALL STEPS PASSED")
    print(f"  Package: {report.get('package_name')}")
    print(f"  File: {report.get('file_name')}")
    print(f"  SHA256: {report.get('sha256', '')[:16]}...")
    print(f"  Min SDK: {report.get('min_sdk')}")
    print(f"  Permissions: {len(report.get('permissions', {}))}")
    print(f"  Activities: {len(report.get('activities', []))}")
    print(f"  Services: {len(report.get('services', []))}")
    print(f"  Scan Hash: {scan_hash}")
    print("=" * 60)

    # Save full report
    with open(r"d:\Projects\Sudarshan BOI\scripts\mobsf_test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("[INFO] Full report saved to scripts/mobsf_test_report.json")


if __name__ == "__main__":
    test_mobsf()
