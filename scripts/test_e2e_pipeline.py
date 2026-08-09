#!/usr/bin/env python3
"""
End-to-end pipeline test: upload real APK through backend, verify result.
"""
import requests
import json
import sys
import time

BACKEND = "http://localhost:8000"
ADMIN_USER = "admin"
ADMIN_PASS = "Sudarshan@2026"
APK_PATH = r"d:\Projects\Sudarshan BOI\test apk\Vulnerable\InsecureBankv2.apk"

print("=" * 60)
print("SUDARSHAN - End-to-End Pipeline Test")
print("APK:", APK_PATH)
print("=" * 60)

# Step 1: Auth
print("\n[1] Authenticating...")
r = requests.post(
    f"{BACKEND}/api/v1/auth/login",
    json={"username": ADMIN_USER, "password": ADMIN_PASS},
    timeout=10,
)
if r.status_code != 200:
    print(f"    Auth failed: HTTP {r.status_code}")
    print(f"    Response: {r.text[:300]}")
    sys.exit(1)

token = r.json().get("access_token")
print(f"    OK JWT token: {token[:40]}...")

headers = {"Authorization": f"Bearer {token}"}

# Step 2: Upload APK (async mode)
print("\n[2] Uploading APK (async analysis)...")
with open(APK_PATH, "rb") as f:
    r = requests.post(
        f"{BACKEND}/api/v1/analyze/async",
        headers=headers,
        files={"file": ("UnCrackable-Level1.apk", f, "application/vnd.android.package-archive")},
        timeout=30,
    )

if r.status_code not in (200, 202):
    print(f"    Upload failed: HTTP {r.status_code}")
    print(f"    Response: {r.text[:500]}")
    sys.exit(1)

data = r.json()
job_id = data.get("job_id")
print(f"    OK Job queued: job_id={job_id}")

# Step 3: Poll for result
print("\n[3] Polling for analysis result (max 5min)...")
max_wait = 300
start = time.time()
poll_interval = 5

while time.time() - start < max_wait:
    r = requests.get(f"{BACKEND}/api/v1/status/{job_id}", headers=headers, timeout=10)
    if r.status_code != 200:
        print(f"    Poll error: HTTP {r.status_code}")
        time.sleep(poll_interval)
        continue

    status = r.json()
    job_status = status.get("status")
    elapsed = int(time.time() - start)
    print(f"    [{elapsed}s] Status: {job_status}")

    if job_status == "done":
        result = status.get("result", {})
        print("\n" + "=" * 60)
        print("ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"  Package:          {result.get('package_name')}")
        print(f"  App Name:         {result.get('app_name')}")
        print(f"  Analysis Mode:    {result.get('analysis_mode')}")
        print(f"  Family:           {result.get('family_classification')}")
        print(f"  Final Risk Score: {result.get('final_risk_score')}")
        print(f"  Risk Band:        {result.get('risk_band')}")
        print(f"  Confidence:       {result.get('confidence')}%")
        print(f"  MobSF Hash:       {result.get('mobsf_scan_hash')}")
        print(f"  APKTool Result:   {bool(result.get('apktool_enrichment'))}")
        print(f"  JADX Result:      {bool(result.get('jadx_enrichment'))}")
        print(f"  Permissions:      {len(result.get('all_permissions', []))}")
        print(f"  Dangerous Perms:  {len(result.get('dangerous_perms', []))}")
        print(f"  Hardcoded URLs:   {len(result.get('hardcoded_urls_ips', []))}")
        print(f"  Dynamic Available:{result.get('dynamic_available')}")
        print(f"  Has Accessibility:{result.get('has_accessibility_abuse')}")
        print(f"  Has SMS:          {result.get('has_sms_read_write')}")
        
        frs = result.get("frs_breakdown") or {}
        if frs:
            print(f"\n  FRS Breakdown:")
            for k, v in frs.items():
                if isinstance(v, (int, float)):
                    print(f"    {k}: {v:.2f}")

        intel = result.get("intelligence_report") or {}
        if intel:
            narrative = intel.get("plain_english_narrative", "")
            if narrative:
                print(f"\n  AI Narrative (excerpt):")
                print(f"    {narrative[:400]}...")

        with open(r"d:\Projects\Sudarshan BOI\scripts\pipeline_test_result.json", "w") as f:
            json.dump(result, f, indent=2)
        print("\n  Full result saved: scripts/pipeline_test_result.json")

        # Verification
        checks = [
            ("package_name", bool(result.get("package_name")) and result.get("package_name") != "Unknown"),
            ("analysis_mode", bool(result.get("analysis_mode"))),
            ("final_risk_score", isinstance(result.get("final_risk_score"), (int, float))),
            ("risk_band", result.get("risk_band") in ("Safe", "Suspicious", "Malicious", "Critical")),
            ("all_permissions", isinstance(result.get("all_permissions"), list)),
            ("frs_breakdown", bool(result.get("frs_breakdown"))),
        ]
        print("\n  Verification:")
        passed = failed = 0
        for name, ok in checks:
            icon = "OK" if ok else "FAIL"
            print(f"    [{icon}] {name}")
            if ok:
                passed += 1
            else:
                failed += 1

        print(f"\n  {passed}/{passed+failed} checks passed")
        sys.exit(0 if failed == 0 else 1)

    elif job_status == "failed":
        print(f"\n    ANALYSIS FAILED: {status.get('error', 'Unknown error')}")
        sys.exit(1)

    time.sleep(poll_interval)

print("\nTIMEOUT: Analysis did not complete within 5 minutes")
sys.exit(1)
