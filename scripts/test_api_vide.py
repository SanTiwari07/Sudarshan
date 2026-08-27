#!/usr/bin/env python3
"""
Sudarshan - API VIDE Integration Test
Uploads all APKs from d:\\Sudarshan\\tests\\apks\\VIDE_testapks to the local
analysis engine backend asynchronously, polls for completion, and asserts that
the VIDE engine correctly attributes each APK to its respective institution_id.
"""

import os
import sys
import time
import requests
from pathlib import Path

BACKEND = "http://localhost:8000"
ADMIN_USER = "admin"
ADMIN_PASS = "Sudarshan@2026"
APK_DIR = Path(r"d:\Sudarshan\tests\apks\VIDE_testapks")
POLL_INTERVAL_SECONDS = 5
TIMEOUT_SECONDS_PER_APK = 180

def print_banner(text: str):
    print("\n" + "=" * 80)
    print(f" {text}")
    print("=" * 80)

def main() -> int:
    print_banner("SUDARSHAN - API VIDE INTEGRATION TEST")
    print(f"Target backend: {BACKEND}")
    print(f"APK source:     {APK_DIR}")
    
    if not APK_DIR.is_dir():
        print(f"ERROR: APK directory not found: {APK_DIR}")
        return 1

    apks = sorted(APK_DIR.glob("*.apk"))
    if not apks:
        print(f"ERROR: No APK files found in {APK_DIR}")
        return 1

    print(f"Found {len(apks)} APK(s) to verify:")
    for apk in apks:
        print(f"  - {apk.name}")

    # Step 1: Authenticate
    print_banner("STEP 1: Authenticating as Admin")
    try:
        r = requests.post(
            f"{BACKEND}/api/v1/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
            timeout=15
        )
        if r.status_code != 200:
            print(f"Authentication failed (HTTP {r.status_code}): {r.text}")
            return 1
        
        token = r.json().get("access_token")
        if not token:
            print("Authentication failed: 'access_token' not found in response.")
            return 1
        
        print("Successfully authenticated.")
        headers = {"Authorization": f"Bearer {token}"}
    except Exception as e:
        print(f"Authentication exception: {e}")
        return 1

    # Step 2: Upload and Poll APKs
    print_banner("STEP 2: Analyzing APKs and Verifying VIDE Attribution")
    
    results = []
    all_passed = True

    for apk_path in apks:
        apk_name = apk_path.name
        expected_id = apk_path.stem  # e.g., BASE-01-SBI
        print(f"\n[{apk_name}] Uploading for asynchronous analysis...")

        job_id = None
        try:
            with open(apk_path, "rb") as f:
                r = requests.post(
                    f"{BACKEND}/api/v1/analyze/async",
                    headers=headers,
                    files={"file": (apk_name, f, "application/vnd.android.package-archive")},
                    timeout=60
                )
            if r.status_code not in (200, 202):
                print(f"[{apk_name}] Upload failed (HTTP {r.status_code}): {r.text}")
                results.append({
                    "apk": apk_name,
                    "expected": expected_id,
                    "attributed": "UPLOAD_FAILED",
                    "correct": False,
                    "score": 0.0,
                    "time": 0
                })
                all_passed = False
                continue

            data = r.json()
            job_id = data.get("job_id")
            if not job_id:
                print(f"[{apk_name}] No job_id returned in upload response: {data}")
                results.append({
                    "apk": apk_name,
                    "expected": expected_id,
                    "attributed": "NO_JOB_ID",
                    "correct": False,
                    "score": 0.0,
                    "time": 0
                })
                all_passed = False
                continue

            print(f"[{apk_name}] Uploaded successfully. job_id={job_id}. Polling for completion...")
        except Exception as e:
            print(f"[{apk_name}] Exception during upload: {e}")
            results.append({
                "apk": apk_name,
                "expected": expected_id,
                "attributed": f"UPLOAD_EXC: {type(e).__name__}",
                "correct": False,
                "score": 0.0,
                "time": 0
            })
            all_passed = False
            continue

        # Poll loop
        start_time = time.time()
        completed = False
        status_data = {}
        
        while time.time() - start_time < TIMEOUT_SECONDS_PER_APK:
            try:
                r = requests.get(
                    f"{BACKEND}/api/v1/status/{job_id}",
                    headers=headers,
                    timeout=15
                )
                if r.status_code != 200:
                    print(f"  - Polling error (HTTP {r.status_code}): {r.text}")
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                status_data = r.json()
                status = status_data.get("status")
                elapsed = int(time.time() - start_time)
                print(f"  - [{elapsed}s] Status: {status}")

                if status == "done" or status == "COMPLETED":
                    completed = True
                    break
                elif status == "failed" or status == "FAILED":
                    print(f"  - Analysis failed for job {job_id}: {status_data.get('error')}")
                    break
            except Exception as e:
                print(f"  - Exception during polling: {e}")
            
            time.sleep(POLL_INTERVAL_SECONDS)

        elapsed_time = int(time.time() - start_time)
        if not completed:
            print(f"[{apk_name}] Timeout or analysis failure after {elapsed_time}s.")
            results.append({
                "apk": apk_name,
                "expected": expected_id,
                "attributed": "TIMEOUT_OR_FAILED",
                "correct": False,
                "score": 0.0,
                "time": elapsed_time
            })
            all_passed = False
            continue

        # Verify VIDE output
        result_payload = status_data.get("result", {})
        vide = result_payload.get("vide") or {}
        
        # Extract fields
        matched_bl = vide.get("matched_baseline") or {}
        vide_comp = vide.get("vide_compare") or {}
        
        attributed_id = matched_bl.get("institution_id") or vide_comp.get("institution_id") or "NONE"
        similarity_score = vide.get("similarity_score", 0.0)
        
        correct = (attributed_id == expected_id)
        if not correct:
            all_passed = False

        print(f"[{apk_name}] Complete in {elapsed_time}s. "
              f"Attribution: {attributed_id} (Expected: {expected_id}) | Score: {similarity_score} | Correct: {correct}")
        
        results.append({
            "apk": apk_name,
            "expected": expected_id,
            "attributed": attributed_id,
            "correct": correct,
            "score": similarity_score,
            "time": elapsed_time
        })

    # Step 3: Print summary
    print_banner("SUMMARY REPORT")
    print(f"{'APK Name':25} | {'Expected ID':15} | {'Attributed ID':15} | {'Status':6} | {'Score':6} | {'Time':5}")
    print("-" * 80)
    
    passed_count = 0
    for r in results:
        status_str = "PASS" if r["correct"] else "FAIL"
        if r["correct"]:
            passed_count += 1
        print(f"{r['apk']:25} | {r['expected']:15} | {r['attributed']:15} | {status_str:6} | {r['score']:<6.4f} | {r['time']:4}s")
    
    print("-" * 80)
    print(f"Attribution Accuracy: {passed_count}/{len(results)} ({100.0 * passed_count / len(results):.1f}%)")
    
    if all_passed:
        print("\n[SUCCESS] All APKs correctly attributed! The newly mounted corpus is fully validated.")
        return 0
    else:
        print("\n[FAILURE] One or more APKs failed verification or attribution check.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
