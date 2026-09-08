import requests
import os
import time
import json

API_URL = "http://localhost:8000/api/v1"
TEST_APK_DIR = "test apk"

def main():
    print("Waiting for API to be ready...")
    while True:
        try:
            # The backend has a /health or similar route, but we can just test /auth/login with GET or POST
            requests.get(f"http://localhost:8000/")
            break
        except Exception:
            time.sleep(5)
            print("API not ready yet, waiting 5 seconds...")
            
    # 1. Register a test user
    print("Registering test user...")
    register_data = {"username": "tester", "password": "password123"}
    try:
        requests.post(f"{API_URL}/auth/register", json=register_data)
    except Exception as e:
        print("Registration might have failed or user exists:", e)
        
    # 2. Login to get token
    print("Logging in...")
    login_data = {"username": "tester", "password": "password123"}
    resp = requests.post(f"{API_URL}/auth/login", json=login_data)
    if resp.status_code != 200:
        print("Failed to login:", resp.text)
        return
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Find all APKs
    apks = []
    for root, dirs, files in os.walk(TEST_APK_DIR):
        for f in files:
            if f.endswith(".apk"):
                apks.append(os.path.join(root, f))
                
    print(f"Found {len(apks)} APKs.")
    
    # 4. Submit each APK and track jobs
    jobs = {}
    for apk_path in apks:
        print(f"Submitting {apk_path}...")
        with open(apk_path, "rb") as f:
            resp = requests.post(
                f"{API_URL}/analyze/async",
                headers=headers,
                files={"file": (os.path.basename(apk_path), f, "application/vnd.android.package-archive")}
            )
            # The async route usually returns 202 Accepted
            if resp.status_code in (200, 202):
                job_id = resp.json()["job_id"]
                print(f"Submitted. Job ID: {job_id}")
                jobs[job_id] = apk_path
            else:
                print(f"Failed to submit {apk_path} ({resp.status_code}): {resp.text}")
                # Wait for rate limit to reset
                if resp.status_code == 429:
                    print("Waiting 60s for rate limit...")
                    time.sleep(60)
                
    # 5. Poll jobs
    print("Polling jobs...")
    completed = 0
    results = {}
    while completed < len(jobs):
        for job_id, apk_path in list(jobs.items()):
            if job_id in results:
                continue
                
            resp = requests.get(f"{API_URL}/status/{job_id}", headers=headers)
            if resp.status_code == 200:
                status_data = resp.json()
                if status_data["status"] == "completed":
                    print(f"\n[{os.path.basename(apk_path)}] COMPLETED!")
                    results[job_id] = status_data
                    completed += 1
                elif status_data["status"] == "failed":
                    print(f"\n[{os.path.basename(apk_path)}] FAILED! Error: {status_data.get('error')}")
                    results[job_id] = status_data
                    completed += 1
                else:
                    # Still processing
                    pass
            else:
                print(f"Error polling {job_id}: {resp.text}")
                results[job_id] = {"status": "error", "error": resp.text}
                completed += 1
                
        time.sleep(10)
        
    print("\n--- ALL JOBS FINISHED ---")
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Results saved to test_results.json")

if __name__ == "__main__":
    main()
