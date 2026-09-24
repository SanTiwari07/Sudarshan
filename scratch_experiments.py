import asyncio
import httpx
import sys
import subprocess
import time
import os
import json

APKS = {
    "Malware": "C:\\Projects\\Sudarshan\\test apk\\Malware\\Krep_Banking_Malware.apk",
    "Safe": "C:\\Projects\\Sudarshan\\test apk\\Safe\\Fossify Calculator.apk"
}
MODES = ["gemini", "jev", "hybrid"]
BACKEND_URL = "http://127.0.0.1:8001"

async def run_experiment(apk_name, apk_path, mode):
    print(f"\n{'='*50}\nStarting {apk_name} with mode: {mode}\n{'='*50}")
    
    env = dict(os.environ)
    env["PYTHONPATH"] = "C:\\Projects\\Sudarshan\\shared;C:\\Projects\\Sudarshan\\analysis-engine"
    env["UPLOADS_DIR"] = "C:\\Projects\\Sudarshan\\uploads"
    env["SUDARSHAN_PLANNER_MODE"] = mode
    
    log_file = open(f"engine_log_{apk_name}_{mode}.txt", "w")
    engine = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8002"], cwd="C:\\Projects\\Sudarshan\\analysis-engine", env=env, stdout=log_file, stderr=subprocess.STDOUT)
    time.sleep(6) # wait for startup
    
    try:
        async with AsyncClient(timeout=60) as client:
            r = await client.post(f"{BACKEND_URL}/api/v1/auth/login", json={'username':'admin', 'password':'Sudarshan@2026'})
            token = r.json().get('access_token')
            
            r = await client.post(f"{BACKEND_URL}/api/v1/analyze/async", headers={'Authorization': 'Bearer '+token}, files={'file': (apk_path.split('\\')[-1], open(apk_path, 'rb'), 'application/vnd.android.package-archive')})
            if r.status_code != 202:
                print("Upload failed:", r.status_code, r.text)
                return
                
            job_id = r.json().get('job_id')
            print(f"Job queued: {job_id}. Polling...")
            
            while True:
                r = await client.get(f"{BACKEND_URL}/api/v1/status/{job_id}", headers={'Authorization': 'Bearer '+token})
                st = r.json()
                status = st.get('status')
                prog = st.get('progress_pct', 0)
                msg = st.get('pipeline_message', '')
                print(f"  [{status}] {prog}% - {msg}")
                
                if status in ('done', 'completed', 'failed'):
                    break
                time.sleep(5)
                
            res_file = f"result_{apk_name}_{mode}.json"
            with open(res_file, "w") as f:
                json.dump(st, f, indent=2)
            print(f"Saved result to {res_file}")
    finally:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(engine.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_file.close()
        time.sleep(3)

async def main():
    for apk_name, apk_path in APKS.items():
        for mode in MODES:
            await run_experiment(apk_name, apk_path, mode)

if __name__ == '__main__':
    from httpx import AsyncClient
    asyncio.run(main())
