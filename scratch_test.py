import asyncio
import sys
import subprocess
import time
from httpx import AsyncClient

async def test():
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"], cwd="C:\\Projects\\Sudarshan\\backend", env={"PYTHONPATH": "C:\\Projects\\Sudarshan\\shared;C:\\Projects\\Sudarshan\\backend", "UPLOADS_DIR": "C:\\Projects\\Sudarshan\\uploads", **dict(os.environ)}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(3)
    
    async with AsyncClient(timeout=30) as client:
        r = await client.post('http://localhost:8000/api/v1/auth/login', json={'username':'admin', 'password':'Sudarshan@2026'})
        token = r.json().get('access_token')
        
        r = await client.post('http://localhost:8000/api/v1/analyze/async', headers={'Authorization': 'Bearer '+token}, files={'file': ('Krep_Banking_Malware.apk', open('C:\\Projects\\Sudarshan\\test apk\\Malware\\Krep_Banking_Malware.apk', 'rb'), 'application/vnd.android.package-archive')})
        print("Response:", r.status_code, r.text)
        
    proc.terminate()
    stdout, _ = proc.communicate()
    print("Server Log:")
    print(stdout.decode('utf-8', errors='replace'))

import os
asyncio.run(test())
