import asyncio
from httpx import AsyncClient

async def test():
    async with AsyncClient(timeout=30) as client:
        r = await client.post('http://127.0.0.1:8001/api/v1/auth/login', json={'username':'admin', 'password':'Sudarshan@2026'})
        token = r.json().get('access_token')
        
        r = await client.get('http://127.0.0.1:8001/api/v1/status/job_cba9667e9040', headers={'Authorization': 'Bearer '+token})
        print(r.status_code, r.text)

asyncio.run(test())
