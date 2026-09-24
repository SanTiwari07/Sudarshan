import asyncio
from httpx import AsyncClient

async def test():
    async with AsyncClient(timeout=30) as client:
        r = await client.post('http://localhost:8000/api/v1/auth/login', json={'username':'admin', 'password':'Sudarshan@2026'})
        token = r.json().get('access_token')
        r = await client.post('http://localhost:8000/api/v1/analyze/async', headers={'Authorization': 'Bearer '+token}, files={'file': ('Krep_Banking_Malware.apk', open('C:\\Projects\\Sudarshan\\test apk\\Malware\\Krep_Banking_Malware.apk', 'rb'), 'application/vnd.android.package-archive')})
        print(r.status_code, r.text)

asyncio.run(test())
