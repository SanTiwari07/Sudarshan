import asyncio
import httpx
import time

async def hit_login(client):
    try:
        resp = await client.post("http://localhost:8000/api/v1/auth/login", json={"username": "test", "password": "abc"})
        return resp.status_code
    except Exception as e:
        return 0

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        print("Testing rate limiting with 100 concurrent requests to /api/v1/auth/login...")
        concurrency = 100
        start = time.time()
        tasks = [hit_login(client) for _ in range(concurrency)]
        results = await asyncio.gather(*tasks)
        duration = time.time() - start
        
        status_counts = {}
        for r in results:
            status_counts[r] = status_counts.get(r, 0) + 1
            
        print(f"Completed in {duration:.2f}s")
        print(f"Status codes: {status_counts}")

if __name__ == "__main__":
    asyncio.run(main())
