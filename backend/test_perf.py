import asyncio
import httpx
import time

async def hit_health(client):
    try:
        resp = await client.get("http://localhost:8000/health")
        return resp.status_code == 200
    except Exception:
        return False

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        print("Warming up...")
        await hit_health(client)
        
        for concurrency in [10, 50, 100]:
            print(f"Testing {concurrency} concurrent requests...")
            start = time.time()
            tasks = [hit_health(client) for _ in range(concurrency)]
            results = await asyncio.gather(*tasks)
            duration = time.time() - start
            success = sum(results)
            print(f"  Completed in {duration:.2f}s. Success: {success}/{concurrency}")
            
if __name__ == "__main__":
    asyncio.run(main())
