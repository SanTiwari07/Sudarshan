import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.pool import connect
from app.db.database import get_case

async def worker(worker_id):
    async with connect() as db:
        await db.execute("SELECT 1")
        await asyncio.sleep(0.1) # hold the connection
        return True

async def main():
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    
    # We will spawn 100 concurrent workers. 
    # Since pool size max is 20, they should wait and succeed without errors.
    print("Spawning 100 concurrent requests...")
    start = time.time()
    
    tasks = [worker(i) for i in range(100)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    success = sum(1 for r in results if r is True)
    errors = sum(1 for r in results if isinstance(r, Exception))
    
    duration = time.time() - start
    print(f"Completed in {duration:.2f}s. Success: {success}, Errors: {errors}")
    assert success == 100, f"Expected 100 successes, got {success} and {errors} errors"
    print("Pool Load Test PASSED")

if __name__ == "__main__":
    asyncio.run(main())
