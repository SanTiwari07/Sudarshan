import pytest
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.workers.durable_queue import (
    enqueue, create_job, get_analysis_fingerprint
)
from app.db.database import (
    get_canonical_analysis, init_db, _connect
)

@pytest.mark.asyncio
async def test_dedup():
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    await init_db()
    
    sha256 = "test_dedup_sha256"
    fingerprint = get_analysis_fingerprint(sha256)
    
    async with _connect() as db:
        await db.execute("DELETE FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,))
        await db.execute("DELETE FROM analysis_jobs WHERE sha256 = ?", (sha256,))
        await db.commit()
    
    # Simulate 5 concurrent duplicate uploads
    jobs = [create_job() for _ in range(5)]
    
    tasks = [
        enqueue(job_id, "/tmp/fake.apk", "fake.apk", sha256, analyst_id=1)
        for job_id in jobs
    ]
    await asyncio.gather(*tasks)
    
    canonical = await get_canonical_analysis(fingerprint)
    assert canonical is not None
    assert canonical["status"] == "QUEUED"
    
    # Check that there is ONLY ONE canonical analysis
    async with _connect() as db:
        cur = await db.execute("SELECT COUNT(*) FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,))
        count = (await cur.fetchone())[0]
        assert count == 1, f"Expected 1 canonical analysis, got {count}"
        
        cur = await db.execute("SELECT COUNT(*) FROM analysis_jobs WHERE canonical_fingerprint = ?", (fingerprint,))
        job_count = (await cur.fetchone())[0]
        assert job_count == 5, f"Expected 5 user jobs, got {job_count}"

    print("Deduplication test PASSED")

if __name__ == "__main__":
    asyncio.run(test_dedup())
