import pytest
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.workers.durable_queue import (
    enqueue, create_job, get_analysis_fingerprint, get_job
)
from app.db.database import (
    get_canonical_analysis, init_db, _connect
)

@pytest.mark.asyncio
async def test_idempotency():
    os.environ["DATABASE_URL"] = "postgresql://sudarshan:sudarshan@localhost:5432/sudarshan"
    await init_db()
    
    sha256 = "test_idem_sha256"
    fingerprint = get_analysis_fingerprint(sha256)
    
    async with _connect() as db:
        await db.execute("DELETE FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,))
        await db.execute("DELETE FROM analysis_jobs WHERE sha256 = ?", (sha256,))
        await db.commit()
    
    job_id = create_job()
    
    # 1. Enqueue once
    await enqueue(job_id, "/tmp/fake.apk", "fake.apk", sha256, analyst_id=1)
    canonical1 = await get_canonical_analysis(fingerprint)
    
    # 2. Enqueue again with exact same job_id (frontend retry)
    await enqueue(job_id, "/tmp/fake.apk", "fake.apk", sha256, analyst_id=1)
    canonical2 = await get_canonical_analysis(fingerprint)
    
    # Job should be identical, no error
    assert canonical1["fingerprint"] == canonical2["fingerprint"]
    
    j = await get_job(job_id)
    assert j["status"] == "queued"
    
    print("Idempotency test PASSED")

if __name__ == "__main__":
    asyncio.run(test_idempotency())
