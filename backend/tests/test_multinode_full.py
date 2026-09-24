import pytest
import asyncio
import os
import shutil
from pathlib import Path

from app.workers.durable_queue import enqueue, get_job
from app.db.database import get_canonical_analysis, init_db, claim_next_canonical_job, _connect, get_case, heartbeat_canonical_job
from app.workers.durable_queue import get_analysis_fingerprint
from sudarshan_core.storage.artifact_storage import get_storage
from app.db.artifact_metadata import init_artifact_metadata, record_artifact

@pytest.fixture
def multinode_env(monkeypatch, tmp_path):
    os.environ["DATABASE_URL"] = "postgresql://sudarshan:sudarshan@localhost:5432/sudarshan"
    
    shared_storage_dir = tmp_path / "shared_gcs_bucket"
    shared_storage_dir.mkdir()
    monkeypatch.setenv("UPLOADS_DIR", str(shared_storage_dir))
    
    node_a_scratch = tmp_path / "node_a_scratch"
    node_b_scratch = tmp_path / "node_b_scratch"
    node_a_scratch.mkdir()
    node_b_scratch.mkdir()
    
    return {
        "shared": shared_storage_dir,
        "node_a": node_a_scratch,
        "node_b": node_b_scratch
    }

@pytest.mark.asyncio
async def test_multinode_full_lifecycle(multinode_env):
    await init_db()
    await init_artifact_metadata()
    
    sha256 = "multinode_full_10k_test"
    fingerprint = get_analysis_fingerprint(sha256)
    
    # Cleanup any previous state
    async with _connect() as db:
        await db.execute("DELETE FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,))
        await db.execute("DELETE FROM analysis_jobs WHERE sha256 = ?", (sha256,))
        await db.commit()

    storage = get_storage()
    test_apk_content = b"fake apk content"
    
    # TEST 1: Node A uploads artifact. Node B can read it.
    local_apk_a = multinode_env["node_a"] / "test.apk"
    local_apk_a.write_bytes(test_apk_content)
    object_key = f"uploads/{sha256}/test.apk"
    await storage.put_file(str(local_apk_a), object_key)
    
    local_apk_b_verify = multinode_env["node_b"] / "test_verify.apk"
    await storage.get_file(object_key, str(local_apk_b_verify))
    assert local_apk_b_verify.read_bytes() == test_apk_content

    # TEST 2: Node A creates durable job.
    job_id = "job_node_a_full"
    await record_artifact(
        artifact_id=f"apk_{sha256}",
        artifact_type="original_apk",
        object_key=object_key,
        status="VERIFIED",
        size_bytes=len(test_apk_content),
        sha256=sha256,
    )
    await enqueue(job_id, object_key, "test.apk", sha256, analyst_id=1)
    
    canonical = await get_canonical_analysis(fingerprint)
    assert canonical["status"] == "QUEUED"

    # Test 6: Two workers cannot simultaneously claim
    claimed_1 = await claim_next_canonical_job("worker-node-a", lease_seconds=10)
    assert claimed_1 is not None
    assert claimed_1["fingerprint"] == fingerprint
    
    claimed_2 = await claim_next_canonical_job("worker-node-b", lease_seconds=10)
    # Node B should not get the same job!
    if claimed_2 is not None:
        assert claimed_2["fingerprint"] != fingerprint

    # Test 8: Heartbeat prevents premature recovery
    await heartbeat_canonical_job(fingerprint, lease_seconds=10)
    
    # Wait some time but less than 10s
    await asyncio.sleep(1)
    claimed_3 = await claim_next_canonical_job("worker-node-b", lease_seconds=10)
    if claimed_3 is not None:
        assert claimed_3["fingerprint"] != fingerprint

    # Test 7: Lease expiry allows recovery
    # Force expiry by manually updating DB
    async with _connect() as db:
        await db.execute("UPDATE canonical_analyses SET lease_expires_at = '2000-01-01T00:00:00' WHERE fingerprint = ?", (fingerprint,))
        await db.commit()

    # TEST 5: Node A dies (local filesystem unavailable)
    shutil.rmtree(multinode_env["node_a"])
    
    # Node B claims it
    claimed_recovery = await claim_next_canonical_job("worker-node-b", lease_seconds=10)
    assert claimed_recovery is not None
    assert claimed_recovery["fingerprint"] == fingerprint
    
    # TEST 3: Node B reconstructs local scratch workspace
    from app.db.artifact_metadata import get_artifact
    art = await get_artifact(f"apk_{sha256}")
    local_apk_b_recover = multinode_env["node_b"] / "downloaded.apk"
    await storage.get_file(art["object_key"], str(local_apk_b_recover))
    assert local_apk_b_recover.read_bytes() == test_apk_content
    
    # TEST 4: Node B completes analysis
    async with _connect() as db:
        await db.execute("UPDATE canonical_analyses SET status = 'COMPLETED' WHERE fingerprint = ?", (fingerprint,))
        await db.commit()
