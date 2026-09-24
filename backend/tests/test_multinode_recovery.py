import pytest
import asyncio
import os
import tempfile
import shutil
from pathlib import Path

from app.workers.durable_queue import enqueue, get_job
from app.db.database import get_canonical_analysis, init_db, claim_next_canonical_job, _connect
from app.workers.durable_queue import get_analysis_fingerprint
from sudarshan_core.storage.artifact_storage import get_storage

@pytest.mark.asyncio
async def test_multinode_recovery(monkeypatch, tmp_path):
    # Setup DB
    os.environ["DATABASE_URL"] = "postgresql://sudarshan:sudarshan@localhost:5432/sudarshan"
    await init_db()
    
    # We simulate a "shared object storage" (like GCS) using a shared directory for LocalArtifactStorage
    shared_storage_dir = tmp_path / "shared_gcs_bucket"
    shared_storage_dir.mkdir()
    monkeypatch.setenv("UPLOADS_DIR", str(shared_storage_dir))
    
    # Node A and Node B local scratch directories
    node_a_scratch = tmp_path / "node_a_scratch"
    node_b_scratch = tmp_path / "node_b_scratch"
    node_a_scratch.mkdir()
    node_b_scratch.mkdir()
    
    sha256 = "multinode_recovery_test_sha256"
    fingerprint = get_analysis_fingerprint(sha256)
    
    from app.db.artifact_metadata import init_artifact_metadata, record_artifact
    await init_artifact_metadata()
    
    # Reset DB state
    async with _connect() as db:
        await db.execute("DELETE FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,))
        await db.execute("DELETE FROM artifact_metadata WHERE artifact_id = ?", (f"apk_{sha256}",))
        await db.commit()

    # --- NODE A UPLOADS ---
    storage = get_storage()
    
    test_apk_content = b"fake apk content"
    local_apk_a = node_a_scratch / "test.apk"
    local_apk_a.write_bytes(test_apk_content)
    
    object_key = f"uploads/{sha256}/test.apk"
    # Node A uploads from its local scratch to shared storage
    await storage.put_file(str(local_apk_a), object_key)
    
    await record_artifact(
        artifact_id=f"apk_{sha256}",
        artifact_type="original_apk",
        object_key=object_key,
        status="VERIFIED",
        size_bytes=len(test_apk_content),
        sha256=sha256,
    )
    
    # Enqueue job from Node A
    job_id = "job_node_a"
    await enqueue(job_id, object_key, "test.apk", sha256, analyst_id=1)
    
    canonical = await get_canonical_analysis(fingerprint)
    assert canonical["status"] == "QUEUED"
    
    # --- NODE A DIES ---
    # Node A's local scratch disappears (simulate by deleting it)
    shutil.rmtree(node_a_scratch)
    assert not node_a_scratch.exists()
    
    # --- NODE B CLAIMS ---
    # Simulate Node B claiming the job
    claimed = await claim_next_canonical_job("worker-node-b", lease_seconds=10)
    assert claimed is not None
    assert claimed["fingerprint"] == fingerprint
    assert claimed["status"] == "PROCESSING"
    
    # Node B downloads from object storage into its own local scratch
    from app.db.artifact_metadata import get_artifact
    art = await get_artifact(f"apk_{sha256}")
    claimed_object_key = art["object_key"]
    assert claimed_object_key == object_key
    
    local_apk_b = node_b_scratch / "downloaded.apk"
    await storage.get_file(claimed_object_key, str(local_apk_b))
    
    # Verify the analysis artifact was safely recovered by Node B
    assert local_apk_b.exists()
    assert local_apk_b.read_bytes() == test_apk_content
    
    print("Multi-node recovery test passed!")
