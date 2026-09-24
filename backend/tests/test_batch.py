"""
Unit and integration tests for Sudarshan Enterprise Batch Scan.
"""

import io
import os
import zipfile
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.db.database import (
    init_db,
    create_user,
    get_user_by_username,
    get_batch,
    get_batch_job,
    get_batch_jobs,
    get_next_queued_batch_job,
    update_batch_job,
    update_batch,
    list_batches,
    count_batches,
)
from app.routes.batch import _batch_progress


def _make_dummy_apk_bytes(filename_in_zip: str = "AndroidManifest.xml") -> bytes:
    """Create a minimal valid ZIP archive representing a dummy APK."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(filename_in_zip, b"<manifest package='com.test.sample'/>")
        z.writestr("classes.dex", b"dex\n035\x00dummy")
    return buf.getvalue()


async def _get_auth_headers(username: str, role: str = "analyst") -> dict:
    # Session-backed: a bare create_access_token() token has no `sessions` row
    # and is rejected by get_current_user.
    from auth_helpers import auth_headers
    return await auth_headers(username, role)


@pytest.mark.anyio
async def test_batch_creation_validation():
    """Test validation rules: reject single file, reject invalid extensions, reject non-ZIP."""
    analyst_auth_header = await _get_auth_headers("test_analyst_batch_val", "analyst")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Reject without auth
        res = await client.post("/api/v1/batches")
        assert res.status_code == 401

        # 2. Reject single file (must be at least 2 APKs)
        apk_bytes = _make_dummy_apk_bytes()
        files = [("files", ("single.apk", apk_bytes, "application/vnd.android.package-archive"))]
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 400
        assert "at least 2 APKs" in res.json()["detail"]

        # 3. Reject non-APK extension
        files = [
            ("files", ("test1.apk", apk_bytes, "application/octet-stream")),
            ("files", ("test2.txt", b"not an apk", "text/plain")),
        ]
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 400
        assert "Only .apk files are allowed" in res.json()["detail"]

        # 4. Reject corrupt non-ZIP apk
        files = [
            ("files", ("test1.apk", apk_bytes, "application/octet-stream")),
            ("files", ("test2.apk", b"not a real zip archive file", "application/octet-stream")),
        ]
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 400
        assert "ZIP archive signature" in res.json()["detail"]


@pytest.mark.anyio
async def test_batch_creation_success():
    """Test successful batch creation with FIFO queue ordering."""
    analyst_auth_header = await _get_auth_headers("test_analyst_batch_succ", "analyst")
    apk1 = _make_dummy_apk_bytes("file1.xml")
    apk2 = _make_dummy_apk_bytes("file2.xml")
    apk3 = _make_dummy_apk_bytes("file3.xml")

    files = [
        ("files", ("bank1.apk", apk1, "application/octet-stream")),
        ("files", ("bank2.apk", apk2, "application/octet-stream")),
        ("files", ("bank3.apk", apk3, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 202
        data = res.json()

        assert "batch_id" in data
        assert data["total_jobs"] == 3
        assert data["status"] == "QUEUED"
        assert len(data["jobs"]) == 3

        batch_id = data["batch_id"]

        # Verify FIFO queue positions
        positions = [j["queue_position"] for j in data["jobs"]]
        assert positions == [0, 1, 2]

        # Verify DB records
        batch_db = await get_batch(batch_id)
        assert batch_db is not None
        assert batch_db["total_jobs"] == 3

        jobs_db = await get_batch_jobs(batch_id)
        assert len(jobs_db) == 3
        assert jobs_db[0]["filename"] == "bank1.apk"
        assert jobs_db[1]["filename"] == "bank2.apk"
        assert jobs_db[2]["filename"] == "bank3.apk"
        assert jobs_db[0]["queue_position"] == 0


import uuid


@pytest.mark.anyio
async def test_batch_fifo_order_logic():
    """Test get_next_queued_batch_job returns lowest queue_position."""
    batch_id = f"test-fifo-{uuid.uuid4()}"
    await init_db()

    from app.db.database import create_batch, create_batch_job
    from auth_helpers import ensure_user
    
    # We assign batch to user 1. We must make sure user 1 exists (or at least a user does, and we get their ID)
    # The simplest is to ensure some user exists and use their ID, but create_batch might just need ANY valid user ID.
    # Let's ensure a user exists and use their ID.
    user = await ensure_user("batch_fifo_user")
    
    await create_batch(batch_id, created_by=user["id"], total_jobs=3)

    job0_id = f"job-0-{uuid.uuid4()}"
    job1_id = f"job-1-{uuid.uuid4()}"
    job2_id = f"job-2-{uuid.uuid4()}"

    await create_batch_job({
        "job_id": job0_id,
        "batch_id": batch_id,
        "filename": "first.apk",
        "sha256": "sha0",
        "queue_position": 0,
        "created_at": "2026-08-24T00:00:00Z",
    })
    await create_batch_job({
        "job_id": job1_id,
        "batch_id": batch_id,
        "filename": "second.apk",
        "sha256": "sha1",
        "queue_position": 1,
        "created_at": "2026-08-24T00:00:00Z",
    })
    await create_batch_job({
        "job_id": job2_id,
        "batch_id": batch_id,
        "filename": "third.apk",
        "sha256": "sha2",
        "queue_position": 2,
        "created_at": "2026-08-24T00:00:00Z",
    })

    # Pick first
    next_job = await get_next_queued_batch_job(batch_id)
    assert next_job is not None
    assert next_job["job_id"] == job0_id
    assert next_job["queue_position"] == 0

    # Mark first completed
    await update_batch_job(job0_id, {"status": "COMPLETED"})

    # Next should be job-1
    next_job2 = await get_next_queued_batch_job(batch_id)
    assert next_job2 is not None
    assert next_job2["job_id"] == job1_id
    assert next_job2["queue_position"] == 1


@pytest.mark.anyio
async def test_batch_pause_resume_cancel():
    """Test pause, resume, and cancel control endpoints."""
    analyst_auth_header = await _get_auth_headers("test_analyst_batch_ctrl", "analyst")
    apk1 = _make_dummy_apk_bytes("a.xml")
    apk2 = _make_dummy_apk_bytes("b.xml")
    files = [
        ("files", ("app1.apk", apk1, "application/octet-stream")),
        ("files", ("app2.apk", apk2, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 202
        batch_id = res.json()["batch_id"]

        # Pause
        p_res = await client.post(f"/api/v1/batches/{batch_id}/pause", headers=analyst_auth_header)
        assert p_res.status_code == 200
        assert p_res.json()["status"] == "PAUSED"

        # Resume
        r_res = await client.post(f"/api/v1/batches/{batch_id}/resume", headers=analyst_auth_header)
        assert r_res.status_code == 200
        assert r_res.json()["status"] == "RUNNING"

        # Cancel
        c_res = await client.post(f"/api/v1/batches/{batch_id}/cancel", headers=analyst_auth_header)
        assert c_res.status_code == 200
        assert c_res.json()["status"] == "CANCELLED"

        # Check DB state
        b = await get_batch(batch_id)
        assert b["status"] == "CANCELLED"


@pytest.mark.anyio
async def test_batch_retry_job():
    """Test retry of a failed job."""
    analyst_auth_header = await _get_auth_headers("test_analyst_batch_retry", "analyst")
    apk1 = _make_dummy_apk_bytes("a.xml")
    apk2 = _make_dummy_apk_bytes("b.xml")
    files = [
        ("files", ("fail_test1.apk", apk1, "application/octet-stream")),
        ("files", ("fail_test2.apk", apk2, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        batch_id = res.json()["batch_id"]
        job_id = res.json()["jobs"][0]["job_id"]

        # Simulate job failure
        await update_batch_job(job_id, {"status": "FAILED", "error": "Sandbox timeout"})
        await update_batch(batch_id, {"failed_jobs": 1, "status": "PARTIAL"})

        # Retry endpoint
        retry_res = await client.post(f"/api/v1/batch-jobs/{job_id}/retry", headers=analyst_auth_header)
        assert retry_res.status_code == 200
        data = retry_res.json()
        assert data["status"] == "QUEUED"
        assert data["error"] is None

        # Verify batch status updated to RUNNING
        b = await get_batch(batch_id)
        assert b["status"] == "RUNNING"
        assert b["failed_jobs"] == 0


@pytest.mark.anyio
async def test_batch_auth_scoping():
    """Test that analysts cannot access or mutate other analysts' batches, but admin can."""
    analyst_auth_header = await _get_auth_headers("test_analyst_scope_1", "analyst")
    other_analyst_auth_header = await _get_auth_headers("test_analyst_scope_2", "analyst")
    admin_auth_header = await _get_auth_headers("test_admin_scope", "admin")

    apk1 = _make_dummy_apk_bytes("a.xml")
    apk2 = _make_dummy_apk_bytes("b.xml")
    files = [
        ("files", ("auth1.apk", apk1, "application/octet-stream")),
        ("files", ("auth2.apk", apk2, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Analyst 1 creates batch
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        batch_id = res.json()["batch_id"]

        # Analyst 2 tries to view batch -> 403 Forbidden
        other_res = await client.get(f"/api/v1/batches/{batch_id}", headers=other_analyst_auth_header)
        assert other_res.status_code == 403

        # Analyst 2 tries to cancel -> 403 Forbidden
        other_cancel = await client.post(f"/api/v1/batches/{batch_id}/cancel", headers=other_analyst_auth_header)
        assert other_cancel.status_code == 403

        # Admin tries to view batch -> 200 OK
        admin_res = await client.get(f"/api/v1/batches/{batch_id}", headers=admin_auth_header)
        assert admin_res.status_code == 200
        assert admin_res.json()["batch_id"] == batch_id


@pytest.mark.anyio
async def test_duplicate_apk_handling_in_batch():
    """Test that uploading identical APKs in a batch creates separate FIFO jobs with matching sha256."""
    analyst_auth_header = await _get_auth_headers("test_analyst_dupe", "analyst")
    identical_apk = _make_dummy_apk_bytes("identical.xml")

    files = [
        ("files", ("original.apk", identical_apk, "application/octet-stream")),
        ("files", ("copy_of_original.apk", identical_apk, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 202
        data = res.json()

        assert data["total_jobs"] == 2
        jobs = data["jobs"]
        assert len(jobs) == 2
        # Both jobs have identical server-calculated SHA256
        assert jobs[0]["sha256"] == jobs[1]["sha256"]
        # But separate unique job_ids and FIFO positions
        assert jobs[0]["job_id"] != jobs[1]["job_id"]
        assert jobs[0]["queue_position"] == 0
        assert jobs[1]["queue_position"] == 1


def test_batch_progress_calculation():
    """Test deterministic progress percentage calculation helper."""
    assert _batch_progress({"total_jobs": 0, "completed_jobs": 0}) == 0
    assert _batch_progress({"total_jobs": 10, "completed_jobs": 2}) == 20
    assert _batch_progress({"total_jobs": 12, "completed_jobs": 6}) == 50
    assert _batch_progress({"total_jobs": 12, "completed_jobs": 12}) == 100


@pytest.mark.anyio
async def test_batch_cancellation_aborts_active_scanning_and_queued_jobs():
    """
    Test that cancelling a batch cancels both QUEUED and active SCANNING jobs,
    aborts the underlying analysis_queue job, and preserves CANCELLED status.
    """
    from app.workers.analysis_queue import create_job as create_aq_job, get_job as get_aq_job, enqueue as enqueue_aq_job
    from app.workers.batch_worker import _finalize_batch

    analyst_auth_header = await _get_auth_headers("test_analyst_cancel_active", "analyst")
    apk1 = _make_dummy_apk_bytes("cancel_1.xml")
    apk2 = _make_dummy_apk_bytes("cancel_2.xml")
    files = [
        ("files", ("cancel_1.apk", apk1, "application/octet-stream")),
        ("files", ("cancel_2.apk", apk2, "application/octet-stream")),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/batches", files=files, headers=analyst_auth_header)
        assert res.status_code == 202
        batch_id = res.json()["batch_id"]
        job0_id = res.json()["jobs"][0]["job_id"]
        job1_id = res.json()["jobs"][1]["job_id"]

        # Simulate job0 is currently SCANNING with an active analysis_queue job
        aq_job_id = create_aq_job(sha256_hash="fake_hash", analyst_id=1)
        await enqueue_aq_job(aq_job_id, object_key="fake", filename="fake", sha256_hash="fake_hash", analyst_id=1)
        await update_batch_job(job0_id, {
            "status": "SCANNING",
            "analyst_queue_job_id": aq_job_id,
            "current_stage": "SCANNING",
        })

        # Cancel the batch
        c_res = await client.post(f"/api/v1/batches/{batch_id}/cancel", headers=analyst_auth_header)
        assert c_res.status_code == 200
        assert c_res.json()["status"] == "CANCELLED"

        # Check that both jobs are CANCELLED
        j0 = await get_batch_job(job0_id)
        j1 = await get_batch_job(job1_id)
        assert j0["status"] == "CANCELLED"
        assert j1["status"] == "CANCELLED"

        # Check analysis_queue job was cancelled
        aq_job = await get_aq_job(aq_job_id)
        assert aq_job["status"] == "cancelled"

        # Check batch counters
        b = await get_batch(batch_id)
        assert b["status"] == "CANCELLED"
        assert b["cancelled_jobs"] == 2

        # Verify _finalize_batch preserves CANCELLED status instead of overwriting with PARTIAL/FAILED
        await _finalize_batch(batch_id)
        b_after = await get_batch(batch_id)
        assert b_after["status"] == "CANCELLED"
