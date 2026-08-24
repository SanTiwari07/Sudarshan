"""
Sudarshan Enterprise Batch Scan API
=====================================
Endpoints:
  POST   /api/v1/batches                        Create batch + upload APKs
  GET    /api/v1/batches                        List batches (paginated, scoped)
  GET    /api/v1/batches/{batch_id}             Get batch + progress summary
  GET    /api/v1/batches/{batch_id}/jobs        Get all jobs (lightweight)
  POST   /api/v1/batches/{batch_id}/pause       Pause queue
  POST   /api/v1/batches/{batch_id}/resume      Resume queue
  POST   /api/v1/batches/{batch_id}/cancel      Cancel remaining jobs
  POST   /api/v1/batch-jobs/{job_id}/retry      Retry a failed job

Security
--------
All endpoints require JWT Bearer (require_analyst).
Analysts see only their own batches; soc_lead/admin see all.
APK validation uses the existing _receive_apk() function (extension check,
ZIP magic bytes, size limit, server-side SHA256 computation).
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.auth.auth import require_analyst
from app.case_access import list_scope_analyst_id
from app.db.database import (
    create_batch,
    create_batch_job,
    get_batch,
    get_batch_job,
    get_batch_jobs,
    list_batches,
    count_batches,
    update_batch,
    update_batch_job,
    cancel_queued_batch_jobs,
)
from app.routes.upload import _receive_apk
from app.workers.batch_worker import enqueue_batch

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _assert_batch_owner(user: dict, batch: dict) -> None:
    """Raise 403 if the user may not access this batch."""
    role = user.get("role", "analyst")
    if role in ("soc_lead", "admin"):
        return
    if batch.get("created_by") != user.get("id"):
        raise HTTPException(status_code=403, detail="Access denied: not your batch.")


def _batch_progress(batch: dict) -> int:
    """Overall completion percentage (completed / total)."""
    total = batch.get("total_jobs") or 0
    if total == 0:
        return 0
    completed = batch.get("completed_jobs") or 0
    return int(completed * 100 / total)


# ─── Response Models ──────────────────────────────────────────────────────────

class BatchJobSummary(BaseModel):
    job_id: str
    batch_id: str
    filename: str
    sha256: Optional[str] = None
    queue_position: int
    status: str
    progress_pct: int = 0
    current_stage: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None
    case_sha256: Optional[str] = None


class BatchSummary(BaseModel):
    batch_id: str
    created_by: int
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    total_jobs: int
    completed_jobs: int = 0
    failed_jobs: int = 0
    cancelled_jobs: int = 0
    status: str
    current_job_id: Optional[str] = None
    progress_pct: int = 0


class BatchListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    batches: List[BatchSummary]


class BatchDetailResponse(BatchSummary):
    jobs: List[BatchJobSummary] = Field(default_factory=list)


class BatchCreateResponse(BaseModel):
    batch_id: str
    total_jobs: int
    status: str
    message: str
    jobs: List[BatchJobSummary]


class BatchControlResponse(BaseModel):
    batch_id: str
    status: str
    message: str


def _row_to_batch_summary(row: dict) -> BatchSummary:
    return BatchSummary(
        batch_id=row["batch_id"],
        created_by=row["created_by"],
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        total_jobs=row.get("total_jobs", 0),
        completed_jobs=row.get("completed_jobs", 0),
        failed_jobs=row.get("failed_jobs", 0),
        cancelled_jobs=row.get("cancelled_jobs", 0),
        status=row.get("status", "QUEUED"),
        current_job_id=row.get("current_job_id"),
        progress_pct=_batch_progress(row),
    )


def _row_to_job_summary(row: dict) -> BatchJobSummary:
    return BatchJobSummary(
        job_id=row["job_id"],
        batch_id=row["batch_id"],
        filename=row["filename"],
        sha256=row.get("sha256"),
        queue_position=row["queue_position"],
        status=row.get("status", "QUEUED"),
        progress_pct=row.get("progress_pct", 0),
        current_stage=row.get("current_stage"),
        created_at=row["created_at"],
        started_at=row.get("started_at"),
        completed_at=row.get("completed_at"),
        error=row.get("error"),
        case_sha256=row.get("case_sha256"),
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/batches", response_model=BatchCreateResponse, status_code=202)
async def create_batch_endpoint(
    files: List[UploadFile] = File(..., description="One or more .apk files"),
    user: dict = Depends(require_analyst),
):
    """
    Create an Enterprise Batch Scan.

    Upload 2–50 APK files in a single multipart request.  The batch and
    individual job records are created synchronously; actual analysis is
    queued for background FIFO processing.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided.")
    if len(files) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 APKs per batch.")
    if len(files) < 2:
        raise HTTPException(
            status_code=400,
            detail="Batch requires at least 2 APKs. Use /analyze/async for a single APK.",
        )

    analyst_id: int = user["id"]
    batch_id = str(uuid.uuid4())
    now = _now_iso()

    # Receive and validate all APKs first (fail early before committing anything)
    received: List[tuple] = []  # (temp_path, sha256, filename)
    for f in files:
        try:
            temp_path, sha256 = await _receive_apk(f)
            received.append((temp_path, sha256, f.filename or "unknown.apk"))
        except HTTPException:
            # Clean up already-received files and re-raise
            import os
            for rp, _, _ in received:
                try:
                    os.remove(rp)
                except OSError:
                    pass
            raise

    total_jobs = len(received)

    # Create the batch record
    await create_batch(batch_id=batch_id, created_by=analyst_id, total_jobs=total_jobs)

    # Create individual job records
    job_rows = []
    for position, (temp_path, sha256, filename) in enumerate(received):
        job_id = str(uuid.uuid4())
        job_data = {
            "job_id": job_id,
            "batch_id": batch_id,
            "filename": filename,
            "sha256": sha256,
            "queue_position": position,
            "created_at": now,
            "temp_path": temp_path,
        }
        await create_batch_job(job_data)
        job_rows.append(job_data)

    # Signal the batch worker to start processing
    await enqueue_batch(batch_id)

    logger.info(
        "[BatchAPI] Batch %s created by analyst %d with %d jobs",
        batch_id[:8], analyst_id, total_jobs,
    )

    return BatchCreateResponse(
        batch_id=batch_id,
        total_jobs=total_jobs,
        status="QUEUED",
        message=f"Batch created with {total_jobs} APKs. Processing started in background.",
        jobs=[
            _row_to_job_summary({
                **j,
                "status": "QUEUED",
                "progress_pct": 0,
                "current_stage": None,
                "started_at": None,
                "completed_at": None,
                "error": None,
                "case_sha256": None,
            })
            for j in job_rows
        ],
    )


@router.get("/batches", response_model=BatchListResponse)
async def list_batches_endpoint(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: dict = Depends(require_analyst),
):
    """Return paginated batch history (scoped to analyst_id for role=analyst)."""
    scope_id = list_scope_analyst_id(user)
    total = await count_batches(created_by=scope_id)
    rows = await list_batches(limit=limit, offset=offset, created_by=scope_id)

    return BatchListResponse(
        total=total,
        limit=limit,
        offset=offset,
        batches=[_row_to_batch_summary(r) for r in rows],
    )


@router.get("/batches/{batch_id}", response_model=BatchDetailResponse)
async def get_batch_detail(
    batch_id: str,
    user: dict = Depends(require_analyst),
):
    """Get full batch details including all job summaries."""
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found.")
    _assert_batch_owner(user, batch)

    jobs = await get_batch_jobs(batch_id)

    return BatchDetailResponse(
        **_row_to_batch_summary(batch).model_dump(),
        jobs=[_row_to_job_summary(j) for j in jobs],
    )


@router.get("/batches/{batch_id}/jobs", response_model=List[BatchJobSummary])
async def get_batch_jobs_endpoint(
    batch_id: str,
    user: dict = Depends(require_analyst),
):
    """Return lightweight job list for a batch (for live polling)."""
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found.")
    _assert_batch_owner(user, batch)

    jobs = await get_batch_jobs(batch_id)
    return [_row_to_job_summary(j) for j in jobs]


@router.post("/batches/{batch_id}/pause", response_model=BatchControlResponse)
async def pause_batch(
    batch_id: str,
    user: dict = Depends(require_analyst),
):
    """
    Pause a running batch.

    The currently-SCANNING job (if any) will finish naturally.
    No new QUEUED job will be dispatched until the batch is resumed.
    """
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found.")
    _assert_batch_owner(user, batch)

    if batch.get("status") not in ("QUEUED", "RUNNING"):
        raise HTTPException(
            status_code=409,
            detail=f"Batch is {batch['status']} and cannot be paused.",
        )

    await update_batch(batch_id, {"status": "PAUSED"})
    logger.info("[BatchAPI] Batch %s paused by analyst %d", batch_id[:8], user["id"])
    return BatchControlResponse(
        batch_id=batch_id,
        status="PAUSED",
        message="Batch paused. Current job will finish; no new jobs will start until resumed.",
    )


@router.post("/batches/{batch_id}/resume", response_model=BatchControlResponse)
async def resume_batch(
    batch_id: str,
    user: dict = Depends(require_analyst),
):
    """Resume a paused batch."""
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found.")
    _assert_batch_owner(user, batch)

    if batch.get("status") != "PAUSED":
        raise HTTPException(
            status_code=409,
            detail=f"Batch is {batch['status']} and cannot be resumed.",
        )

    await update_batch(batch_id, {"status": "RUNNING"})
    # Wake the worker in case it was sleeping
    await enqueue_batch(batch_id)
    logger.info("[BatchAPI] Batch %s resumed by analyst %d", batch_id[:8], user["id"])
    return BatchControlResponse(
        batch_id=batch_id,
        status="RUNNING",
        message="Batch resumed. Processing will continue from where it left off.",
    )


@router.post("/batches/{batch_id}/cancel", response_model=BatchControlResponse)
async def cancel_batch(
    batch_id: str,
    user: dict = Depends(require_analyst),
):
    """
    Cancel remaining queued jobs in a batch.

    Already-completed cases are preserved.
    The currently-SCANNING job (if any) will finish naturally — it is NOT killed.
    All QUEUED jobs are marked CANCELLED immediately.
    """
    batch = await get_batch(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail=f"Batch {batch_id} not found.")
    _assert_batch_owner(user, batch)

    terminal = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}
    if batch.get("status") in terminal:
        raise HTTPException(
            status_code=409,
            detail=f"Batch is already {batch['status']} and cannot be cancelled.",
        )

    cancelled_count = await cancel_queued_batch_jobs(batch_id)
    batch_after = await get_batch(batch_id)
    new_cancelled = (batch_after.get("cancelled_jobs") or 0) + cancelled_count
    await update_batch(batch_id, {
        "status": "CANCELLED",
        "cancelled_jobs": new_cancelled,
    })

    logger.info(
        "[BatchAPI] Batch %s cancelled by analyst %d (%d jobs cancelled)",
        batch_id[:8], user["id"], cancelled_count,
    )
    return BatchControlResponse(
        batch_id=batch_id,
        status="CANCELLED",
        message=f"Batch cancelled. {cancelled_count} queued job(s) cancelled. Completed cases preserved.",
    )


@router.post("/batch-jobs/{job_id}/retry", response_model=BatchJobSummary)
async def retry_batch_job(
    job_id: str,
    user: dict = Depends(require_analyst),
):
    """
    Retry a failed batch job.

    Resets the job to QUEUED and signals the batch worker.
    The batch is set back to RUNNING so the worker re-picks it up.
    Only FAILED jobs may be retried.
    """
    job = await get_batch_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Batch job {job_id} not found.")

    # Check batch ownership
    batch = await get_batch(job["batch_id"])
    if not batch:
        raise HTTPException(status_code=404, detail="Associated batch not found.")
    _assert_batch_owner(user, batch)

    if job.get("status") != "FAILED":
        raise HTTPException(
            status_code=409,
            detail=f"Job status is '{job['status']}'. Only FAILED jobs can be retried.",
        )

    # Reset job
    await update_batch_job(job_id, {
        "status": "QUEUED",
        "error": None,
        "started_at": None,
        "completed_at": None,
        "progress_pct": 0,
        "current_stage": None,
        "analyst_queue_job_id": None,
        "case_sha256": None,
    })

    # Adjust batch counters and status
    new_failed = max(0, (batch.get("failed_jobs") or 0) - 1)
    batch_status = batch.get("status", "")
    if batch_status in ("PARTIAL", "FAILED", "COMPLETED", "CANCELLED"):
        new_batch_status = "RUNNING"
    else:
        new_batch_status = batch_status

    await update_batch(job["batch_id"], {
        "failed_jobs": new_failed,
        "status": new_batch_status,
    })

    # Signal worker
    await enqueue_batch(job["batch_id"])

    logger.info(
        "[BatchAPI] Job %s in batch %s queued for retry by analyst %d",
        job_id[:8], job["batch_id"][:8], user["id"],
    )

    refreshed = await get_batch_job(job_id)
    return _row_to_job_summary(refreshed)
