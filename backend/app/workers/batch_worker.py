"""
Sudarshan Enterprise Batch Worker
===================================
Processes analysis_batch_jobs in FIFO order (queue_position ASC) within
each batch, delegating to the existing analysis_queue.enqueue() mechanism.

Architecture
------------
- One background asyncio.Task started at app startup (via start_batch_worker).
- Completely backend-driven: frontend navigation, page refresh, or case
  viewing has ZERO effect on this worker.
- FIFO guarantee: only one SCANNING job per batch at a time.
- Safe cancellation/pause: currently-running job always completes naturally.

Lifecycle states
----------------
Batch:  QUEUED -> RUNNING -> COMPLETED | PARTIAL | FAILED | CANCELLED
        Can also enter PAUSED (no new jobs dispatched until RUNNING).

Job:    QUEUED -> SCANNING -> COMPLETED | FAILED | CANCELLED

Recovery on restart
-------------------
Any SCANNING job at startup had its asyncio task cancelled by the process
exit.  The worker marks such jobs as FAILED and continues to the next
queued job.  Full durable crash-recovery would require a persistent queue
(out of scope for V1).
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_POLL_INTERVAL = float(os.getenv("BATCH_WORKER_POLL_SECONDS", "3"))
_JOB_POLL_INTERVAL = float(os.getenv("BATCH_JOB_POLL_SECONDS", "2"))
_JOB_TIMEOUT_SECONDS = float(os.getenv("BATCH_JOB_TIMEOUT_SECONDS", "900"))

_wake_event: asyncio.Event = asyncio.Event()


def wake_batch_worker() -> None:
    """Signal the batch worker to wake up immediately."""
    _wake_event.set()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _mark_stale_scanning_jobs_failed() -> None:
    """On startup, mark any SCANNING jobs as FAILED (process was killed mid-run)."""
    from app.db.database import get_active_batches, get_batch_jobs, update_batch_job, update_batch
    try:
        batches = await get_active_batches()
        for batch in batches:
            jobs = await get_batch_jobs(batch["batch_id"])
            failed_count = 0
            for job in jobs:
                if job["status"] == "SCANNING":
                    now = _now_iso()
                    await update_batch_job(job["job_id"], {
                        "status": "FAILED",
                        "completed_at": now,
                        "error": "Worker process restarted while job was scanning",
                    })
                    failed_count += 1
                    logger.warning(
                        "[BatchWorker] Stale SCANNING job marked FAILED on startup: %s",
                        job["job_id"][:12],
                    )
            if failed_count:
                current_failed = batch.get("failed_jobs", 0) + failed_count
                await update_batch(batch["batch_id"], {"failed_jobs": current_failed})
    except Exception as exc:
        logger.warning("[BatchWorker] Startup recovery check failed: %s", exc)


async def _dispatch_and_await_job(batch_id: str, batch_job: dict) -> None:
    """
    Dispatch one batch job through the existing analysis pipeline and wait
    for it to complete (or fail/timeout).
    """
    from app.workers.analysis_queue import create_job, enqueue, get_job, persist_job
    from app.db.database import update_batch_job, update_batch, get_batch

    job_id = batch_job["job_id"]
    sha256 = batch_job.get("sha256", "")
    temp_path = batch_job.get("temp_path", "")
    filename = batch_job.get("filename", "")

    batch = await get_batch(batch_id)
    if not batch:
        logger.error("[BatchWorker] Batch %s not found; skipping job %s", batch_id[:8], job_id[:8])
        return

    analyst_id: Optional[int] = batch.get("created_by")

    started_at = _now_iso()
    await update_batch_job(job_id, {
        "status": "SCANNING",
        "started_at": started_at,
        "current_stage": "QUEUED",
        "progress_pct": 0,
    })
    await update_batch(batch_id, {
        "current_job_id": job_id,
        "status": "RUNNING",
        "started_at": batch.get("started_at") or started_at,
    })

    # Create and enqueue using existing analysis_queue mechanism
    analysis_job_id = create_job(sha256_hash=sha256, analyst_id=analyst_id)
    await update_batch_job(job_id, {"analyst_queue_job_id": analysis_job_id})
    await persist_job(analysis_job_id)
    await enqueue(
        job_id=analysis_job_id,
        temp_path=temp_path,
        filename=filename,
        sha256_hash=sha256,
        analyst_id=analyst_id,
    )
    logger.info(
        "[BatchWorker] Dispatched batch job %s -> analysis job %s (sha256=%s)",
        job_id[:8], analysis_job_id[:8], sha256[:12],
    )

    # Poll until done / failed / timeout
    elapsed = 0.0
    case_sha256: Optional[str] = None
    final_status = "FAILED"
    error_msg: Optional[str] = None

    while elapsed < _JOB_TIMEOUT_SECONDS:
        await asyncio.sleep(_JOB_POLL_INTERVAL)
        elapsed += _JOB_POLL_INTERVAL

        # Check if the batch itself was cancelled
        current_batch = await get_batch(batch_id)
        if not current_batch or current_batch.get("status") == "CANCELLED":
            logger.info("[BatchWorker] Batch %s was CANCELLED; aborting job %s", batch_id[:8], job_id[:8])
            from app.workers.analysis_queue import cancel_job
            await cancel_job(analysis_job_id)
            await update_batch_job(job_id, {
                "status": "CANCELLED",
                "completed_at": _now_iso(),
                "current_stage": "CANCELLED",
            })
            return

        analysis_job = await get_job(analysis_job_id)
        if not analysis_job:
            continue

        current_stage = analysis_job.get("pipeline_stage") or analysis_job.get("status", "")
        progress_pct = analysis_job.get("progress_pct", 0)
        await update_batch_job(job_id, {
            "current_stage": current_stage,
            "progress_pct": progress_pct,
        })

        aq_status = analysis_job.get("status", "")
        if aq_status == "done":
            result = analysis_job.get("result") or {}
            case_sha256 = result.get("sha256") or sha256
            final_status = "COMPLETED"
            break
        elif aq_status == "cancelled":
            logger.info("[BatchWorker] Analysis job %s was CANCELLED", analysis_job_id[:8])
            await update_batch_job(job_id, {
                "status": "CANCELLED",
                "completed_at": _now_iso(),
                "current_stage": "CANCELLED",
            })
            return
        elif aq_status == "failed":
            error_msg = analysis_job.get("error", "Analysis failed")
            final_status = "FAILED"
            break
    else:
        error_msg = f"Batch job timed out after {_JOB_TIMEOUT_SECONDS:.0f}s"
        final_status = "FAILED"
        logger.warning("[BatchWorker] Job %s timed out", job_id[:8])

    # Write final job state
    now = _now_iso()
    job_updates: dict = {
        "status": final_status,
        "completed_at": now,
        "progress_pct": 100 if final_status == "COMPLETED" else 0,
        "current_stage": "COMPLETED" if final_status == "COMPLETED" else "FAILED",
    }
    if case_sha256:
        job_updates["case_sha256"] = case_sha256
    if error_msg:
        job_updates["error"] = error_msg
    await update_batch_job(job_id, job_updates)

    # Update batch progress counters
    batch = await get_batch(batch_id)
    if batch:
        batch_updates: dict = {}
        if final_status == "COMPLETED":
            batch_updates["completed_jobs"] = (batch.get("completed_jobs") or 0) + 1
        else:
            batch_updates["failed_jobs"] = (batch.get("failed_jobs") or 0) + 1
        await update_batch(batch_id, batch_updates)

    logger.info(
        "[BatchWorker] Job %s -> %s  (case=%s)",
        job_id[:8], final_status, (case_sha256 or "-")[:12],
    )


async def _finalize_batch(batch_id: str) -> None:
    """Compute and set final batch status."""
    from app.db.database import get_batch, update_batch
    batch = await get_batch(batch_id)
    if not batch:
        return

    # If already CANCELLED, preserve the CANCELLED status
    if batch.get("status") == "CANCELLED":
        await update_batch(batch_id, {
            "completed_at": batch.get("completed_at") or _now_iso(),
            "current_job_id": None,
        })
        logger.info("[BatchWorker] Batch %s finalized -> CANCELLED", batch_id[:8])
        return

    total = batch.get("total_jobs", 0)
    completed = batch.get("completed_jobs", 0)
    failed = batch.get("failed_jobs", 0)
    cancelled = batch.get("cancelled_jobs", 0)
    done_count = completed + failed + cancelled
    now = _now_iso()

    if failed == 0 and cancelled == 0 and completed == total:
        final_status = "COMPLETED"
    elif completed > 0 and done_count >= total:
        final_status = "PARTIAL"
    elif completed == 0 and done_count >= total:
        final_status = "FAILED"
    else:
        final_status = "PARTIAL"

    await update_batch(batch_id, {
        "status": final_status,
        "completed_at": now,
        "current_job_id": None,
    })
    logger.info(
        "[BatchWorker] Batch %s finalized -> %s  (%d completed, %d failed, %d cancelled)",
        batch_id[:8], final_status, completed, failed, cancelled,
    )


async def _process_batch(batch_id: str) -> None:
    """
    Process all remaining QUEUED jobs in a batch in FIFO order.
    A failed job does NOT stop the queue.
    """
    from app.db.database import get_batch, get_next_queued_batch_job, update_batch

    while True:
        batch = await get_batch(batch_id)
        if not batch:
            logger.error("[BatchWorker] Batch %s disappeared; stopping", batch_id[:8])
            return

        status = batch.get("status", "")

        if status == "CANCELLED":
            logger.info("[BatchWorker] Batch %s is CANCELLED; stopping", batch_id[:8])
            await _finalize_batch(batch_id)
            return

        if status == "PAUSED":
            logger.info("[BatchWorker] Batch %s is PAUSED; waiting", batch_id[:8])
            await asyncio.sleep(_POLL_INTERVAL)
            continue

        next_job = await get_next_queued_batch_job(batch_id)
        if not next_job:
            logger.info("[BatchWorker] No more QUEUED jobs in batch %s", batch_id[:8])
            await _finalize_batch(batch_id)
            return

        try:
            await _dispatch_and_await_job(batch_id, next_job)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception(
                "[BatchWorker] Unexpected error processing job %s: %s",
                next_job["job_id"][:8], exc,
            )
            from app.db.database import update_batch_job
            now = _now_iso()
            await update_batch_job(next_job["job_id"], {
                "status": "FAILED",
                "completed_at": now,
                "error": f"Unexpected worker error: {exc}",
            })
            batch = await get_batch(batch_id)
            if batch:
                await update_batch(batch_id, {
                    "failed_jobs": (batch.get("failed_jobs") or 0) + 1,
                })


# ---- Pending-Batch Queue -----

_pending_batches: "asyncio.Queue[str]" = asyncio.Queue()
_active_batch_ids: set = set()


async def _main_worker_loop() -> None:
    """Main loop: recover stale jobs, resume active batches, then process new ones."""
    from app.db.database import get_active_batches
    logger.info("[BatchWorker] Started")

    await _mark_stale_scanning_jobs_failed()

    try:
        active = await get_active_batches()
        for b in active:
            bid = b["batch_id"]
            if bid not in _active_batch_ids:
                logger.info("[BatchWorker] Resuming batch from previous session: %s", bid[:8])
                await _pending_batches.put(bid)
    except Exception as exc:
        logger.warning("[BatchWorker] Could not load active batches on startup: %s", exc)

    while True:
        try:
            _wake_event.clear()
            try:
                batch_id = await asyncio.wait_for(_pending_batches.get(), timeout=_POLL_INTERVAL)
            except asyncio.TimeoutError:
                try:
                    active = await get_active_batches()
                    for b in active:
                        if b["batch_id"] not in _active_batch_ids:
                            await _pending_batches.put(b["batch_id"])
                except Exception as exc:
                    logger.warning("[BatchWorker] Periodic scan error: %s", exc)
                continue

            if batch_id in _active_batch_ids:
                _pending_batches.task_done()
                continue

            _active_batch_ids.add(batch_id)
            logger.info("[BatchWorker] Starting processing for batch %s", batch_id[:8])

            async def _run_batch(bid: str) -> None:
                try:
                    await _process_batch(bid)
                except asyncio.CancelledError:
                    logger.info("[BatchWorker] Batch %s processing cancelled (shutdown)", bid[:8])
                    raise
                except Exception as exc:
                    logger.exception("[BatchWorker] Batch %s processing error: %s", bid[:8], exc)
                finally:
                    _active_batch_ids.discard(bid)

            asyncio.create_task(_run_batch(batch_id), name=f"batch-{batch_id[:8]}")
            _pending_batches.task_done()

        except asyncio.CancelledError:
            logger.info("[BatchWorker] Main loop cancelled (shutdown)")
            break
        except Exception as exc:
            logger.exception("[BatchWorker] Unexpected main loop error: %s", exc)
            await asyncio.sleep(1)


# ---- Startup / Shutdown -----

_worker_task: Optional[asyncio.Task] = None


async def start_batch_worker() -> None:
    """Launch the batch worker background task at app startup."""
    global _worker_task, _pending_batches, _active_batch_ids
    _pending_batches = asyncio.Queue()
    _active_batch_ids = set()
    _worker_task = asyncio.create_task(_main_worker_loop(), name="batch-worker")
    logger.info("[BatchWorker] Batch worker task started")


async def stop_batch_worker() -> None:
    """Cancel the batch worker on app shutdown."""
    global _worker_task
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
    logger.info("[BatchWorker] Batch worker stopped")


async def enqueue_batch(batch_id: str) -> None:
    """Signal the batch worker to begin (or resume) processing a batch."""
    await _pending_batches.put(batch_id)
    wake_batch_worker()
    logger.info("[BatchWorker] Batch %s enqueued for processing", batch_id[:8])
