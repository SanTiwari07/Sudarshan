"""
Sudarshan Async Analysis Job Queue
====================================
Provides non-blocking APK analysis via an asyncio Queue.

Flow:
  POST /api/v1/analyze/async  → enqueue → return {job_id, status: "queued"}
  GET  /api/v1/status/{job_id}  → poll for result

Workers are started as background asyncio tasks when the FastAPI app starts.
Number of workers is configurable via ANALYSIS_WORKERS env var (default: 2).

Job lifecycle:
  queued → processing → done | failed

Results are held in memory _jobs dict AND persisted to SQLite via save_case().
"""

import asyncio
import logging
import os
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ANALYSIS_WORKERS = int(os.getenv("ANALYSIS_WORKERS", "2"))

# ─── In-Memory Job Store ──────────────────────────────────────────────────────
#
# BOUNDED by TTL and count. This previously grew for the whole process lifetime,
# and each finished entry holds a full AnalysisResponse.model_dump() — which
# embeds dynamic_analysis.logcat (an unbounded string), the attack timeline and
# every API call. A few hundred analyses was a multi-hundred-megabyte resident
# set that nothing ever released.
#
# The analysis-engine already solved exactly this (_evict_finished_jobs, with a
# comment saying "It also used to grow without bound"); the fix was never
# brought back to the gateway. This is that fix.
_jobs: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_queue: asyncio.Queue = asyncio.Queue()

JOB_RETENTION_SECONDS = int(os.getenv("JOB_RETENTION_SECONDS", "3600"))
MAX_RETAINED_JOBS = int(os.getenv("MAX_RETAINED_JOBS", "200"))


def _evict_finished_jobs() -> None:
    """Drop finished jobs past their TTL, then cap total retained jobs."""
    now = time.monotonic()
    for jid in [
        jid for jid, j in _jobs.items()
        if j.get("_finished_at") and now - j["_finished_at"] > JOB_RETENTION_SECONDS
    ]:
        _jobs.pop(jid, None)

    # Over the cap: drop finished jobs oldest-first. An in-flight job is never
    # evicted — losing its result would be worse than the memory it holds.
    if len(_jobs) > MAX_RETAINED_JOBS:
        finished = [jid for jid, j in _jobs.items() if j.get("_finished_at")]
        for jid in finished[: len(_jobs) - MAX_RETAINED_JOBS]:
            _jobs.pop(jid, None)


def create_job(sha256_hash: Optional[str] = None, analyst_id: Optional[int] = None) -> str:
    """Allocate a new job ID and register it as queued (memory; DB write is async)."""
    _evict_finished_jobs()
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "sha256": sha256_hash,
        "analyst_id": analyst_id,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
    }
    return job_id


async def persist_job(job_id: str) -> None:
    """Write the current in-memory job snapshot to SQLite."""
    job = _jobs.get(job_id)
    if not job:
        return
    from app.db.database import upsert_analysis_job
    await upsert_analysis_job(job)


async def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    job = _jobs.get(job_id)
    if job:
        return job
    from app.db.database import load_analysis_job
    row = await load_analysis_job(job_id)
    if row:
        _jobs[job_id] = row
        return row
    return None


async def _set_processing(job_id: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "processing"
        _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
        await persist_job(job_id)


async def _set_done(job_id: str, result: Dict[str, Any]) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _jobs[job_id]["_finished_at"] = time.monotonic()
        await persist_job(job_id)


async def _set_failed(job_id: str, error: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["error"] = error
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        _jobs[job_id]["_finished_at"] = time.monotonic()
        await persist_job(job_id)


# ─── Queue Interface ──────────────────────────────────────────────────────────

async def enqueue(job_id: str, temp_path: str, filename: str, sha256_hash: str, analyst_id: Optional[int] = None) -> None:
    """Push a job onto the queue."""
    await _queue.put({
        "job_id": job_id,
        "temp_path": temp_path,
        "filename": filename,
        "sha256_hash": sha256_hash,
        "analyst_id": analyst_id,
    })
    logger.info(f"[Queue] Job enqueued: {job_id} file={filename}")


# ─── Worker ───────────────────────────────────────────────────────────────────

async def _worker(worker_id: int) -> None:
    """
    Pull jobs from the queue and run the full analysis pipeline.
    Mirrors the logic in upload.py but driven by the queue.
    """
    # Lazy imports to avoid circular dependency at module load
    import hashlib
    import tempfile
    import os as _os

    # The pipeline lives in routes/upload.py and is imported lazily below, at
    # the call site. Every analysis import that used to be here was dead — the
    # worker delegates entirely — and MobSFClient() was constructed once per
    # worker and never referenced.
    logger.info(f"[Queue] Worker {worker_id} started")

    while True:
        try:
            item = await _queue.get()
            job_id     = item["job_id"]
            temp_path  = item["temp_path"]
            filename   = item["filename"]
            sha256_hash = item["sha256_hash"]
            analyst_id = item.get("analyst_id")

            await _set_processing(job_id)
            logger.info(f"[Queue] Worker {worker_id} processing job {job_id}")

            try:
                # ── Delegate to Shared Pipeline ───────────────────────────────
                from app.routes.upload import _run_analysis_pipeline, _build_response
                raw_result = await _run_analysis_pipeline(
                    temp_path=temp_path,
                    sha256_hash=sha256_hash,
                    analyst_id=analyst_id,
                )
                
                # Build the complete Pydantic response and convert to dict for the queue
                full_response = _build_response(raw_result, job_id=job_id)
                result = full_response.model_dump() if hasattr(full_response, "model_dump") else full_response.dict()

                await _set_done(job_id, result)
                logger.info(f"[Queue] Worker {worker_id} completed job {job_id} score={result.get('final_risk_score')}")

            except Exception as e:
                logger.exception(f"[Queue] Worker {worker_id} failed job {job_id}: {e}")
                await _set_failed(job_id, str(e))
            finally:
                try:
                    _os.remove(temp_path)
                except OSError as rm_err:
                    logger.warning("[Queue] Could not remove temp APK %s: %s", temp_path, rm_err)

            _queue.task_done()

        except asyncio.CancelledError:
            logger.info(f"[Queue] Worker {worker_id} shutting down")
            break
        except Exception as e:
            logger.exception(f"[Queue] Worker {worker_id} unexpected error: {e}")
            await asyncio.sleep(1)


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

_worker_tasks: list = []


async def start_workers() -> None:
    """Launch ANALYSIS_WORKERS background worker coroutines."""
    global _worker_tasks
    _worker_tasks = [
        asyncio.create_task(_worker(i + 1), name=f"analysis-worker-{i + 1}")
        for i in range(ANALYSIS_WORKERS)
    ]
    logger.info(f"[Queue] {ANALYSIS_WORKERS} analysis worker(s) started")


async def stop_workers() -> None:
    """Cancel all running worker tasks on app shutdown."""
    for task in _worker_tasks:
        task.cancel()
    await asyncio.gather(*_worker_tasks, return_exceptions=True)
    logger.info("[Queue] Analysis workers stopped")
