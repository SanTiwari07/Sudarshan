import asyncio
import logging
import os
import time
import uuid
import sudarshan_core
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

from app.db.database import (
    get_canonical_analysis,
    upsert_canonical_analysis,
    update_canonical_analysis,
    get_analysis_jobs_by_canonical,
    claim_next_canonical_job,
    heartbeat_canonical_job,
    upsert_analysis_job,
    load_analysis_job
)

logger = logging.getLogger(__name__)

ANALYSIS_WORKERS = int(os.getenv("STATIC_MAX_CONCURRENCY", os.getenv("ANALYSIS_WORKERS", "5")))
LEASE_SECONDS = int(os.getenv("JOB_LEASE_SECONDS", "900"))  # 15 minutes
HEARTBEAT_SECONDS = int(os.getenv("JOB_HEARTBEAT_SECONDS", "60"))

_wake_event: asyncio.Event = asyncio.Event()

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_analysis_fingerprint(sha256_hash: str) -> str:
    from sudarshan_core.sandbox.config import load_sandbox_config
    config = load_sandbox_config()
    mode = os.getenv("SUDARSHAN_ANALYSIS_MODE", "mobsf").lower()
    return f"{sha256_hash}-v{sudarshan_core.__version__}-{mode}-f{config.frida_version}"

# ─── Public API (Compatible with old analysis_queue) ─────────────────────────

def create_job(sha256_hash: Optional[str] = None, analyst_id: Optional[int] = None) -> str:
    """Create a new job ID. It's a stub to keep upload.py/batch_worker.py happy."""
    job_id = str(uuid.uuid4())
    return job_id

async def persist_job(job_id: str) -> None:
    """Stub. All persistence is now driven directly by enqueue or the worker."""
    pass

async def enqueue(job_id: str, object_key: str, filename: str, sha256_hash: str, analyst_id: Optional[int] = None) -> None:
    fingerprint = get_analysis_fingerprint(sha256_hash)
    
    # 1. Create the user's specific request ticket
    job_record = {
        "job_id": job_id,
        "status": "queued",
        "sha256": sha256_hash,
        "analyst_id": analyst_id,
        "queued_at": _now_iso(),
        "canonical_fingerprint": fingerprint
    }
    await upsert_analysis_job(job_record)
    
    # 2. Check if a canonical execution already exists
    canonical = await get_canonical_analysis(fingerprint)
    
    if canonical:
        # Case 1 & 2: Reuse COMPLETED or attach to RUNNING
        if canonical["status"] in ("COMPLETED", "PROCESSING", "QUEUED"):
            logger.info(f"[Queue] Deduplicating job {job_id} to existing canonical {fingerprint} ({canonical['status']})")
            return
            
        # Case 3: Failed but retryable. Let's retry it.
        if canonical["status"] in ("FAILED", "CANCELLED"):
            if canonical["attempt_count"] < canonical["max_attempts"]:
                logger.info(f"[Queue] Retrying failed canonical {fingerprint} for new job {job_id}")
                await update_canonical_analysis(fingerprint, {
                    "status": "QUEUED",
                    "error": None
                })
            else:
                logger.info(f"[Queue] Max retries exhausted for canonical {fingerprint}. Creating new analysis.")
                # We overwrite the old fingerprint, resetting attempt count
                canonical = None
                
    if not canonical:
        # Case 4: Brand new analysis (or exhausted retry)
        await upsert_canonical_analysis({
            "fingerprint": fingerprint,
            "sha256": sha256_hash,
            "status": "QUEUED",
            "max_attempts": 3,
        })
        _pending_objects[fingerprint] = (object_key, filename)

    _wake_event.set()

async def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    job = await load_analysis_job(job_id)
    if not job:
        return None
        
    fingerprint = job.get("canonical_fingerprint")
    if fingerprint:
        canonical = await get_canonical_analysis(fingerprint)
        if canonical:
            job["status"] = canonical.get("status", job.get("status"))
            if job["status"] == "PROCESSING":
                job["status"] = "processing"
            elif job["status"] == "COMPLETED":
                job["status"] = "done"
            elif job["status"] == "FAILED":
                job["status"] = "failed"
            elif job["status"] == "CANCELLED":
                job["status"] = "cancelled"
            elif job["status"] == "QUEUED":
                job["status"] = "queued"
                
            job["progress_pct"] = canonical.get("progress_pct", 0)
            job["pipeline_stage"] = canonical.get("current_stage", "")
            job["result"] = canonical.get("result")
            job["error"] = canonical.get("error")
            
            # Merge active telemetry if it's currently processing on THIS node
            live_telemetry = _active_telemetry.get(fingerprint)
            if live_telemetry:
                job.update(live_telemetry)
                
    return job

async def cancel_job(job_id: str) -> bool:
    job = await load_analysis_job(job_id)
    if not job:
        return False
        
    fingerprint = job.get("canonical_fingerprint")
    if not fingerprint:
        return False
        
    await update_canonical_analysis(fingerprint, {"status": "CANCELLED"})
    
    # Try to cancel active task locally
    task = _active_tasks.get(fingerprint)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=1.0)
        except Exception:
            pass
            
    return True

def update_job_pipeline(fingerprint: str, snapshot: Dict[str, Any]) -> None:
    # fingerprint is passed via job_id parameter from upload.py
    _active_telemetry[fingerprint] = snapshot
    
    # We shouldn't do async DB calls directly in a sync callback, 
    # but we can schedule it. However, the telemetry is fine in memory 
    # and will be retrieved by get_job(). If we crash, we lose the exact pct, 
    # which is fine, it will restart anyway.
    
    # Let's fire and forget a DB update just to keep the DB partially fresh
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(update_canonical_analysis(fingerprint, {
            "progress_pct": snapshot.get("progress_pct", 0),
            "current_stage": snapshot.get("pipeline_stage", "")
        }))
    except RuntimeError:
        pass

# We will provide an async version of update_job_pipeline for the worker to use locally
async def update_pipeline_telemetry(fingerprint: str, snapshot: Dict[str, Any]) -> None:
    _active_telemetry[fingerprint] = snapshot
    # Periodically flush progress to database
    await update_canonical_analysis(fingerprint, {
        "progress_pct": snapshot.get("progress_pct", 0),
        "current_stage": snapshot.get("pipeline_stage", "")
    })

# ─── Worker Internals ────────────────────────────────────────────────────────

_pending_objects: Dict[str, tuple] = {}
_active_tasks: Dict[str, asyncio.Task] = {}
_active_telemetry: Dict[str, Dict[str, Any]] = {}

async def _heartbeat_task(fingerprint: str):
    consecutive_failures = 0
    max_failures = (LEASE_SECONDS // HEARTBEAT_SECONDS) - 1
    if max_failures < 1:
        max_failures = 1
        
    while True:
        try:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            await heartbeat_canonical_job(fingerprint, LEASE_SECONDS)
            consecutive_failures = 0
        except asyncio.CancelledError:
            break
        except Exception as e:
            consecutive_failures += 1
            logger.warning(f"[DurableQueue] Heartbeat failed for {fingerprint} ({consecutive_failures}/{max_failures}): {e}")
            if consecutive_failures >= max_failures:
                logger.error(f"[DurableQueue] Heartbeat failed too many times for {fingerprint}. Cancelling local execution to prevent split-brain.")
                task = _active_tasks.get(fingerprint)
                if task and not task.done():
                    task.cancel()
                break

async def _worker(worker_id: str):
    logger.info(f"[DurableQueue] Worker {worker_id} started")
    
    while True:
        try:
            # 1. Atomic DB claim
            canonical = await claim_next_canonical_job(worker_id, LEASE_SECONDS)
            
            if not canonical:
                # Sleep until woken up by enqueue() or a periodic interval (to check for expired leases)
                try:
                    await asyncio.wait_for(_wake_event.wait(), timeout=30.0)
                except asyncio.TimeoutError:
                    pass
                _wake_event.clear()
                continue
                
            fingerprint = canonical["fingerprint"]
            sha256 = canonical["sha256"]
            
            logger.info(f"[DurableQueue] Worker {worker_id} claimed analysis {fingerprint}")
            
            # Find the file payload.
            file_info = _pending_objects.get(fingerprint)
            if not file_info:
                from app.db.artifact_metadata import get_artifact
                art = await get_artifact(f"apk_{sha256}")
                if art:
                    file_info = (art["object_key"], f"{sha256}.apk")
                else:
                    logger.error(f"[DurableQueue] Payload for {fingerprint} missing from artifact storage. Failing.")
                    await update_canonical_analysis(fingerprint, {
                        "status": "FAILED",
                        "error": "Payload missing from distributed storage."
                    })
                    continue
                
            object_key, filename = file_info
            
            import tempfile
            import os
            from sudarshan_core.storage.artifact_storage import get_storage
            
            storage = get_storage()
            fd, temp_path = tempfile.mkstemp(suffix=".apk", prefix="sudarshan_worker_")
            os.close(fd)
            
            try:
                await storage.get_file(object_key, temp_path)
            except Exception as e:
                logger.exception(f"[DurableQueue] Failed to download {object_key}")
                await update_canonical_analysis(fingerprint, {
                    "status": "FAILED",
                    "error": f"Failed to download payload from artifact storage: {e}"
                })
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
                continue
            
            # Find an associated job for the analyst ID.
            # For deduplicated runs, we just use the analyst_id of the first queued job.
            jobs = await get_analysis_jobs_by_canonical(fingerprint)
            analyst_id = jobs[0].get("analyst_id") if jobs else None
            # We pick the first job_id just for logging and backwards compat with pipeline 
            job_id = jobs[0].get("job_id") if jobs else fingerprint
            
            # Start heartbeat
            heartbeat = asyncio.create_task(_heartbeat_task(fingerprint))
            
            from app.routes.upload import _run_analysis_pipeline, _build_response
            pipeline_coro = _run_analysis_pipeline(
                temp_path=temp_path,
                sha256_hash=sha256,
                analyst_id=analyst_id,
                job_id=fingerprint, # Pass fingerprint so telemetry maps correctly
            )
            pipeline_task = asyncio.create_task(pipeline_coro, name=f"pipeline-{fingerprint[:8]}")
            _active_tasks[fingerprint] = pipeline_task
            
            try:
                raw_result = await pipeline_task
                full_response = _build_response(raw_result, job_id=job_id)
                result = full_response.model_dump() if hasattr(full_response, "model_dump") else full_response.dict()
                
                await update_canonical_analysis(fingerprint, {
                    "status": "COMPLETED",
                    "result": result,
                    "progress_pct": 100,
                    "current_stage": "COMPLETED"
                })
                logger.info(f"[DurableQueue] Worker {worker_id} completed {fingerprint}")
                
            except asyncio.CancelledError:
                logger.info(f"[DurableQueue] Worker {worker_id} pipeline cancelled for {fingerprint}")
                await update_canonical_analysis(fingerprint, {
                    "status": "CANCELLED"
                })
            except Exception as e:
                logger.exception(f"[DurableQueue] Worker {worker_id} failed {fingerprint}: {e}")
                await update_canonical_analysis(fingerprint, {
                    "status": "FAILED",
                    "error": str(e)
                })
            finally:
                heartbeat.cancel()
                _active_tasks.pop(fingerprint, None)
                _active_telemetry.pop(fingerprint, None)
                _pending_objects.pop(fingerprint, None)
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
                    
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.exception(f"[DurableQueue] Worker {worker_id} crashed: {e}")
            await asyncio.sleep(5)

# ─── Startup / Shutdown ───────────────────────────────────────────────────────

_worker_tasks: list = []

async def start_workers() -> None:
    global _worker_tasks
    # Reset any stale Processing to Queued immediately on startup for this node
    # Since we can't tell if we are the only node, actually we rely on lease expiry!
    # But wait, lease expiry works well.
    _worker_tasks = [
        asyncio.create_task(_worker(f"worker-{uuid.uuid4().hex[:6]}"), name=f"analysis-worker-{i + 1}")
        for i in range(ANALYSIS_WORKERS)
    ]
    logger.info(f"[DurableQueue] {ANALYSIS_WORKERS} durable workers started")

async def stop_workers() -> None:
    for task in _worker_tasks:
        task.cancel()
    await asyncio.gather(*_worker_tasks, return_exceptions=True)
    logger.info("[DurableQueue] Durable workers stopped")
