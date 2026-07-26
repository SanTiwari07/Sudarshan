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
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ANALYSIS_WORKERS = int(os.getenv("ANALYSIS_WORKERS", "2"))

# ─── In-Memory Job Store ──────────────────────────────────────────────────────

_jobs: Dict[str, Dict[str, Any]] = {}
_queue: asyncio.Queue = asyncio.Queue()


def create_job() -> str:
    """Allocate a new job ID and register it as queued."""
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
    }
    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _jobs.get(job_id)


def _set_processing(job_id: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "processing"
        _jobs[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()


def _set_done(job_id: str, result: Dict[str, Any]) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "done"
        _jobs[job_id]["result"] = result
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


def _set_failed(job_id: str, error: str) -> None:
    if job_id in _jobs:
        _jobs[job_id]["status"] = "failed"
        _jobs[job_id]["error"] = error
        _jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()


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

    from app.ai.ollama_client import analyze_with_llm
    from sudarshan_core.analyzers.apk_analyzer import analyze_apk
    from sudarshan_core.engines.classification_engine import classify_family
    from sudarshan_core.engines.risk_engine import calculate_risk_score, build_threat_scenario_table
    from sudarshan_core.engines.frida_sandbox import run_frida_analysis, get_sandbox_status
    from sudarshan_core.models.schemas import StaticAnalysisFlags
    from sudarshan_core.services.threat_correlator import correlate
    from sudarshan_core.services.mobsf_client import MobSFClient, MobSFAnalysisError, MobSFNotAvailable
    from app.db.database import save_case

    mobsf = MobSFClient()
    logger.info(f"[Queue] Worker {worker_id} started")

    while True:
        try:
            item = await _queue.get()
            job_id     = item["job_id"]
            temp_path  = item["temp_path"]
            filename   = item["filename"]
            sha256_hash = item["sha256_hash"]
            analyst_id = item.get("analyst_id")

            _set_processing(job_id)
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

                _set_done(job_id, result)
                logger.info(f"[Queue] Worker {worker_id} completed job {job_id} score={result.get('final_risk_score')}")

            except Exception as e:
                logger.exception(f"[Queue] Worker {worker_id} failed job {job_id}: {e}")
                _set_failed(job_id, str(e))
            finally:
                try:
                    _os.remove(temp_path)
                except Exception:
                    pass

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
