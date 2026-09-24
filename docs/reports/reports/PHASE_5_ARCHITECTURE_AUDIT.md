# Phase 5A Architecture Audit

## 1. Goal
Identify all instances of volatile in-memory state used for job tracking, queueing, and deduplication that block production scalability.

## 2. Analyzed Components

### 2.1 `app/workers/analysis_queue.py`
- **Volatile Queue**: Uses `asyncio.Queue` (`_queue`) to dispatch jobs. If the Uvicorn process restarts, all queued items disappear.
- **Volatile State**: Uses an `OrderedDict` (`_jobs`) to store real-time job status, pipeline stages, progress percentages, and final results. DB fallback only retrieves static fields.
- **No Deduplication**: `enqueue()` blindly accepts duplicate hashes.
- **Lifecycle**: `queued -> processing -> done | failed | cancelled`.

### 2.2 `app/routes/upload.py`
- **`analyze_upload_async`**: Generates a random `uuid4()` for every request. It immediately persists the job stub via `persist_job(job_id)`, but drops the actual execution payload into the `asyncio.Queue`.
- **`job_status`**: Reads progress and real-time state from `_jobs` in memory. Does not pull pipeline progress from the database.

### 2.3 `app/models/jobs.py`
- Defines `JobState` enum. This enum represents a good foundational state machine but is not consistently applied across all jobs.

### 2.4 `app/db/database.py`
- **`analysis_jobs` Table**: Tracks user-facing job status, but lacks real-time progress fields (e.g., `pipeline_stage`, `progress_pct`, `current_stage`).
- **Missing Link**: No concept of a canonical "execution" record separate from the user's "request" record.

### 2.5 Batch Processing (`app/workers/batch_worker.py`)
- Actually relies on the database (`analysis_batch_jobs`) as the source of truth!
- However, it delegates actual execution by calling `analysis_queue.enqueue()`, meaning it is still vulnerable to the underlying volatile queue dropping the workload.

## 3. Conclusions
1. The `asyncio.Queue` must be bypassed for durability.
2. We must split jobs into **User Requests** (`analysis_jobs`) and **Canonical Executions** (`canonical_analyses`).
3. We need safe atomic database claiming to prevent duplicate execution across multiple uvicorn workers.
