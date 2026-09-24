"""
Proxy to the new Phase 5 Durable Queue implementation.
This replaces the old volatile asyncio.Queue with a PostgreSQL-backed deduplicating atomic queue.
"""

from app.workers.durable_queue import (
    create_job,
    enqueue,
    get_job,
    persist_job,
    cancel_job,
    update_job_pipeline,
    start_workers,
    stop_workers
)
