"""
Retention sweeper.
==================

Deletes operational state that has aged out. Nothing else.

What is never deleted, and why
------------------------------
    audit_events    the record of who did what. It is evidence in a fraud
                    investigation, and a trail with a rolling window has a hole
                    exactly where an incident review needs to look. Growth is
                    slow (one row per action) and the table is indexed.
    cases           the analysis record
    case_notes      analyst commentary
    case_iocs       indicator relationships - the campaign-linking data
    analysis_runs   trending history; the whole point is the long baseline
    chat_messages   investigation conversations, attributable to an analyst
    export_events   what left the system, and who took it

What is deleted
---------------
    sessions        7 days past expiry. An expired session authorises nothing,
                    and the *fact* of the login is in login_attempts.
    login_attempts  90 days. Long enough for a quarterly review.
    ioc_cache       7 days past expiry. It is a cache.
    analysis_jobs   30 days after completion. These carry a full result_json
                    blob and are the single largest source of growth; the case
                    row is the permanent copy.
    runtime_events  30 days. The index only - the per-session evidence store on
                    disk is untouched, so an old case is still readable from its
                    artifact directory.

Both the interval and each window are configurable, and the sweeper can be
turned off entirely with RETENTION_ENABLED=false.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_task: asyncio.Task | None = None


def _enabled() -> bool:
    return os.getenv("RETENTION_ENABLED", "true").lower() not in ("0", "false", "no")


def _hours() -> float:
    return float(os.getenv("RETENTION_INTERVAL_HOURS", "24"))


def _days(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


async def _purge_expired_ioc_cache(retain_days: int) -> int:
    """
    Drop cache entries that expired more than `retain_days` ago.

    `get_cached_ioc` already filters on `expires_at > now`, so stale rows were
    invisible but never removed - idx_ioc_expires existed for a sweep nobody
    had written.
    """
    from app.db.database import connect

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).isoformat()
    async with connect() as db:
        cur = await db.execute("DELETE FROM ioc_cache WHERE expires_at < ?", (cutoff,))
        await db.commit()
        return cur.rowcount


async def _purge_old_jobs(retain_days: int) -> int:
    """
    Drop completed analysis_jobs rows.

    Each holds `result_json` - a full AnalysisResponse including the logcat
    string - so this table dominates database growth. The case row in `cases`
    is the permanent record; this one exists to answer a poll.
    """
    from app.db.database import connect

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).isoformat()
    async with connect() as db:
        cur = await db.execute(
            "DELETE FROM analysis_jobs "
            "WHERE completed_at IS NOT NULL AND completed_at < ? "
            "AND status IN ('done', 'failed', 'cancelled')",
            (cutoff,),
        )
        await db.commit()
        return cur.rowcount


async def run_retention_once() -> dict:
    """One sweep. Returns rows removed per table."""
    from app.db.intel import purge_old_runtime_events
    from app.db.security import purge_expired_sessions, purge_old_login_attempts

    removed = {
        "sessions": await purge_expired_sessions(
            grace_days=_days("RETENTION_SESSION_DAYS", 7)
        ),
        "login_attempts": await purge_old_login_attempts(
            retain_days=_days("RETENTION_LOGIN_ATTEMPT_DAYS", 90)
        ),
        "ioc_cache": await _purge_expired_ioc_cache(
            retain_days=_days("RETENTION_IOC_CACHE_DAYS", 7)
        ),
        "analysis_jobs": await _purge_old_jobs(
            retain_days=_days("RETENTION_JOB_DAYS", 30)
        ),
        "runtime_events": await purge_old_runtime_events(
            retain_days=_days("RETENTION_RUNTIME_EVENT_DAYS", 30)
        ),
    }
    total = sum(removed.values())
    if total:
        logger.info(
            "[Retention] removed %d row(s): %s",
            total,
            ", ".join(f"{k}={v}" for k, v in removed.items() if v),
        )
    return removed


async def _loop() -> None:
    interval = _hours() * 3600
    while True:
        try:
            # Sleep first: startup is the worst moment to add database work, and
            # a container that restarts often would otherwise sweep on every boot.
            await asyncio.sleep(interval)
            await run_retention_once()
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("[Retention] sweep failed: %s", exc)


async def start_retention_worker() -> None:
    global _task
    if not _enabled():
        logger.info("[Retention] disabled (RETENTION_ENABLED=false)")
        return
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())
        logger.info("[Retention] sweeper started (every %.0fh)", _hours())


async def stop_retention_worker() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None
