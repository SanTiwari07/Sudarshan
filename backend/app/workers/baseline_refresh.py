"""
Periodic VIDE baseline corpus refresh.

Half of the hybrid update model described in the VIDE design: this background
task re-ingests the baseline corpus on an interval so a corpus updated on disk is
picked up without a restart. The other half is the admin-triggered
``POST /api/v1/baselines/refresh`` for immediate invalidation.

Interval is ``VIDE_BASELINE_REFRESH_SECONDS`` (default 1h). Set it to 0 to
disable the worker entirely.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from sudarshan_core.engines.vide.baseline_store import refresh_baselines

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL_SECONDS = 3600
_task: Optional[asyncio.Task] = None


def _interval() -> int:
    raw = os.getenv("VIDE_BASELINE_REFRESH_SECONDS", str(_DEFAULT_INTERVAL_SECONDS))
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning(
            "[Baselines] invalid VIDE_BASELINE_REFRESH_SECONDS=%r; using %ds",
            raw,
            _DEFAULT_INTERVAL_SECONDS,
        )
        return _DEFAULT_INTERVAL_SECONDS


async def _loop(interval: int) -> None:
    while True:
        try:
            await asyncio.sleep(interval)
            report = await asyncio.to_thread(refresh_baselines)
            logger.info(
                "[Baselines] scheduled refresh: %d baselines (%d corpus, gen %s)",
                report["total"],
                report["corpus_baselines"],
                report["generation"],
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # A transient disk/parse failure must not kill the worker; the
            # cache keeps serving the last good corpus until the next tick.
            logger.exception("[Baselines] scheduled refresh failed; keeping cached set")


async def start_baseline_refresh() -> None:
    """Warm the cache once, then schedule periodic re-ingestion."""
    global _task

    try:
        report = await asyncio.to_thread(refresh_baselines)
        logger.info(
            "[Baselines] corpus loaded: %d baselines (%d corpus, %d lab)",
            report["total"],
            report["corpus_baselines"],
            report["lab_baselines"],
        )
    except Exception:
        logger.exception("[Baselines] initial corpus load failed; VIDE will run degraded")

    interval = _interval()
    if interval <= 0:
        logger.info("[Baselines] periodic refresh disabled (interval=0)")
        return
    _task = asyncio.create_task(_loop(interval), name="vide-baseline-refresh")
    logger.info("[Baselines] periodic refresh every %ds", interval)


async def stop_baseline_refresh() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    await asyncio.gather(_task, return_exceptions=True)
    _task = None
