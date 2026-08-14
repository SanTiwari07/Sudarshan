"""
VIDE baseline corpus API.

The Visual Impersonation Detection Engine compares suspect app UIs against a
corpus of legitimate banking baselines (``banking-baseline-corpus/``). Those baselines are
cached in-memory so Tier 1/2 static analysis can look them up per-sample
without re-reading ~40 files each time.

Endpoints:
    GET  /api/v1/baselines            list the loaded corpus (analyst+)
    GET  /api/v1/baselines/{id}       one baseline's design schema + screens
    POST /api/v1/baselines/refresh    invalidate + reload the cache (admin)

Refresh is admin-only: it is the control that decides which institutions the
platform will claim are being impersonated.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.auth.auth import require_admin, require_analyst

from sudarshan_core.engines.vide.baseline_store import (
    cache_status,
    get_baselines,
    refresh_baselines,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/baselines")


@router.get("")
async def list_baselines(user: dict = Depends(require_analyst)) -> Dict[str, Any]:
    """Loaded baseline corpus, as served to the analysis engine."""
    baselines = get_baselines()
    return {
        "cache": cache_status(),
        "count": len(baselines),
        "baselines": [b.summary() for b in baselines],
    }


@router.get("/{institution_id}")
async def get_baseline(
    institution_id: str,
    user: dict = Depends(require_analyst),
) -> Dict[str, Any]:
    """Full design schema for one institution - backs the Visual Diff Viewer."""
    for baseline in get_baselines():
        if baseline.institution_id != institution_id:
            continue
        return {
            **baseline.summary(),
            "design": baseline.design.to_dict() if baseline.design else None,
            "screens": [s.to_dict() for s in baseline.screens],
            "navigation": baseline.navigation,
            "profile": baseline.profile.to_dict(),
        }
    raise HTTPException(status_code=404, detail=f"Unknown baseline '{institution_id}'")


@router.post("/refresh")
async def refresh(user: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Invalidate the in-memory cache and re-ingest the corpus from disk."""
    try:
        report = refresh_baselines()
    except Exception as exc:
        logger.exception("[Baselines] refresh failed")
        raise HTTPException(status_code=500, detail=f"Baseline refresh failed: {exc}")
    logger.info(
        "[Baselines] refreshed by %s: %d baselines (gen %s)",
        user.get("username", "?"),
        report["total"],
        report["generation"],
    )
    return report
