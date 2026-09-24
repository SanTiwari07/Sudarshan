"""
Resolve per-sample forensic artifact directories for API routes.

Cases store ``dynamic_result.artifact_dir`` when analysis completes. After
container restarts or path moves, the stored string may not exist on disk.
This module normalises Docker/host paths and discovers directories by SHA-256
when the hint is missing or stale.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
_SCAN_CACHE: Dict[str, Any] = {"at": 0.0, "dirs": []}
_SCAN_TTL_SEC = 30.0


def _candidate_paths_from_hint(raw_dir: str) -> List[Path]:
    raw_str = str(raw_dir).replace("\\", "/")
    candidates: list[Path] = []

    try:
        candidates.append(Path(raw_dir).resolve())
    except (OSError, RuntimeError):
        pass

    if raw_str.startswith("/app/uploads/"):
        suffix = raw_str[len("/app/uploads/") :]
        candidates.append((_UPLOADS_DIR / suffix).resolve())
    elif raw_str.startswith("/app/uploads"):
        candidates.append(_UPLOADS_DIR.resolve())

    folder_name = Path(raw_str).name
    if folder_name:
        candidates.append((_UPLOADS_DIR / "sudarshan_artifacts" / folder_name).resolve())
        candidates.append((_UPLOADS_DIR / folder_name).resolve())

    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _scan_artifact_directories() -> List[Path]:
    now = time.time()
    if now - float(_SCAN_CACHE["at"]) < _SCAN_TTL_SEC:
        return list(_SCAN_CACHE["dirs"])

    found: List[tuple[float, Path]] = []
    roots = [
        _UPLOADS_DIR,
        Path.cwd(),
        Path(__file__).resolve().parents[2],
    ]
    for root in roots:
        artifacts_root = root / "sudarshan_artifacts"
        if not artifacts_root.is_dir():
            continue
        try:
            for child in artifacts_root.iterdir():
                if not child.is_dir():
                    continue
                if (child / "evidence.json").is_file() or (child / "screenshots").is_dir():
                    try:
                        found.append((child.stat().st_mtime, child.resolve()))
                    except OSError:
                        continue
        except OSError as exc:
            logger.debug("[ArtifactResolve] scan skip %s: %s", artifacts_root, exc)

    dirs = [p for _, p in sorted(found, key=lambda t: t[0], reverse=True)]
    _SCAN_CACHE["at"] = now
    _SCAN_CACHE["dirs"] = dirs
    return dirs


def discover_artifact_dir_by_sha256(sha256: str) -> Optional[Path]:
    if not sha256 or len(sha256) < 12:
        return None
    needle = sha256.lower()
    for art in _scan_artifact_directories():
        if needle in str(art).lower():
            return art
    return None


def resolve_case_artifact_dir(sha256: str, stored_artifact_dir: Optional[str] = None) -> Optional[Path]:
    """
    Resolve per-sample forensic artifact directories robustly across Docker/host boundaries.
    """
    if not sha256 or len(sha256) < 12:
        return None

    candidates = []
    if stored_artifact_dir:
        candidates.extend(_candidate_paths_from_hint(stored_artifact_dir))

    for candidate in candidates:
        try:
            if candidate.is_dir():
                logger.info(f"[ArtifactResolve] Resolved via hint or prefix mapping: {candidate}")
                return candidate
        except (OSError, RuntimeError):
            continue

    discovered = discover_artifact_dir_by_sha256(sha256)
    if discovered is not None:
        logger.info(f"[ArtifactResolve] Resolved via SHA256 search: {discovered}")
        return discovered

    logger.warning(f"[ArtifactResolve] Could not resolve artifact directory for {sha256[:12]}")
    return None


def resolve_artifact_dir(
    report: Optional[Dict[str, Any]] = None,
    *,
    sha256: Optional[str] = None,
) -> Optional[Path]:
    """Legacy wrapper for backward compatibility."""
    report = report or {}
    dyn = report.get("dynamic_result") or report.get("dynamic_analysis") or {}
    if not isinstance(dyn, dict):
        dyn = {}

    raw_dir = dyn.get("artifact_dir") or report.get("artifact_dir") or report.get("_artifact_dir")
    case_sha = sha256 or str(report.get("sha256") or "")
    
    return resolve_case_artifact_dir(case_sha, str(raw_dir) if raw_dir else None)
