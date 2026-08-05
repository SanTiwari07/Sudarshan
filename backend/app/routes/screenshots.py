"""
Serve runtime screenshot PNGs from per-sample artifact directories.

GET /api/v1/screenshots/{sha256}/{filename}

Requires JWT (img tags cannot send Authorization — the dashboard loads these
via fetch + blob URLs). Paths are resolved only under the case's artifact_dir
with traversal checks.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.auth.auth import require_analyst
from app.routes.report import load_report

logger = logging.getLogger(__name__)

router = APIRouter()

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_UPLOADS_DIR = Path(__import__("os").getenv("UPLOADS_DIR", "/app/uploads"))


def _artifact_dir_from_report(report: Dict[str, Any]) -> Optional[Path]:
    dyn = report.get("dynamic_result") or {}
    raw_dir = dyn.get("artifact_dir") or report.get("artifact_dir") or report.get("_artifact_dir")
    if not raw_dir:
        return None
    try:
        return Path(raw_dir).resolve()
    except (OSError, RuntimeError):
        return None


def _resolve_image_path(artifact_dir: Path, filename: str) -> Path:
    """
    Map a manifest filename to an on-disk PNG under artifact_dir.
    Mirrors report_generator._build_visual_gallery resolution.
    """
    rel = filename.replace("\\", "/").lstrip("/")
    if ".." in rel.split("/"):
        raise HTTPException(status_code=400, detail="Invalid screenshot path.")

    candidates = []
    if rel:
        candidates.append(artifact_dir / rel)
        candidates.append(artifact_dir / "screenshots" / Path(rel).name)
    else:
        candidates.append(artifact_dir / "screenshots" / Path(filename).name)

    root = artifact_dir.resolve()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if not resolved.is_relative_to(root):
            continue
        if resolved.is_file():
            return resolved

    raise HTTPException(status_code=404, detail="Screenshot not found.")


@router.get("/screenshots/{sha256}/{filename}")
async def get_screenshot(
    sha256: str,
    filename: str,
    user: dict = Depends(require_analyst),
):
    if not _SHA256_RE.match(sha256):
        raise HTTPException(status_code=400, detail="Invalid SHA256.")

    safe_name = Path(filename).name
    if not safe_name or safe_name != filename.replace("\\", "/").split("/")[-1]:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    report = await load_report(sha256)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Case not found. Analyze the APK first.",
        )

    artifact_dir = _artifact_dir_from_report(report if isinstance(report, dict) else {})
    if artifact_dir is None or not artifact_dir.is_dir():
        raise HTTPException(status_code=404, detail="No artifact directory for this case.")

    # Manifest entries may be full relative paths (screenshots/foo.png) or basenames.
    rel_for_lookup = filename
    dyn = (report.get("dynamic_result") or {}) if isinstance(report, dict) else {}
    for entry in dyn.get("screenshots") or []:
        if not entry:
            continue
        entry_str = str(entry)
        if entry_str.endswith(safe_name) or Path(entry_str).name == safe_name:
            rel_for_lookup = entry_str
            break

    img_path = _resolve_image_path(artifact_dir, rel_for_lookup)

    if img_path.suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        raise HTTPException(status_code=400, detail="Unsupported image type.")

    return FileResponse(
        img_path,
        media_type="image/png",
        filename=safe_name,
    )
