"""
Load Frida evidence.json records from forensic artifact directories.
Shared by runtime API and cases evidence endpoint.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_evidence_scan_cache: Dict[str, Any] = {"at": 0.0, "paths": []}
_CACHE_TTL_SEC = 30.0


def _scan_evidence_files() -> List[Path]:
    now = time.time()
    if now - _evidence_scan_cache["at"] < _CACHE_TTL_SEC:
        return list(_evidence_scan_cache["paths"])

    found: List[tuple[float, Path]] = []
    roots = [
        Path.cwd(),
        Path(__file__).resolve().parents[2],
    ]
    for root in roots:
        artifacts = root / "sudarshan_artifacts"
        if not artifacts.is_dir():
            continue
        for ev_path in artifacts.rglob("evidence.json"):
            try:
                mtime = ev_path.stat().st_mtime
                found.append((mtime, ev_path))
            except OSError:
                continue

    paths = [p for _, p in sorted(found, key=lambda t: t[0], reverse=True)]
    _evidence_scan_cache["at"] = now
    _evidence_scan_cache["paths"] = paths
    return paths


def load_evidence_records(
    case_id: Optional[str] = None,
    sha256: Optional[str] = None,
    artifact_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load evidence records for a case.

    Resolution order:
      1. Explicit artifact_dir/evidence.json
      2. case_id matched against artifact directory name
      3. sha256 matched against path or directory name
      4. Most recently modified evidence.json (only if no identifiers given)
    """
    if artifact_dir:
        path = Path(artifact_dir) / "evidence.json"
        if path.is_file():
            return _read_evidence_file(path)

    candidates = _scan_evidence_files()

    if case_id:
        needle = case_id.lower()
        candidates = [
            p for p in candidates
            if needle in p.parent.name.lower() or needle in str(p.parent).lower()
        ]
    elif sha256:
        needle = sha256.lower()
        candidates = [
            p for p in candidates
            if needle in p.parent.name.lower() or needle in str(p.parent).lower()
        ]

    best_path = candidates[0] if candidates else None
    if best_path is None:
        return []

    return _read_evidence_file(best_path)


def _read_evidence_file(path: Path) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return data.get("records", []) if isinstance(data, dict) else []
    except Exception as e:
        logger.warning("[EvidenceLoader] Could not read %s: %s", path, e)
        return []
