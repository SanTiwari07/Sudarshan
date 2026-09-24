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
    In Phase 3, this fetches from GCS ArtifactStorage.
    """
    import asyncio
    from sudarshan_core.storage.artifact_storage import get_storage
    import tempfile
    import os
    import json
    
    if not sha256 and not case_id:
        return []
        
    lookup_sha256 = sha256 or case_id
    object_key = f"evidence/{lookup_sha256}/evidence.json"
    
    storage = get_storage()
    fd, temp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio
            nest_asyncio.apply()
        loop.run_until_complete(storage.get_file(object_key, temp_path))
        
        return _read_evidence_file(Path(temp_path))
    except Exception as e:
        logger.debug(f"[EvidenceLoader] Could not load evidence.json from {object_key}: {e}")
        return []
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


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
