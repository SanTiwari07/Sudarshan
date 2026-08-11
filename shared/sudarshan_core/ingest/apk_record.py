"""
Deterministic APK ingestion — SHA256 case identity and manifest metadata.

Every downstream pipeline stage should key evidence off the content SHA256
returned here, not the filesystem path digest used by artifact_dir_for().
"""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.apk_repair import compute_sha256

REPO_ROOT = Path(__file__).resolve().parents[3]

DRINIK_CANDIDATE_PATHS: List[Path] = [
    Path(os.environ.get("DRINIK_APK_PATH", "")) if os.environ.get("DRINIK_APK_PATH") else Path(),
    REPO_ROOT / "tests" / "apks" / "categories" / "drinik.apk",
    REPO_ROOT / "test apk" / "drinik.apk",
    REPO_ROOT / "test apk" / "TaxRefund_IncomeTax.apk",
    REPO_ROOT / "test apk" / "TaxRefund_IncomeTax" / "TaxRefund_IncomeTax.apk",
]


def resolve_drinik_apk_path(explicit: Optional[str] = None) -> Optional[Path]:
    """
    Locate a researcher-supplied Drinik APK without substituting fixtures.

    Search order: explicit arg → DRINIK_APK_PATH env → standard corpus paths.
    """
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(p for p in DRINIK_CANDIDATE_PATHS if str(p))

    for path in candidates:
        try:
            if path.is_file() and path.suffix.lower() == ".apk":
                return path.resolve()
        except OSError:
            continue
    return None


def _read_manifest_fields(apk_path: Path) -> Dict[str, Any]:
    """Best-effort manifest fields from APK zip without full Androguard."""
    out: Dict[str, Any] = {
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "min_sdk": None,
        "target_sdk": None,
    }
    try:
        from sudarshan_core.analyzers.apk_analyzer import analyze_apk

        ag = analyze_apk(str(apk_path))
        out["package_name"] = ag.package_name
        out["permissions_count"] = len(ag.permissions or [])
    except Exception:
        pass

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            out["zip_entries"] = len(zf.namelist())
    except Exception:
        out["zip_entries"] = None

    return out


def build_apk_record(apk_path: str | Path) -> Dict[str, Any]:
    """
    Build a deterministic ingestion record for one APK file.

    SHA256 is the case identifier used across static/dynamic/evidence/report.
    """
    path = Path(apk_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"APK not found: {path}")

    stat = path.stat()
    sha256 = compute_sha256(str(path))
    manifest_fields = _read_manifest_fields(path)

    return {
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "filename": path.name,
        "path": str(path),
        "sha256": sha256,
        "case_id": sha256,
        "file_size_bytes": stat.st_size,
        "package_name": manifest_fields.get("package_name"),
        "permissions_count": manifest_fields.get("permissions_count"),
        "zip_entries": manifest_fields.get("zip_entries"),
        "signing_information": "see static pipeline / MobSF certificate block",
    }


def write_ingestion_record(
    apk_path: str | Path,
    output_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """Write ingestion_record.json beside the APK or under output_dir."""
    record = build_apk_record(apk_path)
    sha256 = record["sha256"]

    if output_dir:
        dest = Path(output_dir)
    else:
        dest = Path(apk_path).resolve().parent / "sudarshan_artifacts" / sha256[:16]
    dest.mkdir(parents=True, exist_ok=True)

    out_path = dest / "ingestion_record.json"
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["ingestion_record_path"] = str(out_path)
    return record
