"""Merge screenshot manifest rows with visual_evidence.json for API consumers."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def load_visual_evidence_records(artifact_dir: Optional[Path]) -> List[Dict[str, Any]]:
    if not artifact_dir:
        return []
    path = Path(artifact_dir) / "visual_evidence.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[VisualEvidence] Could not read %s: %s", path, exc)
        return []
    records = data.get("records")
    return list(records) if isinstance(records, list) else []


def index_visual_evidence_by_scr(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        sid = str(rec.get("screenshot_id") or "")
        if sid:
            out[sid] = rec
    return out


def merge_entry_with_visual_evidence(
    manifest_entry: Dict[str, Any],
    ver: Optional[Dict[str, Any]],
    *,
    sha256: str,
    api_prefix: str = "/api/v1",
) -> Dict[str, Any]:
    """Normalize manifest + VER for API (no host filesystem paths)."""
    filename = str(manifest_entry.get("filename") or "")
    base = Path(filename.replace("\\", "/")).name
    sid = str(manifest_entry.get("screenshot_id") or manifest_entry.get("id") or "")

    merged: Dict[str, Any] = {
        **manifest_entry,
        "screenshot_id": sid,
        "id": sid or base,
        "filename": filename,
        "capture_trigger": manifest_entry.get("reason") or manifest_entry.get("source") or "",
        "png_url": f"{api_prefix}/screenshots/{sha256}/{base}" if base else "",
    }

    if not ver:
        merged["visual_evidence"] = None
        return merged

    # What the frame shows. The linker prefers the manifest's own reading and
    # falls back to one derived from the frame's metadata, so the VER value
    # leads here; the manifest value remains as a floor for a row the linker
    # never saw.
    merged["visual_observation"] = (
        ver.get("visual_observation")
        or manifest_entry.get("visual_observation")
        or ""
    )
    merged["screen_summary"] = (
        ver.get("screen_summary") or manifest_entry.get("screen_summary") or ""
    )
    merged["corroboration_summary"] = ver.get("corroboration_summary") or ""

    merged["visual_evidence"] = {
        "screenshot_id": ver.get("screenshot_id"),
        "claim_type": ver.get("claim_type"),
        "investigative_claim": ver.get("investigative_claim"),
        "claim": ver.get("investigative_claim"),
        "quality": ver.get("quality"),
        "priority": ver.get("priority"),
        "correlation_status": ver.get("correlation_status"),
        "linked_evidence_ids": list(ver.get("linked_evidence_ids") or []),
        "linked_finding_keys": list(ver.get("linked_finding_keys") or []),
        "workflow_stage_label": ver.get("workflow_stage_label") or "",
        "report_tier": ver.get("report_tier"),
        "timeline_eligible": bool(ver.get("timeline_eligible")),
        "png_sha256": ver.get("png_sha256"),
        "timestamp_ms": ver.get("timestamp_ms"),
        "capture_trigger": ver.get("capture_trigger") or merged.get("capture_trigger"),
        "visual_observation": merged["visual_observation"],
        "screen_summary": merged["screen_summary"],
        "corroboration_summary": merged["corroboration_summary"],
    }
    # Top-level aliases for simpler clients
    merged["claim_type"] = ver.get("claim_type")
    merged["investigative_claim"] = ver.get("investigative_claim")
    merged["quality"] = ver.get("quality")
    merged["priority"] = ver.get("priority")
    merged["correlation_status"] = ver.get("correlation_status")
    merged["linked_evidence_ids"] = list(ver.get("linked_evidence_ids") or [])
    merged["linked_finding_keys"] = list(ver.get("linked_finding_keys") or [])
    merged["workflow_stage_label"] = ver.get("workflow_stage_label") or ""
    merged["report_tier"] = ver.get("report_tier")
    merged["timeline_eligible"] = bool(ver.get("timeline_eligible"))
    return merged


def build_visual_evidence_index(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Indexes for finding / EVID lookup (API meta block)."""
    by_finding: Dict[str, List[str]] = {}
    by_evid: Dict[str, List[str]] = {}
    for rec in records:
        sid = str(rec.get("screenshot_id") or "")
        if not sid:
            continue
        for fk in rec.get("linked_finding_keys") or []:
            by_finding.setdefault(str(fk), []).append(sid)
        for eid in rec.get("linked_evidence_ids") or []:
            by_evid.setdefault(str(eid), []).append(sid)
    return {"by_finding_key": by_finding, "by_evidence_id": by_evid}
