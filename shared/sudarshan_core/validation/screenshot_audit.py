"""Screenshot integrity checks for validation runs."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.report_generator import _load_screenshot_entries


@dataclass
class ScreenshotValidation:
    screenshot_id: str
    path: str
    exists: bool
    readable: bool
    size_bytes: int
    in_manifest: bool
    in_evidence: bool
    in_html: bool
    html_embedded: bool
    errors: List[str] = field(default_factory=list)


def validate_screenshots(
    artifact_dir: Path,
    report_dict: Dict[str, Any],
    html_content: str,
) -> List[ScreenshotValidation]:
    results: List[ScreenshotValidation] = []
    manifest_entries = _load_screenshot_entries(artifact_dir, report_dict)
    manifest_ids = {e.get("screenshot_id") for e in manifest_entries}

    evidence_refs: set = set()
    ev_path = artifact_dir / "evidence.json"
    if ev_path.is_file():
        import json
        try:
            ev = json.loads(ev_path.read_text(encoding="utf-8"))
            for rec in ev.get("records", []):
                ref = rec.get("screenshot_ref") or ""
                sid = rec.get("screenshot_id") or ""
                if ref:
                    evidence_refs.add(ref)
                if sid:
                    evidence_refs.add(sid)
        except Exception:
            pass

    for entry in manifest_entries:
        sid = entry.get("screenshot_id", "?")
        rel = entry.get("filename", "")
        img = artifact_dir / rel if rel else Path()
        if not img.is_file() and rel:
            img = artifact_dir / "screenshots" / Path(rel).name

        v = ScreenshotValidation(
            screenshot_id=sid,
            path=str(img),
            exists=img.is_file(),
            readable=False,
            size_bytes=0,
            in_manifest=sid in manifest_ids,
            in_evidence=rel in evidence_refs or sid in evidence_refs,
            in_html=sid in html_content or Path(rel).name in html_content,
            html_embedded=False,
        )
        if v.exists:
            try:
                data = img.read_bytes()
                v.size_bytes = len(data)
                v.readable = len(data) > 64 and data[:8].startswith(b"\x89PNG\r\n\x1a")
                if not v.readable:
                    v.errors.append("not a valid PNG header or too small")
            except OSError as exc:
                v.errors.append(str(exc))
        else:
            v.errors.append("file missing on disk")

        if v.in_html and f"data:image/png;base64," in html_content:
            if rel and Path(rel).name in html_content:
                v.html_embedded = bool(
                    re.search(r"data:image/png;base64,[A-Za-z0-9+/=]{100,}", html_content)
                )
        if not v.html_embedded and v.exists:
            v.errors.append("not embedded as base64 in HTML (PDF print would be broken)")

        results.append(v)
    return results
