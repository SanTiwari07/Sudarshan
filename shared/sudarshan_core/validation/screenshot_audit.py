"""Screenshot integrity checks for validation runs."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

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


def _screenshot_referenced_in_html(
    html_content: str,
    screenshot_id: str,
    rel_filename: str,
) -> bool:
    """True if the HTML report references this screenshot (gallery card or alt text)."""
    if screenshot_id and screenshot_id in html_content:
        return True
    name = Path(rel_filename).name if rel_filename else ""
    if name and name in html_content:
        return True
    return False


def _png_embedded_in_html(html_content: str, png_bytes: bytes) -> bool:
    """
    Report generator embeds PNGs as data:image/png;base64,... in <img src>.
    Filenames are not repeated in the HTML body, so match on the encoded payload.
    """
    if not png_bytes or not html_content:
        return False
    b64 = base64.b64encode(png_bytes).decode("ascii")
    if f"data:image/png;base64,{b64}" in html_content:
        return True
    # Guard against rare whitespace/normalization differences in very large HTML.
    if len(b64) > 120 and b64[:120] in html_content:
        return True
    return False


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
        try:
            ev = json.loads(ev_path.read_text(encoding="utf-8"))
            for rec in ev.get("records", []):
                ref = rec.get("screenshot_ref") or ""
                sid = rec.get("screenshot_id") or ""
                if ref:
                    evidence_refs.add(ref)
                    evidence_refs.add(Path(ref).name)
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
            in_evidence=(
                rel in evidence_refs
                or sid in evidence_refs
                or (Path(rel).name in evidence_refs if rel else False)
            ),
            in_html=_screenshot_referenced_in_html(html_content, sid, rel),
            html_embedded=False,
        )
        if v.exists:
            try:
                data = img.read_bytes()
                v.size_bytes = len(data)
                v.readable = len(data) > 64 and data[:8].startswith(b"\x89PNG\r\n\x1a")
                if not v.readable:
                    v.errors.append("not a valid PNG header or too small")
                elif html_content:
                    v.html_embedded = _png_embedded_in_html(html_content, data)
            except OSError as exc:
                v.errors.append(str(exc))
        else:
            v.errors.append("file missing on disk")

        if v.exists and v.readable and not v.html_embedded:
            v.errors.append(
                "PNG not embedded as data URI in HTML (PDF/standalone export would be missing this image)"
            )
        if v.exists and v.readable and not v.in_html:
            v.errors.append("screenshot not referenced in HTML gallery (missing SCR id or label)")

        results.append(v)
    return results
