"""HTML report sections for visual investigation evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.visual_evidence.api_merge import load_visual_evidence_records


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _tier_filter(records: List[Dict[str, Any]], tiers: Tuple[str, ...]) -> List[Dict[str, Any]]:
    return [r for r in records if str(r.get("report_tier") or "") in tiers]


def _quality_ok(rec: Dict[str, Any]) -> bool:
    return str(rec.get("quality") or "") in ("A", "B")


def build_executive_visual_html(apk_dir: Optional[Path]) -> str:
    records = load_visual_evidence_records(apk_dir)
    exec_rows = [r for r in records if str(r.get("report_tier") or "") == "executive_key" and _quality_ok(r)]
    exec_rows.sort(key=lambda r: (0 if r.get("correlation_status") == "causal" else 1, -int(r.get("timestamp_ms") or 0)))
    exec_rows = exec_rows[:2]
    if not exec_rows:
        return ""

    parts = [
        '<section class="section" id="executive-visual-evidence">',
        '<h2>Executive Visual Evidence</h2>',
        '<p class="section-lead">High-confidence runtime screenshots corroborating critical findings (max 2).</p>',
        '<div class="gallery-grid">',
    ]
    for rec in exec_rows:
        sid = _esc(str(rec.get("screenshot_id") or ""))
        claim = _esc(str(rec.get("investigative_claim") or ""))
        qual = _esc(str(rec.get("quality") or ""))
        corr = _esc(str(rec.get("correlation_status") or ""))
        evids = ", ".join(_esc(e) for e in (rec.get("linked_evidence_ids") or []))
        fn = str(rec.get("filename") or "")
        img_name = Path(fn.replace("\\", "/")).name
        img_path = apk_dir / "screenshots" / img_name if apk_dir else None
        img_tag = ""
        if img_path and img_path.is_file():
            import base64

            b64 = base64.b64encode(img_path.read_bytes()).decode("ascii")
            img_tag = f'<img src="data:image/png;base64,{b64}" alt="{sid}" style="width:100%;border-radius:8px"/>'
        parts.append(
            f'<div class="gallery-card"><div style="padding:12px">{img_tag}</div>'
            f'<div style="padding:12px"><strong>{sid}</strong> · Quality {qual} · {_esc(corr)}<br/>'
            f'<p style="margin-top:8px;font-size:13px">{claim}</p>'
            f'<p style="font-size:12px;color:#666">Supported by: {evids or "—"}</p></div></div>'
        )
    parts.append("</div></section>")
    return "\n".join(parts)


def build_technical_visual_html(apk_dir: Optional[Path]) -> str:
    records = load_visual_evidence_records(apk_dir)
    rows = [
        r for r in records
        if _quality_ok(r)
        and str(r.get("quality") or "") in ("A", "B")
        and str(r.get("correlation_status") or "") in ("causal", "linked", "temporal")
    ]
    if not rows:
        return ""
    parts = [
        '<section class="section" id="technical-visual-evidence">',
        "<h2>Visual Evidence (Technical)</h2>",
        "<table class=\"data-table\"><thead><tr>"
        "<th>SCR</th><th>Claim</th><th>Quality</th><th>Correlation</th><th>EVID</th><th>Workflow</th></tr></thead><tbody>",
    ]
    for rec in rows:
        parts.append(
            "<tr>"
            f"<td>{_esc(str(rec.get('screenshot_id') or ''))}</td>"
            f"<td>{_esc(str(rec.get('investigative_claim') or '')[:200])}</td>"
            f"<td>{_esc(str(rec.get('quality') or ''))}</td>"
            f"<td>{_esc(str(rec.get('correlation_status') or ''))}</td>"
            f"<td>{_esc(', '.join(rec.get('linked_evidence_ids') or []))}</td>"
            f"<td>{_esc(str(rec.get('workflow_stage_label') or ''))}</td>"
            "</tr>"
        )
    parts.append("</tbody></table></section>")
    return "\n".join(parts)


def build_appendix_visual_html(apk_dir: Optional[Path]) -> str:
    records = load_visual_evidence_records(apk_dir)
    rows = [
        r for r in records
        if str(r.get("quality") or "") == "C"
        and str(r.get("report_tier") or "") in ("appendix_only", "technical")
    ]
    if not rows:
        return ""
    parts = [
        '<section class="section" id="appendix-visual-evidence">',
        "<h2>Appendix — Additional Visual Context</h2><ul>",
    ]
    for rec in rows:
        parts.append(
            f"<li><strong>{_esc(str(rec.get('screenshot_id') or ''))}</strong> — "
            f"{_esc(str(rec.get('investigative_claim') or '')[:160])}</li>"
        )
    parts.append("</ul></section>")
    return "\n".join(parts)
