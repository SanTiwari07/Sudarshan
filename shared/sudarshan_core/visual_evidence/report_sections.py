"""
HTML report sections for visual investigation evidence.

Three tiers, three presentations, one alignment grid:
  executive_key -> full-width plates, image beside a fixed metadata grid
  technical     -> a correlation table
  appendix_only -> a compact index of the frames that carry background only

The class names here are the ones defined in report_generator._CSS; nothing in
this module styles inline, so a palette change lands in one place.
"""

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


def _grade(grade: str) -> str:
    g = str(grade or "").strip().upper()[:1]
    if not g:
        return '<span class="muted">not graded</span>'
    cls = {"A": "grade-a", "B": "grade-b", "C": "grade-c"}.get(g, "grade-b")
    return f'<span class="grade {cls}">{g}</span>'


def _first(rec: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", [], {}):
            return str(v)
    return ""


def _img_data_uri(apk_dir: Optional[Path], filename: str) -> str:
    """Inline the frame. Reports must survive being emailed as one file."""
    if not apk_dir or not filename:
        return ""
    name = Path(str(filename).replace("\\", "/")).name
    for candidate in (apk_dir / "screenshots" / name, apk_dir / name):
        if candidate.is_file():
            import base64

            try:
                b64 = base64.b64encode(candidate.read_bytes()).decode("ascii")
                return f"data:image/png;base64,{b64}"
            except OSError:
                return ""
    return ""


def _meta_rows(rec: Dict[str, Any]) -> str:
    """
    The fixed metadata grid. Row order never varies between plates, so the
    labels hold one left edge and the values another straight down the section.
    """
    rows: List[Tuple[str, str, bool]] = [
        ("Lifecycle trigger",
         _first(rec, "capture_trigger", "trigger_event", "trigger_reason", "stage"), False),
        ("Screen state",
         _first(rec, "screen_summary", "visual_observation", "semantic_type"), False),
        ("Workflow stage", _first(rec, "workflow_stage_label"), False),
        ("Activity", _first(rec, "activity", "window"), True),
    ]

    out = ""
    for label, value, mono in rows:
        if not value:
            continue
        cls = ' class="mono"' if mono else ""
        out += f"<dt>{_esc(label)}</dt><dd{cls}>{_esc(value[:200])}</dd>"

    corr = _first(rec, "correlation_status")
    if corr:
        out += f"<dt>Correlation</dt><dd>{_esc(corr)}</dd>"

    evids = ", ".join(_esc(e) for e in (rec.get("linked_evidence_ids") or []))
    out += f'<dt>Linked evidence</dt><dd class="mono">{evids or "&mdash;"}</dd>'
    out += f"<dt>Quality grade</dt><dd>{_grade(rec.get('quality'))}</dd>"
    return out


def build_executive_visual_html(apk_dir: Optional[Path]) -> str:
    records = load_visual_evidence_records(apk_dir)
    exec_rows = [
        r for r in records
        if str(r.get("report_tier") or "") == "executive_key" and _quality_ok(r)
    ]
    exec_rows.sort(
        key=lambda r: (0 if r.get("correlation_status") == "causal" else 1,
                       -int(r.get("timestamp_ms") or 0))
    )
    exec_rows = exec_rows[:2]
    if not exec_rows:
        return ""

    parts = [
        '<section class="section" id="executive-visual-evidence">',
        '<div class="section-header"><h2>Corroborating Visual Evidence</h2>'
        f'<span class="section-note">{len(exec_rows)} of the highest-confidence frames</span>'
        "</div>",
        '<p class="section-lead">Frames the correlation pass tied directly to a '
        "recorded finding. The full capture set is in the appendix.</p>",
    ]
    for rec in exec_rows:
        sid = _esc(str(rec.get("screenshot_id") or ""))
        claim = _esc(str(rec.get("investigative_claim") or ""))
        uri = _img_data_uri(apk_dir, str(rec.get("filename") or ""))
        figure = (
            f'<img src="{uri}" alt="Runtime capture {sid}"/>'
            if uri else '<div class="no-data">Frame not retained</div>'
        )
        parts.append(
            '<div class="plate">'
            f'<figure class="plate-figure">{figure}'
            f"<figcaption>{sid}</figcaption></figure>"
            '<div class="plate-body">'
            f'<div class="plate-claim">{claim or "No claim recorded for this frame."}</div>'
            f'<dl class="plate-meta">{_meta_rows(rec)}</dl>'
            "</div></div>"
        )
    parts.append("</section>")
    return "\n".join(parts)


def build_technical_visual_html(apk_dir: Optional[Path]) -> str:
    records = load_visual_evidence_records(apk_dir)
    rows = [
        r for r in records
        if _quality_ok(r)
        and str(r.get("correlation_status") or "") in ("causal", "linked", "temporal")
    ]
    if not rows:
        return ""
    parts = [
        '<section class="section" id="technical-visual-evidence">',
        '<div class="section-header"><h2>Visual Evidence Correlation</h2>'
        f'<span class="section-note">{len(rows)} correlated frames</span></div>',
        '<p class="section-lead">Each frame against the finding it corroborates '
        "and the strength of that link.</p>",
        '<table class="data-table"><thead><tr>'
        "<th>Frame</th><th>Observation</th><th>Grade</th><th>Correlation</th>"
        "<th>Evidence</th><th>Workflow stage</th></tr></thead><tbody>",
    ]
    for rec in rows:
        parts.append(
            "<tr>"
            f'<td class="col-id">{_esc(str(rec.get("screenshot_id") or ""))}</td>'
            f'<td>{_esc(str(rec.get("investigative_claim") or "")[:200])}</td>'
            f"<td>{_grade(rec.get('quality'))}</td>"
            f'<td>{_esc(str(rec.get("correlation_status") or ""))}</td>'
            f'<td class="col-id">{_esc(", ".join(rec.get("linked_evidence_ids") or []))}</td>'
            f'<td>{_esc(str(rec.get("workflow_stage_label") or ""))}</td>'
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
        '<div class="section-header"><h2>Additional Visual Context</h2>'
        f'<span class="section-note">{len(rows)} background frames</span></div>',
        '<p class="section-lead">Frames retained for completeness. Grade C carries '
        "background only and corroborates no finding on its own.</p>",
        '<table class="data-table"><thead><tr>'
        "<th>Frame</th><th>Observation</th><th>Lifecycle trigger</th>"
        "</tr></thead><tbody>",
    ]
    for rec in rows:
        parts.append(
            "<tr>"
            f'<td class="col-id">{_esc(str(rec.get("screenshot_id") or ""))}</td>'
            f'<td>{_esc(str(rec.get("investigative_claim") or "")[:180])}</td>'
            f'<td>{_esc(_first(rec, "capture_trigger", "trigger_event", "stage")[:80])}</td>'
            "</tr>"
        )
    parts.append("</tbody></table></section>")
    return "\n".join(parts)
