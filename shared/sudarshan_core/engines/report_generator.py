"""
SUDARSHAN — Report Generator v2
=================================
Generates a standalone, single-file HTML malware analysis report from the
collected AnalysisResponse and per-sample JSON artifacts of a pipeline run.

Design principles:
  - Self-contained: inline CSS only, no external CDN, no JavaScript
  - State-aware: renders honestly whether dynamic evidence is full, empty, or absent
  - Evidence IDs: every finding is indexed [STAT-NNN], [INTEL-NNN], [EVID-NNN]
  - No fabrication: dynamic section ALWAYS renders — either a timeline or an
    explicit [DYNAMIC-STATUS: NO TELEMETRY CAPTURED] diagnostic panel
  - Print-ready: @media print light theme for PDF via browser Ctrl+P

Usage:
    from sudarshan_core.engines.report_generator import ReportGenerator, build_report
    html = build_report(analysis_response_dict, apk_artifact_dir)
    # or write to disk:
    build_report(analysis_response_dict, apk_artifact_dir, output_path=Path("report.html"))
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.visual_evidence.report_sections import (
    build_appendix_visual_html,
    build_executive_visual_html,
    build_technical_visual_html,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CSS — self-contained, dark screen theme + light print theme
# ---------------------------------------------------------------------------

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;--bg4:#21262d;
  --border:#30363d;--border2:#21262d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --blue:#58a6ff;--green:#3fb950;--yellow:#d29922;
  --orange:#f0883e;--red:#f85149;--purple:#d2a8ff;
  --radius:6px;--radius2:12px;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  --font-mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;font-weight:700}
h2{font-size:1.15rem;font-weight:600;margin-bottom:12px}
h3{font-size:.9rem;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}
p{color:var(--text2);margin-bottom:8px}
code{font-family:var(--font-mono);font-size:.82em;background:var(--bg3);padding:1px 5px;border-radius:3px;color:var(--purple)}
a{color:var(--blue);text-decoration:none}

/* Layout */
.section{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius2);padding:24px;margin-bottom:20px}
.section-header{display:flex;align-items:center;gap:10px;margin-bottom:18px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.section-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

/* Report header */
.report-header{background:linear-gradient(135deg,#1a2332 0%,#0d1117 60%,#1a1420 100%);border:1px solid var(--border);border-radius:var(--radius2);padding:28px 32px;margin-bottom:20px}
.report-meta{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px}
.brand-mark{background:linear-gradient(135deg,#1f6feb,#388bfd);width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:900;color:#fff}
.brand-name{font-size:1.1rem;font-weight:700;color:var(--blue)}
.brand-sub{font-size:.75rem;color:var(--text3);text-transform:uppercase;letter-spacing:.08em}
.report-brand{display:flex;align-items:center;gap:12px}
.report-ts{font-size:.78rem;color:var(--text3);text-align:right}
.app-identity{margin-top:20px}
.app-name{font-size:1.4rem;font-weight:700;margin-bottom:4px}
.app-pkg{font-family:var(--font-mono);font-size:.85rem;color:var(--text2)}
.hash-row{display:flex;align-items:center;gap:8px;margin-top:10px;font-family:var(--font-mono);font-size:.78rem;color:var(--text3)}

/* Score dial */
.score-block{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius2);padding:20px 24px;display:flex;align-items:center;gap:24px}
.dial-wrap{position:relative;width:90px;height:90px;flex-shrink:0}
.dial-svg{width:90px;height:90px}
.dial-track{fill:none;stroke:var(--border);stroke-width:8}
.dial-fill{fill:none;stroke-width:8;stroke-linecap:round;transform:rotate(-90deg);transform-origin:45px 45px}
.dial-value{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.3rem;font-weight:900;text-align:center;line-height:1}
.dial-label{font-size:.6rem;color:var(--text3);letter-spacing:.05em;margin-top:2px}
.score-detail{flex:1}
.risk-band-badge{display:inline-block;padding:4px 14px;border-radius:20px;font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.band-critical{background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.35)}
.band-high{background:rgba(240,136,62,.15);color:#f0883e;border:1px solid rgba(240,136,62,.35)}
.band-medium{background:rgba(210,153,34,.15);color:#d29922;border:1px solid rgba(210,153,34,.35)}
.band-safe{background:rgba(63,185,80,.15);color:#3fb950;border:1px solid rgba(63,185,80,.35)}
.score-tagline{font-size:.95rem;font-weight:600;margin-bottom:6px}
.score-subtext{font-size:.82rem;color:var(--text2)}

/* Verdict banner */
.verdict-banner{border-radius:var(--radius);padding:14px 18px;margin-top:16px;display:flex;align-items:flex-start;gap:12px}
.verdict-critical{background:rgba(248,81,73,.08);border-left:3px solid #f85149}
.verdict-high{background:rgba(240,136,62,.08);border-left:3px solid #f0883e}
.verdict-medium{background:rgba(210,153,34,.08);border-left:3px solid #d29922}
.verdict-safe{background:rgba(63,185,80,.08);border-left:3px solid #3fb950}
.verdict-icon{font-size:1.2rem;flex-shrink:0;margin-top:1px}
.verdict-q{font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px}
.verdict-answer{font-size:.9rem;font-weight:600}
.verdict-narrative{font-size:.84rem;color:var(--text2);margin-top:6px}

/* STEI */
.stei-grid{display:flex;flex-direction:column;gap:10px}
.stei-row{display:flex;align-items:center;gap:10px}
.stei-label{font-size:.8rem;color:var(--text2);width:130px;flex-shrink:0}
.stei-bar-track{flex:1;background:var(--bg4);border-radius:4px;height:8px;overflow:hidden}
.stei-bar-fill{height:100%;border-radius:4px}
.stei-score{font-size:.8rem;font-family:var(--font-mono);color:var(--text);width:38px;text-align:right;flex-shrink:0}
.axis-ct .stei-bar-fill{background:linear-gradient(90deg,#f85149,#ff7b72)}
.axis-bt .stei-bar-fill{background:linear-gradient(90deg,#d29922,#e3b341)}
.axis-pr .stei-bar-fill{background:linear-gradient(90deg,#f0883e,#ffa657)}
.axis-ob .stei-bar-fill{background:linear-gradient(90deg,#8b949e,#c9d1d9)}
.axis-ir .stei-bar-fill{background:linear-gradient(90deg,#58a6ff,#79c0ff)}

/* Info cards */
.info-card{background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);padding:12px 14px}
.info-key{font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin-bottom:3px}
.info-val{font-size:.88rem;color:var(--text);word-break:break-all}
.info-val-mono{font-family:var(--font-mono);font-size:.78rem}

/* Tables */
.data-table{width:100%;border-collapse:collapse;font-size:.83rem}
.data-table th{text-align:left;padding:8px 10px;background:var(--bg3);color:var(--text3);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
.data-table td{padding:8px 10px;border-bottom:1px solid var(--border2);color:var(--text2);vertical-align:top}
.data-table tr:last-child td{border-bottom:none}

/* Permission / tag badges */
.perm-grid{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
.perm-tag{display:inline-block;padding:3px 9px;border-radius:12px;font-family:var(--font-mono);font-size:.72rem}
.perm-danger{background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.25)}
.perm-normal{background:var(--bg4);color:var(--text3);border:1px solid var(--border2)}

/* Finding cards */
.finding{display:flex;gap:12px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);margin-bottom:8px}
.finding-id{font-family:var(--font-mono);font-size:.7rem;color:var(--text3);white-space:nowrap;padding-top:2px;min-width:80px}
.finding-body{flex:1}
.finding-title{font-size:.85rem;font-weight:600;color:var(--text);margin-bottom:2px}
.finding-desc{font-size:.8rem;color:var(--text2)}
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.68rem;font-weight:700;text-transform:uppercase;margin-left:6px}
.sev-critical{background:rgba(248,81,73,.15);color:#f85149}
.sev-high{background:rgba(240,136,62,.15);color:#f0883e}
.sev-medium{background:rgba(210,153,34,.15);color:#d29922}
.sev-low{background:rgba(63,185,80,.15);color:#3fb950}

/* MITRE chips */
.mitre-grid{display:flex;flex-wrap:wrap;gap:8px}
.mitre-chip{background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.2);border-radius:var(--radius);padding:6px 10px}
.mitre-id{font-family:var(--font-mono);font-size:.75rem;color:var(--blue);font-weight:700}
.mitre-name{font-size:.78rem;color:var(--text2);margin-top:2px}

/* Dynamic / state-aware banner */
.dynamic-status-banner{background:rgba(139,148,158,.05);border:1px dashed var(--border);border-radius:var(--radius);padding:20px 24px;text-align:center}
.dynamic-status-title{font-size:.82rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text3);margin-bottom:10px}
.dynamic-status-code{font-family:var(--font-mono);font-size:.88rem;color:#d29922;margin-bottom:12px}
.dynamic-status-detail{font-size:.82rem;color:var(--text3);line-height:1.7}

/* Timeline */
.timeline{position:relative;padding-left:28px}
.timeline::before{content:"";position:absolute;left:10px;top:0;bottom:0;width:1px;background:var(--border)}
.tl-event{position:relative;margin-bottom:12px;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);padding:10px 12px}
.tl-event::before{content:"";position:absolute;left:-22px;top:14px;width:8px;height:8px;border-radius:50%;background:var(--blue);border:2px solid var(--bg)}
.tl-ts{font-family:var(--font-mono);font-size:.7rem;color:var(--text3)}
.tl-api{font-family:var(--font-mono);font-size:.82rem;color:var(--purple);font-weight:600}
.tl-desc{font-size:.8rem;color:var(--text2);margin-top:2px}

/* Threat intel */
.intel-stat{background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);padding:14px;text-align:center}
.intel-num{font-size:1.5rem;font-weight:900;line-height:1}
.intel-sub{font-size:.72rem;color:var(--text3);text-transform:uppercase;margin-top:4px}
.rep-malicious{color:#f85149}
.rep-suspicious{color:#f0883e}
.rep-clean{color:#3fb950}
.rep-unknown{color:var(--text3)}

/* Recommendations */
.rec-list{list-style:none;display:flex;flex-direction:column;gap:8px}
.rec-item{display:flex;gap:10px;align-items:flex-start;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);padding:10px 12px}
.rec-num{background:rgba(88,166,255,.15);color:var(--blue);border-radius:50%;width:20px;height:20px;min-width:20px;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;flex-shrink:0;margin-top:1px}
.rec-text{font-size:.84rem;color:var(--text2)}

/* Utility */
.mt8{margin-top:8px}.mt12{margin-top:12px}.mt16{margin-top:16px}
.mb8{margin-bottom:8px}
.no-data{color:var(--text3);font-style:italic;font-size:.82rem;padding:8px 0}

/* Visual Gallery */
.gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-top:12px}
.gallery-card{background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius);overflow:hidden;display:flex;flex-direction:column}
.scr-header{padding:8px 12px;background:var(--bg4);border-bottom:1px solid var(--border2);display:flex;align-items:center;justify-content:space-between;font-size:.78rem}
.scr-id{font-family:var(--font-mono);font-weight:700;color:var(--blue)}
.scr-label{color:var(--text2);font-weight:600}
.scr-body{padding:10px;display:flex;align-items:center;justify-content:center;background:#000;min-height:160px}
.scr-img{max-width:100%;max-height:320px;object-fit:contain;border-radius:4px;border:1px solid var(--border)}
.scr-meta{padding:8px 12px;background:var(--bg3);border-top:1px solid var(--border2);display:flex;align-items:center;justify-content:space-between;font-size:.72rem;color:var(--text3)}

/* Footer */
.report-footer{text-align:center;padding:20px;font-size:.75rem;color:var(--text3);border-top:1px solid var(--border);margin-top:8px}

/* Print */
@media print{
  :root{--bg:#fff;--bg2:#f8f9fa;--bg3:#f0f2f4;--bg4:#e8eaed;--border:#d0d7de;--border2:#e8eaed;--text:#24292f;--text2:#57606a;--text3:#8c959f}
  body{background:#fff;color:#24292f;font-size:12px}
  .container{max-width:100%;padding:8px}
  .section{break-inside:avoid;margin-bottom:12px}
  .brand-mark,.dial-fill,.stei-bar-fill,.risk-band-badge,.sev,.perm-tag,.mitre-chip,.dynamic-status-code{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DANGEROUS_PERMS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.WRITE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.DEVICE_ADMIN",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.USE_BIOMETRIC",
}


def _esc(s: Any) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _band_css(band: str) -> str:
    b = band.lower()
    if "critical" in b: return "band-critical"
    if "high" in b: return "band-high"
    if "suspicious" in b or "medium" in b: return "band-medium"
    return "band-safe"


def _verdict_css(band: str) -> str:
    b = band.lower()
    if "critical" in b: return "verdict-critical"
    if "high" in b: return "verdict-high"
    if "suspicious" in b or "medium" in b: return "verdict-medium"
    return "verdict-safe"


def _verdict_icon(band: str) -> str:
    b = band.lower()
    if "critical" in b: return "&#x1F6A8;"   # 🚨
    if "high" in b: return "&#x26A0;&#xFE0F;"  # ⚠️
    if "suspicious" in b or "medium" in b: return "&#x1F536;"  # 🔶
    return "&#x2705;"  # ✅


def _verdict_answer(band: str) -> str:
    b = band.lower()
    if "critical" in b:
        return "NO &#x2014; This application is highly likely to be malicious and should not be trusted."
    if "high" in b:
        return "LIKELY NOT &#x2014; High-risk behaviors consistent with banking fraud were detected."
    if "suspicious" in b or "medium" in b:
        return "EXERCISE CAUTION &#x2014; Suspicious characteristics detected; further investigation recommended."
    return "LIKELY SAFE &#x2014; No significant threat indicators detected in this analysis."


def _score_color(score: float) -> str:
    if score >= 90: return "#f85149"
    if score >= 60: return "#f0883e"
    if score >= 30: return "#d29922"
    return "#3fb950"


def _sev_class(sev: str) -> str:
    s = sev.lower()
    if s == "critical": return "sev-critical"
    if s == "high": return "sev-high"
    if s in ("medium", "med"): return "sev-medium"
    return "sev-low"


def _rep_class(rep: str) -> str:
    r = rep.lower()
    if r == "malicious": return "rep-malicious"
    if r == "suspicious": return "rep-suspicious"
    if r == "clean": return "rep-clean"
    return "rep-unknown"


def _get(obj: Any, *keys: str, default: Any = "") -> Any:
    """Safe attribute-or-key access for both dicts and Pydantic objects."""
    cur = obj
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k, default)
        else:
            cur = getattr(cur, k, default)
    return cur if cur is not None else default


# ---------------------------------------------------------------------------
# Finding ID index
# ---------------------------------------------------------------------------

class _FindingIndex:
    """Assigns sequential IDs across all finding categories."""

    def __init__(self):
        self._counters: Dict[str, int] = {}
        self.ledger: List[Tuple[str, str, str]] = []  # (id, prefix, title)

    def next(self, prefix: str, title: str) -> str:
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        fid = f"{prefix}-{n:03d}"
        self.ledger.append((fid, prefix, title))
        return fid


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_header(icon: str, icon_bg: str, title: str, subtitle: str = "") -> str:
    sub = (f'<span style="font-size:.78rem;color:var(--text3);margin-left:6px">'
           f'{_esc(subtitle)}</span>') if subtitle else ""
    return (
        f'<div class="section-header">'
        f'<div class="section-icon" style="background:{icon_bg}">{icon}</div>'
        f'<h2 style="margin:0">{_esc(title)}{sub}</h2>'
        f'</div>'
    )


def _build_header(r: Dict, ts: str) -> str:
    pkg = _esc(_get(r, "package_name", default="Unknown"))
    app = _esc(_get(r, "app_name") or _get(r, "package_name", default="Unknown"))
    sha = _esc(_get(r, "sha256", default=""))
    band = _get(r, "risk_band", default="Unknown")
    frs = float(_get(r, "final_risk_score", default=0))
    conf = float(_get(r, "confidence", default=70))
    action = _esc(_get(r, "recommended_action", default=""))
    mode = _esc(_get(r, "analysis_mode", default="androguard"))

    circ = 251.3
    offset = circ * (1.0 - min(frs, 100.0) / 100.0)
    dial_col = _score_color(frs)
    band_css = _band_css(band)
    verdict_css = _verdict_css(band)
    v_icon = _verdict_icon(band)
    v_answer = _verdict_answer(band)

    intel = _get(r, "intelligence_report") or {}
    narrative = _esc(_get(intel, "plain_english_narrative", default=""))
    if not narrative:
        ev = _get(r, "executive_view") or {}
        narrative = _esc(_get(ev, "plain_english_narrative", default=""))

    narrative_html = f'<div class="verdict-narrative">{narrative}</div>' if narrative else ""

    return (
        f'<div class="report-header">'
        f'<div class="report-meta">'
        f'<div class="report-brand">'
        f'<div class="brand-mark">S</div>'
        f'<div><div class="brand-name">Sudarshan</div>'
        f'<div class="brand-sub">Banking Malware Intelligence Platform</div></div>'
        f'</div>'
        f'<div class="report-ts">Generated: {_esc(ts)}<br>Mode: <code>{mode}</code><br>Confidence: {conf:.0f}%</div>'
        f'</div>'
        f'<div class="app-identity">'
        f'<div class="app-name">{app}</div>'
        f'<div class="app-pkg">{pkg}</div>'
        f'<div class="hash-row">SHA-256: {sha[:16]}&hellip;{sha[-8:] if len(sha) > 24 else sha}</div>'
        f'</div>'
        f'<div class="score-block mt16">'
        f'<div class="dial-wrap">'
        f'<svg class="dial-svg" viewBox="0 0 90 90">'
        f'<circle class="dial-track" cx="45" cy="45" r="36"/>'
        f'<circle class="dial-fill" cx="45" cy="45" r="36"'
        f' stroke="{dial_col}"'
        f' stroke-dasharray="{circ:.1f}"'
        f' stroke-dashoffset="{offset:.1f}"/>'
        f'</svg>'
        f'<div class="dial-value" style="color:{dial_col}">'
        f'{frs:.0f}<div class="dial-label">/ 100</div>'
        f'</div>'
        f'</div>'
        f'<div class="score-detail">'
        f'<span class="risk-band-badge {band_css}">{_esc(band)}</span>'
        f'<div class="score-tagline">Fraud Risk Score (FRS): <strong>{frs:.1f}</strong></div>'
        f'<div class="score-subtext">{action}</div>'
        f'</div>'
        f'</div>'
        f'<div class="verdict-banner {verdict_css}">'
        f'<div class="verdict-icon">{v_icon}</div>'
        f'<div>'
        f'<div class="verdict-q">Should this application be trusted?</div>'
        f'<div class="verdict-answer">{v_answer}</div>'
        f'{narrative_html}'
        f'</div>'
        f'</div>'
        f'</div>'
    )


def _build_stei(r: Dict) -> str:
    frs_bd = _get(r, "frs_breakdown") or {}
    axes = _get(frs_bd, "stei_axes") or {}

    if not axes:
        ct = 0.0
        if _get(r, "has_accessibility_abuse"): ct += 40
        if _get(r, "has_sms_read_write"): ct += 35
        if _get(r, "has_system_alert_window"): ct += 25
        axes = {
            "CT": min(ct, 100),
            "BT": 60.0 if _get(r, "targets_indian_banks") else 0.0,
            "PR": min(len(_get(r, "all_permissions") or []) * 5, 100),
            "OB": round(float(_get(r, "obfuscation_score", default=0)) * 100, 1),
            "IR": min(len(_get(r, "hardcoded_urls_ips") or []) * 10, 100),
        }

    axis_defs = [
        ("CT", "Credential Theft", "axis-ct"),
        ("BT", "Banking Targeting", "axis-bt"),
        ("PR", "Permission Risk", "axis-pr"),
        ("OB", "Obfuscation", "axis-ob"),
        ("IR", "Infrastructure Risk", "axis-ir"),
    ]
    rows = ""
    for key, label, cls in axis_defs:
        val = float(axes.get(key, 0))
        rows += (
            f'<div class="stei-row {cls}">'
            f'<div class="stei-label">{label}</div>'
            f'<div class="stei-bar-track">'
            f'<div class="stei-bar-fill" style="width:{min(val, 100):.1f}%"></div>'
            f'</div>'
            f'<div class="stei-score">{val:.0f}</div>'
            f'</div>'
        )

    formula = _get(frs_bd, "formula_used", default="static_only_frs")
    formula_label = "Dynamic-Weighted FRS" if "dynamic" in str(formula) else "Static-Only FRS"

    return (
        f'<div class="section">'
        + _section_header("&#x1F4CA;", "rgba(88,166,255,.15)", "5-Axis STEI Breakdown", formula_label)
        + f'<div class="stei-grid">{rows}</div>'
        f'</div>'
    )


def _build_static(r: Dict, idx: _FindingIndex) -> str:
    perms = _get(r, "all_permissions") or []
    urls = _get(r, "hardcoded_urls_ips") or []
    secrets = _get(r, "hardcoded_secrets") or []
    cert = _get(r, "certificate") or {}
    manifest_findings = _get(r, "manifest_findings") or []
    activities = _get(r, "activities") or []
    services = _get(r, "services") or []
    receivers = _get(r, "receivers") or []
    obf = float(_get(r, "obfuscation_score", default=0))
    has_ref = bool(_get(r, "has_reflection"))
    jadx = _get(r, "jadx_enrichment") or {}

    html = f'<div class="section">' + _section_header("&#x1F52C;", "rgba(63,185,80,.15)", "Static Forensic Analysis")

    cert_subject = _get(cert, "subject") or _get(cert, "issuer") or ""
    cert_valid = _get(cert, "valid_from") or ""

    cert_subj_html = _esc(cert_subject) if cert_subject else '<span class="no-data">Not available</span>'
    cert_valid_html = _esc(cert_valid) if cert_valid else '<span class="no-data">Not available</span>'

    html += (
        f'<div class="grid-2 mt8">'
        f'<div class="info-card"><div class="info-key">Package Name</div>'
        f'<div class="info-val info-val-mono">{_esc(_get(r, "package_name"))}</div></div>'
        f'<div class="info-card"><div class="info-key">Family Classification</div>'
        f'<div class="info-val">{_esc(_get(r, "family_classification", default="Unknown"))}</div></div>'
        f'<div class="info-card"><div class="info-key">Certificate Subject</div>'
        f'<div class="info-val info-val-mono">'
        f'{cert_subj_html}</div></div>'
        f'<div class="info-card"><div class="info-key">Cert Valid From</div>'
        f'<div class="info-val">'
        f'{cert_valid_html}</div></div>'
        f'</div>'
    )

    # Permissions
    html += '<div class="mt12"><h3>Permission Exposure Matrix</h3><div class="perm-grid">'
    if perms:
        for p in sorted(perms):
            is_d = p in _DANGEROUS_PERMS
            cls = "perm-danger" if is_d else "perm-normal"
            short = p.replace("android.permission.", "")
            fid_label = ""
            if is_d:
                fid = idx.next("STAT", f"Dangerous permission: {short}")
                fid_label = f"[{fid}] "
            html += f'<span class="perm-tag {cls}" title="{_esc(p)}">{fid_label}{_esc(short)}</span>'
    else:
        html += '<span class="no-data">No permissions declared</span>'
    html += '</div></div>'

    # Obfuscation
    obf_pct = obf * 100 if obf <= 1.0 else obf
    obf_fid = f'<span class="sev sev-high">[{idx.next("STAT", f"Obfuscation Score: {obf_pct:.0f}%")}]</span>' if obf_pct > 30 else ""
    ref_fid = f'<span class="sev sev-high">[{idx.next("STAT", "Dynamic Reflection detected")}]</span>' if has_ref else ""

    html += (
        f'<div class="grid-2 mt12">'
        f'<div class="info-card"><div class="info-key">Obfuscation Score {obf_fid}</div>'
        f'<div class="info-val">{obf_pct:.0f}% string entropy</div></div>'
        f'<div class="info-card"><div class="info-key">Dynamic Reflection {ref_fid}</div>'
        f'<div class="info-val">{"Detected &mdash; Class.forName / Method.invoke" if has_ref else "Not detected"}</div></div>'
        f'</div>'
    )

    # Hardcoded URLs
    if urls:
        html += '<div class="mt12"><h3>Hardcoded Network Indicators</h3>'
        for u in urls[:20]:
            fid = idx.next("STAT", f"Hardcoded URL/IP: {u[:60]}")
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title"><code>{_esc(u[:80])}</code>'
                f'<span class="sev sev-high">HIGH</span></div>'
                f'<div class="finding-desc">Hardcoded network indicator. May indicate C2 infrastructure or exfiltration endpoint.</div>'
                f'</div></div>'
            )
        html += '</div>'

    # Hardcoded Secrets
    if secrets:
        html += '<div class="mt12"><h3>Hardcoded Secrets</h3>'
        for s in secrets[:10]:
            fid = idx.next("STAT", f"Hardcoded secret: {str(s)[:40]}")
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title"><code>{_esc(str(s)[:80])}</code>'
                f'<span class="sev sev-medium">MEDIUM</span></div>'
                f'<div class="finding-desc">Credential or key material embedded in APK strings.</div>'
                f'</div></div>'
            )
        html += '</div>'

    # Manifest findings
    if manifest_findings:
        html += '<div class="mt12"><h3>Manifest Security Findings</h3>'
        for mf in manifest_findings[:15]:
            sev = _get(mf, "severity", default="LOW")
            title = _get(mf, "title", default="")
            desc = _get(mf, "description", default="")
            comp = _get(mf, "component", default="")
            fid = idx.next("STAT", f"Manifest: {str(title)[:50]}")
            comp_str = f' &mdash; Component: <code>{_esc(comp)}</code>' if comp else ""
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">{_esc(title)}'
                f'<span class="sev {_sev_class(str(sev))}">{_esc(sev)}</span></div>'
                f'<div class="finding-desc">{_esc(desc)}{comp_str}</div>'
                f'</div></div>'
            )
        html += '</div>'

    # Exported components
    comp_rows = ""
    for ctype, clist in [("Activity", activities), ("Service", services), ("Receiver", receivers)]:
        for c in clist[:8]:
            comp_rows += f'<tr><td>{_esc(ctype)}</td><td><code>{_esc(c)}</code></td></tr>'
    if comp_rows:
        html += (
            f'<div class="mt12"><h3>Exported Components</h3>'
            f'<table class="data-table"><thead><tr><th>Type</th><th>Component</th></tr></thead>'
            f'<tbody>{comp_rows}</tbody></table></div>'
        )

    # JADX findings
    jadx_sigs = _get(jadx, "signature_matches") or _get(jadx, "findings") or []
    if jadx_sigs:
        html += '<div class="mt12"><h3>JADX Code Signature Findings</h3>'
        for sig in jadx_sigs[:8]:
            fid = idx.next("STAT", f"JADX: {str(sig)[:50]}")
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">{_esc(str(sig)[:120])}'
                f'<span class="sev sev-medium">MEDIUM</span></div>'
                f'<div class="finding-desc">Static code signature matched during JADX Java source decompilation.</div>'
                f'</div></div>'
            )
        html += '</div>'

    html += '</div>'
    return html


def _build_threat_intel(r: Dict, idx: _FindingIndex) -> str:
    tc = _get(r, "threat_correlation") or {}
    available = bool(_get(tc, "available"))
    sha_det = int(_get(tc, "sha256_detections", default=0))
    sha_tot = int(_get(tc, "sha256_total", default=0))
    vt_ratio = float(_get(tc, "vt_detection_ratio", default=0.0))
    vt_vendors = _get(tc, "vt_malicious_vendors") or []
    ioc_rep = _get(tc, "ioc_reputation") or []
    known_family = _get(tc, "known_family") or None
    campaign = _get(tc, "campaign") or None
    threat_score = float(_get(tc, "threat_score", default=0.0))
    sources = _get(tc, "sources_queried") or []

    intel = _get(r, "intelligence_report") or {}
    mitre_techs = _get(intel, "mitre_techniques_used") or []

    html = (
        f'<div class="section">'
        + _section_header("&#x1F310;", "rgba(210,153,34,.15)", "Threat Intelligence &amp; MITRE ATT&amp;CK")
    )

    if not available:
        sources_str = ", ".join(sources) if sources else "VirusTotal, AlienVault OTX, AbuseIPDB"
        html += (
            f'<div class="dynamic-status-banner">'
            f'<div class="dynamic-status-title">Threat Intelligence Correlation</div>'
            f'<div class="dynamic-status-code">[INTEL-STATUS: API KEYS NOT CONFIGURED]</div>'
            f'<div class="dynamic-status-detail">'
            f'Correlation requires API keys for {_esc(sources_str)}.<br>'
            f'Configure <code>VT_API_KEY</code>, <code>OTX_API_KEY</code>, <code>ABUSEIPDB_API_KEY</code> in <code>.env</code>.<br>'
            f'<strong>FRS uses the static-only formula</strong> (0.50&middot;STEI + 0.25&middot;Correlation + 0.25&middot;BankingImpact) when correlation is unavailable.'
            f'</div></div>'
        )
    else:
        ratio_pct = vt_ratio * 100 if vt_ratio <= 1.0 else vt_ratio
        num_cls = "rep-malicious" if sha_det > 0 else "rep-clean"
        ratio_cls = "rep-malicious" if ratio_pct > 30 else ("rep-suspicious" if ratio_pct > 0 else "rep-clean")
        ts_cls = "rep-malicious" if threat_score > 50 else "rep-suspicious"

        html += (
            f'<div class="grid-3 mb8">'
            f'<div class="intel-stat"><div class="intel-num {num_cls}">{sha_det}/{sha_tot}</div>'
            f'<div class="intel-sub">VT Detections</div></div>'
            f'<div class="intel-stat"><div class="intel-num {ratio_cls}">{ratio_pct:.0f}%</div>'
            f'<div class="intel-sub">Detection Ratio</div></div>'
            f'<div class="intel-stat"><div class="intel-num {ts_cls}">{threat_score:.0f}</div>'
            f'<div class="intel-sub">Threat Intel Score</div></div>'
            f'</div>'
        )

        if known_family:
            fid = idx.next("INTEL", f"Known malware family: {known_family}")
            camp_str = f' Campaign: <strong>{_esc(campaign)}</strong>.' if campaign else ""
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">Known Malware Family: <strong>{_esc(known_family)}</strong>'
                f'<span class="sev sev-critical">CRITICAL</span></div>'
                f'<div class="finding-desc">SHA-256 matches a known malware family in threat intelligence databases.{camp_str}</div>'
                f'</div></div>'
            )

        if vt_vendors:
            html += f'<div class="mt8"><h3>Detecting Vendors ({len(vt_vendors)})</h3><div class="perm-grid">'
            for v in vt_vendors[:20]:
                html += f'<span class="perm-tag perm-danger">{_esc(v)}</span>'
            html += '</div></div>'

        if ioc_rep:
            ioc_rows = ""
            for ioc in ioc_rep:
                ind = _get(ioc, "indicator", default="")
                itype = _get(ioc, "type", default="")
                rep = _get(ioc, "reputation", default="unknown")
                src = _get(ioc, "source", default="")
                fid = idx.next("INTEL", f"IOC: {str(ind)[:50]}")
                ioc_rows += (
                    f'<tr>'
                    f'<td style="font-family:var(--font-mono);color:var(--blue)">[{fid}]</td>'
                    f'<td><code>{_esc(str(ind)[:60])}</code></td>'
                    f'<td>{_esc(itype)}</td>'
                    f'<td class="{_rep_class(str(rep))}">{_esc(rep)}</td>'
                    f'<td>{_esc(src)}</td>'
                    f'</tr>'
                )
            html += (
                f'<div class="mt12"><h3>IOC Reputation</h3>'
                f'<table class="data-table"><thead>'
                f'<tr><th>ID</th><th>Indicator</th><th>Type</th><th>Reputation</th><th>Source</th></tr>'
                f'</thead><tbody>{ioc_rows}</tbody></table></div>'
            )

    # MITRE techniques
    if mitre_techs:
        html += '<div class="mt12"><h3>MITRE ATT&amp;CK Mobile Techniques</h3><div class="mitre-grid">'
        for tech in mitre_techs[:12]:
            parts = str(tech).split("\u2014", 1)
            tid = parts[0].strip()
            tname = parts[1].strip() if len(parts) > 1 else ""
            fid = idx.next("INTEL", f"MITRE: {str(tech)[:60]}")
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/" if re.match(r"T\d{4}", tid) else ""
            link = f'<a href="{url}" target="_blank">{_esc(tid)}</a>' if url else _esc(tid)
            tname_html = f'<div class="mitre-name">{_esc(tname)}</div>' if tname else ""
            html += (
                f'<div class="mitre-chip">'
                f'<div class="mitre-id">[{fid}] {link}</div>'
                f'{tname_html}'
                f'</div>'
            )
        html += '</div></div>'
    else:
        html += '<div class="mt12"><h3>MITRE ATT&amp;CK Mobile Techniques</h3><p class="no-data">No MITRE techniques mapped in this analysis run.</p></div>'

    html += '</div>'
    return html


def _build_dynamic(r: Dict, evidence_json: Optional[Dict], idx: _FindingIndex) -> str:
    """
    State-aware dynamic section.

    This section ALWAYS renders. It either shows a timeline (if evidence exists)
    or a diagnostic banner (if no evidence was captured). It NEVER renders blank
    and NEVER fabricates event rows when evidence_json is empty.
    """
    dyn = _get(r, "dynamic_analysis") or {}
    attack_timeline = _get(dyn, "attack_timeline") or []
    anti_analysis = _get(dyn, "anti_analysis_events") or []

    ev_records: List[Dict] = []
    if isinstance(evidence_json, dict):
        ev_records = evidence_json.get("records") or []

    fraud_wf = _get(r, "fraud_workflow") or {}
    wf_stages = _get(fraud_wf, "stages") or []

    has_any_dynamic = bool(ev_records or attack_timeline or wf_stages)

    html = (
        f'<div class="section">'
        + _section_header("&#x26A1;", "rgba(248,81,73,.15)",
                          "Dynamic Analysis", "Runtime Telemetry &amp; Attack Narrative")
    )

    if not has_any_dynamic:
        # ── Diagnostic banner — mandatory when no dynamic evidence ──
        frs_bd = _get(r, "frs_breakdown") or {}
        dyn_ran = bool(_get(frs_bd, "dynamic_ran"))

        if dyn_ran:
            cause = (
                "The sandbox executed but no hook-triggering behaviour was observed during the analysis window. "
                "Likely causes: the application detects the Frida environment and goes dormant; "
                "the malicious payload requires a specific external trigger (SMS, locale match, C2 command, or time delay) "
                "not present in the analysis session; or the hardcoded accessibility service class name is obfuscated "
                "and was not resolved correctly (see DAE_CURRENT_STATE.md Defect #1)."
            )
        else:
            cause = (
                "The dynamic sandbox did not execute for this sample. "
                "Likely causes: SELinux enforcement blocked ptrace injection; "
                "the APK has no launchable activity declared in the manifest; "
                "or the sample failed to install (malformed manifest, missing signature). "
                "The FRS score above reflects static-only analysis."
            )

        html += (
            f'<div class="dynamic-status-banner">'
            f'<div class="dynamic-status-title">Dynamic Execution Status</div>'
            f'<div class="dynamic-status-code">[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]</div>'
            f'<div class="dynamic-status-detail">'
            f'{_esc(cause)}<br><br>'
            f'<strong>This is an honest system state, not a report error.</strong> '
            f'No dynamic event rows have been generated because no runtime events were observed. '
            f'The FRS score and all findings above are based solely on static analysis evidence.'
            f'</div></div>'
        )
    else:
        # ── Evidence timeline ──
        if ev_records:
            html += '<h3 class="mt8">Runtime Evidence Timeline</h3><div class="timeline">'
            for rec in ev_records[:30]:
                fid_in = _get(rec, "finding_id") or idx.next("EVID", str(_get(rec, "api", default="Event"))[:50])
                ts_raw = _get(rec, "timestamp", default=0)
                try:
                    ts_str = datetime.fromtimestamp(float(ts_raw) / 1000, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
                except Exception:
                    ts_str = "—"
                api = _esc(_get(rec, "api", default="Unknown API"))
                desc = _esc(_get(rec, "description") or _get(rec, "human_description", default=""))
                sev = str(_get(rec, "severity", default="LOW"))
                mitre = _esc(_get(rec, "mitre_technique_id", default=""))
                mitre_str = f" &mdash; {mitre}" if mitre else ""
                desc_html = f'<div class="tl-desc">{desc}</div>' if desc else ""
                html += (
                    f'<div class="tl-event">'
                    f'<div class="tl-ts">[{fid_in}] {ts_str}{mitre_str} '
                    f'<span class="sev {_sev_class(sev)}">{_esc(sev)}</span></div>'
                    f'<div class="tl-api">{api}</div>'
                    f'{desc_html}'
                    f'</div>'
                )
            html += '</div>'

        # ── Fraud workflow ──
        if wf_stages:
            html += '<h3 class="mt12">Reconstructed Fraud Workflow</h3><div class="timeline">'
            for stage in wf_stages:
                label = _esc(_get(stage, "label", default=""))
                tid = _esc(_get(stage, "technique_id", default=""))
                desc = _esc(_get(stage, "description", default=""))
                conf = float(_get(stage, "confidence", default=0))
                ev_ids = _get(stage, "evidence_ids") or []
                fid = idx.next("EVID", f"Workflow stage: {_get(stage, 'label', default='')[:40]}")
                ev_refs = ", ".join(ev_ids[:4]) if ev_ids else ""
                ev_refs_str = f" | Evidence: {_esc(ev_refs)}" if ev_refs else ""
                desc_html = f'<div class="tl-desc">{desc}</div>' if desc else ""
                html += (
                    f'<div class="tl-event">'
                    f'<div class="tl-ts">[{fid}] {tid} &mdash; Confidence: {conf*100:.0f}%'
                    f'{ev_refs_str}</div>'
                    f'<div class="tl-api">{label}</div>'
                    f'{desc_html}'
                    f'</div>'
                )
            html += '</div>'

    # Anti-analysis detections (shown regardless of telemetry state)
    if anti_analysis:
        html += '<h3 class="mt12">Anti-Analysis Detections</h3>'
        for aa in anti_analysis[:8]:
            tech = _esc(_get(aa, "technique", default=str(aa)))
            desc = _esc(_get(aa, "description", default=""))
            fid = idx.next("EVID", f"Anti-analysis: {str(_get(aa, 'technique', default=''))[:50]}")
            desc_html = f'<div class="finding-desc">{desc}</div>' if desc else ""
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">{tech}'
                f'<span class="sev sev-high">HIGH</span></div>'
                f'{desc_html}'
                f'</div></div>'
            )

    html += '</div>'
    return html


def _load_screenshot_entries(
    apk_dir: Optional[Path],
    report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Resolve screenshot manifest from every persisted location.

    Historical bug: manifests were flushed to screenshots.json at artifact root
    while the report generator only read screenshots/manifest.json — gallery
    sections appeared empty despite PNGs on disk.
    """
    if report is None:
        report = {}
    entries: List[Dict[str, Any]] = []
    candidates: List[Path] = []
    if apk_dir:
        candidates.extend([
            apk_dir / "screenshots" / "manifest.json",
            apk_dir / "manifest.json",
            apk_dir / "screenshots.json",
        ])
    for manifest_path in candidates:
        if not manifest_path.is_file():
            continue
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            shots = data.get("screenshots", [])
            if shots:
                entries = shots
                break
        except Exception as e:
            logger.warning("[ReportGen] Failed to load %s: %s", manifest_path, e)

    if entries:
        return entries

    # Fallback: paths listed on the analysis result (API / DB rehydration).
    dyn = _get(report, "dynamic_analysis") or {}
    paths = (
        _get(dyn, "screenshots")
        or _get(report, "screenshots")
        or []
    )
    for i, rel in enumerate(paths):
        if not rel:
            continue
        entries.append({
            "screenshot_id": f"SCR-{i + 1:03d}",
            "filename": rel,
            "label": Path(str(rel)).stem,
            "source": "result_fallback",
        })
    return entries


def _build_visual_gallery(
    apk_dir: Optional[Path],
    idx: _FindingIndex,
    report: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Renders the Visual UI & Dynamic Evidence Gallery section.
    Loads screenshots/manifest.json from apk_dir, reads screenshot PNG files,
    encodes them as Base64 data URIs, and renders responsive cards.
    """
    if not apk_dir and not report:
        return ""

    screenshots = _load_screenshot_entries(apk_dir, report)
    if not screenshots:
        return ""

    html = (
        f'<div class="section">'
        + _section_header("&#x1F4F8;", "rgba(88,166,255,.15)", "Visual UI &amp; Dynamic Evidence Gallery", f"{len(screenshots)} screenshots captured")
        + '<div class="gallery-grid">'
    )

    import base64
    for scr in screenshots:
        scr_id = _esc(scr.get("screenshot_id", "SCR-???"))
        label = _esc(scr.get("label", "ui_capture"))
        trigger_evid = _esc(scr.get("trigger_event", ""))
        category = _esc(scr.get("category", "ui"))
        source = _esc(scr.get("source", "manual"))
        reason = _esc(scr.get("reason", ""))
        activity = _esc(scr.get("activity", ""))
        rel_fn = scr.get("filename", "")

        img_path = Path(rel_fn) if rel_fn else Path()
        if apk_dir:
            if rel_fn:
                img_path = apk_dir / rel_fn
                if not img_path.exists():
                    img_path = apk_dir / "screenshots" / Path(rel_fn).name
            else:
                img_path = apk_dir / "screenshots" / "missing.png"

        b64_uri = ""
        if apk_dir and img_path.exists():
            try:
                img_bytes = img_path.read_bytes()
                b64_str = base64.b64encode(img_bytes).decode("utf-8")
                b64_uri = f"data:image/png;base64,{b64_str}"
            except Exception as e:
                logger.warning("[ReportGen] Failed to encode %s: %s", img_path, e)

        fid = idx.next("SCR", f"Screenshot {scr_id}: {label}")
        evid_badge = f'<span class="perm-tag perm-danger">Ref: [{trigger_evid}]</span>' if trigger_evid else ""
        src_badge = f'<span class="perm-tag perm-normal">{source}</span>'
        reason_line = (
            f'<span>Reason: {reason}</span>' if reason else ""
        )
        act_line = (
            f'<span>Activity: {activity}</span>' if activity else ""
        )

        img_html = (
            f'<img src="{b64_uri}" alt="{scr_id}" class="scr-img" loading="lazy" />'
            if b64_uri else '<div class="no-data">Image payload unavailable</div>'
        )

        html += (
            f'<div class="gallery-card">'
            f'<div class="scr-header">'
            f'<span class="scr-id">[{fid}] {scr_id}</span>'
            f'<span class="scr-label">{label}</span>'
            f'</div>'
            f'<div class="scr-body">{img_html}</div>'
            f'<div class="scr-meta">'
            f'<span>Cat: {category}</span>'
            f'{reason_line}{act_line}'
            f'<div>{src_badge}{evid_badge}</div>'
            f'</div>'
            f'</div>'
        )

    html += '</div></div>'
    return html


def _build_exploration_coverage(r: Dict, apk_dir: Optional[Path], idx: _FindingIndex) -> str:
    """
    Renders the Autonomous UI Exploration & Coverage Metrics section.
    Reads coverage metrics and screen graph from apk_dir if present.
    """
    dyn = _get(r, "dynamic_analysis") or {}
    cov = _get(dyn, "coverage_metrics") or {}

    sg_data = None
    if apk_dir:
        sg_path = apk_dir / "screen_graph.json"
        if sg_path.exists():
            try:
                sg_data = json.loads(sg_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    total_screens = _get(cov, "total_screens_discovered", default=_get(sg_data or {}, "total_unique_screens", default=0))
    visited_screens = _get(cov, "unique_screens_visited", default=total_screens)
    cov_pct = _get(cov, "exploration_coverage_percent", default=100.0 if visited_screens > 0 else 0.0)
    nodes_interacted = _get(cov, "nodes_interacted", default=0)
    loops_broken = _get(cov, "loops_detected_and_broken", default=0)
    perms_granted = _get(cov, "permissions_granted", default=0)

    if not total_screens and not sg_data and not cov:
        return ""

    fid = idx.next("INTEL", "UI Exploration Coverage Summary")

    html = (
        f'<div class="section">'
        + _section_header("&#x1F9E0;", "rgba(139,148,158,.15)", "Autonomous UI Exploration &amp; Coverage Metrics", f"[{fid}]")
        + '<div class="grid-3 mb8">'
        + f'<div class="intel-stat"><div class="intel-num">{visited_screens}/{total_screens}</div><div class="intel-sub">Screens Visited</div></div>'
        + f'<div class="intel-stat"><div class="intel-num">{cov_pct:.1f}%</div><div class="intel-sub">Coverage Score</div></div>'
        + f'<div class="intel-stat"><div class="intel-num">{nodes_interacted}</div><div class="intel-sub">Nodes Interacted</div></div>'
        + '</div>'
        + '<div class="grid-2 mt12">'
        + f'<div class="info-card"><div class="info-key">Permissions Granted</div><div class="info-val">{perms_granted}</div></div>'
        + f'<div class="info-card"><div class="info-key">Loops Broken</div><div class="info-val">{loops_broken}</div></div>'
        + '</div></div>'
    )
    return html




def _build_recommendations(r: Dict) -> str:
    intel = _get(r, "intelligence_report") or {}
    actions = _get(intel, "recommended_actions") or []
    if not actions:
        ev = _get(r, "executive_view") or {}
        actions = _get(ev, "recommended_actions") or []

    if not actions:
        band = str(_get(r, "risk_band", default="")).lower()
        if "critical" in band:
            actions = [
                "Immediately block this application from all managed devices via MDM policy.",
                "Revoke any banking credentials that may have been exposed on this device.",
                "Alert affected users with the customer advisory draft below.",
                "Submit SHA-256 to your SIEM / threat intelligence platform as a malicious indicator.",
                "Escalate to SOC Level 2 for full incident response procedures.",
            ]
        elif "high" in band:
            actions = [
                "Flag application for quarantine pending further investigation.",
                "Enable step-up authentication for accounts that accessed this device.",
                "Monitor for unusual transaction patterns over the next 72 hours.",
                "Submit IOCs to your threat intelligence platform.",
            ]
        else:
            actions = [
                "Review the application source and distribution channel.",
                "Continue monitoring; no immediate action required based on current evidence.",
            ]

    advisory = _get(intel, "customer_advisory_draft") or ""
    if not advisory:
        ev = _get(r, "executive_view") or {}
        advisory = _get(ev, "customer_advisory_draft") or ""

    html = (
        f'<div class="section">'
        + _section_header("&#x1F6E1;&#xFE0F;", "rgba(63,185,80,.15)", "Recommendations &amp; Remediation")
        + '<ul class="rec-list">'
    )
    for i, act in enumerate(actions, 1):
        html += (
            f'<li class="rec-item">'
            f'<div class="rec-num">{i}</div>'
            f'<div class="rec-text">{_esc(act)}</div>'
            f'</li>'
        )
    html += '</ul>'

    if advisory:
        html += (
            f'<div class="verdict-banner verdict-medium mt12">'
            f'<div class="verdict-icon">&#x1F4E2;</div>'
            f'<div><div class="verdict-q">Customer Advisory Draft</div>'
            f'<div class="verdict-narrative">{_esc(advisory)}</div>'
            f'</div></div>'
        )

    html += '</div>'
    return html


def _build_threat_scenario_table(r: Dict, idx: _FindingIndex) -> str:
    rows_data = _get(r, "threat_scenario_table") or []
    if not rows_data:
        return ""

    def rbadge(v: str) -> str:
        c = {"high": "sev-high", "critical": "sev-critical",
             "medium": "sev-medium", "low": "sev-low"}.get(str(v).lower(), "sev-low")
        return f'<span class="sev {c}">{_esc(v)}</span>'

    html = (
        f'<div class="section">'
        + _section_header("&#x1F3AF;", "rgba(240,136,62,.15)", "Threat Scenario Correlation Table")
        + '<table class="data-table"><thead>'
        + '<tr><th>ID</th><th>Indicator</th><th>Threat Scenario</th>'
        + '<th>Overlay</th><th>Credential Theft</th><th>C2 Risk</th><th>Confidence</th></tr>'
        + '</thead><tbody>'
    )
    for row in rows_data:
        ind = _get(row, "indicator", default="")
        scenario = _get(row, "threat_scenario", default="")
        overlay = str(_get(row, "overlay_risk", default=""))
        cred = str(_get(row, "credential_theft_risk", default=""))
        c2 = str(_get(row, "c2_risk", default=""))
        conf = _get(row, "confidence", default=0)
        fid = idx.next("STAT", f"Threat scenario: {str(scenario)[:50]}")
        html += (
            f'<tr>'
            f'<td style="font-family:var(--font-mono);color:var(--blue)">[{fid}]</td>'
            f'<td>{_esc(ind)}</td><td>{_esc(scenario)}</td>'
            f'<td>{rbadge(overlay)}</td><td>{rbadge(cred)}</td><td>{rbadge(c2)}</td>'
            f'<td>{conf}%</td>'
            f'</tr>'
        )
    html += '</tbody></table></div>'
    return html


def _build_ledger(idx: _FindingIndex) -> str:
    if not idx.ledger:
        return ""
    html = (
        f'<div class="section">'
        + _section_header(
            "&#x1F4CB;", "rgba(139,148,158,.15)",
            "Evidence Ledger",
            f"{len(idx.ledger)} findings indexed"
        )
        + '<table class="data-table"><thead>'
        + '<tr><th>Finding ID</th><th>Category</th><th>Description</th></tr>'
        + '</thead><tbody>'
    )
    for fid, cat, title in idx.ledger:
        html += f'<tr><td style="font-family:var(--font-mono);color:var(--blue)">[{fid}]</td><td>{_esc(cat)}</td><td>{_esc(title[:100])}</td></tr>'
    html += '</tbody></table></div>'
    return html


def _build_footer(r: Dict) -> str:
    sha = _esc(_get(r, "sha256", default=""))
    return (
        f'<div class="report-footer">'
        f'Sudarshan Banking Malware Intelligence Platform &nbsp;&middot;&nbsp; '
        f'Deterministic scoring &mdash; AI explains, AI does not decide &nbsp;&middot;&nbsp; '
        f'SHA-256: {sha} &nbsp;&middot;&nbsp; '
        f'Dynamic findings marked [TARGET-STATE] are design intent not confirmed by runtime instrumentation.'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Generates a standalone, single-file HTML malware analysis report.

    Parameters
    ----------
    report : dict
        Serialised AnalysisResponse (dict or Pydantic .model_dump()).
    apk_dir : Path, optional
        Directory containing per-sample JSON artifacts (evidence.json, etc.).
        Missing files are handled gracefully.
    """

    def __init__(self, report: Dict[str, Any], apk_dir: Optional[Path] = None):
        self.r = report
        self.apk_dir = Path(apk_dir) if apk_dir else None

    def _load_artifact(self, filename: str) -> Optional[Any]:
        if not self.apk_dir:
            return None
        path = self.apk_dir / filename
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("[ReportGen] Could not load %s: %s", filename, e)
        return None

    def render(self, output_path: Optional[Path] = None) -> str:
        """Render the report. Optionally write to disk. Returns HTML string."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        idx = _FindingIndex()
        evidence_json = self._load_artifact("evidence.json")
        visual_exec = build_executive_visual_html(self.apk_dir)
        visual_tech = build_technical_visual_html(self.apk_dir)
        visual_appendix = build_appendix_visual_html(self.apk_dir)

        body = (
            _build_header(self.r, ts)
            + _build_stei(self.r)
            + _build_threat_scenario_table(self.r, idx)
            + _build_static(self.r, idx)
            + _build_threat_intel(self.r, idx)
            + _build_dynamic(self.r, evidence_json, idx)
            + visual_exec
            + _build_visual_gallery(self.apk_dir, idx, self.r)
            + visual_tech
            + _build_exploration_coverage(self.r, self.apk_dir, idx)
            + _build_recommendations(self.r)
            + visual_appendix
            + _build_ledger(idx)
            + _build_footer(self.r)
        )

        pkg = _esc(_get(self.r, "package_name", default="Unknown"))
        frs = float(_get(self.r, "final_risk_score", default=0))
        band = _esc(_get(self.r, "risk_band", default="Unknown"))

        html = (
            f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            f'<meta charset="UTF-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>Sudarshan Report &mdash; {pkg}</title>\n'
            f'<meta name="description" content="Sudarshan malware analysis report for {pkg}. '
            f'FRS: {frs:.0f}, Band: {band}.">\n'
            f'<style>{_CSS}</style>\n'
            f'</head>\n<body>\n<div class="container">\n'
            f'{body}\n'
            f'</div>\n</body>\n</html>'
        )

        if output_path:
            try:
                Path(output_path).write_text(html, encoding="utf-8")
                logger.info("[ReportGen] Report written to %s", output_path)
            except Exception as e:
                logger.error("[ReportGen] Failed to write report: %s", e)

        return html


def build_report(
    report: Dict[str, Any],
    apk_dir: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> str:
    """
    Convenience function: build and return the HTML report.

    Parameters
    ----------
    report : dict
        Serialised AnalysisResponse.
    apk_dir : Path, optional
        Directory containing per-sample JSON artifacts.
    output_path : Path, optional
        If provided, write HTML to this path.
    """
    return ReportGenerator(report, apk_dir).render(output_path)
