"""
SUDARSHAN - Report Generator v2
=================================
Generates a standalone, single-file HTML malware analysis report from the
collected AnalysisResponse and per-sample JSON artifacts of a pipeline run.

Design principles:
  - Self-contained: inline CSS only, no external CDN, no JavaScript
  - State-aware: renders honestly whether dynamic evidence is full, empty, or absent
  - Evidence IDs: every finding is indexed [STAT-NNN], [INTEL-NNN], [EVID-NNN]
  - No fabrication: dynamic section ALWAYS renders - either a timeline or an
    explicit [DYNAMIC-STATUS: NO TELEMETRY CAPTURED] diagnostic panel
  - Print-ready: @media print light theme for PDF via browser Ctrl+P

Usage:
    from sudarshan_core.engines.report_generator import ReportGenerator, build_report
    html = build_report(analysis_response_dict, apk_artifact_dir)
    # or write to disk:
    build_report(analysis_response_dict, apk_artifact_dir, output_path=Path("report.html"))
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core import brand as BRAND
from sudarshan_core.visual_evidence.report_sections import (
    build_appendix_visual_html,
    build_executive_visual_html,
    build_technical_visual_html,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CSS - self-contained, dark screen theme + light print theme
# ---------------------------------------------------------------------------

from sudarshan_core.engines import report_theme as T

_CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --ink:%(INK)s;--ink-strong:%(INK_STRONG)s;--ink-muted:%(INK_MUTED)s;
  --ink-faint:%(INK_FAINT)s;--ink-disabled:%(INK_DISABLED)s;
  --paper:%(PAPER)s;--surface:%(SURFACE)s;--surface-inset:%(SURFACE_INSET)s;
  --surface-sunk:%(SURFACE_SUNK)s;
  --border:%(BORDER)s;--border-strong:%(BORDER_STRONG)s;--rule-hair:%(RULE_HAIR)s;
  --accent:%(ACCENT)s;--accent-soft:%(ACCENT_SOFT)s;

  --risk-critical:%(RISK_CRITICAL)s;--risk-high:%(RISK_HIGH)s;
  --risk-suspicious:%(RISK_SUSPICIOUS)s;--risk-safe:%(RISK_SAFE)s;
  --risk-neutral:%(RISK_NEUTRAL)s;
  --tint-critical:%(TINT_CRITICAL)s;--tint-high:%(TINT_HIGH)s;
  --tint-suspicious:%(TINT_SUSPICIOUS)s;--tint-safe:%(TINT_SAFE)s;
  --tint-neutral:%(TINT_NEUTRAL)s;
  --edge-critical:%(EDGE_CRITICAL)s;--edge-high:%(EDGE_HIGH)s;
  --edge-suspicious:%(EDGE_SUSPICIOUS)s;--edge-safe:%(EDGE_SAFE)s;
  --edge-neutral:%(EDGE_NEUTRAL)s;

  --font:%(FONT_SANS)s;
  --font-serif:%(FONT_SERIF)s;
  --font-mono:%(FONT_MONO)s;

  /* 4pt spacing scale - every gap in the document is a multiple of it */
  --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:20px;--s6:24px;
  --s7:32px;--s8:40px;--s9:56px;
  --radius:2px;
  --label:.6875rem;   /* 11px - all uppercase micro-labels */
}

html{-webkit-text-size-adjust:100%%}
body{
  font-family:var(--font-serif);background:var(--surface-inset);color:var(--ink);
  font-size:14px;line-height:1.62;
  font-variant-numeric:lining-nums;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;
}

/* Page shell */
.container{
  max-width:1000px;margin:0 auto;background:var(--paper);
  padding:var(--s9) var(--s8) var(--s8);
  border-left:1px solid var(--border);border-right:1px solid var(--border);
  min-height:100vh;
}

/* Type */
h1{font-family:var(--font-serif);font-size:1.75rem;font-weight:600;
   line-height:1.25;color:var(--ink-strong);letter-spacing:-.01em}
h2{font-family:var(--font);font-size:1.0625rem;font-weight:600;
   color:var(--ink-strong);letter-spacing:-.005em;line-height:1.4}
h3{font-family:var(--font);font-size:.8125rem;font-weight:700;
   color:var(--ink-strong);letter-spacing:.01em;margin-bottom:var(--s3);
   padding-bottom:var(--s2);border-bottom:1px solid var(--rule-hair)}
h4{font-family:var(--font);font-size:.8125rem;font-weight:600;
   color:var(--ink);margin-bottom:var(--s2)}
/* Continuous prose is held to a 90-character measure; only tables and
   evidence blocks are set to the full width of the text block. */
p{color:var(--ink);margin-bottom:var(--s3);max-width:90ch}
p:last-child{margin-bottom:0}
strong,b{color:var(--ink-strong);font-weight:600}
code{font-family:var(--font-mono);font-size:.8125em;background:var(--surface-inset);
     padding:1px 5px;border-radius:var(--radius);color:var(--ink);
     border:1px solid var(--rule-hair)}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid var(--border-strong)}

/* Cover */
.report-header{
  border-bottom:1px solid var(--border-strong);
  padding:0 0 var(--s7);margin-bottom:var(--s8);
}
/* Masthead band: brand left, document control right, 2pt rule beneath. */
.report-meta{display:flex;align-items:center;justify-content:space-between;
             gap:var(--s6);flex-wrap:wrap;
             padding-bottom:var(--s4);
             border-bottom:2px solid var(--ink-strong)}
.report-brand{display:flex;align-items:center;gap:var(--s4)}
/* The mark is the one image in the document's furniture. It is black line art
   on transparency - the same single ink as the type beside it - so it prints,
   photocopies and greyscales without turning to mush, which the colour
   version of the mark would not. */
.brand-mark{width:46px;height:46px;flex-shrink:0;display:block}
.brand-mark-fallback{
  width:46px;height:46px;border:1px solid var(--ink-strong);
  color:var(--ink-strong);display:flex;align-items:center;justify-content:center;
  font-family:var(--font-serif);font-size:22px;font-weight:600;flex-shrink:0;
}
.brand-name{font-family:var(--font);font-size:1.5rem;font-weight:700;
            color:var(--ink-strong);letter-spacing:.02em;
            text-transform:uppercase;line-height:1.05}
.brand-sub{font-family:var(--font);font-size:.8125rem;color:var(--ink-muted);
           letter-spacing:.01em;margin-top:3px}
.report-ts{font-family:var(--font);font-size:.6875rem;color:var(--ink-faint);
           text-align:right;line-height:1.85}
.report-ts b{color:var(--ink-strong);font-weight:600}
.report-ts .doc-classification{letter-spacing:.04em}

.app-identity{margin-top:var(--s7);padding-top:var(--s6);
              border-top:1px solid var(--rule-hair)}
.doc-kicker{font-size:var(--label);letter-spacing:.14em;text-transform:uppercase;
            color:var(--ink-faint);margin-bottom:var(--s2)}
.app-name{font-family:var(--font-serif);font-size:1.75rem;font-weight:600;
          color:var(--ink-strong);line-height:1.25;margin-bottom:var(--s1)}
.app-pkg{font-family:var(--font-mono);font-size:.8125rem;color:var(--ink-muted)}
.hash-row{margin-top:var(--s3);font-family:var(--font-mono);font-size:.75rem;
          color:var(--ink-faint);word-break:break-all}

/* Verdict block. There is no dial: a dial encodes with angle, which reads
   worse than position or length and cannot be read to a decimal place, and
   the exact figure is printed here anyway. */
.score-block{
  display:grid;grid-template-columns:1fr;
  gap:var(--s3);padding:var(--s5) 0;margin-top:var(--s6);
  border-top:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);
}
.score-figure{font-family:var(--font-serif);font-size:2rem;font-weight:600;
              line-height:1;color:var(--ink-strong);
              font-variant-numeric:lining-nums tabular-nums}
.score-of{font-size:.8125rem;color:var(--ink-faint);margin-left:var(--s2)}
.score-detail{min-width:0}
.risk-band-badge{
  font-family:var(--font);display:inline-block;padding:2px 0;
  font-size:.8125rem;font-weight:700;text-transform:uppercase;
  letter-spacing:.04em;margin-bottom:var(--s2);border:0;background:none;
}
.band-critical{background:var(--tint-critical);color:var(--risk-critical);border-color:var(--edge-critical)}
.band-high{background:var(--tint-high);color:var(--risk-high);border-color:var(--edge-high)}
.band-medium{background:var(--tint-suspicious);color:var(--risk-suspicious);border-color:var(--edge-suspicious)}
.band-safe{background:var(--tint-safe);color:var(--risk-safe);border-color:var(--edge-safe)}
.score-subtext{font-size:.8125rem;color:var(--ink-muted);max-width:90ch}
.scope-note{font-size:.75rem;color:var(--ink-faint);line-height:1.65;
            max-width:90ch;margin-top:var(--s4)}

/* Verdict / advisory callout */
/* A ruled block, not a tinted panel with a coloured edge. */
.verdict-banner{
  border:0;border-top:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);
  padding:var(--s5) 0;margin-top:var(--s4);
  display:grid;grid-template-columns:1fr;gap:var(--s2);
}
.verdict-critical,.verdict-high,.verdict-medium,.verdict-safe{background:none}
.verdict-icon{display:none}
.verdict-q{font-size:var(--label);font-weight:700;text-transform:uppercase;
           letter-spacing:.11em;color:var(--ink-faint)}
.verdict-answer{font-size:.9375rem;font-weight:600;color:var(--ink-strong);line-height:1.55}
.verdict-narrative{font-size:.8438rem;color:var(--ink-muted);line-height:1.75;max-width:76ch}

/* Part dividers */
.part{margin-top:var(--s9)}
.part-divider{
  display:grid;grid-template-columns:auto 1fr;align-items:baseline;
  column-gap:var(--s5);row-gap:var(--s2);
  border-top:2px solid var(--ink-strong);padding-top:var(--s4);
  margin-bottom:var(--s6);
}
.part-label{
  font-size:var(--label);font-weight:700;letter-spacing:.16em;
  text-transform:uppercase;color:var(--ink-faint);white-space:nowrap;
}
.part-title{font-family:var(--font-serif);font-size:1.25rem;font-weight:600;
            color:var(--ink-strong)}
.part-desc{grid-column:2;font-size:.8125rem;color:var(--ink-muted);
           margin:0;max-width:76ch}

/* Sections */
/* A section is a run of the document, not a card floated on a ground. The
   border and the inset padding both went: a page of outlined panels is
   dashboard furniture, and it is the first thing that reads as generated. */
.section{
  background:var(--paper);padding:0;margin-bottom:var(--s7);
}
.section-header{
  display:grid;grid-template-columns:1fr auto;align-items:baseline;
  gap:var(--s4);margin-bottom:var(--s5);padding-bottom:var(--s3);
  border-bottom:1px solid var(--border);
}
.section-icon{display:none}
.section-note{font-size:var(--label);color:var(--ink-faint);letter-spacing:.06em;
              text-transform:uppercase;white-space:nowrap;text-align:right}
.section-lead{font-size:.8125rem;color:var(--ink-muted);margin-bottom:var(--s4)}

.grid-2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--s3)}
.grid-3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--s3)}

/* Key/value cards */
.info-card{
  background:var(--paper);border:0;border-top:1px solid var(--rule-hair);
  padding:var(--s3) 0;
  display:grid;grid-template-rows:auto 1fr;gap:var(--s1);align-content:start;
}
.info-key{font-size:.6875rem;font-weight:700;text-transform:uppercase;
          letter-spacing:.09em;color:var(--ink-faint)}
.info-val{font-size:.875rem;color:var(--ink-strong);word-break:break-word;line-height:1.5}
.info-val-mono{font-family:var(--font-mono);font-size:.75rem}

/* Tables */
.data-table,.tbl{width:100%%;border-collapse:collapse;font-size:.8125rem}
.data-table th,.tbl th{
  font-family:var(--font);text-align:left;padding:var(--s2) var(--s3);
  background:var(--surface-inset);color:var(--ink-strong);font-weight:700;
  font-size:.6875rem;letter-spacing:.02em;
  border-top:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);white-space:nowrap;
}
.data-table td,.tbl td{
  padding:var(--s3);border-bottom:1px solid var(--rule-hair);
  color:var(--ink-muted);vertical-align:top;line-height:1.6;
}
.data-table tbody tr:last-child td,.tbl tbody tr:last-child td{
  border-bottom:1px solid var(--border-strong);
}
/* Numerals in a table column align on the decimal point. */
.data-table td,.tbl td,.col-num,.ledger-num,.stei-score{
  font-variant-numeric:lining-nums tabular-nums;
}
.data-table td b,.tbl td b{color:var(--ink-strong)}
.col-id{font-family:var(--font-mono);font-size:.75rem;color:var(--ink-faint);
        white-space:nowrap;width:1%%}
.col-num{text-align:right;font-family:var(--font-mono);white-space:nowrap;width:1%%}

/* Score ledger (deterministic contribution grid) */
.ledger{display:grid;grid-template-columns:1fr;gap:0;
        border-top:1px solid var(--border-strong)}
.ledger-row{
  display:grid;
  grid-template-columns:minmax(130px,1.3fr) minmax(100px,1.6fr) 62px 62px 92px;
  align-items:center;gap:var(--s4);
  padding:var(--s3) 0;border-bottom:1px solid var(--rule-hair);
}
.ledger-head{
  font-size:.625rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
  color:var(--ink-faint);border-bottom:1px solid var(--border-strong);
  align-items:end;line-height:1.4;
}
.ledger-head>span{min-width:0;overflow-wrap:anywhere}
.ledger-head>span:nth-child(n+3){text-align:right}
.ledger-name{font-size:.8125rem;color:var(--ink-strong);font-weight:600}
.ledger-num{font-family:var(--font-mono);font-size:.8125rem;color:var(--ink-muted);
            text-align:right}
.ledger-num-strong{color:var(--ink-strong);font-weight:600}
.ledger-total{border-bottom:none;border-top:1px solid var(--border-strong);
              padding-top:var(--s4);margin-top:var(--s1)}
.meter{background:var(--surface-sunk);border-radius:1px;height:6px;overflow:hidden}
.meter-fill{height:100%%;background:var(--accent)}

/* STEI axes */
.stei-grid{display:grid;grid-template-columns:1fr;gap:0;
           border-top:1px solid var(--border-strong)}
.stei-row{
  display:grid;grid-template-columns:minmax(150px,180px) 1fr 52px;
  align-items:center;gap:var(--s4);
  padding:var(--s3) 0;border-bottom:1px solid var(--rule-hair);
}
.stei-row:last-child{border-bottom:none}
.stei-label{font-size:.8125rem;color:var(--ink-strong);font-weight:600}
.stei-bar-track{background:var(--surface-sunk);border-radius:1px;height:6px;overflow:hidden}
.stei-bar-fill{height:100%%;background:var(--ink-muted)}
.stei-score{font-family:var(--font-mono);font-size:.8125rem;color:var(--ink-strong);
            text-align:right}
.axis-ct .stei-bar-fill{background:var(--risk-critical)}
.axis-bt .stei-bar-fill{background:var(--risk-high)}
.axis-pr .stei-bar-fill{background:var(--risk-suspicious)}
.axis-ob .stei-bar-fill{background:var(--ink-faint)}
.axis-ir .stei-bar-fill{background:var(--accent)}

/* Tags */
.perm-grid{display:flex;flex-wrap:wrap;gap:var(--s2)}
.perm-tag{
  display:inline-block;padding:2px 9px;border-radius:var(--radius);
  font-family:var(--font-mono);font-size:.6875rem;line-height:1.7;
  border:1px solid var(--border);background:var(--surface);color:var(--ink-muted);
}
.perm-danger{background:var(--tint-high);color:var(--risk-high);border-color:var(--edge-high)}
.perm-normal{background:var(--surface);color:var(--ink-muted);border-color:var(--border)}

/* Findings */
.finding{
  display:grid;grid-template-columns:82px 1fr;gap:var(--s4);
  padding:var(--s3) 0;border-bottom:1px solid var(--rule-hair);
}
.finding:last-child{border-bottom:none}
.finding-id{font-family:var(--font-mono);font-size:.6875rem;color:var(--ink-faint);
            white-space:nowrap;padding-top:2px}
.finding-body{min-width:0}
.finding-title{font-size:.875rem;font-weight:600;color:var(--ink-strong);
               margin-bottom:2px;line-height:1.5;word-break:break-word}
.finding-desc{font-size:.8125rem;color:var(--ink-muted);line-height:1.65;max-width:76ch}
.sev{
  display:inline-block;padding:0 7px;border-radius:var(--radius);
  font-size:.625rem;font-weight:700;text-transform:uppercase;letter-spacing:.09em;
  margin-left:var(--s2);vertical-align:1px;border:1px solid;line-height:1.7;
}
.sev-critical{background:var(--tint-critical);color:var(--risk-critical);border-color:var(--edge-critical)}
.sev-high{background:var(--tint-high);color:var(--risk-high);border-color:var(--edge-high)}
.sev-medium{background:var(--tint-suspicious);color:var(--risk-suspicious);border-color:var(--edge-suspicious)}
.sev-low{background:var(--tint-safe);color:var(--risk-safe);border-color:var(--edge-safe)}

/* MITRE */
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));
            gap:var(--s2)}
.mitre-chip{background:var(--paper);border:0;
            border-top:1px solid var(--rule-hair);padding:var(--s2) 0}
.mitre-id{font-family:var(--font-mono);font-size:.75rem;color:var(--accent);font-weight:600}
.mitre-name{font-size:.75rem;color:var(--ink-muted);margin-top:2px;line-height:1.5}

/* State banners */
.dynamic-status-banner{
  background:none;border:0;border-top:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);padding:var(--s5) 0;
}
.dynamic-status-title{font-size:var(--label);font-weight:700;text-transform:uppercase;
                      letter-spacing:.11em;color:var(--ink-faint);margin-bottom:var(--s2)}
.dynamic-status-code{font-family:var(--font-mono);font-size:.8125rem;
                     color:var(--risk-suspicious);margin-bottom:var(--s3)}
.dynamic-status-detail{font-size:.8125rem;color:var(--ink-muted);line-height:1.8;max-width:80ch}
.qualifier{
  background:none;border:0;border-top:1px solid var(--border-strong);
  border-bottom:1px solid var(--border-strong);
  padding:var(--s4) 0;margin-bottom:var(--s4);
}
.qualifier-title{font-size:var(--label);font-weight:700;text-transform:uppercase;
                 letter-spacing:.11em;color:var(--risk-suspicious);margin-bottom:var(--s1)}
.qualifier-body{font-size:.8125rem;line-height:1.7;color:var(--ink-muted);max-width:80ch}

/* Timeline */
.timeline{border-left:1px solid var(--border);padding-left:var(--s5);
          margin-left:var(--s1)}
.tl-event{position:relative;padding:var(--s3) 0;
          border-bottom:1px solid var(--rule-hair)}
.tl-event:last-child{border-bottom:none}
.tl-event::before{content:"";position:absolute;left:calc(-1 * var(--s5) - 3px);
                  top:20px;width:5px;height:5px;border-radius:50%%;
                  background:var(--ink-faint)}
.tl-ts{font-family:var(--font-mono);font-size:.6875rem;color:var(--ink-faint);
       margin-bottom:2px}
.tl-api{font-family:var(--font-mono);font-size:.8125rem;color:var(--ink-strong);
        font-weight:600;word-break:break-word}
.tl-desc{font-size:.8125rem;color:var(--ink-muted);margin-top:2px;
         line-height:1.65;max-width:76ch}

/* Stat tiles */
.intel-stat{
  background:var(--paper);border:0;border-top:1px solid var(--border-strong);
  padding:var(--s3) 0;display:grid;gap:var(--s1);align-content:start;
  text-align:left;
}
.intel-num{font-family:var(--font-serif);font-size:1.5rem;font-weight:600;
           line-height:1.1;color:var(--ink-strong)}
.intel-sub{font-size:.6875rem;color:var(--ink-faint);text-transform:uppercase;
           letter-spacing:.09em;font-weight:700}
.rep-malicious{color:var(--risk-critical)}
.rep-suspicious{color:var(--risk-suspicious)}
.rep-clean{color:var(--risk-safe)}
.rep-unknown{color:var(--ink-faint)}

/* Recommendations */
.rec-list{list-style:none;display:grid;grid-template-columns:1fr;gap:0;
          border-top:1px solid var(--border-strong)}
.rec-item{display:grid;grid-template-columns:28px 1fr;gap:var(--s3);
          align-items:baseline;padding:var(--s3) 0;
          border-bottom:1px solid var(--rule-hair)}
.rec-item:last-child{border-bottom:none}
.rec-num{font-family:var(--font-mono);font-size:.75rem;font-weight:700;
         color:var(--ink-faint)}
.rec-text{font-size:.875rem;color:var(--ink-muted);line-height:1.7;max-width:76ch}

/* Screenshot plates */
.gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
              gap:var(--s5);margin-top:var(--s4)}
.gallery-card{
  background:var(--paper);border:1px solid var(--border);border-radius:var(--radius);
  display:grid;grid-template-rows:auto auto 1fr;overflow:hidden;
}
.scr-header{
  display:grid;grid-template-columns:auto 1fr;align-items:baseline;
  gap:var(--s3);padding:var(--s3) var(--s4);
  border-bottom:1px solid var(--border);background:var(--surface-inset);
}
.scr-id{font-family:var(--font-mono);font-size:.6875rem;font-weight:700;
        color:var(--ink-faint);letter-spacing:.04em;white-space:nowrap}
.scr-label{font-size:.8125rem;font-weight:600;color:var(--ink-strong);
           text-align:right;word-break:break-word}
.scr-body{
  display:flex;align-items:center;justify-content:center;
  padding:var(--s4);background:var(--surface-inset);
  border-bottom:1px solid var(--border);min-height:180px;
}
.scr-img{max-width:100%%;max-height:340px;object-fit:contain;display:block;
         border:1px solid var(--border-strong);background:var(--paper)}
/* Metadata is a two-column definition grid: every label sits on the same
   left edge and every value on the same one, plate to plate. */
.scr-meta{display:grid;grid-template-columns:auto 1fr;
          column-gap:var(--s4);row-gap:var(--s2);
          padding:var(--s4);align-content:start}
.scr-meta dt{font-size:.6875rem;font-weight:700;text-transform:uppercase;
             letter-spacing:.09em;color:var(--ink-faint);white-space:nowrap;
             line-height:1.6}
.scr-meta dd{font-size:.8125rem;color:var(--ink);line-height:1.6;
             word-break:break-word;min-width:0}
.scr-meta dd.mono{font-family:var(--font-mono);font-size:.75rem;color:var(--ink-muted)}
.scr-caption{grid-column:1 / -1;font-size:.8125rem;color:var(--ink-muted);
             line-height:1.7;padding-top:var(--s3);
             border-top:1px solid var(--rule-hair)}
.scr-tags{grid-column:1 / -1;display:flex;flex-wrap:wrap;gap:var(--s1);
          padding-top:var(--s1)}
.grade{display:inline-block;min-width:20px;text-align:center;padding:0 6px;
       border:1px solid;border-radius:var(--radius);font-size:.6875rem;
       font-weight:700;letter-spacing:.06em;line-height:1.7}
.grade-a{background:var(--tint-safe);color:var(--risk-safe);border-color:var(--edge-safe)}
.grade-b{background:var(--tint-neutral);color:var(--ink-muted);border-color:var(--edge-neutral)}
.grade-c{background:var(--tint-suspicious);color:var(--risk-suspicious);border-color:var(--edge-suspicious)}

/* Full-width evidence plate: image beside metadata, both top-aligned. */
.plate{display:grid;grid-template-columns:minmax(200px,240px) 1fr;
       gap:var(--s6);align-items:start;padding:var(--s5) 0;
       border-bottom:1px solid var(--rule-hair)}
.plate:last-of-type{border-bottom:none}
.plate-figure{margin:0;display:grid;gap:var(--s2)}
.plate-figure img{width:100%%;display:block;border:1px solid var(--border-strong);
                  background:var(--surface-inset)}
.plate-figure figcaption{font-family:var(--font-mono);font-size:.6875rem;
                         color:var(--ink-faint);letter-spacing:.04em}
.plate-body{min-width:0;display:grid;gap:var(--s3);align-content:start}
.plate-claim{font-size:.875rem;color:var(--ink-strong);line-height:1.65;
             font-weight:600;max-width:70ch}
.plate-meta{display:grid;grid-template-columns:auto 1fr;
            column-gap:var(--s5);row-gap:var(--s2);
            border-top:1px solid var(--rule-hair);padding-top:var(--s3)}
.plate-meta dt{font-size:.6875rem;font-weight:700;text-transform:uppercase;
               letter-spacing:.09em;color:var(--ink-faint);white-space:nowrap;
               line-height:1.6}
.plate-meta dd{font-size:.8125rem;color:var(--ink);line-height:1.6;min-width:0;
               word-break:break-word}

/* Footer */
.report-footer{
  margin-top:var(--s9);padding-top:var(--s5);
  border-top:2px solid var(--ink-strong);
  font-size:.75rem;color:var(--ink-faint);line-height:1.9;
}
.report-footer .fine{display:block;margin-top:var(--s2);color:var(--ink-disabled)}

/* Utility */
.mt8{margin-top:var(--s2)}.mt12{margin-top:var(--s3)}.mt16{margin-top:var(--s4)}
.mb8{margin-bottom:var(--s2)}
.muted{color:var(--ink-faint)}
.no-data{color:var(--ink-disabled);font-size:.8125rem;padding:var(--s2) 0;display:inline-block}

/* Print / PDF */
@page{
  size:A4;
  margin:25mm 20mm 22mm 28mm;
  @top-left{content:string(report-id);font-size:8pt;color:#3D4655}
  @top-center{content:string(classification);font-size:8pt;color:#3D4655}
  @top-right{content:"Page " counter(page) " of " counter(pages);
             font-size:8pt;color:#3D4655}
  @bottom-center{content:"Uncontrolled when printed";font-size:7pt;color:#6B7280}
}
/* The running head reads these from the cover block, so a printed extract
   still carries its case reference and its handling marking. */
.doc-report-id{string-set:report-id content()}
.doc-classification{string-set:classification content()}
@media print{
  body{background:var(--paper);font-size:10.5pt;line-height:1.24}
  .container{max-width:100%%;padding:0;border:none;min-height:0}
  .section{border:0;padding:0;margin-bottom:14pt;break-inside:avoid}
  .part{margin-top:0;break-before:page}
  .report-header{break-after:avoid}
  .part-divider{break-after:avoid}
  .section-header,h3,h4{break-after:avoid}
  table,.finding,.ledger-row,.stei-row,.gallery-card,.plate{break-inside:avoid}
  thead{display:table-header-group}
  a{color:var(--ink);border-bottom:none}
  .scr-img{max-height:200pt}
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}

@media (max-width:760px){
  .container{padding:var(--s6) var(--s4)}
  .grid-2,.grid-3,.score-block,.plate{grid-template-columns:1fr}
  .ledger-row{grid-template-columns:1fr 1fr;row-gap:var(--s2)}
  .part-divider{grid-template-columns:1fr}
  .part-desc{grid-column:1}
  /* Dense forensic tables cannot narrow past their content. Let the section
     scroll them rather than the page: a document that scrolls sideways as a
     whole loses the left margin every other section is aligned to. */
  .section{overflow-x:auto}
  .scr-meta,.plate-meta{grid-template-columns:1fr;row-gap:0}
  .scr-meta dt,.plate-meta dt{padding-top:var(--s2)}
}
""" % {
    "INK": T.INK, "INK_STRONG": T.INK_STRONG, "INK_MUTED": T.INK_MUTED,
    "INK_FAINT": T.INK_FAINT, "INK_DISABLED": T.INK_DISABLED,
    "PAPER": T.PAPER, "SURFACE": T.SURFACE, "SURFACE_INSET": T.SURFACE_INSET,
    "SURFACE_SUNK": T.SURFACE_SUNK,
    "BORDER": T.BORDER, "BORDER_STRONG": T.BORDER_STRONG, "RULE_HAIR": T.RULE_HAIR,
    "ACCENT": T.ACCENT, "ACCENT_SOFT": T.ACCENT_SOFT,
    "RISK_CRITICAL": T.RISK_CRITICAL, "RISK_HIGH": T.RISK_HIGH,
    "RISK_SUSPICIOUS": T.RISK_SUSPICIOUS, "RISK_SAFE": T.RISK_SAFE,
    "RISK_NEUTRAL": T.RISK_NEUTRAL,
    "TINT_CRITICAL": T.TINT_CRITICAL, "TINT_HIGH": T.TINT_HIGH,
    "TINT_SUSPICIOUS": T.TINT_SUSPICIOUS, "TINT_SAFE": T.TINT_SAFE,
    "TINT_NEUTRAL": T.TINT_NEUTRAL,
    "EDGE_CRITICAL": T.EDGE_CRITICAL, "EDGE_HIGH": T.EDGE_HIGH,
    "EDGE_SUSPICIOUS": T.EDGE_SUSPICIOUS, "EDGE_SAFE": T.EDGE_SAFE,
    "EDGE_NEUTRAL": T.EDGE_NEUTRAL,
    "FONT_SANS": T.FONT_SANS, "FONT_SERIF": T.FONT_SERIF, "FONT_MONO": T.FONT_MONO,
}

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
    """Retained for call-site compatibility. The dossier carries no pictograms."""
    return ""


def _verdict_answer(band: str) -> str:
    b = band.lower()
    if "critical" in b:
        return ("NOT TRUSTED &#x2014; the evidence below is consistent with an "
                "operational banking trojan. Treat every device that ran this "
                "package as compromised.")
    if "high" in b:
        return ("NOT TRUSTED &#x2014; capabilities and indicators consistent with "
                "banking fraud are present. Withhold trust pending containment.")
    if "suspicious" in b or "medium" in b:
        return ("QUALIFIED &#x2014; indicators warrant scrutiny but fall short of a "
                "fraud determination on this evidence. Escalate for analyst review.")
    return ("NO ADVERSE FINDING &#x2014; this run surfaced no indicator meeting the "
            "threshold for a fraud determination. The scope statement below "
            "bounds that conclusion.")


def _score_color(score: float) -> str:
    return T.score_ink(score)


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

def _render_investigation(r: Any, idx: Any) -> str:
    """
    What was investigated, what the sandbox did, and how the run ended.

    The dynamic section already answers "which hooks fired". It could not answer
    "what did we look for, what did we grant, and did any of it work" - so a
    reader could not tell a sample that requested nothing from one whose
    permission grants silently failed.

    Renders nothing when there is nothing to say, so a static-only report is
    unchanged.
    """
    investigation = _get(r, "investigation") or {}
    permissions = _get(r, "permission_findings") or {}
    crashes = _get(r, "crashes") or []

    transitions = _get(investigation, "transitions") or []
    perm_records = _get(permissions, "records") or []
    profile = _get(permissions, "profile") or {}

    # Only INFO-severity permissions is not worth a section: every ordinary
    # permission would become a finding and the section would be noise.
    notable = [
        rec for rec in perm_records
        if str(_get(rec, "severity", default="INFO")).upper() != "INFO"
    ]
    category = _get(profile, "category", default="")
    known_category = bool(category) and category != "UNKNOWN"

    if not (transitions or notable or crashes or known_category):
        return ""

    html = '<h3 class="mt12">Investigation</h3>'

    # ── What we took the app to be ──
    if known_category:
        signals = _get(profile, "signals") or []
        signal_str = _esc("; ".join(str(x) for x in signals[:2]))
        html += (
            f'<div class="tl-desc" style="margin-bottom:8px">'
            f'Assessed as <strong>{_esc(str(category))}</strong> '
            f'(confidence {_esc(str(_get(profile, "confidence", default="")))})'
            f'{f" &mdash; {signal_str}" if signal_str else ""}. '
            f'Permission expectations below are judged against that reading; '
            f'an unexpected permission is a question for review, not a verdict.'
            f'</div>'
        )

    # ── Stage transitions ──
    if transitions:
        html += '<h4 class="mt8">Stages</h4><div class="timeline">'
        for t in transitions[:20]:
            elapsed = _get(t, "elapsed_seconds", default=0)
            try:
                stamp = f"{int(float(elapsed)) // 60:02d}:{int(float(elapsed)) % 60:02d}"
            except Exception:
                stamp = "--:--"
            html += (
                f'<div class="tl-event">'
                f'<div class="tl-ts">{stamp}</div>'
                f'<div class="tl-api">{_esc(str(_get(t, "from", default="")))} '
                f'&rarr; {_esc(str(_get(t, "to", default="")))}</div>'
                f'<div class="tl-desc">{_esc(str(_get(t, "reason", default="")))}</div>'
                f'</div>'
            )
        html += '</div>'

    # ── Permission findings ──
    if notable:
        html += '<h4 class="mt12">Permission Findings</h4>'
        for rec in notable[:15]:
            name = _esc(str(_get(rec, "permission", default="")).replace("android.permission.", ""))
            sev = str(_get(rec, "severity", default="INFO"))
            classification = _esc(str(_get(rec, "classification", default="")))
            fid = idx.next("EVID", f"Permission: {name}")
            # The four facts, so a reader can see WHY it is a finding.
            facts = ", ".join(filter(None, [
                "declared" if _get(rec, "declared") else "",
                "requested at runtime" if _get(rec, "requested_at_runtime") else "",
                "granted" if _get(rec, "granted") else "not granted",
            ]))
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">{name}'
                f'<span class="sev {_sev_class(sev)}">{_esc(sev)}</span></div>'
                f'<div class="finding-desc">{classification} &mdash; {_esc(facts)}</div>'
                f'</div></div>'
            )

    # ── Crashes ──
    if crashes:
        html += '<h4 class="mt12">Process Crashes</h4>'
        for crash in crashes[:8]:
            ctype = _esc(str(_get(crash, "crash_type", default="UNKNOWN_CRASH")))
            summary = _esc(str(_get(crash, "summary", default="")))
            confidence = _esc(str(_get(crash, "confidence", default="")))
            fid = idx.next("EVID", f"Crash: {ctype}")
            html += (
                f'<div class="finding">'
                f'<div class="finding-id">[{fid}]</div>'
                f'<div class="finding-body">'
                f'<div class="finding-title">{ctype}'
                f'<span class="sev {_sev_class(str(_get(crash, "severity", default="INFO")))}">'
                f'{_esc(str(_get(crash, "severity", default="INFO")))}</span></div>'
                f'<div class="finding-desc">{summary} (confidence: {confidence})</div>'
                f'</div></div>'
            )

    return html


def _section_header(icon: str, icon_bg: str, title: str, subtitle: str = "") -> str:
    """
    Section rule: title left, run qualifier right, hairline underneath.

    `icon` / `icon_bg` are accepted and ignored. Every call site passed an emoji
    and a translucent neon wash; both are gone from the dossier, and dropping
    the parameters would have meant editing twenty call sites for no gain.
    Subtitles arrive already entity-encoded from several call sites, so they are
    emitted verbatim rather than double-escaped.
    """
    note = f'<span class="section-note">{subtitle}</span>' if subtitle else "<span></span>"
    return (
        f'<div class="section-header">'
        f'<h2>{_esc(title)}</h2>'
        f'{note}'
        f'</div>'
    )


def _part(label: str, title: str, description: str) -> str:
    """Opens a numbered part of the dossier. Forces a page break in print."""
    return (
        f'<div class="part">'
        f'<div class="part-divider">'
        f'<div class="part-label">{_esc(label)}</div>'
        f'<div class="part-title">{_esc(title)}</div>'
        f'<p class="part-desc">{_esc(description)}</p>'
        f'</div>'
    )


def _part_end() -> str:
    return "</div>"


DOCUMENT_CLASSIFICATION = "CONFIDENTIAL &mdash; TLP:AMBER"


def _brand_mark_html() -> str:
    """
    The mark, inlined as a data URI.

    This export is a single file that has to survive being emailed with no
    network behind it, so the mark travels in the document rather than beside
    it. If the asset is missing the masthead falls back to a ruled monogram
    and the report still renders - a dossier without its logo is still a
    dossier, one that fails to export is not.
    """
    uri = BRAND.mark_data_uri(small=True)
    if not uri:
        return '<div class="brand-mark-fallback" aria-hidden="true">S</div>'
    return (f'<img class="brand-mark" src="{uri}" alt="" width="46" height="46">')


def _build_header(r: Dict, ts: str) -> str:
    """
    The cover block: what the document is, what it examined, and what it found.

    The verdict used to open on a 104px dial. A dial encodes its value with
    angle - third in Cleveland and McGill's ordering of the elementary
    perceptual tasks, behind position and length - and it cannot be read to a
    decimal place. In an evidentiary document the reader does not need to
    estimate the score at all: the figure is printed, and the arithmetic that
    produced it is printed under it in the score ledger. What replaced the dial
    is the figure, the band with its position on the four-step scale, and the
    determination as a sentence.
    """
    pkg = _esc(_get(r, "package_name", default="Unknown"))
    app = _esc(_get(r, "app_name") or _get(r, "package_name", default="Unknown"))
    sha = _esc(_get(r, "sha256", default=""))
    band = _get(r, "risk_band", default="Unknown")
    frs = float(_get(r, "final_risk_score", default=0))
    conf = float(_get(r, "confidence", default=70))
    action = _esc(_get(r, "recommended_action", default=""))
    mode = _esc(_get(r, "analysis_mode", default="androguard"))
    case_id = _esc(_get(r, "case_id", default="") or
                   _get(r, "job_id", default="") or "unassigned")

    band_phrase = _esc(T.band_label(band))
    band_css = _band_css(band)
    verdict_css = _verdict_css(band)
    v_answer = _verdict_answer(band)

    intel = _get(r, "intelligence_report") or {}
    narrative = _esc(_get(intel, "plain_english_narrative", default=""))
    if not narrative:
        ev = _get(r, "executive_view") or {}
        narrative = _esc(_get(ev, "plain_english_narrative", default=""))

    narrative_html = f'<div class="verdict-narrative">{narrative}</div>' if narrative else ""

    sha_display = f"{sha[:32]}&#8203;{sha[32:]}" if len(sha) > 32 else (sha or "not recorded")

    return (
        f'<div class="report-header">'
        f'<div class="report-meta">'
        f'<div class="report-brand">'
        f'{_brand_mark_html()}'
        f'<div><div class="brand-name">{BRAND.WORDMARK}</div>'
        f'<div class="brand-sub">{BRAND.DESCRIPTOR}</div></div>'
        f'</div>'
        f'<div class="report-ts">'
        f'Reference <b class="doc-report-id">{case_id}</b><br>'
        f'Issued <b>{_esc(ts)}</b><br>'
        f'Analysis mode <b>{mode}</b><br>'
        f'Confidence <b>{conf:.0f}%</b><br>'
        f'<b class="doc-classification">{DOCUMENT_CLASSIFICATION}</b>'
        f'</div>'
        f'</div>'
        f'<div class="app-identity">'
        f'<div class="doc-kicker">Threat Investigation Report</div>'
        f'<div class="app-name">{app}</div>'
        f'<div class="app-pkg">{pkg}</div>'
        f'<div class="hash-row">SHA-256 {sha_display}</div>'
        f'</div>'
        f'<div class="score-block">'
        f'<div class="score-detail">'
        f'<span class="risk-band-badge {band_css}">{band_phrase}</span>'
        f'<div><span class="score-figure">{frs:.1f}</span>'
        f'<span class="score-of">of 100 &mdash; verdict score, computed by the '
        f'fixed formula in the score ledger below</span></div>'
        f'<div class="score-subtext mt8">{action}</div>'
        f'</div>'
        f'</div>'
        f'<div class="verdict-banner {verdict_css}">'
        f'<div class="verdict-q">Determination</div>'
        f'<div class="verdict-answer">{v_answer}</div>'
        f'{narrative_html}'
        f'</div>'
        f'<p class="scope-note">The results relate only to the item identified '
        f'above, as submitted. They do not extend to any other build, version '
        f'or repackaging of the same application. A section recording an '
        f'absence of evidence records exactly that and is not a finding that '
        f'the sample is benign. Severity is stated on a four-step ordinal '
        f'scale &mdash; SAFE (1 of 4), SUSPICIOUS (2 of 4), HIGH (3 of 4), '
        f'CRITICAL (4 of 4) &mdash; and colour is never the only thing '
        f'carrying it.</p>'
        f'</div>'
    )


def _build_stei(r: Dict) -> str:
    frs_bd = _get(r, "frs_breakdown") or {}
    raw_axes = _get(frs_bd, "stei_axes") or {}
    # risk_engine emits lowercase axis keys; older persisted cases and the test
    # fixtures use uppercase. Reading only one spelling rendered every axis at
    # zero next to a non-zero STEI total, which is an unexplained number.
    axes = {str(k).upper(): v for k, v in raw_axes.items()} if raw_axes else {}

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
        ("CT", "Credential Theft", "axis-ct", 0.60),
        ("BT", "Banking Targeting", "axis-bt", 0.20),
        ("PR", "Permission Risk", "axis-pr", 0.10),
        ("OB", "Obfuscation", "axis-ob", 0.05),
        ("IR", "Infrastructure Risk", "axis-ir", 0.05),
    ]
    dropped = {str(a).upper() for a in (_get(frs_bd, "stei_axes_excluded") or [])}

    rows = (
        '<div class="stei-row ledger-head">'
        '<span>Axis</span><span></span><span>Score</span>'
        '</div>'
    )
    for key, label, cls, weight in axis_defs:
        val = float(axes.get(key, 0))
        note = " &mdash; not scored" if key in dropped else f" &mdash; weight {weight:.2f}"
        rows += (
            f'<div class="stei-row {cls}">'
            f'<div class="stei-label">{label}'
            f'<span class="muted" style="font-weight:400">{note}</span></div>'
            f'<div class="stei-bar-track">'
            f'<div class="stei-bar-fill" style="width:{min(val, 100):.1f}%"></div>'
            f'</div>'
            f'<div class="stei-score">{val:.0f}</div>'
            f'</div>'
        )

    formula = _get(frs_bd, "formula_used", default="static_only_frs")
    formula_label = ("Dynamic-weighted formula" if "dynamic" in str(formula)
                     else "Static-only formula")

    return (
        f'<div class="section">'
        + _section_header("", "", "Five-Axis STEI Breakdown", formula_label)
        + '<p class="section-lead">Each axis scores 0&ndash;100 against its own '
          'evidence set. An axis marked <em>not scored</em> carried no evidence '
          'in this run and was dropped from the weighting rather than recorded '
          'as a zero.</p>'
        + f'<div class="stei-grid">{rows}</div>'
        f'</div>'
    )


_AXIS_LABELS = {
    "stei": "Static Threat Evidence Index (STEI)",
    "dynamic": "Runtime behaviour (BFCI)",
    "correlation": "External threat-intelligence correlation",
    "banking_impact": "Banking impact assessment",
    "vide": "Visual impersonation (VIDE)",
}


def _build_score_ledger(r: Dict) -> str:
    """
    Risk contributors: which axes were scored, at what renormalised weight, and
    what each one contributed to the verdict score. This is the arithmetic the
    verdict rests on, printed so a reviewer can reproduce it by hand.
    """
    frs_bd = _get(r, "frs_breakdown") or {}
    weights = _get(frs_bd, "axes_used") or {}
    excluded = _get(frs_bd, "axes_excluded") or []
    frs = float(_get(r, "final_risk_score", default=0))
    multiplier = float(_get(r, "ai_confidence_multiplier", default=1.0) or 1.0)

    if not weights and not excluded:
        return ""

    rows = (
        '<div class="ledger-row ledger-head">'
        '<span>Contributor</span><span>Share of verdict</span>'
        '<span>Score</span><span>Weight</span><span>Contribution</span>'
        '</div>'
    )
    running = 0.0
    for axis, weight in weights.items():
        raw = float(_get(frs_bd, axis, default=0) or 0)
        w = float(weight or 0)
        contribution = raw * w
        running += contribution
        rows += (
            f'<div class="ledger-row">'
            f'<div class="ledger-name">{_esc(_AXIS_LABELS.get(axis, axis))}</div>'
            f'<div class="meter"><div class="meter-fill" '
            f'style="width:{min(w * 100, 100):.1f}%"></div></div>'
            f'<div class="ledger-num">{raw:.1f}</div>'
            f'<div class="ledger-num">{w:.3f}</div>'
            f'<div class="ledger-num ledger-num-strong">{contribution:.2f}</div>'
            f'</div>'
        )

    for axis in excluded:
        rows += (
            f'<div class="ledger-row">'
            f'<div class="ledger-name">{_esc(_AXIS_LABELS.get(axis, axis))}</div>'
            f'<div class="muted" style="font-size:.8125rem">'
            f'excluded &mdash; no evidence to score</div>'
            f'<div class="ledger-num">&mdash;</div>'
            f'<div class="ledger-num">0.000</div>'
            f'<div class="ledger-num">0.00</div>'
            f'</div>'
        )

    mult_row = ""
    if abs(multiplier - 1.0) > 1e-6:
        mult_row = (
            f'<div class="ledger-row">'
            f'<div class="ledger-name">Confidence multiplier</div>'
            f'<div class="muted" style="font-size:.8125rem">'
            f'applied to the weighted sum</div>'
            f'<div class="ledger-num">&mdash;</div>'
            f'<div class="ledger-num">&times;{multiplier:.2f}</div>'
            f'<div class="ledger-num ledger-num-strong">'
            f'{running * multiplier - running:+.2f}</div>'
            f'</div>'
        )

    rows += mult_row + (
        f'<div class="ledger-row ledger-total">'
        f'<div class="ledger-name">Verdict score</div>'
        f'<div class="muted" style="font-size:.8125rem">'
        f'weighted sum, capped at 100</div>'
        f'<div class="ledger-num">&mdash;</div>'
        f'<div class="ledger-num">&mdash;</div>'
        f'<div class="ledger-num ledger-num-strong">{frs:.1f}</div>'
        f'</div>'
    )

    floors = [
        ("verdict_floored_for_visibility", "sandbox visibility was insufficient"),
        ("verdict_floored_for_evasion", "the sample resisted instrumentation"),
        ("verdict_floored_for_static_evidence", "static evidence alone met the floor"),
        ("verdict_floored_for_incomplete_exercise", "the run did not exercise the sample"),
    ]
    applied = [text for key, text in floors if _get(frs_bd, key)]
    floor_note = ""
    if applied:
        floor_note = (
            '<p class="section-lead mt12" style="margin-bottom:0">'
            'A verdict floor was applied because ' + _esc("; ".join(applied)) +
            '. The floor raises the score above the weighted sum; it never lowers it.'
            '</p>'
        )

    return (
        '<div class="section">'
        + _section_header("", "", "Risk Contributors",
                          "Deterministic &mdash; no model output in this table")
        + '<p class="section-lead">Weights are renormalised across the axes that '
          'carried evidence. Contribution is score multiplied by weight.</p>'
        + f'<div class="ledger">{rows}</div>'
        + floor_note
        + '</div>'
    )


def _build_key_findings(r: Dict) -> str:
    """
    The ten findings a reviewer should read first, ranked by severity.

    Assembled from the same underlying fields the technical part enumerates in
    full - this is a précis of that evidence, not a second source for it.
    """
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows: List[Tuple[str, str, str, str]] = []  # (severity, area, finding, basis)

    def add(sev: str, area: str, finding: str, basis: str) -> None:
        rows.append((sev, area, finding, basis))

    tc = _get(r, "threat_correlation") or {}
    if _get(tc, "known_family"):
        add("CRITICAL", "Threat intelligence",
            f'Sample matches known family {_get(tc, "known_family")}',
            "SHA-256 match against external intelligence sources")
    vt_det = int(_get(tc, "sha256_detections", default=0) or 0)
    if vt_det:
        add("HIGH", "Threat intelligence",
            f"{vt_det} anti-malware vendors flag this binary",
            "Multi-engine detection ratio")

    if _get(r, "has_accessibility_abuse"):
        add("CRITICAL", "Capability",
            "Accessibility service abuse capability present",
            "Manifest declaration and service binding")
    if _get(r, "has_sms_read_write"):
        add("HIGH", "Capability", "SMS read and write capability present",
            "Declared SMS permissions - the standard OTP interception path")
    if _get(r, "has_system_alert_window"):
        add("HIGH", "Capability", "Screen overlay capability present",
            "SYSTEM_ALERT_WINDOW - the standard credential-overlay path")
    if _get(r, "targets_indian_banks"):
        add("HIGH", "Targeting", "References Indian banking application packages",
            "Package-name targets extracted from application resources")

    urls = _get(r, "hardcoded_urls_ips") or []
    if urls:
        add("HIGH", "Infrastructure",
            f"{len(urls)} hardcoded network endpoints embedded in the binary",
            f"First: {str(urls[0])[:64]}")
    secrets = _get(r, "hardcoded_secrets") or []
    if secrets:
        add("MEDIUM", "Credentials",
            f"{len(secrets)} embedded secrets recovered from application strings",
            "Static string extraction")

    obf = float(_get(r, "obfuscation_score", default=0) or 0)
    obf_pct = obf * 100 if obf <= 1.0 else obf
    if obf_pct > 30:
        add("MEDIUM", "Evasion", f"Obfuscation at {obf_pct:.0f}% string entropy",
            "Identifier and string entropy measurement")
    if _get(r, "has_reflection"):
        add("MEDIUM", "Evasion", "Dynamic reflection used to resolve call targets",
            "Class.forName / Method.invoke references in decompiled code")

    for mf in (_get(r, "manifest_findings") or [])[:6]:
        sev = str(_get(mf, "severity", default="LOW")).upper()
        if sev in ("CRITICAL", "HIGH"):
            add(sev, "Manifest", str(_get(mf, "title", default=""))[:110],
                str(_get(mf, "description", default=""))[:130])

    anti_analysis = _get(_get(r, "dynamic_analysis") or {}, "anti_analysis_events") or []
    for aa in anti_analysis[:3]:
        add("HIGH", "Anti-analysis",
            str(_get(aa, "technique", default=str(aa)))[:110],
            "Observed during instrumented execution")

    for crash in (_get(r, "crashes") or [])[:2]:
        add(str(_get(crash, "severity", default="MEDIUM")).upper(), "Stability",
            str(_get(crash, "crash_type", default="Process crash"))[:110],
            str(_get(crash, "summary", default=""))[:130])

    if not rows:
        return (
            '<div class="section">'
            + _section_header("", "", "Key Findings", "None at reportable severity")
            + '<p>No finding in this run reached a severity that warrants '
              'executive escalation. The technical part records the full '
              'enumeration, including findings held below that threshold.</p>'
              '</div>'
        )

    rows.sort(key=lambda x: order.get(x[0].lower(), 5))
    body = ""
    for i, (sev, area, finding, basis) in enumerate(rows[:10], 1):
        body += (
            f'<tr>'
            f'<td class="col-id">KF-{i:02d}</td>'
            f'<td><span class="sev {_sev_class(sev)}" style="margin-left:0">'
            f'{_esc(sev)}</span></td>'
            f'<td>{_esc(area)}</td>'
            f'<td><b>{_esc(finding)}</b></td>'
            f'<td>{_esc(basis)}</td>'
            f'</tr>'
        )

    return (
        '<div class="section">'
        + _section_header("", "", "Key Findings",
                          f"{min(len(rows), 10)} of {len(rows)} shown, by severity")
        + '<table class="data-table"><thead><tr>'
          '<th>Ref</th><th>Severity</th><th>Area</th><th>Finding</th><th>Basis</th>'
          '</tr></thead><tbody>' + body + '</tbody></table>'
        + '</div>'
    )


def _build_executive_conclusion(r: Dict) -> str:
    """Prose statement of the determination, its scope, and its limits."""
    intel = _get(r, "intelligence_report") or {}
    ev = _get(r, "executive_view") or {}

    narrative = _get(intel, "plain_english_narrative") or _get(ev, "plain_english_narrative") or ""
    objective = _get(intel, "fraud_objective") or ""
    impact = (_get(intel, "customer_impact")
              or _get(intel, "banking_impact_assessment")
              or _get(intel, "banking_impact") or "")

    frs_bd = _get(r, "frs_breakdown") or {}
    dyn_ran = bool(_get(frs_bd, "dynamic_ran"))
    dyn_conclusive = bool(_get(frs_bd, "dynamic_conclusive"))
    corr_available = bool(_get(_get(r, "threat_correlation") or {}, "available"))
    incomplete = bool(_get(r, "incomplete_exercise"))

    # ── Say what the dynamic run actually achieved ───────────────────────────
    #
    # The three branches below could only describe a run as conclusive,
    # inconclusive or absent, so a run that confirmed nine of fifteen
    # investigation goals and captured 47 events was written up in the same
    # sentence as one that captured none: "returned no conclusive telemetry".
    #
    # The coverage block carries its own narrative, computed once in
    # dynamic_coverage so the HTML, the PDF and the JSON cannot drift apart, and
    # so no report can claim all fraud stages executed when they did not. It is
    # used when present; the original three branches remain for a stored case
    # from before it existed.
    dyn_coverage = _get(frs_bd, "dynamic_coverage") or {}
    coverage_narrative = _get(dyn_coverage, "coverage_narrative") or ""
    if not coverage_narrative:
        coverage_narrative = _get(_get(r, "dynamic_result") or {}, "dynamic_coverage")
        coverage_narrative = (
            _get(coverage_narrative or {}, "narrative") if coverage_narrative else ""
        )

    if coverage_narrative:
        scope = f"Static decomposition completed. {coverage_narrative}"
    elif dyn_ran and dyn_conclusive:
        scope = ("Static decomposition and instrumented execution both completed; "
                 "runtime telemetry was conclusive.")
    elif dyn_ran:
        scope = ("Static decomposition completed. The sandbox executed but returned "
                 "no conclusive telemetry, so the runtime axis is excluded from the "
                 "score rather than scored as benign.")
    else:
        scope = ("Static decomposition completed. The sandbox did not execute this "
                 "sample, so this determination rests on static evidence alone.")

    # Limitations are stated, not implied. An analyst reading a partial result
    # has to be able to see WHICH parts of the investigation did not happen,
    # rather than inferring it from a percentage.
    limitations = _get(dyn_coverage, "limitations") or []
    if limitations:
        scope += " Limitations: " + "; ".join(str(x) for x in limitations[:4]) + "."

    scope += (" External threat-intelligence correlation was available."
              if corr_available else
              " External threat-intelligence correlation was unavailable in this run.")

    if incomplete:
        scope += (" The run reached none of the sample's own trigger conditions; "
                  "reported confidence is reduced accordingly and this dossier "
                  "does not certify the sample as benign.")

    blocks = ""
    if narrative:
        blocks += f'<p>{_esc(narrative)}</p>'
    if objective and str(objective).lower() not in ("not available", "unknown"):
        blocks += (f'<p><b>Assessed objective.</b> {_esc(objective)}</p>')
    if impact and str(impact).lower() not in ("not available", "unknown"):
        blocks += (f'<p><b>Exposure.</b> {_esc(impact)}</p>')
    if not blocks:
        blocks = (
            '<p>No narrative assessment was recorded for this run. The '
            'determination above rests entirely on the deterministic evidence '
            'enumerated in Part B.</p>'
        )

    return (
        '<div class="section">'
        + _section_header("", "", "Executive Conclusion")
        + blocks
        + f'<h3 class="mt16">Scope of this determination</h3><p>{_esc(scope)}</p>'
        + '</div>'
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

    html = f'<div class="section">' + _section_header("", "", "Forensic Evidence — Static",
                                                        "APK identity and static findings")

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
        + _section_header("", "", "Threat Intelligence & MITRE ATT&CK",
                          "External corroboration")
    )

    if not available:
        sources_str = ", ".join(sources) if sources else "VirusTotal, AlienVault OTX, AbuseIPDB"
        html += (
            f'<div class="dynamic-status-banner">'
            f'<div class="dynamic-status-title">External Correlation Status</div>'
            f'<div class="dynamic-status-code">[INTEL-STATUS: API KEYS NOT CONFIGURED]</div>'
            f'<div class="dynamic-status-detail">'
            f'No external source was queried for this sample. Correlation is '
            f'configured against {_esc(sources_str)}, and credentials for those '
            f'services were not present in this deployment.<br><br>'
            f'The correlation axis is therefore excluded from the weighting rather '
            f'than scored as clean, and the verdict uses the '
            f'<strong>static-only formula</strong>. A sample with no external '
            f'reputation in this dossier has not been checked against one.'
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
                    f'<td class="col-id">[{fid}]</td>'
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
        + _section_header("", "", "Attack & Behaviour Analysis",
                          "Runtime telemetry")
    )

    if not has_any_dynamic:
        # ── Diagnostic banner - mandatory when no dynamic evidence ──
        frs_bd = _get(r, "frs_breakdown") or {}
        dyn_ran = bool(_get(frs_bd, "dynamic_ran"))

        if dyn_ran:
            cause = (
                "The sandbox executed the sample but no instrumented API fired within "
                "the analysis window. Three explanations account for nearly all such "
                "runs: the sample detects the instrumentation and stays dormant; the "
                "payload waits on an external trigger — an inbound message, a locale "
                "match, an operator command, a dormancy timer — that the session did "
                "not supply; or the class name the hooks target is obfuscated and did "
                "not resolve."
            )
        else:
            cause = (
                "The sandbox did not execute this sample. The usual causes are an "
                "SELinux policy that blocks process injection, a manifest that "
                "declares no launchable activity, or an installation that failed on a "
                "malformed manifest or an absent signature. The verdict score above "
                "rests on static evidence alone."
            )

        html += (
            f'<div class="dynamic-status-banner">'
            f'<div class="dynamic-status-title">Runtime Telemetry Status</div>'
            f'<div class="dynamic-status-code">[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]</div>'
            f'<div class="dynamic-status-detail">'
            f'{_esc(cause)}<br><br>'
            f'<strong>This is an honest system state, not a report error.</strong> '
            f'No runtime rows appear below because no runtime events were observed. '
            f'Nothing has been inferred to fill the gap, and absence of observed '
            f'behaviour is not a finding of benign behaviour.'
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
                    ts_str = "-"
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
        #
        # Preconditions are rendered in their own block. A stage recording that
        # the SANDBOX enabled accessibility, shown under "Reconstructed Fraud
        # Workflow" at 100% confidence, reads to an analyst as something the app
        # did - which is the opposite of what it means.
        behaviour_stages = [s for s in wf_stages if not _get(s, "is_precondition")]
        precondition_stages = [s for s in wf_stages if _get(s, "is_precondition")]

        if precondition_stages:
            html += (
                '<h3 class="mt12">Sandbox Preconditions</h3>'
                '<div class="tl-desc" style="margin-bottom:8px">'
                'Capabilities the analysis sandbox enabled so the sample could be '
                'exercised. These are harness actions, not application behaviour, '
                'and do not contribute to the fraud verdict.'
                '</div><div class="timeline">'
            )
            for stage in precondition_stages:
                label = _esc(_get(stage, "label", default=""))
                desc = _esc(_get(stage, "description", default=""))
                desc_html = f'<div class="tl-desc">{desc}</div>' if desc else ""
                html += (
                    f'<div class="tl-event">'
                    f'<div class="tl-ts">SANDBOX ACTION</div>'
                    f'<div class="tl-api">{label}</div>'
                    f'{desc_html}'
                    f'</div>'
                )
            html += '</div>'

        if behaviour_stages:
            html += '<h3 class="mt12">Reconstructed Fraud Workflow</h3><div class="timeline">'
            for stage in behaviour_stages:
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

    # ── Investigation stages, permissions and crashes ──
    html += _render_investigation(r, idx)

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
    while the report generator only read screenshots/manifest.json - gallery
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
        # _collect_screenshots() now yields full manifest dicts; older results
        # (and DB rehydration) still yield bare path strings. Accept both.
        if isinstance(rel, dict):
            entries.append(rel)
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
    Runtime screenshot plates.

    Every plate carries the same metadata grid in the same order - lifecycle
    trigger, screen state, quality grade, then provenance - so the labels line
    up column-for-column down the page and a reader comparing two frames scans
    one axis instead of hunting. Fields the manifest did not record are omitted
    from that frame rather than printed empty, which keeps a sparse capture
    honest without breaking the alignment of the rest.
    """
    if not apk_dir and not report:
        return ""

    screenshots = _load_screenshot_entries(apk_dir, report)
    if not screenshots:
        return ""

    count = len(screenshots)
    html = (
        '<div class="section">'
        + _section_header("", "", "Runtime Screenshot Plates",
                          f"{count} frame{'s' if count != 1 else ''} captured")
        + '<p class="section-lead">Frames recorded by the instrumented sandbox '
          'during execution. Each plate states what triggered the capture, what '
          'the screen was showing, and how far the frame can be relied upon.</p>'
        + '<div class="gallery-grid">'
    )

    import base64
    for scr in screenshots:
        scr_id = _esc(scr.get("screenshot_id", "SCR-???"))
        label = _esc(scr.get("label") or scr.get("title") or "UI capture")
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

        img_html = (
            f'<img src="{b64_uri}" alt="Runtime capture {scr_id}" '
            f'class="scr-img" loading="lazy" />'
            if b64_uri else
            '<div class="no-data">Frame not retained in this artifact set</div>'
        )

        html += (
            f'<div class="gallery-card">'
            f'<div class="scr-header">'
            f'<span class="scr-id">{fid} &middot; {scr_id}</span>'
            f'<span class="scr-label">{label}</span>'
            f'</div>'
            f'<div class="scr-body">{img_html}</div>'
            f'<dl class="scr-meta">'
            + _screenshot_meta_rows(scr)
            + '</dl></div>'
        )

    html += '</div></div>'
    return html


def _quality_grade_html(grade: str) -> str:
    """A / B / C capture-quality grade as a muted pill."""
    g = str(grade or "").strip().upper()[:1]
    cls = {"A": "grade-a", "B": "grade-b", "C": "grade-c"}.get(g, "grade-b")
    if not g:
        return '<span class="muted">not graded</span>'
    caption = {
        "A": "corroborates a finding directly",
        "B": "supporting context",
        "C": "background only",
    }.get(g, "")
    tail = f' <span class="muted">&mdash; {caption}</span>' if caption else ""
    return f'<span class="grade {cls}">{g}</span>{tail}'


def _screenshot_meta_rows(scr: Dict[str, Any]) -> str:
    """
    The aligned definition grid shared by every screenshot plate.

    Row order is fixed and never varies with what a frame happens to carry;
    absent rows collapse, present rows keep their position, so labels stay on
    one left edge and values on another across the whole appendix.
    """
    def first(*keys: str) -> str:
        for k in keys:
            v = scr.get(k)
            if v not in (None, "", [], {}):
                return str(v)
        return ""

    trigger = first("capture_trigger", "trigger_event", "trigger_reason", "stage", "reason")
    screen_state = first("screen_summary", "visual_observation", "semantic_type", "category")
    activity = first("activity", "window", "fragment")
    package = first("foreground_package", "target_package", "package")
    linked = scr.get("linked_evidence_ids") or []
    if isinstance(linked, (list, tuple)):
        linked_str = ", ".join(str(x) for x in linked if x)
    else:
        linked_str = str(linked)
    if not linked_str:
        linked_str = first("evidence_id", "evidence_moment_id")
    claim = first("investigative_claim", "description")
    source = first("source", "observation_source")
    correlation = first("correlation_status", "deduplication_status")

    rows: List[Tuple[str, str, bool]] = [
        ("Lifecycle trigger", trigger, False),
        ("Screen state", screen_state, False),
        ("Activity", activity, True),
        ("Package", package, True),
        ("Linked evidence", linked_str, True),
        ("Correlation", correlation, False),
        ("Capture source", source, False),
    ]

    out = ""
    for label, value, mono in rows:
        if not value:
            continue
        cls = ' class="mono"' if mono else ""
        out += f'<dt>{_esc(label)}</dt><dd{cls}>{_esc(value[:220])}</dd>'

    out += f'<dt>Quality grade</dt><dd>{_quality_grade_html(scr.get("quality", ""))}</dd>'

    if claim:
        out += f'<div class="scr-caption">{_esc(claim[:300])}</div>'
    return out


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
        + _section_header("", "", "Exploration Coverage", f"[{fid}]")
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




def _build_execution_assertions(r: Dict, idx: _FindingIndex) -> str:
    """
    Execution Assertion Matrix and INCOMPLETE EXERCISE gap analysis.

    Sits alongside coverage because it answers the same question from the other
    side: coverage says how much of the app we walked, this says which of the
    sample's own fraud preconditions were ever met. A reader interpreting "no
    malicious behaviour observed" needs the second one to know what that
    sentence is worth.
    """
    assertions = _get(r, "execution_assertions") or {}
    rows = _get(assertions, "assertions") or []
    if not rows:
        return ""

    incomplete = bool(_get(assertions, "incomplete_exercise"))
    fired = int(_get(assertions, "fired_count", default=0) or 0)
    total = int(_get(assertions, "total_count", default=len(rows)) or len(rows))
    fid = idx.next("INTEL", "Execution Assertion Matrix")

    banner = ""
    if incomplete:
        banner = (
            '<div class="qualifier">'
            '<div class="qualifier-title">Incomplete exercise &mdash; verdict qualified</div>'
            '<div class="qualifier-body">'
            'This run did not exercise the sample. The sandbox reached none of the '
            'trigger conditions below and observed no threat behaviour. '
            '<b>Absence of evidence is not evidence of absence</b> &mdash; an '
            'evasion-first banking trojan waiting on a target app, an OTP, an '
            'accessibility grant or a dormancy timer produces exactly this result. '
            'Reported confidence is reduced by 50%, and this run does not certify '
            'the sample as benign.'
            '</div></div>'
        )

    body = [
        '<div class="section">',
        _section_header(
            "", "",
            "Execution Assertion Matrix",
            f"[{fid}] &mdash; {fired}/{total} trigger conditions reached",
        ),
        banner,
        '<table class="tbl"><thead><tr>'
        '<th>Trigger condition</th><th>Reached</th><th>Evidence / remediation</th>'
        '</tr></thead><tbody>',
    ]
    for row in rows:
        reached = bool(_get(row, "fired"))
        detail = _get(row, "evidence") if reached else _get(row, "remediation")
        mark = (
            '<span class="sev sev-low" style="margin-left:0">Reached</span>'
            if reached
            else '<span class="sev sev-medium" style="margin-left:0">Not reached</span>'
        )
        body.append(
            f'<tr><td><b>{_esc(_get(row, "label", default=""))}</b></td>'
            f"<td>{mark}</td>"
            f'<td>{_esc(str(detail or "&mdash;")[:300])}</td></tr>'
        )
    body.append("</tbody></table>")
    body.append(
        '<div class="muted" style="font-size:12px;margin-top:6px">'
        'A &ldquo;NO&rdquo; row is an unmet precondition, not a cleared check: the '
        'corresponding fraud behaviour could not have been observed during this '
        'run regardless of whether the sample implements it.</div>'
    )

    suggestions = _get(r, "remedial_suggestions") or []
    if suggestions:
        body.append(
            '<h3 style="margin:14px 0 6px">Gap analysis &mdash; recommended re-run actions</h3>'
        )
        body.append(
            '<table class="tbl"><thead><tr><th>Priority</th><th>Action</th>'
            "<th>Why it matters</th></tr></thead><tbody>"
        )
        for suggestion in suggestions[:8]:
            rationale = str(_get(suggestion, "rationale", default="") or "")
            context = str(_get(suggestion, "threat_context", default="") or "")
            body.append(
                f'<tr><td><b>{_esc(_get(suggestion, "priority", default=""))}</b></td>'
                f'<td>{_esc(_get(suggestion, "title", default=""))}</td>'
                f"<td>{_esc(f'{rationale} {context}'.strip()[:320])}</td></tr>"
            )
        body.append("</tbody></table>")

    body.append("</div>")
    return "".join(body)


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
        + _section_header("", "", "Recommended Response")
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
            f'<div class="verdict-banner verdict-medium mt16">'
            f'<div class="verdict-q">Customer advisory &mdash; draft for approval</div>'
            f'<div class="verdict-narrative">{_esc(advisory)}</div>'
            f'</div>'
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
        + _section_header("", "", "Threat Scenario Correlation")
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
            f'<td class="col-id">[{fid}]</td>'
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
            "", "",
            "Evidence Ledger",
            f"{len(idx.ledger)} findings indexed"
        )
        + '<table class="data-table"><thead>'
        + '<tr><th>Finding ID</th><th>Category</th><th>Description</th></tr>'
        + '</thead><tbody>'
    )
    for fid, cat, title in idx.ledger:
        html += f'<tr><td class="col-id">[{fid}]</td><td>{_esc(cat)}</td><td>{_esc(title[:100])}</td></tr>'
    html += '</tbody></table></div>'
    return html


def _build_chain_of_custody(r: Dict, ts: str) -> str:
    """
    Chain of custody: the hashes and run identifiers that bind this document to
    the artifacts it was rendered from.
    """
    sha = str(_get(r, "sha256", default="") or "")
    pkg = str(_get(r, "package_name", default="") or "")
    mode = str(_get(r, "analysis_mode", default="") or "")
    case_id = str(_get(r, "case_id", default="") or _get(r, "job_id", default="") or "")

    integrity_src = "|".join([sha, pkg, str(_get(r, "final_risk_score", default="")), ts])
    integrity = hashlib.sha256(integrity_src.encode("utf-8")).hexdigest()

    rows = [
        ("Sample SHA-256", sha or "not recorded", True),
        ("Package name", pkg or "not recorded", True),
        ("Case reference", case_id or "not assigned", True),
        ("Analysis mode", mode or "not recorded", False),
        ("Document rendered", ts, False),
        ("Document integrity digest", integrity, True),
    ]
    body = ""
    for label, value, mono in rows:
        cls = ' class="info-val info-val-mono"' if mono else ' class="info-val"'
        body += (
            f'<div class="info-card">'
            f'<div class="info-key">{_esc(label)}</div>'
            f'<div{cls}>{_esc(value)}</div>'
            f'</div>'
        )

    return (
        '<div class="section">'
        + _section_header("", "", "Chain of Custody",
                          "Bind this document to its artifacts")
        + '<p class="section-lead">The integrity digest is computed over the '
          'sample hash, package name, verdict score and render timestamp. A '
          'document whose digest does not reproduce has been altered after '
          'rendering.</p>'
        + f'<div class="grid-2">{body}</div>'
        + '</div>'
    )


def _build_footer(r: Dict) -> str:
    sha = _esc(_get(r, "sha256", default=""))
    return (
        f'<div class="report-footer">'
        f'<b>Sudarshan</b> &middot; Banking Malware Intelligence &middot; '
        f'SHA-256 {sha}'
        f'<span class="fine">Scoring is deterministic. Narrative sections are '
        f'generated from the recorded evidence and do not influence the verdict '
        f'score. Findings marked [TARGET-STATE] describe design intent inferred '
        f'from static structure and were not confirmed by runtime '
        f'instrumentation in this run.</span>'
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

        def _build_screenshot_index(apk_dir, report) -> str:
            screenshots = _load_screenshot_entries(apk_dir, report)
            if not screenshots:
                return ""
            
            html = (
                '<div class="section">'
                + _section_header("", "", "Screenshot Index")
                + '<table class="data-table"><thead><tr><th>ID</th><th>Label</th><th>Reason</th><th>Time</th></tr></thead><tbody>'
            )
            for scr in screenshots:
                scr_id = _esc(scr.get("screenshot_id", "SCR-???"))
                label = _esc(scr.get("label") or scr.get("title") or "UI capture")
                reason = _esc(scr.get("reason", ""))
                ts = scr.get("timestamp_ms", 0)
                try:
                    ts_str = datetime.fromtimestamp(ts/1000.0, timezone.utc).strftime("%H:%M:%S") if ts else ""
                except:
                    ts_str = ""
                
                html += f'<tr><td class="col-id">{scr_id}</td><td>{label}</td><td>{reason}</td><td class="col-num">{ts_str}</td></tr>'
            
            html += '</tbody></table></div>'
            return html

        scr_index = _build_screenshot_index(self.apk_dir, self.r)

        # Part order mirrors the PDF edition exactly, so a reader who has one
        # in front of them can find the same section in the other.
        #
        # The gallery is rendered ahead of composition even though it prints
        # last: it mints SCR-NNN identifiers, and the Evidence Ledger in Part C
        # has to already know about them.
        gallery = _build_visual_gallery(self.apk_dir, idx, self.r)

        body = (
            _build_header(self.r, ts)

            + _part("Part A", "Executive Summary",
                    "The determination, the arithmetic behind it, and the findings "
                    "that carry it. Written to be read without reference to the "
                    "technical part.")
            + _build_executive_conclusion(self.r)
            + _build_key_findings(self.r)
            + _build_score_ledger(self.r)
            + visual_exec
            + _build_recommendations(self.r)
            + _part_end()

            + _part("Part B", "Technical Analysis",
                    "The full evidence set: score decomposition, static forensics, "
                    "external correlation, and observed runtime behaviour.")
            + _build_stei(self.r)
            + _build_static(self.r, idx)
            + _build_threat_scenario_table(self.r, idx)
            + _build_threat_intel(self.r, idx)
            + _build_dynamic(self.r, evidence_json, idx)
            + visual_tech
            + _part_end()

            + _part("Part C", "Audit & Traceability",
                    "What this run reached, what it did not, and the record binding "
                    "each finding to the artifact it came from.")
            + _build_exploration_coverage(self.r, self.apk_dir, idx)
            + _build_execution_assertions(self.r, idx)
            + _build_ledger(idx)
            + _build_chain_of_custody(self.r, ts)
            + _part_end()

            + _part("Appendix", "Runtime Screenshots & Visual Evidence",
                    "Frames captured during instrumented execution, each with the "
                    "trigger that produced it and the weight it can carry.")
            + scr_index
            + gallery
            + visual_appendix
            + _part_end()

            + _build_footer(self.r)
        )

        pkg = _esc(_get(self.r, "package_name", default="Unknown"))
        frs = float(_get(self.r, "final_risk_score", default=0))
        band = _esc(_get(self.r, "risk_band", default="Unknown"))

        html = (
            f'<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            f'<meta charset="UTF-8">\n'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>Threat Investigation Dossier &mdash; {pkg}</title>\n'
            f'<meta name="description" content="Sudarshan threat investigation dossier '
            f'for {pkg}. Verdict score {frs:.0f} of 100, risk band {band}.">\n'
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
