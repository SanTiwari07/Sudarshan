"""Generate final engineering validation report (HTML + JSON)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.validation.runner import ApkValidationResult


def _reliability_score(results: List[ApkValidationResult]) -> float:
    executed = [r for r in results if not r.skipped]
    if not executed:
        return 0.0
    passed = sum(1 for r in executed if r.status == "PASS")
    return round(100.0 * passed / len(executed), 1)


def _coverage_score(results: List[ApkValidationResult]) -> float:
    vals = [r.coverage.get("coverage_percent", 0) for r in results if not r.skipped]
    return round(sum(vals) / len(vals), 1) if vals else 0.0


def _performance_score(results: List[ApkValidationResult]) -> float:
    durs = [r.timings.get("analysis_seconds", 0) for r in results if not r.skipped]
    if not durs:
        return 0.0
    avg = sum(durs) / len(durs)
    if avg <= 45:
        return 100.0
    if avg <= 90:
        return 75.0
    return 50.0


def build_engineering_report(
    results: List[ApkValidationResult],
    stress_reports: List[Dict[str, Any]],
    recovery_report: Optional[Dict[str, Any]],
    output_dir: Path,
) -> Path:
    rel = _reliability_score(results)
    cov = _coverage_score(results)
    perf = _performance_score(results)
    overall = round((rel * 0.5 + cov * 0.25 + perf * 0.25), 1)

    executed = [r for r in results if not r.skipped]
    failures_matrix = [
        {"apk": r.entry_id, "failures": r.failures, "status": r.status}
        for r in executed
        if r.failures
    ]

    production_ready = (
        rel == 100.0
        and all(r.html_success for r in executed if r.screenshots_count > 0)
        and not failures_matrix
        and overall >= 85
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reliability_score": rel,
        "coverage_score": cov,
        "performance_score": perf,
        "overall_score": overall,
        "production_ready": production_ready,
        "stable_declaration": "STABLE" if production_ready else "NOT STABLE",
        "apk_results": [r.to_dict() for r in results],
        "stress": stress_reports,
        "recovery": recovery_report,
        "failures_matrix": failures_matrix,
    }
    json_path = output_dir / "engineering_report.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    rows = ""
    for r in results:
        rows += (
            f"<tr><td>{r.entry_id}</td><td>{r.category}</td><td>{r.status}</td>"
            f"<td>{'yes' if r.launch_success else 'no'}</td>"
            f"<td>{r.launch_time_ms or '-'}</td>"
            f"<td>{r.frida_attach_time_ms or '-'}</td>"
            f"<td>{r.runtime_events}</td>"
            f"<td>{r.screenshots_count}</td>"
            f"<td>{'yes' if r.html_success else 'no'}</td>"
            f"<td>{'yes' if r.pdf_success else 'no'}</td>"
            f"<td>{'; '.join(r.failures[:3])}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Sudarshan DAE Validation Report</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#0d1117;color:#e6edf3;padding:24px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}}
th,td{{border:1px solid #30363d;padding:8px;text-align:left;font-size:13px}}
th{{background:#161b22}}
.score{{font-size:2rem;font-weight:bold;color:#58a6ff}}
.warn{{color:#f85149}}
.ok{{color:#3fb950}}
</style></head><body>
<h1>Dynamic Analysis Engine - Validation Report</h1>
<p>Generated {payload['generated_at']}</p>
<p class="score">Overall: {overall}% - <span class="{'ok' if production_ready else 'warn'}">{payload['stable_declaration']}</span></p>
<ul>
<li>Reliability: {rel}%</li>
<li>Coverage: {cov}%</li>
<li>Performance: {perf}%</li>
<li>Production readiness recommendation: <strong>{'GO' if production_ready else 'NO-GO'}</strong></li>
</ul>
<h2>Architecture (validation path)</h2>
<pre class="mermaid">
flowchart TD
  UPLOAD[Corpus APK] --> INSTALL[ADB Install]
  INSTALL --> LAUNCH[Launch Ladder]
  LAUNCH --> FRIDA[Frida Attach]
  FRIDA --> HOOKS[Hooks + Canary]
  HOOKS --> BUS[Event Bus]
  BUS --> EXP[Agentic Explorer]
  EXP --> SCR[Screenshot Manager]
  SCR --> EV[Evidence Store]
  EV --> WF[Workflow]
  WF --> RISK[Risk Engine]
  RISK --> HTML[HTML Report]
  HTML --> PDF[PDF via print embed]
</pre>
<h2>Validation matrix</h2>
<table>
<tr><th>ID</th><th>Category</th><th>Status</th><th>Launch</th><th>Launch ms</th><th>Attach ms</th>
<th>Events</th><th>Screenshots</th><th>HTML</th><th>PDF-ready</th><th>Failures</th></tr>
{rows}
</table>
<h2>Remaining risks</h2>
<ul>
<li>Corpus completeness: optional APKs skipped until placed under tests/apks/categories/</li>
<li>Stress/recovery results in engineering_report.json</li>
<li>Stability requires 100% pass on all non-optional samples with full screenshot/report integrity</li>
</ul>
</body></html>"""

    html_path = output_dir / "engineering_report.html"
    html_path.write_text(html, encoding="utf-8")
    return html_path
