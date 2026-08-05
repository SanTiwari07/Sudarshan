"""Per-APK dynamic validation execution."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.frida_sandbox import artifact_dir_for, run_frida_analysis
from sudarshan_core.engines.report_generator import build_report
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.validation.corpus import CorpusEntry
from sudarshan_core.validation.coverage import compute_coverage
from sudarshan_core.validation.screenshot_audit import validate_screenshots

logger = logging.getLogger(__name__)


@dataclass
class ApkValidationResult:
    entry_id: str
    category: str
    label: str
    apk_path: str
    status: str  # PASS | FAIL | SKIP | ERROR
    skipped: bool = False
    skip_reason: str = ""

    launch_success: bool = False
    launch_time_ms: Optional[float] = None
    frida_attach_time_ms: Optional[float] = None
    dynamic_status: str = ""
    explorer_used: str = ""
    explorer_coverage: Dict[str, Any] = field(default_factory=dict)
    permission_dialogs_found: int = 0
    runtime_events: int = 0
    screenshots_count: int = 0
    evidence_objects: int = 0
    workflow_nodes: int = 0
    risk_score: Optional[float] = None
    html_success: bool = False
    pdf_success: bool = False
    failures: List[str] = field(default_factory=list)
    recovery_attempts: List[str] = field(default_factory=list)
    timings: Dict[str, float] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    screenshot_validation: List[Dict[str, Any]] = field(default_factory=list)
    artifact_dir: str = ""
    log_excerpt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "category": self.category,
            "label": self.label,
            "apk_path": self.apk_path,
            "status": self.status,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "launch_success": self.launch_success,
            "launch_time_ms": self.launch_time_ms,
            "frida_attach_time_ms": self.frida_attach_time_ms,
            "dynamic_status": self.dynamic_status,
            "explorer_used": self.explorer_used,
            "explorer_coverage": self.explorer_coverage,
            "permission_dialogs_found": self.permission_dialogs_found,
            "runtime_events": self.runtime_events,
            "screenshots_count": self.screenshots_count,
            "evidence_objects": self.evidence_objects,
            "workflow_nodes": self.workflow_nodes,
            "risk_score": self.risk_score,
            "html_success": self.html_success,
            "pdf_success": self.pdf_success,
            "failures": self.failures,
            "recovery_attempts": self.recovery_attempts,
            "timings": self.timings,
            "coverage": self.coverage,
            "screenshot_validation": self.screenshot_validation,
            "artifact_dir": self.artifact_dir,
        }


def _timeline_ms(timeline: Dict[str, Any], key: str) -> Optional[float]:
    if not timeline:
        return None
    val = timeline.get(key)
    if val is None:
        return None
    try:
        return float(val) * 1000.0
    except (TypeError, ValueError):
        return None


def _minimal_report_dict(dynamic: Dict[str, Any]) -> Dict[str, Any]:
    pkg = dynamic.get("package_name") or "unknown"
    return {
        "sha256": dynamic.get("sha256") or ("0" * 64),
        "package_name": pkg,
        "app_name": pkg,
        "final_risk_score": dynamic.get("bfci", 0.0),
        "risk_band": "Validation",
        "dynamic_analysis": dynamic,
        "dynamic_available": dynamic.get("available", False),
        "frs_breakdown": {
            "stei": 0.0,
            "dynamic": dynamic.get("bfci", 0.0),
            "dynamic_ran": dynamic.get("available", False),
            "dynamic_conclusive": dynamic.get("dynamic_status") == "EVENTS_CAPTURED",
        },
        "fraud_workflow": dynamic.get("fraud_workflow"),
        "screenshots": dynamic.get("screenshots", []),
        "artifact_dir": dynamic.get("artifact_dir"),
    }


async def validate_apk(entry: CorpusEntry, run_log_dir: Path) -> ApkValidationResult:
    res = ApkValidationResult(
        entry_id=entry.id,
        category=entry.category,
        label=entry.label,
        apk_path=str(entry.apk_path),
        status="SKIP",
    )

    if entry.missing:
        if entry.optional:
            res.skipped = True
            res.skip_reason = entry.missing_reason
            return res
        res.status = "SKIP"
        res.skip_reason = entry.missing_reason
        res.failures.append(entry.missing_reason)
        return res

    t0 = time.monotonic()
    log_file = run_log_dir / f"{entry.id}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(file_handler)
    root.setLevel(logging.INFO)

    try:
        t_analysis = time.monotonic()
        dynamic = await run_frida_analysis(str(entry.apk_path), package_name=entry.package_hint or None)
        res.timings["analysis_seconds"] = time.monotonic() - t_analysis

        res.dynamic_status = dynamic.get("dynamic_status", "")
        res.explorer_used = dynamic.get("explorer_used", "")
        res.artifact_dir = dynamic.get("artifact_dir", "") or str(artifact_dir_for(str(entry.apk_path)))
        art = Path(res.artifact_dir)

        timeline = dynamic.get("launch_timeline") or {}
        res.launch_time_ms = _timeline_ms(timeline, "first_pid")
        res.frida_attach_time_ms = _timeline_ms(timeline, "frida_attach")
        res.launch_success = (
            dynamic.get("launch_method_used") not in (None, "failed")
            and not dynamic.get("crash_report")
        )
        if dynamic.get("error"):
            res.failures.append(str(dynamic["error"]))
            if "install" in str(dynamic["error"]).lower():
                res.launch_success = False

        raw_counts = dynamic.get("raw_event_counts") or {}
        res.runtime_events = sum(int(v) for v in raw_counts.values())
        res.screenshots_count = len(dynamic.get("screenshots") or [])
        res.evidence_objects = int(dynamic.get("evidence_record_count") or 0)
        wf = dynamic.get("fraud_workflow") or {}
        res.workflow_nodes = len(wf.get("stages") or [])

        cov = compute_coverage(dynamic, art)
        res.coverage = cov.to_dict()
        res.explorer_coverage = dynamic.get("coverage_metrics") or {}
        res.permission_dialogs_found = cov.permission_dialogs_found

        flags = {
            "has_accessibility_abuse": cov.accessibility_callbacks > 0,
            "has_sms_read_write": int(raw_counts.get("sms", 0)) > 0,
            "has_system_alert_window": int(raw_counts.get("overlay", 0)) > 0,
        }
        risk = calculate_risk_score(flags=flags, dynamic_result=dynamic, family="Validation")
        res.risk_score = float(risk.get("final_risk_score", 0))

        report_dict = _minimal_report_dict(dynamic)
        report_dict["final_risk_score"] = res.risk_score
        html_path = art / "validation_report.html"
        try:
            html = build_report(report_dict, apk_dir=art, output_path=html_path)
            res.html_success = html_path.is_file() and len(html) > 500
            res.pdf_success = res.html_success and "data:image/png;base64," in html
            if not res.pdf_success and res.screenshots_count > 0:
                res.failures.append("HTML missing embedded screenshot base64 (PDF would be empty)")
        except Exception as exc:
            res.failures.append(f"HTML report: {exc}")

        if res.screenshots_count > 0:
            html_text = html_path.read_text(encoding="utf-8") if html_path.is_file() else ""
            for sv in validate_screenshots(art, report_dict, html_text):
                res.screenshot_validation.append(sv.__dict__)
                if sv.errors:
                    res.failures.extend([f"screenshot {sv.screenshot_id}: {e}" for e in sv.errors])

        if dynamic.get("dae_pipeline"):
            dae = dynamic["dae_pipeline"]
            if dae.get("failure_reason"):
                res.failures.append(dae["failure_reason"])

        res.status = "PASS" if not res.failures and dynamic.get("dynamic_status") != "INSTRUMENTATION_FAILED" else "FAIL"
        if dynamic.get("error") and res.status == "PASS":
            res.status = "FAIL"

    except Exception as exc:
        res.status = "ERROR"
        res.failures.append(f"{type(exc).__name__}: {exc}")
        res.log_excerpt = traceback.format_exc()
    finally:
        root.removeHandler(file_handler)
        file_handler.close()
        if log_file.is_file():
            res.log_excerpt = log_file.read_text(encoding="utf-8", errors="replace")[-8000:]

    res.timings["total_seconds"] = time.monotonic() - t0
    (run_log_dir / f"{entry.id}.json").write_text(
        json.dumps(res.to_dict(), indent=2), encoding="utf-8"
    )
    return res


async def validate_all(entries: List[CorpusEntry], output_dir: Path) -> List[ApkValidationResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results: List[ApkValidationResult] = []
    for entry in entries:
        logger.info("=== Validating %s (%s) ===", entry.id, entry.label)
        r = await validate_apk(entry, output_dir)
        results.append(r)
        logger.info("=== %s -> %s failures=%s ===", entry.id, r.status, len(r.failures))
    return results
