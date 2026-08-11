#!/usr/bin/env python3
"""
End-to-end validation for a REAL Drinik APK through the Sudarshan pipeline.

Does NOT fabricate runtime events or substitute fixture scores for live APK output.
Fails at the first stage that cannot be honestly verified.

Usage:
    PYTHONPATH=backend;shared python scripts/validate_real_drinik_e2e.py
    PYTHONPATH=backend;shared python scripts/validate_real_drinik_e2e.py --apk path/to/drinik.apk
    PYTHONPATH=backend;shared python scripts/validate_real_drinik_e2e.py --dynamic  # requires ADB+emulator
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend" / "tests"))

from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.ingest.apk_record import (
    build_apk_record,
    resolve_drinik_apk_path,
    write_ingestion_record,
)
from sudarshan_core.models.schemas import StaticAnalysisFlags

from case_study_fixtures import CORRELATION_UNAVAILABLE


@dataclass
class StageResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class E2EResult:
    stages: List[StageResult] = field(default_factory=list)
    sha256: str = ""
    classification: str = ""
    matched_rule: str = ""
    static_frs: float = 0.0
    static_band: str = ""
    dynamic_frs: float = 0.0
    dynamic_band: str = ""
    runtime_event_count: int = 0
    runtime_event_types: List[str] = field(default_factory=list)
    evidence_record_count: int = 0
    report_path: str = ""
    aborted: bool = False

    def add(self, name: str, passed: bool, detail: str = "") -> None:
        self.stages.append(StageResult(name=name, passed=passed, detail=detail))
        if not passed:
            self.aborted = True


def _adb_devices() -> List[str]:
    try:
        out = subprocess.run(
            ["adb", "devices"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        serials = []
        for line in (out.stdout or "").splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])
        return serials
    except Exception:
        return []


def _run_static(apk_path: Path) -> Tuple[StaticAnalysisFlags, List[str], str]:
    from sudarshan_core.analyzers.apk_analyzer import analyze_apk

    out = analyze_apk(str(apk_path))
    return out.flags, out.permissions or [], out.package_name


def _score_static(flags: StaticAnalysisFlags, permissions: List[str], family: str) -> Dict[str, Any]:
    return calculate_risk_score(
        flags,
        ai_confidence=1.0,
        dynamic_result=None,
        correlation_result=CORRELATION_UNAVAILABLE,
        family=family,
        all_permissions=permissions,
    )


async def _run_dynamic(apk_path: Path, package_name: str) -> Dict[str, Any]:
    from sudarshan_core.engines.frida_sandbox import run_frida_analysis

    return await run_frida_analysis(str(apk_path), package_name=package_name)


def _count_runtime_events(dynamic: Dict[str, Any]) -> Tuple[int, List[str]]:
    types: List[str] = []
    count = int(dynamic.get("total_hook_events_received") or 0)
    hook_fires = dynamic.get("hook_fire_counts") or {}
    if hook_fires:
        types.extend(sorted(hook_fires.keys()))
    api_calls = dynamic.get("api_calls") or []
    if api_calls and not types:
        types.append("api_calls")
    return count, types


def _evidence_count(dynamic: Dict[str, Any], artifact_dir: Optional[str]) -> int:
    n = int(dynamic.get("evidence_record_count") or 0)
    if n:
        return n
    if artifact_dir:
        ev_path = Path(artifact_dir) / "evidence.json"
        if ev_path.is_file():
            try:
                data = json.loads(ev_path.read_text(encoding="utf-8"))
                return len(data.get("records") or [])
            except Exception:
                pass
    return 0


async def run_e2e(apk_path: Path, run_dynamic: bool) -> E2EResult:
    result = E2EResult()

    # [1] APK exists
    if not apk_path.is_file():
        result.add("APK", False, f"Not found: {apk_path}")
        return result
    result.add("APK", True, str(apk_path))

    # [2] SHA256 / ingestion
    try:
        record = write_ingestion_record(apk_path)
        result.sha256 = record["sha256"]
        result.add("SHA256", True, result.sha256)
    except Exception as exc:
        result.add("SHA256", False, str(exc))
        return result

    # [3] Static analysis
    try:
        flags, permissions, package_name = _run_static(apk_path)
        result.add("Static Analysis", True, f"package={package_name}")
    except Exception as exc:
        result.add("Static Analysis", False, str(exc))
        return result

    # [4] Classification
    family, rule = classify_family(flags)
    result.classification = family
    result.matched_rule = rule
    drinik_ok = family == "Drinik"
    result.add(
        "Classification",
        drinik_ok,
        f"{family} — {rule}" if drinik_ok else f"Expected Drinik, got {family}: {rule}",
    )

    # [5] Static risk engine
    try:
        static_risk = _score_static(flags, permissions, family)
        result.static_frs = float(static_risk["final_risk_score"])
        result.static_band = str(static_risk["risk_band"])
        result.add(
            "Risk Engine (static-only)",
            True,
            f"FRS={result.static_frs:.2f} band={result.static_band}",
        )
    except Exception as exc:
        result.add("Risk Engine (static-only)", False, str(exc))
        return result

    if not run_dynamic:
        result.add("Frida", False, "Skipped (--dynamic not set or no device)")
        result.add("Runtime Events", False, "Skipped")
        result.add("EvidenceStore", False, "Skipped")
        result.add("Correlation", False, "Skipped (run full pipeline via API)")
        result.add("AI Investigation", False, "Skipped")
        result.add("Report Generation", False, "Skipped")
        return result

    # [6] Frida / dynamic
    devices = _adb_devices()
    if not devices:
        result.add("Frida", False, "No ADB device connected")
        result.add("Runtime Events", False, "Blocked — no emulator")
        result.add("EvidenceStore", False, "Blocked")
        result.add("Correlation", False, "Blocked")
        result.add("AI Investigation", False, "Blocked")
        result.add("Report Generation", False, "Blocked")
        return result

    try:
        dynamic = await _run_dynamic(apk_path, package_name)
        frida_ok = bool(dynamic.get("available"))
        status = dynamic.get("dynamic_status", "unknown")
        result.add(
            "Frida",
            frida_ok,
            f"status={status} canary={dynamic.get('canary_received')} "
            f"java_hooks={dynamic.get('java_hooks_installed')}",
        )
    except Exception as exc:
        result.add("Frida", False, str(exc))
        return result

    if not dynamic.get("available"):
        result.add("Runtime Events", False, dynamic.get("error", "dynamic unavailable"))
        result.add("EvidenceStore", False, "Blocked")
        result.add("Correlation", False, "Blocked")
        result.add("Risk Engine (full)", False, "Blocked")
        result.add("AI Investigation", False, "Blocked")
        result.add("Report Generation", False, "Blocked")
        return result

    # [7] Runtime events
    event_count, event_types = _count_runtime_events(dynamic)
    result.runtime_event_count = event_count
    result.runtime_event_types = event_types
    result.add(
        "Runtime Events",
        event_count > 0,
        f"count={event_count} types={event_types[:5]}",
    )

    # [8] EvidenceStore
    artifact_dir = dynamic.get("artifact_dir")
    ev_count = _evidence_count(dynamic, artifact_dir)
    result.evidence_record_count = ev_count
    result.add("EvidenceStore", ev_count > 0, f"records={ev_count} dir={artifact_dir}")

    # [9] Correlation — requires API keys; mark pass only if available flag set
    try:
        from sudarshan_core.services.threat_correlator import correlate

        corr = await correlate(
            sha256=result.sha256,
            urls=flags.hardcoded_urls_ips,
            package_name=package_name,
            dynamic_urls=[],
        )
        corr_ok = bool(corr and corr.get("available"))
        result.add(
            "Correlation",
            corr_ok,
            "TI keys configured" if corr_ok else "No TI keys or no hits (axis excluded)",
        )
    except Exception as exc:
        result.add("Correlation", False, str(exc))
        corr = {"available": False}

    # [10] Full risk engine with dynamic
    try:
        full_risk = calculate_risk_score(
            flags,
            ai_confidence=1.0,
            dynamic_result=dynamic,
            correlation_result=corr,
            family=family,
            all_permissions=permissions,
        )
        result.dynamic_frs = float(full_risk["final_risk_score"])
        result.dynamic_band = str(full_risk["risk_band"])
        b = full_risk.get("frs_breakdown") or {}
        breakdown = (
            f"STEI={b.get('stei')} dyn={b.get('dynamic')} "
            f"corr={b.get('correlation')} bank={b.get('banking_impact')} "
            f"axes={b.get('axes_used')} excluded={b.get('axes_excluded')}"
        )
        result.add(
            "Risk Engine (full)",
            True,
            f"FRS={result.dynamic_frs:.2f} band={result.dynamic_band} | {breakdown}",
        )
    except Exception as exc:
        result.add("Risk Engine (full)", False, str(exc))

    # [11] Report
    report_candidates = []
    if artifact_dir:
        report_candidates.append(Path(artifact_dir) / "report.html")
    for p in report_candidates:
        if p.is_file():
            result.report_path = str(p)
            break
    result.add(
        "Report Generation",
        bool(result.report_path),
        result.report_path or "report.html not found in artifact dir",
    )

    # [12] AI — gateway only; not run in this script without live API
    result.add("AI Investigation", False, "Requires gateway POST /api/v1/analyze (not run here)")

    return result


def _print_report(result: E2EResult) -> None:
    print("=" * 40)
    print(" SUDARSHAN E2E VALIDATION")
    print("=" * 40)
    print()

    labels = [
        "APK",
        "SHA256",
        "Static Analysis",
        "Classification",
        "Frida",
        "Runtime Events",
        "EvidenceStore",
        "Correlation",
        "Risk Engine (static-only)",
        "Risk Engine (full)",
        "AI Investigation",
        "Report Generation",
    ]
    seen = {s.name: s for s in result.stages}
    for label in labels:
        if label not in seen:
            continue
        s = seen[label]
        status = "PASS" if s.passed else "FAIL"
        print(f"{label:<28} {status}")
        if s.detail:
            print(f"  {s.detail}")

    print()
    print(f"Runtime Events:      {result.runtime_event_count}")
    if result.runtime_event_types:
        print(f"Event types:         {', '.join(result.runtime_event_types[:8])}")
    print(f"Static FRS:            {result.static_frs:.2f} ({result.static_band})")
    if result.dynamic_frs:
        print(f"Dynamic FRS:           {result.dynamic_frs:.2f} ({result.dynamic_band})")
    if result.sha256:
        print(f"SHA256:                {result.sha256}")
    if result.classification:
        print(f"Classification:        {result.classification}")
    print()
    all_pass = all(s.passed for s in result.stages if s.name not in ("AI Investigation",))
    overall = "PASS" if all_pass and not result.aborted else "FAIL"
    print("=" * 40)
    print(f" END-TO-END: {overall}")
    print("=" * 40)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate real Drinik APK E2E pipeline")
    parser.add_argument("--apk", help="Path to Drinik APK (default: resolve from env/corpus)")
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Run Frida dynamic analysis (requires ADB emulator)",
    )
    args = parser.parse_args(argv)

    apk = resolve_drinik_apk_path(args.apk)
    if not apk:
        print(
            "BLOCKER: No real Drinik APK found.\n"
            "  Place at: tests/apks/categories/drinik.apk\n"
            "  Or set:   DRINIK_APK_PATH=/path/to/sample.apk\n"
            "Fixtures in case_study_fixtures.py are NOT used for this validation.",
            file=sys.stderr,
        )
        return 2

    result = asyncio.run(run_e2e(apk, run_dynamic=args.dynamic))
    _print_report(result)

    out_path = REPO_ROOT / "scripts" / "drinik_e2e_validation.json"
    out_path.write_text(
        json.dumps(
            {
                "sha256": result.sha256,
                "classification": result.classification,
                "static_frs": result.static_frs,
                "static_band": result.static_band,
                "dynamic_frs": result.dynamic_frs,
                "dynamic_band": result.dynamic_band,
                "runtime_event_count": result.runtime_event_count,
                "stages": [
                    {"name": s.name, "passed": s.passed, "detail": s.detail}
                    for s in result.stages
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    critical_fail = any(
        not s.passed
        for s in result.stages
        if s.name in ("APK", "SHA256", "Static Analysis", "Classification")
    )
    return 1 if critical_fail else (0 if not result.aborted else 1)


if __name__ == "__main__":
    sys.exit(main())
