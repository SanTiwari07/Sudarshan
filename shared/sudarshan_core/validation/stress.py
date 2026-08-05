"""Consecutive analysis stress tests."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.frida_sandbox import get_connected_emulators, run_frida_analysis
from sudarshan_core.validation.corpus import CorpusEntry

logger = logging.getLogger(__name__)


@dataclass
class StressRunMetrics:
    iteration: int
    duration_seconds: float
    dynamic_status: str
    error: str = ""
    memory_rss_mb: Optional[float] = None


@dataclass
class StressReport:
    apk_path: str
    iterations: int
    runs: List[StressRunMetrics] = field(default_factory=list)
    adb_devices_before: List[str] = field(default_factory=list)
    adb_devices_after: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "iterations": self.iterations,
            "runs": [r.__dict__ for r in self.runs],
            "adb_devices_before": self.adb_devices_before,
            "adb_devices_after": self.adb_devices_after,
            "failures": self.failures,
            "avg_duration": (
                sum(r.duration_seconds for r in self.runs) / len(self.runs) if self.runs else 0
            ),
        }


def _rss_mb() -> Optional[float]:
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        return None


async def run_stress(entry: CorpusEntry, iterations: int) -> StressReport:
    report = StressReport(apk_path=str(entry.apk_path), iterations=iterations)
    report.adb_devices_before = get_connected_emulators()

    for i in range(1, iterations + 1):
        t0 = time.monotonic()
        mem_before = _rss_mb()
        try:
            dynamic = await run_frida_analysis(str(entry.apk_path), package_name=entry.package_hint or None)
            err = dynamic.get("error") or ""
            status = dynamic.get("dynamic_status", "")
        except Exception as exc:
            err = str(exc)
            status = "ERROR"
        dur = time.monotonic() - t0
        mem_after = _rss_mb()
        report.runs.append(
            StressRunMetrics(
                iteration=i,
                duration_seconds=round(dur, 2),
                dynamic_status=status,
                error=err,
                memory_rss_mb=mem_after,
            )
        )
        if mem_before and mem_after and mem_after - mem_before > 200:
            report.failures.append(f"iteration {i}: RSS grew {mem_after - mem_before:.0f} MB")

    report.adb_devices_after = get_connected_emulators()
    if report.adb_devices_before and not report.adb_devices_after:
        report.failures.append("ADB device list empty after stress (possible zombie/disconnect)")

    return report


def save_stress_report(report: StressReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
