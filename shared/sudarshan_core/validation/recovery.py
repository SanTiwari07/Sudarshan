"""Recovery scenario probes (live sandbox required)."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from sudarshan_core.engines.frida_sandbox import _adb, get_connected_emulators, run_frida_analysis
from sudarshan_core.sandbox import get_sandbox_provider
from sudarshan_core.validation.corpus import CorpusEntry

logger = logging.getLogger(__name__)


@dataclass
class RecoveryScenarioResult:
    name: str
    success: bool
    detail: str
    recovery_attempted: str = ""


@dataclass
class RecoveryReport:
    scenarios: List[RecoveryScenarioResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"scenarios": [s.__dict__ for s in self.scenarios]}


async def run_recovery_suite(entry: CorpusEntry, serial: str) -> RecoveryReport:
    report = RecoveryReport()

    async def _mini_analysis(label: str) -> RecoveryScenarioResult:
        try:
            dyn = await run_frida_analysis(str(entry.apk_path), package_name=entry.package_hint or None)
            ok = dyn.get("dynamic_status") != "INSTRUMENTATION_FAILED" and not dyn.get("error")
            return RecoveryScenarioResult(
                name=label,
                success=ok,
                detail=dyn.get("dynamic_status", "") + (f" err={dyn.get('error')}" if dyn.get("error") else ""),
                recovery_attempted="full pipeline re-run",
            )
        except Exception as exc:
            return RecoveryScenarioResult(name=label, success=False, detail=str(exc))

    # ADB disconnect / reconnect
    _adb("disconnect", serial, timeout=10)
    time.sleep(1)
    _adb("connect", serial, timeout=15)
    time.sleep(2)
    devices = get_connected_emulators()
    adb_ok = serial in devices or any(serial in d for d in devices)
    report.scenarios.append(
        RecoveryScenarioResult(
            name="adb_disconnect",
            success=adb_ok,
            detail=f"devices after reconnect: {devices}",
            recovery_attempted="adb connect",
        )
    )
    if adb_ok:
        report.scenarios.append(await _mini_analysis("post_adb_reconnect"))

    # Frida restart
    try:
        provider = get_sandbox_provider()
        provider.adb_shell(serial, "pkill -f sudarshan_agent_srv 2>/dev/null", timeout=10)
        time.sleep(1)
        st = provider.ensure_frida(serial, restart_if_needed=True)
        report.scenarios.append(
            RecoveryScenarioResult(
                name="frida_restart",
                success=st.running,
                detail=st.message,
                recovery_attempted="ensure_frida(restart_if_needed=True)",
            )
        )
    except Exception as exc:
        report.scenarios.append(
            RecoveryScenarioResult(name="frida_restart", success=False, detail=str(exc))
        )

    if entry.apk_path.is_file():
        report.scenarios.append(await _mini_analysis("post_frida_restart"))

    return report


def save_recovery_report(report: RecoveryReport, path: Path) -> None:
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
