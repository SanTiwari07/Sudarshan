"""
SUDARSHAN - Multi-Stage Analysis Engine
========================================
Orchestrates multiple analysis runs for a single APK across different
simulated device states (e.g. Fresh Install -> Accessibility Enabled -> Rebooted).
Aggregates the highest BFCI score across all stages.

Every stage produces an explicit, truthful record
-------------------------------------------------
Previously each stage that returned at all was labelled ``"success"`` - a
stage whose sandbox never attached, or whose device-state profile could not
be applied, read the same as one that observed the sample. Stages skipped
after a device disconnect simply vanished from the summary, and an exception
while applying a profile escaped the loop and left the device in a modified
state.

Each stage now records ``stage_id``, start/end timestamps, ``stage_status``,
whether its device condition was actually applied, the limitations of how
that condition is simulated, and a structured error. The stage statuses are:

    COMPLETED_WITH_EVENTS   the dynamic run observed runtime events
    COMPLETED_NO_EVENTS     the run completed with telemetry but no events
    DYNAMIC_FAILED          the dynamic run itself failed / was inconclusive
    PROFILE_NOT_APPLIED     the device condition could not be set up; the
                            analysis was NOT run (it would only duplicate the
                            fresh-install stage under a misleading name)
    SKIPPED                 not attempted (device gone, earlier abort)
    ERROR                   the stage raised; the error is recorded

The primary result is chosen ONLY among stages whose dynamic run produced
usable telemetry, so a failed stage can never become the face of the
analysis. The BFCI of each stage is untouched - aggregation is unchanged.
"""

import json
import logging
import asyncio
import time
from typing import Dict, Any, List, Optional

from sudarshan_core.engines.frida_sandbox import run_frida_analysis, get_connected_emulators
from sudarshan_core.engines.device_state_simulator import DeviceStateSimulator

logger = logging.getLogger(__name__)

#: Dynamic statuses meaning the run observed something we can score.
_USABLE_DYNAMIC_STATUSES = frozenset({"EVENTS_CAPTURED", "RUNTIME_COMPLETED_NO_EVENTS"})

#: The four stages. `limitations` states, in the result, how far each
#: simulated condition is from the real one - so a report never implies
#: the device was rebooted or that banking apps were installed.
STAGES: List[Dict[str, Any]] = [
    {
        "name": "fresh_install",
        "profile": None,
        "description": "Sample installed on a clean device state.",
        "limitations": [],
    },
    {
        "name": "sim_active",
        "profile": "sim_present",
        "description": "An inbound SMS is injected so SMS/OTP-dependent code paths are reachable.",
        "limitations": [
            "No real SIM or telephony state is created; only one inbound SMS is "
            "injected (emulator console on Android Studio AVD, an SMS_RECEIVED "
            "broadcast on Genymotion, which Android may restrict).",
        ],
    },
    {
        "name": "banking_apps",
        "profile": "banking_apps",
        "description": "Banking-app presence is simulated on the device.",
        "limitations": [
            "Banking apps are not installed; only their /data/data directories "
            "are created (root required). PackageManager queries do not see them.",
        ],
    },
    {
        "name": "rebooted",
        "profile": "reboot",
        "description": "Boot-time behaviour is probed with a BOOT_COMPLETED broadcast.",
        "limitations": [
            "The device is NOT rebooted. A BOOT_COMPLETED broadcast is sent "
            "before this stage's analysis run reinstalls and launches the sample, "
            "and Android may refuse that broadcast from a non-system sender.",
        ],
    },
]


def _now() -> float:
    return time.time()


def _stage_status_from_result(result: Dict[str, Any]) -> str:
    dyn = str(result.get("dynamic_status") or "").upper()
    if result.get("available") and dyn == "EVENTS_CAPTURED":
        return "COMPLETED_WITH_EVENTS"
    if result.get("available") and dyn == "RUNTIME_COMPLETED_NO_EVENTS":
        return "COMPLETED_NO_EVENTS"
    return "DYNAMIC_FAILED"


class MultiStageEngine:
    def __init__(
        self,
        apk_path: str,
        device_serial: Optional[str] = None,
        package_name: Optional[str] = None,
        *,
        static_findings: Optional[Dict[str, Any]] = None,
    ):
        if not device_serial:
            try:
                from sudarshan_core.sandbox import get_sandbox_provider
                device_serial = get_sandbox_provider().select_device().serial
            except Exception:
                emulators = get_connected_emulators()
                if emulators:
                    device_serial = emulators[0]
                else:
                    logger.warning("[MultiStage] No sandbox devices connected. Multi-stage will likely fail.")
                    device_serial = None
        self.device_serial = device_serial
        self.apk_path = apk_path
        self.package_name = package_name
        self.static_findings = dict(static_findings or {})
        self.stages = [dict(s) for s in STAGES]
        self.simulator = DeviceStateSimulator(device_serial or "")

    def _stage_record(self, index: int, stage: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "stage": stage["name"],
            "stage_id": f"stage-{index + 1:02d}-{stage['name']}",
            "profile": stage["profile"],
            "description": stage.get("description", ""),
            "limitations": list(stage.get("limitations", [])),
            "profile_applied": None if stage["profile"] is None else False,
            "started_at": None,
            "ended_at": None,
            "stage_status": "SKIPPED",
            "dynamic_status": None,
            "bfci": 0.0,
            "error": None,
        }

    async def run_all_stages(self) -> Dict[str, Any]:
        logger.info(f"[MultiStage] Starting multi-stage analysis for {self.apk_path}")

        records = [self._stage_record(i, s) for i, s in enumerate(self.stages)]
        full_results: Dict[str, Dict[str, Any]] = {}
        abort_reason: Optional[str] = None

        try:
            # Ensure clean state before starting
            self.simulator.reset()

            for stage, rec in zip(self.stages, records):
                if abort_reason:
                    rec["error"] = {"type": "Skipped", "message": abort_reason}
                    continue
                logger.info(f"[MultiStage] --- Executing Stage: {stage['name']} ---")
                rec["started_at"] = _now()
                try:
                    # Device Health Check
                    emulators = get_connected_emulators()
                    if self.device_serial and self.device_serial not in emulators:
                        abort_reason = f"device {self.device_serial} disconnected before stage {stage['name']}"
                        logger.error(f"[MultiStage] {abort_reason} - remaining stages skipped.")
                        rec["error"] = {"type": "DeviceDisconnected", "message": abort_reason}
                        continue

                    if stage["profile"]:
                        applied = bool(self.simulator.apply_profile(stage["profile"]))
                        rec["profile_applied"] = applied
                        if not applied:
                            rec["stage_status"] = "PROFILE_NOT_APPLIED"
                            rec["error"] = {
                                "type": "ProfileNotApplied",
                                "message": f"device profile {stage['profile']!r} could not be applied",
                            }
                            logger.warning(
                                "[MultiStage] Stage %s: profile %r not applied - analysis not run "
                                "(it would only repeat fresh_install under this stage's name).",
                                stage["name"], stage["profile"],
                            )
                            continue
                        await asyncio.sleep(2)

                    result = await run_frida_analysis(
                        self.apk_path,
                        package_name=self.package_name,
                        static_findings=self.static_findings or None,
                        stage_name=stage["name"],
                    )
                    result["stage"] = stage["name"]
                    result["stage_id"] = rec["stage_id"]
                    rec["stage_status"] = _stage_status_from_result(result)
                    rec["dynamic_status"] = result.get("dynamic_status")
                    rec["bfci"] = float(result.get("bfci", 0.0) or 0.0)
                    rec["telemetry_classification"] = (
                        (result.get("telemetry_diagnostics") or {}).get("classification")
                    )
                    if result.get("error"):
                        rec["error"] = {"type": "DynamicError", "message": str(result["error"])[:500]}
                    result["stage_status"] = rec["stage_status"]
                    full_results[stage["name"]] = result
                    logger.info(
                        f"[MultiStage] Stage {stage['name']} {rec['stage_status']}. BFCI: {rec['bfci']}"
                    )
                except Exception as e:
                    logger.error(f"[MultiStage] Stage {stage['name']} failed: {e}", exc_info=True)
                    rec["stage_status"] = "ERROR"
                    rec["error"] = {"type": type(e).__name__, "message": str(e)[:500]}
                finally:
                    rec["ended_at"] = _now()
        finally:
            # Always restore the device, even when a stage raised.
            try:
                self.simulator.reset()
            except Exception as e:  # pragma: no cover - reset already swallows
                logger.error(f"[MultiStage] Device reset failed: {e}")

        summary = {
            "total_stages": len(self.stages),
            "stages": records,
            "stages_run": [r["stage"] for r in records if r["stage"] in full_results],
            "stage_scores": {r["stage"]: r["bfci"] for r in records},
            "stage_statuses": {r["stage"]: r["stage_status"] for r in records},
        }

        usable = [
            full_results[r["stage"]] for r in records
            if r["stage"] in full_results
            and str(full_results[r["stage"]].get("dynamic_status") or "").upper() in _USABLE_DYNAMIC_STATUSES
            and full_results[r["stage"]].get("available")
        ]
        if usable:
            # Worst-case behaviour among stages that actually observed. Ties
            # keep the earliest stage, so the choice is deterministic.
            primary_result = dict(max(usable, key=lambda r: float(r.get("bfci", 0.0) or 0.0)))
        elif full_results:
            # Nothing usable: surface the first stage's real failure rather
            # than inventing a result. It stays unavailable/inconclusive.
            primary_result = dict(next(iter(full_results.values())))
        else:
            primary_result = {
                "available": False,
                "runtime_requested": True,
                "runtime_attempted": any(r["started_at"] for r in records),
                "engine": "frida",
                "dynamic_status": "FAILED",
                "bfci": 0.0,
                "error": "All stages failed.",
            }

        summary["highest_bfci_stage"] = primary_result.get("stage")
        summary["usable_stages"] = [r.get("stage") for r in usable]
        primary_result["multi_stage_summary"] = summary

        logger.info(
            "[MultiStage] Multi-stage complete. Primary stage: %s, statuses: %s",
            summary["highest_bfci_stage"], summary["stage_statuses"],
        )
        return primary_result

# Example entry point for CLI usage
async def main(apk_path: str, device_serial: Optional[str] = None):
    engine = MultiStageEngine(apk_path, device_serial)
    result = await engine.run_all_stages()
    print(json.dumps(result["multi_stage_summary"], indent=4, default=str))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        asyncio.run(main(sys.argv[1], sys.argv[2]))
    else:
        print("Usage: python multi_stage_engine.py <apk_path> <device_serial>")
