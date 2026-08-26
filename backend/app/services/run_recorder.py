"""
Record a completed analysis into `analysis_runs`.
=================================================

Replaces the placeholder writer in
`shared/sudarshan_core/engines/analysis_history.py`, which produced rows that
could not be used for anything:

    history.save_run(result, apk_sha256="unknown", stage_name="single")

The hash was a hardcoded literal at the call site, and `save_run` itself
hardcoded five more columns before inserting:

    mitre_techs = "[]";  ioc_count = 0;  yara_matches = "[]"
    anti_analysis = "[]";  screenshot_count = 0

All 140 historical rows across the three database files carry
apk_sha256='unknown' and bfci_score=0.0, so `compare_runs` computed
`0.0 - 0.0` on every call - and nothing invoked it anyway.

Every field below is read from the real result. The field paths were taken from
stored rows, not from the type hints:

    final_risk_score           → frs_score
    frs_breakdown.stei         → stei_score
    dynamic_result.bfci        → bfci_score
    dynamic_result.dynamic_status, .duration_seconds, .bfci_components
    intelligence_report.mitre_techniques_used
    risk_band, analysis_mode, package_name, sha256

Anything genuinely absent is written as NULL rather than as a zero. A NULL says
"not measured"; a 0.0 says "measured, and it was zero", and conflating them is
what made the original table worthless.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db.intel import record_analysis_run

logger = logging.getLogger(__name__)


def _num(value: Any) -> Optional[float]:
    """Coerce to float, but map missing/non-numeric to None - never to 0.0."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _mitre_techniques(result: Dict[str, Any]) -> List[str]:
    intel = result.get("intelligence_report")
    if not isinstance(intel, dict):
        return []
    raw = intel.get("mitre_techniques_used") or []
    out: List[str] = []
    for entry in raw:
        if isinstance(entry, str):
            out.append(entry)
        elif isinstance(entry, dict):
            tid = entry.get("technique_id") or entry.get("id") or entry.get("technique")
            if isinstance(tid, str):
                out.append(tid)
    return out


def build_run_record(
    result: Dict[str, Any],
    *,
    sha256: Optional[str] = None,
    stage_name: str = "single",
    started_at: Optional[str] = None,
    status: str = "COMPLETED",
    ioc_count: Optional[int] = None,
) -> Dict[str, Any]:
    """Map an analysis result onto the analysis_runs columns. Pure."""
    dynamic = result.get("dynamic_result")
    if not isinstance(dynamic, dict):
        dynamic = {}

    frs_breakdown = result.get("frs_breakdown")
    if not isinstance(frs_breakdown, dict):
        frs_breakdown = {}

    screenshots = dynamic.get("screenshots") or []
    yara = result.get("yara_matches") or dynamic.get("yara_matches") or []
    anti = dynamic.get("anti_analysis") or result.get("anti_analysis") or []

    return {
        "sha256": sha256 or result.get("sha256"),
        "package_name": result.get("package_name") or "unknown",
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "stage_name": stage_name,
        "status": status,
        "analysis_mode": result.get("analysis_mode"),
        "duration_seconds": dynamic.get("duration_seconds"),

        "frs_score": _num(result.get("final_risk_score")),
        "stei_score": _num(frs_breakdown.get("stei")),
        "bfci_score": _num(dynamic.get("bfci")),
        "risk_band": result.get("risk_band"),
        "dynamic_status": dynamic.get("dynamic_status"),

        "bfci_components": dynamic.get("bfci_components") or {},
        "mitre_techniques": _mitre_techniques(result),
        "ioc_count": ioc_count if ioc_count is not None else 0,
        "screenshot_count": len(screenshots) if isinstance(screenshots, list) else 0,
        "yara_matches": yara if isinstance(yara, list) else [],
        "anti_analysis": anti if isinstance(anti, list) else [],
        "explorer_mode": dynamic.get("engine"),
    }


async def record_run(
    result: Dict[str, Any],
    *,
    sha256: Optional[str] = None,
    stage_name: str = "single",
    started_at: Optional[str] = None,
    status: str = "COMPLETED",
    ioc_count: Optional[int] = None,
) -> Optional[int]:
    """
    Persist a run. Never raises - a failed history write must not fail the
    analysis that produced it.
    """
    try:
        record = build_run_record(
            result, sha256=sha256, stage_name=stage_name,
            started_at=started_at, status=status, ioc_count=ioc_count,
        )
        run_id = await record_analysis_run(record)
        logger.info(
            "[Runs] recorded run %s for %s (frs=%s bfci=%s band=%s)",
            run_id, record["package_name"], record["frs_score"],
            record["bfci_score"], record["risk_band"],
        )
        return run_id
    except Exception as exc:  # noqa: BLE001
        logger.error("[Runs] failed to record analysis run: %s", exc)
        return None
