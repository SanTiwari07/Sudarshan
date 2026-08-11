"""
Backfill threat correlation for cases analysed before TI API keys were configured.

When keys are added later, stored cases still have threat_correlation.available=False
and correlation excluded from FRS. This module re-runs correlation on case serve and
refreshes the FRS breakdown when new intelligence is available.
"""

from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any, Dict, Optional

from sudarshan_core.engines.risk_engine import calculate_risk_score
from sudarshan_core.models.schemas import StaticAnalysisFlags
from sudarshan_core.services.threat_correlator import (
    _get_abuseipdb_key,
    _get_otx_key,
    _get_vt_key,
    correlate,
    extract_dynamic_urls,
)

logger = logging.getLogger(__name__)


def should_recorrelate_threat_intel(tc: Optional[Dict[str, Any]]) -> bool:
    """True when configured TI sources were not queried for this case payload."""
    tc = tc or {}
    queried_sources = set(tc.get("sources_queried") or [])
    vt_key = _get_vt_key()
    otx_key = _get_otx_key()
    abuse_key = _get_abuseipdb_key()
    return (
        (vt_key and "VirusTotal" not in queried_sources)
        or (otx_key and "AlienVault OTX" not in queried_sources)
        or (abuse_key and "AbuseIPDB" not in queried_sources)
        or (not tc.get("available") and not queried_sources)
    )


def _flags_from_case(case: Dict[str, Any]) -> StaticAnalysisFlags:
    return StaticAnalysisFlags(
        has_accessibility_abuse=bool(case.get("has_accessibility_abuse")),
        has_sms_read_write=bool(case.get("has_sms_read_write")),
        has_system_alert_window=bool(case.get("has_system_alert_window")),
        targets_indian_banks=bool(case.get("targets_indian_banks")),
        dangerous_apis_found=case.get("dangerous_apis_found") or [],
        hardcoded_urls_ips=case.get("hardcoded_urls_ips") or [],
        indian_bank_packages_found=case.get("indian_bank_packages_found") or [],
        obfuscation_score=float(case.get("obfuscation_score") or 0.0),
        has_reflection=bool(case.get("has_reflection")),
        has_concealed_payload=bool(case.get("has_concealed_payload")),
        concealment_evidence=case.get("concealment_evidence") or [],
        limited_static_visibility=bool(case.get("limited_static_visibility")),
    )


async def enrich_case_threat_intel(case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Re-run threat correlation when API keys are available but the case was stored
    without TI data. Updates threat_correlation and FRS fields in-place on a copy.
  """
    tc = case.get("threat_correlation") or {}
    if not should_recorrelate_threat_intel(tc):
        return case

    sha256 = case.get("sha256") or ""
    if not sha256:
        return case

    dynamic = case.get("dynamic_result") or case.get("dynamic_analysis")
    try:
        new_tc = await correlate(
            sha256=sha256,
            urls=case.get("hardcoded_urls_ips") or [],
            package_name=case.get("package_name") or "",
            dynamic_urls=extract_dynamic_urls(dynamic if isinstance(dynamic, dict) else None),
        )
    except Exception as exc:
        logger.warning("[CaseIntel] Live correlation failed for %s…: %s", sha256[:12], exc)
        return case

    if new_tc == tc:
        return case

    updated = deepcopy(case)
    updated["threat_correlation"] = new_tc

    if new_tc.get("available"):
        family = updated.get("family_classification") or "Unknown"
        if new_tc.get("known_family") and family == "Unknown":
            family = new_tc["known_family"]
            updated["family_classification"] = family

        ai_confidence = float(updated.get("ai_confidence_multiplier") or 1.0)
        if new_tc.get("known_family") and ai_confidence == 1.0:
            ai_confidence = 1.15

        risk = calculate_risk_score(
            flags=_flags_from_case(updated),
            ai_confidence=ai_confidence,
            dynamic_result=dynamic if isinstance(dynamic, dict) else None,
            correlation_result=new_tc,
            family=family,
            all_permissions=updated.get("all_permissions") or [],
            vide_result=updated.get("vide"),
        )
        updated["frs_breakdown"] = risk.get("frs_breakdown", updated.get("frs_breakdown"))
        updated["final_risk_score"] = risk.get("final_risk_score", updated.get("final_risk_score"))
        updated["risk_band"] = risk.get("risk_band", updated.get("risk_band"))
        updated["confidence"] = risk.get("confidence", updated.get("confidence"))
        updated["base_score"] = risk.get("base_score", updated.get("base_score"))
        updated["recommended_action"] = risk.get("recommended_action", updated.get("recommended_action"))
        updated["risk_explanation"] = risk.get("risk_explanation", updated.get("risk_explanation"))
        updated["threat_scenario_table"] = risk.get("threat_scenario_table", updated.get("threat_scenario_table"))
        updated["ai_confidence_multiplier"] = ai_confidence

    logger.info(
        "[CaseIntel] Backfilled threat correlation for %s… available=%s score=%.1f",
        sha256[:12],
        new_tc.get("available"),
        float(new_tc.get("threat_score") or 0.0),
    )
    return updated
