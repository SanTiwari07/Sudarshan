# backend/app/routes/intelligence.py
"""
Sudarshan Threat Intelligence API
===================================
Provides a comprehensive Threat Intelligence endpoint:
  GET /api/v1/intelligence/{sha256}

Integrates live threat correlation (VirusTotal, AlienVault OTX, AbuseIPDB),
deterministic malware family classification, comprehensive IOC extraction,
analysis mode detection (dynamic vs static), timeline reconstruction,
and AI-grounded threat summary.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.auth import require_analyst
from app.db.database import get_case
from sudarshan_core.engines.classification_engine import classify_family
from sudarshan_core.models.schemas import StaticAnalysisFlags
from sudarshan_core.services.threat_correlator import (
    correlate, _get_vt_key, _get_otx_key, _get_abuseipdb_key, extract_dynamic_urls,
)
from app.services.case_intel_enrichment import should_recorrelate_threat_intel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])

# In-memory report cache imported from report.py if populated
def _get_cached_report_ref(sha256: str) -> Optional[Any]:
    from app.routes.report import get_cached_report
    return get_cached_report(sha256)


# ─── Data Models ─────────────────────────────────────────────────────────────

class SourceStatus(BaseModel):
    name: str
    status: str  # "active" | "missing_key" | "error" | "no_match"
    message: str


class VirusTotalDetail(BaseModel):
    available: bool = False
    malicious: int = 0
    total: int = 0
    ratio: float = 0.0
    permalink: str = ""
    vendors: List[str] = []
    reputation: int = 0
    suggested_label: Optional[str] = None


class AlienVaultDetail(BaseModel):
    available: bool = False
    pulse_count: int = 0
    campaign: str = "None"
    pulses: List[Dict[str, Any]] = []


class AbuseIPDBDetail(BaseModel):
    available: bool = False
    confidence: int = 0
    reports: int = 0


class IOCItem(BaseModel):
    type: str  # "URL" | "Domain" | "IP" | "Certificate" | "SHA256" | "Package" | "Telegram Bot" | "Firebase URL"
    value: str
    severity: str  # "Critical" | "High" | "Medium" | "Low" | "Info"
    source: str  # "Static" | "Dynamic" | "Network" | "MobSF" | "Frida"
    reputation: str = "unknown"  # "malicious" | "suspicious" | "clean" | "unknown"


class TimelineStep(BaseModel):
    step: str
    status: str  # "completed" | "skipped" | "in_progress" | "failed"
    timestamp: str
    detail: str


class IntelligenceResponse(BaseModel):
    available: bool
    mode: str  # "dynamic" | "static"
    sha256: str
    package_name: str
    app_name: str
    threat_score: float
    malware_family: str
    family_rule_matched: str
    campaign: str
    confidence: float
    risk_band: str
    sources: List[str]
    sources_status: List[SourceStatus]
    virus_total: VirusTotalDetail
    alienvault: AlienVaultDetail
    abuseipdb: AbuseIPDBDetail
    iocs: List[IOCItem]
    timeline: List[TimelineStep]
    ai_summary: str


# ─── Helper Functions ────────────────────────────────────────────────────────

def _extract_all_iocs(report: Dict[str, Any]) -> List[IOCItem]:
    """Gather unique IOCs from static, dynamic, network, and correlator outputs."""
    seen = set()
    items: List[IOCItem] = []

    def _add(type_: str, val: str, sev: str, src: str, rep: str = "unknown"):
        if not val or val in seen:
            return
        seen.add(val)
        items.append(IOCItem(type=type_, value=val, severity=sev, source=src, reputation=rep))

    # 1. SHA256 & Package
    sha = report.get("sha256", "")
    pkg = report.get("package_name", "")
    if sha:
        _add("SHA256", sha, "Info", "Static", "clean")
    if pkg:
        _add("Package", pkg, "Medium" if report.get("targets_indian_banks") else "Info", "Androguard", "suspicious" if report.get("targets_indian_banks") else "clean")

    # 2. Hardcoded URLs/IPs
    urls = report.get("hardcoded_urls_ips", []) or []
    for u in urls:
        if u.startswith("http://") or u.startswith("https://"):
            sev = "Critical" if any(b in u.lower() for b in ["api", "login", "admin", "c2", "gate"]) else "High"
            rep = "malicious" if sev == "Critical" else "suspicious"
            if "telegram.org" in u or "api.telegram.org" in u:
                _add("Telegram Bot", u, "Critical", "Static", "malicious")
            elif "firebaseio.com" in u or "firebasestorage" in u:
                _add("Firebase URL", u, "High", "Static", "suspicious")
            else:
                _add("URL", u, sev, "Static", rep)
        elif __import__("re").match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", u):
            _add("IP", u, "High", "Static", "suspicious")
        else:
            _add("Domain", u, "Medium", "Static", "suspicious")

    # 3. Dynamic Frida & Net Ingest IOCs
    dyn = report.get("dynamic_result") or {}
    if isinstance(dyn, dict):
        net_flows = dyn.get("network_flows", []) or []
        for flow in net_flows:
            if isinstance(flow, dict):
                dst = flow.get("dst_ip") or flow.get("host")
                if dst:
                    _add("IP" if __import__("re").match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dst) else "Domain", dst, "High", "Network (mitmproxy)", "malicious")

        hooks = dyn.get("hook_events", []) or []
        for h in hooks:
            if isinstance(h, dict) and "http" in str(h.get("data", "")).lower():
                _add("URL", str(h.get("data")), "High", "Frida Dynamic", "suspicious")

    # 4. MobSF Domains & Secrets
    mobsf_domains = report.get("domains", {})
    if isinstance(mobsf_domains, dict):
        for dom in mobsf_domains.keys():
            _add("Domain", dom, "Medium", "MobSF Static", "suspicious")

    # 5. Threat Correlation Reputations
    tc = report.get("threat_correlation") or {}
    if isinstance(tc, dict):
        for ioc in tc.get("ioc_reputation", []) or []:
            if isinstance(ioc, dict):
                _add(
                    ioc.get("type", "Indicator"),
                    ioc.get("indicator", ""),
                    "Critical" if ioc.get("reputation") == "malicious" else "High",
                    ioc.get("source", "Threat Intel"),
                    ioc.get("reputation", "suspicious"),
                )

    return items


# ─── Main Endpoint ────────────────────────────────────────────────────────────

@router.get("/{sha256}", response_model=IntelligenceResponse)
async def get_threat_intelligence(
    sha256: str,
    user: dict = Depends(require_analyst),
):
    """
    Retrieve live threat intelligence analysis for a given SHA256 APK hash.

    Calculates deterministic malware family attribution, VirusTotal / AlienVault / AbuseIPDB
    reputation, extracts all IOCs across static, dynamic, and network analysis,
    and returns exact status reasons for unconfigured or failing API sources.
    """
    # 1. Fetch report from cache, DB, or disk
    report = _get_cached_report_ref(sha256)
    if not report:
        report = await get_case(sha256)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"No analysis record found for SHA256 {sha256}. Analyze the APK first."
        )

    # Convert to dict if object
    if hasattr(report, "model_dump"):
        rdict = report.model_dump()
    elif hasattr(report, "dict"):
        rdict = report.dict()
    elif isinstance(report, dict):
        rdict = dict(report)
    else:
        rdict = {}

    sha256_clean = rdict.get("sha256") or sha256
    package_name = rdict.get("package_name") or "unknown"
    app_name = rdict.get("app_name") or package_name
    dynamic_available = bool(rdict.get("dynamic_available") or (rdict.get("dynamic_result") or {}).get("available"))

    # 2. Check / Trigger Threat Correlation
    tc = rdict.get("threat_correlation") or {}
    if not isinstance(tc, dict):
        tc = {}

    vt_key = _get_vt_key()
    otx_key = _get_otx_key()
    abuse_key = _get_abuseipdb_key()

    # Re-run correlation if new API keys are configured that were not queried yet
    should_recorrelate = should_recorrelate_threat_intel(tc)

    if should_recorrelate:
        try:
            urls = rdict.get("hardcoded_urls_ips", [])
            dyn_urls = extract_dynamic_urls(rdict.get("dynamic_result"))
            tc = await correlate(
                sha256_clean,
                urls=urls,
                package_name=package_name,
                dynamic_urls=dyn_urls,
            )
            rdict["threat_correlation"] = tc
        except Exception as e:
            logger.warning(f"Live correlation execution failed: {e}")

    # 3. Deterministic Family Classification
    flags = StaticAnalysisFlags(
        has_accessibility_abuse=rdict.get("has_accessibility_abuse", False),
        has_sms_read_write=rdict.get("has_sms_read_write", False),
        has_system_alert_window=rdict.get("has_system_alert_window", False),
        targets_indian_banks=rdict.get("targets_indian_banks", False),
        dangerous_apis_found=[],
    )
    family_name, family_rule = classify_family(flags)
    if family_name == "Unknown" and rdict.get("family_classification"):
        family_name = rdict.get("family_classification")
        family_rule = "Family classified via static rule analysis"

    # 4. Sources Status Breakdown
    sources_status: List[SourceStatus] = []
    active_sources: List[str] = []

    # VirusTotal Status
    vt_detections = tc.get("sha256_detections", 0)
    vt_total = tc.get("sha256_total", 0)
    vt_ratio = tc.get("vt_detection_ratio", 0.0)
    if vt_key:
        if vt_total > 0:
            sources_status.append(SourceStatus(
                name="VirusTotal",
                status="active",
                message=f"{vt_detections}/{vt_total} engines detected as malicious ({(vt_ratio*100):.0f}%)"
            ))
            active_sources.append("VirusTotal")
        elif tc.get("vt_hash_in_database") is False:
            sources_status.append(SourceStatus(
                name="VirusTotal",
                status="active",
                message="API connected - hash not in VirusTotal yet (upload sample for vendor scan)"
            ))
            active_sources.append("VirusTotal")
        else:
            sources_status.append(SourceStatus(
                name="VirusTotal",
                status="active",
                message="Hash lookup returned no engine stats"
            ))
            active_sources.append("VirusTotal")
    else:
        sources_status.append(SourceStatus(
            name="VirusTotal",
            status="missing_key",
            message="VIRUSTOTAL_API_KEY not configured in .env"
        ))

    # AlienVault OTX Status
    otx_pulses = tc.get("otx_pulses", [])
    if otx_key:
        sources_status.append(SourceStatus(
            name="AlienVault OTX",
            status="active",
            message=f"{len(otx_pulses)} threat pulses correlated"
        ))
        active_sources.append("AlienVault OTX")
    else:
        sources_status.append(SourceStatus(
            name="AlienVault OTX",
            status="missing_key",
            message="OTX_API_KEY not configured in .env"
        ))

    # AbuseIPDB Status
    if abuse_key:
        sources_status.append(SourceStatus(
            name="AbuseIPDB",
            status="active",
            message="IP reputation service active"
        ))
        active_sources.append("AbuseIPDB")
    else:
        sources_status.append(SourceStatus(
            name="AbuseIPDB",
            status="missing_key",
            message="ABUSEIPDB_API_KEY not configured in .env"
        ))

    # 5. Extract Detailed Vendor & Source Data
    vt_detail = VirusTotalDetail(
        available=bool(vt_key),
        malicious=vt_detections,
        total=vt_total,
        ratio=vt_ratio,
        permalink=f"https://www.virustotal.com/gui/file/{sha256_clean}",
        vendors=tc.get("vt_malicious_vendors", []),
        reputation=int(tc.get("reputation", 0) if isinstance(tc.get("reputation"), (int, float)) else 0),
        suggested_label=tc.get("vt_family") or tc.get("known_family"),
    )

    otx_detail = AlienVaultDetail(
        available=bool(otx_key),
        pulse_count=len(otx_pulses),
        # Only a campaign the correlator actually attributed. This previously
        # invented "Indian Banking Campaign" from a static bank-package flag,
        # or "Android Trojan Campaign" from the mere existence of OTX pulses.
        campaign=tc.get("campaign") or "Not attributed",
        pulses=otx_pulses,
    )

    abuseipdb_detail = AbuseIPDBDetail(
        available=bool(abuse_key),
        confidence=int(tc.get("correlation_confidence", 0) * 100),
        reports=len(tc.get("malicious_ips", [])),
    )

    # 6. Gather Comprehensive IOCs
    iocs = _extract_all_iocs(rdict)

    # 7. Build Timeline Steps
    now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
    timeline = [
        TimelineStep(
            step="Static Analysis & Extraction",
            status="completed",
            timestamp=now_str,
            detail=f"Decompiled {package_name}; extracted {len(rdict.get('hardcoded_urls_ips', []))} hardcoded endpoints."
        ),
        TimelineStep(
            step="VirusTotal Hash Lookup",
            status="completed" if vt_key else "skipped",
            timestamp=now_str,
            detail=f"{vt_detections}/{vt_total} detections returned." if vt_key else "Skipped (VIRUSTOTAL_API_KEY not configured)."
        ),
        TimelineStep(
            step="AlienVault OTX Pulse Lookup",
            status="completed" if otx_key else "skipped",
            timestamp=now_str,
            detail=f"{len(otx_pulses)} pulses found." if otx_key else "Skipped (OTX_API_KEY not configured)."
        ),
        TimelineStep(
            step="AbuseIPDB IP Reputation",
            status="completed" if abuse_key else "skipped",
            timestamp=now_str,
            detail="Checked IP reputations." if abuse_key else "Skipped (ABUSEIPDB_API_KEY not configured)."
        ),
        TimelineStep(
            step="IOC Graph Correlation",
            status="completed",
            timestamp=now_str,
            detail=f"Correlated {len(iocs)} total indicators of compromise."
        ),
        TimelineStep(
            step="Deterministic Risk Engine",
            status="completed",
            timestamp=now_str,
            detail=f"Computed FRS {rdict.get('final_risk_score', 0):.1f}/100 ({rdict.get('risk_band', 'UNKNOWN')})."
        ),
    ]

    # 8. AI Summary Narrative
    # AI summary.
    #
    # The fallback here used to ASSERT A VERDICT that no engine had reached:
    #
    #   "Sample X exhibits {family_name} banking trojan characteristics ...
    #    Recommended immediate SOC quarantine."
    #
    # For a benign sample with no family match that rendered as "exhibits
    # Unknown banking trojan characteristics ... Recommended immediate SOC
    # quarantine" - an invented conclusion, in a field named `ai_summary`, with
    # nothing marking it as a template. The rest of this codebase is careful
    # about exactly this (the engine explicitly removed a fabricated
    # appsec_score; _collect_observed_activities returns [] rather than a
    # placeholder). This was the exception, and the one an executive reads.
    #
    # The replacement states only what was measured, and says plainly when the
    # narrative is unavailable.
    intel_report = rdict.get("intelligence_report") or {}
    if isinstance(intel_report, dict) and intel_report.get("plain_english_narrative"):
        ai_summary = intel_report["plain_english_narrative"]
    else:
        facts = [
            f"Package {package_name} (SHA-256 {sha256_clean[:12]}…).",
            f"Deterministic risk score {rdict.get('final_risk_score', 0):.1f}/100"
            f" - {rdict.get('risk_band') or 'not scored'}.",
        ]
        if vt_key and vt_total > 0:
            facts.append(f"VirusTotal: {vt_detections}/{vt_total} engines flagged this file.")
        elif vt_key:
            facts.append("VirusTotal: no detections recorded for this hash.")
        else:
            facts.append("VirusTotal: not queried (no API key configured).")

        if family_name and family_name != "Unknown":
            facts.append(f"Matched family signature: {family_name}.")
        else:
            facts.append("No known malware family signature matched.")

        facts.append(f"{len(iocs)} indicator(s) of compromise extracted.")
        facts.append(
            "AI narrative generation was unavailable for this case; the figures "
            "above are the deterministic engine's own output."
        )
        ai_summary = " ".join(facts)

    threat_score = float(tc.get("threat_score") or rdict.get("final_risk_score") or 0.0)

    return IntelligenceResponse(
        available=bool(tc.get("available") or vt_key),
        mode="dynamic" if dynamic_available else "static",
        sha256=sha256_clean,
        package_name=package_name,
        app_name=app_name,
        threat_score=round(threat_score, 1),
        malware_family=family_name,
        family_rule_matched=family_rule,
        # No invented campaign attribution. These defaulted to "Indian Banking
        # Campaign" / "Android Trojan Campaign" whenever no campaign had been
        # attributed, presenting a guess as intelligence. Likewise `confidence`
        # defaulted to 85.0 for a case that carried no confidence at all, and
        # `risk_band` to "SUSPICIOUS" for a case that had not been banded.
        campaign=tc.get("campaign") or "Not attributed",
        confidence=float(rdict.get("confidence") or 0.0),
        risk_band=rdict.get("risk_band") or "Not scored",
        sources=active_sources,
        sources_status=sources_status,
        virus_total=vt_detail,
        alienvault=otx_detail,
        abuseipdb=abuseipdb_detail,
        iocs=iocs,
        timeline=timeline,
        ai_summary=ai_summary,
    )
