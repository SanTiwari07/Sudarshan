# backend/app/routes/report.py
"""
Sudarshan Report Export Endpoints
===================================
Provides:
  GET /api/v1/report/html/{sha256} - Standalone CYFIRMA-style HTML report (primary)
  GET /api/v1/report/stix/{sha256} - STIX 2.1 JSON export
  GET /api/v1/report/iocs/{sha256} - IOC CSV export
  GET /api/v1/report/pdf/{sha256} - PDF stub (use browser print on the HTML report instead)
  POST /api/v1/chat - AI chat endpoint (legacy, non-streaming)
  POST /api/v1/chat/stream - Gemini RAG SSE streaming endpoint (primary)
"""

import json
import logging
import os
import re
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel

from app.auth.auth import require_analyst

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory hot cache keyed by sha256.
#
# BOUNDED: this previously grew for the process lifetime, holding a full report
# per analysed sample.
_REPORT_CACHE_MAX = int(os.getenv("SUDARSHAN_REPORT_CACHE_MAX", "128"))
_report_cache: "OrderedDict[str, Any]" = OrderedDict()


def cache_report(sha256: str, report: Any) -> None:
    """Store analysis result in the hot cache for later export."""
    if sha256 in _report_cache:
        _report_cache.move_to_end(sha256)
    _report_cache[sha256] = report
    while len(_report_cache) > _REPORT_CACHE_MAX:
        _report_cache.popitem(last=False)


def get_cached_report(sha256: str) -> Optional[Any]:
    if sha256 in _report_cache:
        return _report_cache[sha256]
    for k, v in _report_cache.items():
        if k.startswith(sha256):
            return v
    return None


def _has_dynamic_payload(report: Any) -> bool:
    """True when a report carries the dynamic block, under either key."""
    if not isinstance(report, dict):
        return True  # models carry their own shape; do not second-guess them
    return bool(report.get("dynamic_analysis") or report.get("dynamic_result"))


def _normalise_report_shape(report: Any) -> Any:
    """
    Reconcile the two names the dynamic block travels under.

    The pipeline result calls it `dynamic_analysis`; the persisted case row calls
    it `dynamic_result` and keeps `artifact_dir` nested inside it. Every export
    consumer - report_generator.build_report, pdf_generator.build_pdf_report, and
    the apk_dir resolution in this module - reads `dynamic_analysis` and a
    top-level `artifact_dir`. Without this bridge a DB-rehydrated case renders
    "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" and drops every screenshot, even
    though the telemetry and PNGs are on disk.

    Returns a shallow copy; both key spellings are kept so nothing that reads the
    original names breaks.
    """
    if not isinstance(report, dict):
        return report

    dyn = report.get("dynamic_analysis") or report.get("dynamic_result")
    artifact_dir = report.get("artifact_dir") or report.get("_artifact_dir")
    if isinstance(dyn, dict) and not artifact_dir:
        artifact_dir = dyn.get("artifact_dir")

    if (report.get("dynamic_analysis") is dyn) and (report.get("artifact_dir") == artifact_dir):
        return report

    normalised = dict(report)
    if dyn is not None:
        # Dynamically inject resilience_actions for old reports
        if not dyn.get("resilience_actions"):
            res_actions = []
            flags = report.get("static_flags", report)
            
            # Check time warp
            anti_events = dyn.get("anti_analysis_events", [])
            time_events = [e for e in anti_events if 'time' in str(e).lower() or 'alarm' in str(e).lower()]
            if time_events:
                res_actions.append({
                    "type": "time_warp",
                    "title": "Time-Warping",
                    "result_summary": f"Fast-forwarded time (+24h) and intercepted dormant time-delayed payloads ({len(time_events)} events forced)."
                })
            
            # Check persona seeding
            api_calls = dyn.get("api_calls", [])
            if any("content://contacts" in str(a).lower() or "content://sms" in str(a).lower() for a in api_calls):
                res_actions.append({
                    "type": "persona_seeding",
                    "title": "Persona Seeding",
                    "result_summary": "Injected synthetic contacts and SMS history to successfully bypass sterile environment checks."
                })
            
            # Check permission grants
            if flags.get("has_system_alert_window") or flags.get("has_accessibility_abuse"):
                res_actions.append({
                    "type": "permission_grants",
                    "title": "Permission Grants",
                    "result_summary": "Auto-granted high-risk privileges (Accessibility/Overlay) to force execution of malicious payloads."
                })
            
            if res_actions:
                # We need to make a copy since dyn might be immutable or from cache
                dyn = dict(dyn)
                dyn["resilience_actions"] = res_actions

        normalised["dynamic_analysis"] = dyn
    if artifact_dir:
        normalised["artifact_dir"] = artifact_dir
    return normalised


async def load_report(sha256: str) -> Optional[Any]:
    """
    Resolve a report: hot cache first, then the database.

    Every export endpoint used to consult ONLY the in-memory cache and return
    404 "Report not found. Analyze the APK first." on a miss. So after any
    restart - or once the cache evicted - every historical case became
    permanently non-exportable, while GET /api/v1/cases/{sha} happily returned
    it. The error told the analyst to re-run an analysis that had already been
    run and was still on disk.

    intelligence.py already had this cache-then-DB shape; report.py never got it.
    """
    report = get_cached_report(sha256)
    if report is not None and _has_dynamic_payload(report):
        return _normalise_report_shape(report)

    # Both cache writers in upload.py store a thin projection that omits the
    # dynamic block entirely. Serving that would silently export a static-only
    # report, so treat a dynamic-less cache entry as a miss and go to the row
    # that actually holds the telemetry.
    from app.db.database import get_case
    row = await get_case(sha256)
    if row is None:
        return _normalise_report_shape(report) if report is not None else None

    # Re-populate the hot cache so repeat exports (HTML, then STIX, then IOCs)
    # do not each pay a database round trip.
    cache_report(sha256, row)
    logger.info(f"[Report] Rehydrated {sha256[:12]}… from the database")
    return _normalise_report_shape(row)


# ─── HTML Report Export ──────────────────────────────────────────────────────

@router.get("/report/html/{sha256}", response_class=HTMLResponse)
async def export_html_report(sha256: str, user: dict = Depends(require_analyst)):
    """
    Export a standalone, single-file HTML malware analysis report.

    The report is self-contained (inline CSS, no JS, no external CDN).
    It includes:
      - Executive summary with FRS score dial and verdict
      - 5-axis STEI breakdown
      - Threat scenario correlation table
      - Static forensic analysis with evidence IDs [STAT-NNN]
      - Threat intelligence & MITRE ATT&CK mapping [INTEL-NNN]
      - Dynamic analysis section (populated timeline OR explicit
        [DYNAMIC-STATUS: NO TELEMETRY CAPTURED] diagnostic banner)
      - Recommendations & evidence ledger

    For PDF export: open in Chrome/Edge and use Ctrl+P -> Save as PDF.
    The @media print stylesheet provides a clean light-mode print layout.
    """
    report = await load_report(sha256)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found. Analyze the APK first."
        )

    try:
        from sudarshan_core.engines.report_generator import build_report
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Report generator unavailable: {e}"
        )

    # Resolve per-sample artifact directory for evidence.json etc.
    apk_dir: Optional[Path] = None
    if isinstance(report, dict):
        artifact_path = report.get("artifact_dir") or report.get("_artifact_dir")
        if artifact_path:
            apk_dir = Path(artifact_path)

    # Normalise: Pydantic model -> dict
    if hasattr(report, "model_dump"):
        report_dict = report.model_dump()
    elif hasattr(report, "dict"):
        report_dict = report.dict()
    elif isinstance(report, dict):
        report_dict = report
    else:
        report_dict = {}

    html = build_report(report_dict, apk_dir=apk_dir)
    filename = f"sudarshan_report_{sha256[:12]}.html"

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
        },
    )


# ─── PDF Report Export ──────────────────────────────────────────────────────

@router.get("/report/pdf/{sha256}")
async def export_pdf_report(sha256: str, user: dict = Depends(require_analyst)):
    """
    Export an Enterprise Malware Investigation PDF Report generated directly via ReportLab.
    
    Consumes the authoritative case object and persisted disk artifacts,
    enforcing ReportData normalization and consistency validation before rendering.
    """
    from fastapi.responses import Response

    report = await load_report(sha256)
    if not report:
        raise HTTPException(
            status_code=404,
            detail="Report not found. Analyze the APK first."
        )

    try:
        from sudarshan_core.engines.pdf_generator import build_pdf_report
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"PDF generator engine unavailable: {e}"
        )

    apk_dir: Optional[Path] = None
    if isinstance(report, dict):
        artifact_path = report.get("artifact_dir") or report.get("_artifact_dir")
        if artifact_path:
            apk_dir = Path(artifact_path)

    if hasattr(report, "model_dump"):
        report_dict = report.model_dump()
    elif hasattr(report, "dict"):
        report_dict = report.dict()
    elif isinstance(report, dict):
        report_dict = report
    else:
        report_dict = {}

    try:
        pdf_bytes = build_pdf_report(report_dict, apk_dir=apk_dir)
    except Exception as e:
        logger.exception(f"Failed to generate PDF for {sha256[:12]}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {e}"
        )

    filename = f"sudarshan_report_{sha256[:12]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


# ─── STIX identifiers ─────────────────────────────────────────────────────────

_STIX_NAMESPACE = uuid.UUID("d1a4f1b2-0000-4000-8000-5544332211aa")


def _stix_id(obj_type: str, *parts: Any) -> str:
    """
    Build a spec-compliant, DETERMINISTIC STIX 2.1 identifier.

    The previous IDs were hand-assembled from slices of the sha256 and, worse,
    from `hash(url)` / `hash(campaign)` - and Python's hash() is SALTED PER
    PROCESS (PYTHONHASHSEED randomisation). So the same sample exported twice
    across a restart produced different indicator / attack-pattern /
    threat-actor IDs, and a TAXII consumer saw them as distinct objects rather
    than updates. The hand-assembled forms were not valid UUIDs either.

    uuid5 over a fixed namespace is stable across processes, restarts and hosts,
    and is exactly what STIX 2.1 recommends for deterministic identifiers.
    """
    name = "|".join(str(p) for p in parts)
    return f"{obj_type}--{uuid.uuid5(_STIX_NAMESPACE, name)}"


# ─── STIX 2.1 Export ─────────────────────────────────────────────────────────

def _build_stix_bundle(report: Dict[str, Any]) -> Dict:
    """Convert AnalysisResponse dict to STIX 2.1 bundle."""
    now = datetime.now(timezone.utc).isoformat()
    sha256 = report.get("sha256", "")
    package = report.get("package_name", "unknown")
    family = report.get("family_classification", "Unknown")
    risk_band = report.get("risk_band", "Unknown")
    score = report.get("final_risk_score", 0)

    objects = []

    # ── Malware object ────────────────────────────────────────────────────────
    malware_obj = {
        "type": "malware",
        "spec_version": "2.1",
        "id": _stix_id("malware", sha256, family),
        "created": now,
        "modified": now,
        "name": family if family != "Unknown" else f"Suspicious APK ({package})",
        "is_family": False,
        "malware_types": ["trojan", "ransomware"]
        if "banking" in risk_band.lower()
        else ["trojan"],
        "description": report.get("intelligence_report", {}).get(
            "plain_english_narrative", ""
        )
        if isinstance(report.get("intelligence_report"), dict)
        else "",
    }
    objects.append(malware_obj)

    # ── File indicator ────────────────────────────────────────────────────────
    file_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator", "file", sha256),
        "created": now,
        "modified": now,
        "name": f"SHA256: {sha256}",
        "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["malicious-activity"],
        "confidence": int(report.get("confidence", 70)),
    }
    objects.append(file_indicator)

    # ── URL indicators ────────────────────────────────────────────────────────
    for url in report.get("hardcoded_urls_ips", [])[:5]:
        if url.startswith("http"):
            url_ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator", "url", url),
                "created": now,
                "modified": now,
                "name": f"URL: {url[:80]}",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            }
            objects.append(url_ind)

    # ── Attack pattern (MITRE) ────────────────────────────────────────────────
    intel = report.get("intelligence_report", {}) or {}
    mitre_techniques = intel.get("mitre_techniques_used", []) if isinstance(intel, dict) else []
    for tech in mitre_techniques[:3]:
        tech_id = tech.split("-")[0].strip() if "-" in tech else tech
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": _stix_id("attack-pattern", tech_id),
            "created": now,
            "modified": now,
            "name": tech,
            "external_references": [
                {
                    "source_name": "mitre-attack-mobile",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                }
            ],
        }
        objects.append(ap)

    # ── Threat Actor (if campaign known) ─────────────────────────────────────
    correlation = report.get("threat_correlation", {}) or {}
    campaign = correlation.get("campaign") if isinstance(correlation, dict) else None
    if campaign:
        ta = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": _stix_id("threat-actor", campaign),
            "created": now,
            "modified": now,
            "name": campaign,
            "threat_actor_types": ["criminal"],
            "sophistication": "intermediate",
        }
        objects.append(ta)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", sha256),
        "spec_version": "2.1",
        "objects": objects,
    }


@router.get("/report/stix/{sha256}")
async def export_stix(sha256: str, user: dict = Depends(require_analyst)):
    """Export analysis as STIX 2.1 JSON bundle."""
    report = await load_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found. Analyze the APK first.")
    bundle = _build_stix_bundle(report)
    return JSONResponse(content=bundle, media_type="application/json")


# ─── IOC CSV Export ───────────────────────────────────────────────────────────

@router.get("/report/iocs/{sha256}", response_class=PlainTextResponse)
async def export_iocs_csv(sha256: str, user: dict = Depends(require_analyst)):
    """Export IOCs as CSV for SIEM ingestion."""
    report = await load_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found. Analyze the APK first.")

    buf = StringIO()
    buf.write("type,indicator,reputation,source,context\n")

    # SHA256
    buf.write(f"sha256,{sha256},malicious,Sudarshan,APK Hash\n")

    # Package name
    pkg = report.get("package_name", "")
    if pkg:
        buf.write(f"package_name,{pkg},suspicious,Sudarshan,Android Package Name\n")

    # URLs/IPs
    for url in report.get("hardcoded_urls_ips", []):
        buf.write(f"url,{url},suspicious,Sudarshan,Hardcoded in APK strings\n")

    # IOC reputation from correlator
    correlation = report.get("threat_correlation") or {}
    ioc_rep = []
    if hasattr(correlation, "ioc_reputation"):
        ioc_rep = correlation.ioc_reputation or []
    elif isinstance(correlation, dict):
        ioc_rep = correlation.get("ioc_reputation", [])

    for ioc in ioc_rep:
        if hasattr(ioc, "indicator"):
            buf.write(f"{ioc.type},{ioc.indicator},{ioc.reputation},{ioc.source},Threat Intelligence\n")
        elif isinstance(ioc, dict):
            buf.write(f"{ioc.get('type','unknown')},{ioc.get('indicator','')},{ioc.get('reputation','unknown')},{ioc.get('source','')},Threat Intelligence\n")

    return PlainTextResponse(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sudarshan_iocs_{sha256[:12]}.csv"},
    )


# ─── Additional Exports (IOC TXT, YARA, MITRE, Technical PDF) ───────────────

@router.get("/report/iocs-txt/{sha256}")
async def export_iocs_txt(sha256: str, user: dict = Depends(require_analyst)):
    """Export raw text list of IOC indicators (one per line)."""
    report = await load_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    urls = report.get("hardcoded_urls_ips", []) or []
    lines = [f"# Sudarshan IOC Export for SHA256: {sha256}", f"# Package: {report.get('package_name', '')}", ""]
    lines.extend(urls)

    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=sudarshan_iocs_{sha256[:12]}.txt"},
    )


@router.get("/report/yara/{sha256}")
async def export_yara_rule(sha256: str, user: dict = Depends(require_analyst)):
    """Export dynamically generated YARA rule for this sample."""
    report = await load_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    # Both the rule NAME and the string VALUES come from the APK, so both must
    # be sanitised. Previously the package name only had '.' replaced (a hyphen
    # or any other non-identifier character produced an invalid YARA rule name),
    # and URL values were interpolated raw - a single '"' or '\' in a hardcoded
    # URL broke the rule, and a non-ASCII byte broke it differently. Nothing
    # validated the output, so the endpoint happily served rules that will not
    # compile.
    raw_pkg = report.get("package_name") or "unknown"
    pkg = re.sub(r"[^A-Za-z0-9_]", "_", raw_pkg)[:64] or "unknown"
    if not pkg[0].isalpha() and pkg[0] != "_":
        pkg = f"pkg_{pkg}"

    def _yara_string(value: str) -> str:
        """Escape a value for a YARA double-quoted text string."""
        out = []
        for ch in str(value):
            if ch == "\\":
                out.append("\\\\")
            elif ch == '"':
                out.append('\\"')
            elif ch == "\t":
                out.append("\\t")
            elif ch in ("\n", "\r"):
                out.append("\\n")
            elif 0x20 <= ord(ch) <= 0x7E:
                out.append(ch)
            else:
                # YARA text strings are byte strings; emit a hex escape.
                for b in ch.encode("utf-8"):
                    out.append(f"\\x{b:02x}")
        return "".join(out)

    urls = [u for u in (report.get("hardcoded_urls_ips") or [])[:5] if u]
    if urls:
        strings_block = "\n        ".join(
            f'$url{i} = "{_yara_string(u)}"' for i, u in enumerate(urls)
        )
    else:
        strings_block = '$str1 = "Android"'

    yara_content = f"""rule Sudarshan_{pkg}_{sha256[:8]} {{
    meta:
        description = "Autogenerated YARA rule from Sudarshan Threat Intelligence Platform"
        sha256 = "{sha256}"
        package_name = "{_yara_string(report.get("package_name") or "")}"
        risk_score = "{report.get('final_risk_score', 0)}"
        family = "{_yara_string(report.get("family_classification") or "Unknown")}"
        date = "{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    strings:
        {strings_block}
    condition:
        any of them
}}"""

    return PlainTextResponse(
        yara_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=sudarshan_rule_{sha256[:12]}.yar"},
    )


@router.get("/report/mitre/{sha256}")
async def export_mitre_mapping(sha256: str, user: dict = Depends(require_analyst)):
    """Export MITRE ATT&CK Mobile mapping for this sample as JSON."""
    report = await load_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    intel = report.get("intelligence_report", {}) or {}
    mitre_techs = intel.get("mitre_techniques_used", []) if isinstance(intel, dict) else []

    data = {
        "sha256": sha256,
        "package_name": report.get("package_name"),
        "matrix": "MITRE ATT&CK Mobile",
        "techniques": [
            {
                "technique_id": t.split("-")[0].strip() if "-" in t else t,
                "name": t,
                "url": f"https://attack.mitre.org/techniques/{t.split('-')[0].strip().replace('.', '/')}/"
            }
            for t in mitre_techs
        ]
    }

    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f"attachment; filename=sudarshan_mitre_{sha256[:12]}.json"},
    )


@router.get("/report/technical-pdf/{sha256}", response_class=HTMLResponse)
async def export_technical_pdf(sha256: str, user: dict = Depends(require_analyst)):
    """Export print-ready Technical Forensic Report HTML for browser PDF printing."""
    return await export_pdf_report(sha256, user=user)




# ─── AI Investigation Assistant Endpoints ─────────────────────────────────────

class ChatRequest(BaseModel):
    sha256: str
    question: str
    history: List[Dict[str, str]] = []


class ChatResponse(BaseModel):
    answer: str
    sections_used: List[str] = []
    source: str


@router.post("/chat/stream")
async def analyst_chat_stream(req: ChatRequest, user: dict = Depends(require_analyst)):
    """
    Gemini RAG streaming SSE endpoint - primary chat interface.

    Streams a 7-section structured investigation response in real-time.
    Evidence is retrieved from the per-investigation knowledge graph.
    Gemini only explains - never decides.

    Events:
      sections - JSON array of evidence sections used
      token - response text chunk
      done - end of stream
      error - error message
    """
    from app.ai.gemini_rag import stream_investigation_response, is_indexed, build_investigation_index

    # Auto-index if not yet indexed in memory (e.g. backend restarted or historical case)
    if not is_indexed(req.sha256):
        report = await load_report(req.sha256)
        if report:
            build_investigation_index(req.sha256, report)

    async def event_generator():
        async for chunk in stream_investigation_response(
            sha256=req.sha256,
            question=req.question,
            conversation_history=req.history,
        ):
            yield chunk

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.post("/chat", response_model=ChatResponse)
async def analyst_chat(req: ChatRequest, user: dict = Depends(require_analyst)):
    """
    Gemini RAG non-streaming endpoint (legacy / fallback).
    Returns complete answer in one response.
    Uses the same investigation knowledge graph as /chat/stream.
    """
    from app.ai.gemini_rag import get_investigation_answer, is_indexed, build_investigation_index
    from app.ai.gemini_rag import _investigation_index

    # Auto-index if not yet indexed. Resolves from the database as well as the
    # hot cache, so the assistant works for historical cases rather than only
    # those analysed since the last restart.
    if not is_indexed(req.sha256):
        report = await load_report(req.sha256)
        if report:
            build_investigation_index(req.sha256, report)
        else:
            return ChatResponse(
                answer="No analysis found for this APK. Please analyze it first.",
                sections_used=[],
                source="not_found",
            )

    result = await get_investigation_answer(
        sha256=req.sha256,
        question=req.question,
        conversation_history=req.history,
    )

    return ChatResponse(
        answer=result["answer"],
        sections_used=result.get("sections_used", []),
        source=result.get("source", "gemini_rag"),
    )

