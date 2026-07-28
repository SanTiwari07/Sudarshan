# backend/app/routes/report.py
"""
Sudarshan Report Export Endpoints
===================================
Provides:
  GET /api/v1/report/html/{sha256}  — Standalone CYFIRMA-style HTML report (primary)
  GET /api/v1/report/stix/{sha256}  — STIX 2.1 JSON export
  GET /api/v1/report/iocs/{sha256}  — IOC CSV export
  GET /api/v1/report/pdf/{sha256}   — PDF stub (use browser print on the HTML report instead)
  POST /api/v1/chat                 — AI chat endpoint (legacy, non-streaming)
  POST /api/v1/chat/stream          — Gemini RAG SSE streaming endpoint (primary)
"""

import json
import logging
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

# In-memory report cache keyed by sha256
# In production this would be Redis or a DB
_report_cache: Dict[str, Any] = {}


def cache_report(sha256: str, report: Any) -> None:
    """Store analysis result for later export."""
    _report_cache[sha256] = report


def get_cached_report(sha256: str) -> Optional[Any]:
    return _report_cache.get(sha256)


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
    report = get_cached_report(sha256)
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
        "id": f"malware--{sha256[:8]}-0000-0000-0000-{sha256[8:20]}",
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
        "id": f"indicator--{sha256[:8]}-0001-0000-0000-{sha256[8:20]}",
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
                "id": f"indicator--{hash(url) & 0xFFFFFFFF:08x}-0002-0000-0000-{sha256[8:20]}",
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
        tech_id = tech.split("—")[0].strip() if "—" in tech else tech
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{hash(tech_id) & 0xFFFFFFFF:08x}-0003-0000-0000-{sha256[8:20]}",
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
            "id": f"threat-actor--{hash(campaign) & 0xFFFFFFFF:08x}-0004-0000-0000-{sha256[8:20]}",
            "created": now,
            "modified": now,
            "name": campaign,
            "threat_actor_types": ["criminal"],
            "sophistication": "intermediate",
        }
        objects.append(ta)

    return {
        "type": "bundle",
        "id": f"bundle--{sha256[:8]}-ffff-0000-0000-{sha256[8:20]}",
        "spec_version": "2.1",
        "objects": objects,
    }


@router.get("/report/stix/{sha256}")
async def export_stix(sha256: str, user: dict = Depends(require_analyst)):
    """Export analysis as STIX 2.1 JSON bundle."""
    report = get_cached_report(sha256)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found. Analyze the APK first.")
    bundle = _build_stix_bundle(report)
    return JSONResponse(content=bundle, media_type="application/json")


# ─── IOC CSV Export ───────────────────────────────────────────────────────────

@router.get("/report/iocs/{sha256}", response_class=PlainTextResponse)
async def export_iocs_csv(sha256: str, user: dict = Depends(require_analyst)):
    """Export IOCs as CSV for SIEM ingestion."""
    report = get_cached_report(sha256)
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
    Gemini RAG streaming SSE endpoint — primary chat interface.

    Streams a 7-section structured investigation response in real-time.
    Evidence is retrieved from the per-investigation knowledge graph.
    Gemini only explains — never decides.

    Events:
      sections — JSON array of evidence sections used
      token    — response text chunk
      done     — end of stream
      error    — error message
    """
    from app.ai.gemini_rag import stream_investigation_response

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

    # Auto-index from cache if not yet indexed
    if not is_indexed(req.sha256):
        report = get_cached_report(req.sha256)
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

