# backend/app/routes/cases.py
"""
Sudarshan Cases API
=====================
Provides persistent case history retrieved from SQLite.

Endpoints:
  GET /api/v1/cases            — paginated list (JWT required, analyst+)
  GET /api/v1/cases/{sha256}   — single case by hash (JWT required, analyst+)
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth.auth import require_analyst
from app.db.database import get_case, list_cases, count_cases, add_case_note, get_case_notes

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cases", tags=["Case History"])


class NoteCreateRequest(BaseModel):
    text: str
    author: Optional[str] = "SOC Analyst"


@router.get("/{sha256}/notes")
async def list_case_notes_endpoint(sha256: str, user: dict = Depends(require_analyst)):
    """Retrieve analyst notes for a case."""
    notes = await get_case_notes(sha256)
    return {"sha256": sha256, "notes": notes}


@router.post("/{sha256}/notes")
async def add_case_note_endpoint(sha256: str, req: NoteCreateRequest, user: dict = Depends(require_analyst)):
    """Add a new analyst note for a case."""
    author = req.author or user.get("username", "SOC Analyst")
    note = await add_case_note(sha256, req.text, author)
    return note



# ─── Response Models ──────────────────────────────────────────────────────────

class CaseSummary(BaseModel):
    sha256: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    analysis_mode: Optional[str] = None
    family_classification: Optional[str] = None
    final_risk_score: Optional[float] = None
    risk_band: Optional[str] = None
    confidence: Optional[float] = None
    dynamic_available: bool = False
    obfuscation_score: float = 0.0
    has_reflection: bool = False
    created_at: str


class CaseDetail(CaseSummary):
    frs_breakdown: Optional[Dict[str, Any]] = None
    threat_scenario_table: Optional[List[Dict[str, Any]]] = None
    intelligence_report: Optional[Dict[str, Any]] = None


class CaseListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    cases: List[CaseSummary]


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=CaseListResponse)
async def list_all_cases(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    user: dict = Depends(require_analyst),
):
    """
    Return paginated list of all past APK analyses.
    Analysts see all cases (no per-user scoping — analysts share context).
    """
    total = await count_cases()
    rows = await list_cases(limit=limit, offset=offset)

    cases = [
        CaseSummary(
            sha256=r["sha256"],
            package_name=r.get("package_name"),
            app_name=r.get("app_name"),
            analysis_mode=r.get("analysis_mode"),
            family_classification=r.get("family_classification"),
            final_risk_score=r.get("final_risk_score"),
            risk_band=r.get("risk_band"),
            confidence=r.get("confidence"),
            dynamic_available=bool(r.get("dynamic_available")),
            obfuscation_score=float(r.get("obfuscation_score") or 0.0),
            has_reflection=bool(r.get("has_reflection")),
            created_at=r.get("created_at", ""),
        )
        for r in rows
    ]

    return CaseListResponse(total=total, limit=limit, offset=offset, cases=cases)


@router.get("/{sha256}", response_model=CaseDetail)
async def get_case_detail(
    sha256: str,
    user: dict = Depends(require_analyst),
):
    """Retrieve a single past analysis by its SHA256 hash."""
    row = await get_case(sha256)
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Case not found for SHA256 {sha256}. Analyze the APK first.",
        )

    return CaseDetail(
        sha256=row["sha256"],
        package_name=row.get("package_name"),
        app_name=row.get("app_name"),
        analysis_mode=row.get("analysis_mode"),
        family_classification=row.get("family_classification"),
        final_risk_score=row.get("final_risk_score"),
        risk_band=row.get("risk_band"),
        confidence=row.get("confidence"),
        dynamic_available=bool(row.get("dynamic_available")),
        obfuscation_score=float(row.get("obfuscation_score") or 0.0),
        has_reflection=bool(row.get("has_reflection")),
        created_at=row.get("created_at", ""),
        frs_breakdown=row.get("frs_breakdown"),
        threat_scenario_table=row.get("threat_scenario_table"),
        intelligence_report=row.get("intelligence_report"),
    )
