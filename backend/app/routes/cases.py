# backend/app/routes/cases.py - expanded CaseDetail + evidence endpoint
"""
Sudarshan Cases API
=====================
Provides persistent case history retrieved from SQLite.

Endpoints:
  GET /api/v1/cases - paginated list (JWT required, analyst+)
  GET /api/v1/cases/{sha256} - single case by hash (JWT required, analyst+)
  GET /api/v1/cases/{sha256}/evidence - Frida evidence.json for case
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth.auth import require_analyst, require_soc_lead
from app.case_access import assert_case_visible, list_scope_analyst_id
from app.db.database import (
    ANALYST_VERDICTS, CASE_STATUSES, add_case_note, assign_case, count_cases,
    get_case, get_case_notes, get_user_by_id, list_cases, save_case,
    set_case_status, set_case_verdict,
)
from app.db.intel import iocs_for_case, shared_indicators
from app.evidence_loader import load_evidence_records
from app.services import audit_service
from app.services.audit_service import Action
from app.services.case_intel_enrichment import enrich_case_threat_intel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cases", tags=["Case History"])


from sudarshan_core.engines.risk_engine import reconcile_frs_breakdown
class NoteCreateRequest(BaseModel):
    text: str
    author: Optional[str] = "SOC Analyst"


@router.get("/{sha256}/notes")
async def list_case_notes_endpoint(sha256: str, user: dict = Depends(require_analyst)):
    """Retrieve analyst notes for a case."""
    notes = await get_case_notes(sha256)
    return {"sha256": sha256, "notes": notes}


@router.post("/{sha256}/notes")
async def add_case_note_endpoint(
    sha256: str,
    req: NoteCreateRequest,
    request: Request,
    user: dict = Depends(require_analyst),
):
    """Add a new analyst note for a case."""
    author = req.author or user.get("username", "SOC Analyst")
    note = await add_case_note(sha256, req.text, author)
    await audit_service.record(
        Action.CASE_NOTE_ADDED,
        actor=user,
        target_type="case",
        target_id=sha256,
        detail={"note_id": note.get("id"), "author": author},
        request=request,
    )
    return note


# ─── Lifecycle ────────────────────────────────────────────────────────────────

class StatusChangeRequest(BaseModel):
    status: str = Field(..., description=f"One of {list(CASE_STATUSES)}")


class VerdictRequest(BaseModel):
    verdict: str = Field(..., description=f"One of {list(ANALYST_VERDICTS)}")
    reason: str = Field(..., min_length=3, max_length=2000)


class AssignRequest(BaseModel):
    assigned_to: Optional[int] = Field(None, description="User id, or null to unassign")


@router.patch("/{sha256}/status")
async def change_case_status(
    sha256: str,
    req: StatusChangeRequest,
    request: Request,
    user: dict = Depends(require_analyst),
):
    """Move a case through OPEN → IN_REVIEW → CLOSED / FALSE_POSITIVE."""
    existing = await get_case(sha256)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")
    assert_case_visible(user, existing)

    if req.status not in CASE_STATUSES:
        raise HTTPException(
            status_code=400, detail=f"status must be one of {list(CASE_STATUSES)}"
        )

    previous = existing.get("status") or "OPEN"
    await set_case_status(sha256, req.status)
    await audit_service.record(
        Action.CASE_STATUS_CHANGED,
        actor=user,
        target_type="case",
        target_id=sha256,
        detail={"from": previous, "to": req.status},
        request=request,
    )
    return {"sha256": sha256, "status": req.status, "previous_status": previous}


@router.patch("/{sha256}/verdict")
async def change_case_verdict(
    sha256: str,
    req: VerdictRequest,
    request: Request,
    user: dict = Depends(require_soc_lead),
):
    """
    Record the analyst's verdict.

    Restricted to soc_lead and above: overriding the engine is a judgement call
    with reporting consequences, and it must be attributable.

    The engine's own output is untouched. The response returns both so the
    disagreement is visible rather than silently resolved in the analyst's
    favour.
    """
    existing = await get_case(sha256)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")
    assert_case_visible(user, existing)

    if req.verdict not in ANALYST_VERDICTS:
        raise HTTPException(
            status_code=400, detail=f"verdict must be one of {list(ANALYST_VERDICTS)}"
        )

    previous = existing.get("analyst_verdict")
    await set_case_verdict(sha256, req.verdict, req.reason, user["id"])
    await audit_service.record(
        Action.CASE_VERDICT_CHANGED,
        actor=user,
        target_type="case",
        target_id=sha256,
        detail={
            "from": previous,
            "to": req.verdict,
            "reason": req.reason,
            # Recorded so an auditor can see what the analyst was overruling.
            "engine_risk_band": existing.get("risk_band"),
            "engine_final_risk_score": existing.get("final_risk_score"),
        },
        request=request,
    )
    return {
        "sha256": sha256,
        "analyst_verdict": req.verdict,
        "verdict_reason": req.reason,
        "verdict_set_by": user["username"],
        "engine_verdict": {
            "final_risk_score": existing.get("final_risk_score"),
            "risk_band": existing.get("risk_band"),
            "family_classification": existing.get("family_classification"),
            "confidence": existing.get("confidence"),
        },
    }


@router.patch("/{sha256}/assign")
async def assign_case_endpoint(
    sha256: str,
    req: AssignRequest,
    request: Request,
    user: dict = Depends(require_soc_lead),
):
    """Assign a case to an analyst, or pass null to unassign."""
    existing = await get_case(sha256)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")

    assignee_name = None
    if req.assigned_to is not None:
        assignee = await get_user_by_id(req.assigned_to)
        if not assignee:
            raise HTTPException(status_code=404, detail="Assignee not found")
        assignee_name = assignee["username"]

    await assign_case(sha256, req.assigned_to)
    await audit_service.record(
        Action.CASE_ASSIGNED,
        actor=user,
        target_type="case",
        target_id=sha256,
        detail={"assigned_to": req.assigned_to, "assignee_username": assignee_name},
        request=request,
    )
    return {"sha256": sha256, "assigned_to": req.assigned_to, "username": assignee_name}


# ─── IOC pivot ────────────────────────────────────────────────────────────────

@router.get("/{sha256}/iocs")
async def case_iocs_endpoint(sha256: str, user: dict = Depends(require_analyst)):
    """
    Indicators extracted from this case, plus which of them appear elsewhere.

    `shared_with` is the query that the JSON blob could not answer: the same C2
    domain seen on another sample is the strongest campaign signal the platform
    has.
    """
    existing = await get_case(sha256)
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found")
    assert_case_visible(user, existing)

    iocs = await iocs_for_case(sha256)
    shared = await shared_indicators(sha256)
    return {
        "sha256": sha256,
        "iocs": iocs,
        "count": len(iocs),
        "shared_with_other_cases": shared,
    }


@router.get("/{sha256}/evidence")
async def get_case_evidence(
    sha256: str,
    user: dict = Depends(require_analyst),
    limit: int = Query(500, ge=1, le=2000),
    severity: Optional[str] = Query(None),
):
    """Return structured Frida evidence records for a persisted case."""
    row = await get_case(sha256)
    if not row:
        raise HTTPException(status_code=404, detail=f"Case not found for SHA256 {sha256}.")
    assert_case_visible(user, row)

    dyn = row.get("dynamic_result") or {}
    artifact_dir = dyn.get("artifact_dir")
    records = load_evidence_records(
        sha256=sha256,
        artifact_dir=artifact_dir,
    )
    if severity:
        records = [r for r in records if str(r.get("severity", "")).upper() == severity.upper()]
    records = records[:limit]
    return {
        "sha256": sha256,
        "artifact_dir": artifact_dir,
        "total_found": len(records),
        "returned": len(records),
        "evidence": records,
    }


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
    base_score: Optional[float] = None
    ai_confidence_multiplier: Optional[float] = None
    recommended_action: Optional[str] = None
    # `risk_band` in the ordinary case, INCOMPLETE_EXERCISE when the sandbox ran
    # but never reached any of the sample's trigger conditions. Restoring a case
    # from history without these dropped the one signal that stops a low score
    # from reading as a clean bill of health.
    verdict: Optional[str] = None
    execution_assertions: Optional[Dict[str, Any]] = None
    incomplete_exercise: bool = False
    frs_breakdown: Optional[Dict[str, Any]] = None
    risk_explanation: Optional[Dict[str, Any]] = None
    threat_scenario_table: Optional[List[Dict[str, Any]]] = None
    intelligence_report: Optional[Dict[str, Any]] = None
    threat_correlation: Optional[Dict[str, Any]] = None
    dynamic_analysis: Optional[Dict[str, Any]] = None
    fraud_workflow: Optional[Dict[str, Any]] = None
    executive_view: Optional[Dict[str, Any]] = None
    technical_view: Optional[Dict[str, Any]] = None
    all_permissions: List[str] = Field(default_factory=list)
    hardcoded_urls_ips: List[str] = Field(default_factory=list)
    targets_indian_banks: bool = False
    has_accessibility_abuse: bool = False
    has_sms_read_write: bool = False
    has_system_alert_window: bool = False
    manifest_findings: List[Dict[str, Any]] = Field(default_factory=list)
    code_findings: List[Dict[str, Any]] = Field(default_factory=list)
    dangerous_permissions: List[Any] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    certificate: Dict[str, Any] = Field(default_factory=dict)
    domains: Dict[str, Any] = Field(default_factory=dict)
    hardcoded_secrets: List[str] = Field(default_factory=list)
    apktool_enrichment: Optional[Dict[str, Any]] = None
    jadx_enrichment: Optional[Dict[str, Any]] = None
    providers: List[str] = Field(default_factory=list)
    exported_activities: List[str] = Field(default_factory=list)
    exported_services: List[str] = Field(default_factory=list)
    exported_receivers: List[str] = Field(default_factory=list)
    binary_analysis: List[Dict[str, Any]] = Field(default_factory=list)
    network_security: Dict[str, Any] = Field(default_factory=dict)
    trackers: List[Dict[str, Any]] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    vide: Optional[Dict[str, Any]] = None


class CaseListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    cases: List[CaseSummary]


def _dynamic_analysis_from_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    dyn = row.get("dynamic_result")
    if dyn and isinstance(dyn, dict):
        return dyn
    da = row.get("dynamic_analysis")
    if da and isinstance(da, dict):
        return da
    return None


def _case_detail_from_row(row: Dict[str, Any]) -> CaseDetail:
    dyn = _dynamic_analysis_from_row(row)
    frs_breakdown = reconcile_frs_breakdown(row.get("frs_breakdown"), dyn)
    services = row.get("services_list") or row.get("services") or []
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
        base_score=row.get("base_score"),
        ai_confidence_multiplier=row.get("ai_confidence_multiplier"),
        recommended_action=row.get("recommended_action"),
        verdict=row.get("verdict") or row.get("risk_band"),
        execution_assertions=row.get("execution_assertions"),
        incomplete_exercise=bool(
            row.get("incomplete_exercise")
            or (row.get("execution_assertions") or {}).get("incomplete_exercise")
        ),
        frs_breakdown=frs_breakdown,
        risk_explanation=row.get("risk_explanation"),
        threat_scenario_table=row.get("threat_scenario_table"),
        intelligence_report=row.get("intelligence_report"),
        threat_correlation=row.get("threat_correlation"),
        dynamic_analysis=dyn,
        fraud_workflow=row.get("fraud_workflow"),
        executive_view=row.get("executive_view"),
        technical_view=row.get("technical_view") or {
            "permissions_fired": [],
            "strings_fired": row.get("suspicious_strings", [])[:20] if row.get("suspicious_strings") else [],
            "apis_fired": row.get("dangerous_apis_found_raw", []) or [],
            "matched_rule": row.get("matched_rule", ""),
            "decoded_manifest_excerpts": [],
        },
        all_permissions=row.get("all_permissions") or [],
        hardcoded_urls_ips=row.get("hardcoded_urls_ips") or [],
        targets_indian_banks=bool(row.get("targets_indian_banks")),
        has_accessibility_abuse=bool(row.get("has_accessibility_abuse")),
        has_sms_read_write=bool(row.get("has_sms_read_write")),
        has_system_alert_window=bool(row.get("has_system_alert_window")),
        manifest_findings=row.get("manifest_findings") or [],
        code_findings=row.get("code_findings") or [],
        dangerous_permissions=row.get("dangerous_perms") or row.get("dangerous_permissions") or [],
        activities=row.get("activities") or [],
        services=services if isinstance(services, list) else [],
        receivers=row.get("receivers") or [],
        certificate=row.get("certificate") or {},
        domains=row.get("domains") or {},
        hardcoded_secrets=row.get("hardcoded_secrets") or [],
        apktool_enrichment=row.get("apktool_enrichment"),
        jadx_enrichment=row.get("jadx_enrichment"),
        providers=row.get("providers") or [],
        exported_activities=row.get("exported_activities") or [],
        exported_services=row.get("exported_services") or [],
        exported_receivers=row.get("exported_receivers") or [],
        binary_analysis=row.get("binary_analysis") or [],
        network_security=row.get("network_security") or {},
        trackers=row.get("trackers") or [],
        emails=row.get("emails") or [],
        vide=row.get("vide"),
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=CaseListResponse)
async def list_all_cases(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    q: Optional[str] = Query(default=None, max_length=200, description="Match sha256, package, app name or family"),
    band: Optional[str] = Query(default=None, max_length=40, description="Exact risk band, or 'all'"),
    user: dict = Depends(require_analyst),
):
    """
    Return paginated case history (scoped to analyst_id for role=analyst).

    `q` and `band` are applied in SQL rather than by the client: the page only
    ever holds one page of rows, so a client-side filter silently searched
    1/N of the registry.
    """
    scope_id = list_scope_analyst_id(user)
    total = await count_cases(analyst_id=scope_id, q=q, band=band)
    rows = await list_cases(limit=limit, offset=offset, analyst_id=scope_id, q=q, band=band)

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


@router.get("/{sha256}")
async def get_case_detail(
    sha256: str,
    request: Request,
    user: dict = Depends(require_analyst),
):
    """Retrieve a single past analysis by its SHA256 hash."""
    row = await get_case(sha256)
    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Case not found for SHA256 {sha256}. Analyze the APK first.",
        )
    assert_case_visible(user, row)

    # Who opened which case is a reportable fact in a fraud investigation.
    await audit_service.record(
        Action.CASE_VIEWED,
        actor=user,
        target_type="case",
        target_id=sha256,
        detail={"package_name": row.get("package_name")},
        request=request,
    )

    prior_tc = row.get("threat_correlation") or {}
    prior_frs = row.get("frs_breakdown")
    row = await enrich_case_threat_intel(row)
    if (row.get("threat_correlation") or {}) != prior_tc or row.get("frs_breakdown") != prior_frs:
        await save_case(sha256, row, analyst_id=row.get("analyst_id"))

    # Return the merged persistence record (raw_result + summary columns) so
    # fields like `vide` and dynamic artifacts are not dropped by response_model.
    dyn = _dynamic_analysis_from_row(row)
    if dyn is not None:
        row.setdefault("dynamic_analysis", dyn)
        row.setdefault("dynamic_result", dyn)
    reconciled_frs = reconcile_frs_breakdown(row.get("frs_breakdown"), dyn)
    if reconciled_frs is not None:
        row["frs_breakdown"] = reconciled_frs
    row.setdefault(
        "technical_view",
        {
            "permissions_fired": [],
            "strings_fired": row.get("suspicious_strings", [])[:20]
            if row.get("suspicious_strings")
            else [],
            "apis_fired": row.get("dangerous_apis_found_raw", []) or [],
            "matched_rule": row.get("matched_rule", ""),
            "decoded_manifest_excerpts": [],
        },
    )
    # Resilience banner rows. Built from the recorded anti-evasion sequence
    # when the case has one, and from observed telemetry for older cases.
    dyn = row.get("dynamic_result") or row.get("dynamic_analysis")
    if isinstance(dyn, dict) and not dyn.get("resilience_actions"):
        from app.services.resilience_summary import build_resilience_actions

        actions = build_resilience_actions(dyn, row.get("static_flags", row))
        if actions:
            dyn["resilience_actions"] = actions
            row["dynamic_result"] = dyn
            if "dynamic_analysis" in row:
                row["dynamic_analysis"] = dyn

    # Normalise the verdict contract so a restored case carries the same three
    # keys as a fresh /analyze response. Cases persisted before the Execution
    # Assertion Matrix existed have no assertions: they report verdict=risk_band
    # and execution_assertions=None, which the UI must render as "coverage not
    # assessed". Rebuilding a matrix after the fact would fabricate a forensic
    # record, so we deliberately do not.
    assertions = row.get("execution_assertions") or None
    row["execution_assertions"] = assertions
    row["verdict"] = row.get("verdict") or row.get("risk_band")
    row["incomplete_exercise"] = bool(
        row.get("incomplete_exercise")
        or (assertions or {}).get("incomplete_exercise")
    )

    return row
