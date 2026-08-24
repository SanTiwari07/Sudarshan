"""Deterministic quality and report tier assignment."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from sudarshan_core.visual_evidence.constants import (  # noqa: I001
    CORRELATION_CAUSAL,
    CORRELATION_NOT_APPLICABLE,
    CORRELATION_LINKED,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_BANKING_TARGET_UI,
    CLAIM_BENIGN_NEGATIVE_PROOF,
    CLAIM_CREDENTIAL_COLLECTION_UI,
    CLAIM_DROPPER_UI,
    CLAIM_FAKE_LOGIN_UI,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_OTP_UI,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_PAYMENT_UI,
    CLAIM_VISUAL_IMPERSONATION,
    CLAIM_VPN_REQUEST,
    CLAIM_UPDATE_REQUEST,
    CLAIM_PERMISSION_REQUEST,
    CLAIM_EXTERNAL_APK_REQUEST,
    CLAIM_DOWNLOAD_PROMPT,
    PRIORITY_P0,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    QUALITY_A,
    QUALITY_B,
    QUALITY_C,
    QUALITY_D,
    TIER_APPENDIX_ONLY,
    TIER_EXCLUDE,
    TIER_EXECUTIVE_KEY,
    TIER_TECHNICAL,
    VISUAL_LINK_MIN_EVID_SEVERITY_FOR_A,
)

_CLAIM_A_TYPES = frozenset({
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_FAKE_LOGIN_UI,
    CLAIM_VISUAL_IMPERSONATION,
})

_CLAIM_B_TYPES = frozenset({
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_OTP_UI,
    CLAIM_PAYMENT_UI,
    CLAIM_BANKING_TARGET_UI,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_DROPPER_UI,
    CLAIM_BENIGN_NEGATIVE_PROOF,
    CLAIM_CREDENTIAL_COLLECTION_UI,
    CLAIM_VPN_REQUEST,
    CLAIM_UPDATE_REQUEST,
    CLAIM_PERMISSION_REQUEST,
    CLAIM_EXTERNAL_APK_REQUEST,
    CLAIM_DOWNLOAD_PROMPT,
})

_CLAIM_C_TYPES = frozenset({
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
})


def _has_high_severity_link(
    linked_evidence_ids: List[str],
    evidence_by_finding_id: Dict[str, Dict[str, Any]],
) -> bool:
    for eid in linked_evidence_ids:
        rec = evidence_by_finding_id.get(eid)
        if not rec:
            continue
        sev = str(rec.get("severity") or "").upper()
        if sev in VISUAL_LINK_MIN_EVID_SEVERITY_FOR_A:
            return True
    return False


def _static_supports_claim(claim_type: str, static_flags: Dict[str, bool]) -> bool:
    if claim_type == CLAIM_ACCESSIBILITY_GUIDANCE:
        return bool(static_flags.get("has_accessibility_abuse"))
    if claim_type in (CLAIM_OVERLAY_OBSERVED, CLAIM_FAKE_LOGIN_UI):
        return bool(static_flags.get("has_system_alert_window"))
    if claim_type == CLAIM_OTP_UI:
        return bool(static_flags.get("has_sms_read_write"))
    if claim_type == CLAIM_BANKING_TARGET_UI:
        return bool(static_flags.get("targets_indian_banks"))
    return False


def assign_quality(
    *,
    claim_type: str,
    correlation_status: str,
    linked_evidence_ids: List[str],
    evidence_by_finding_id: Dict[str, Dict[str, Any]],
    static_flags: Dict[str, bool],
    vide_detected: bool,
    is_duplicate: bool,
    png_missing: bool,
) -> str:
    if is_duplicate or png_missing:
        return QUALITY_D

    if correlation_status in (CORRELATION_UNRESOLVED, CORRELATION_NOT_APPLICABLE):
        if claim_type in _CLAIM_C_TYPES:
            return QUALITY_C
        if claim_type == CLAIM_INCONCLUSIVE_VISUAL:
            return QUALITY_C
        if correlation_status == CORRELATION_NOT_APPLICABLE:
            return QUALITY_C
        return QUALITY_C

    if claim_type in _CLAIM_A_TYPES:
        if vide_detected and claim_type == CLAIM_VISUAL_IMPERSONATION:
            return QUALITY_A
        if _has_high_severity_link(linked_evidence_ids, evidence_by_finding_id):
            if correlation_status == CORRELATION_TEMPORAL:
                return QUALITY_B
            return QUALITY_A
        if correlation_status in (
            CORRELATION_CAUSAL,
            CORRELATION_LINKED,
            CORRELATION_TEMPORAL,
        ):
            return QUALITY_B
        return QUALITY_B

    if claim_type in _CLAIM_B_TYPES:
        if linked_evidence_ids or _static_supports_claim(claim_type, static_flags):
            return QUALITY_B
        return QUALITY_C

    if claim_type in _CLAIM_C_TYPES:
        return QUALITY_C

    return QUALITY_C


def assign_report_tier(claim_type: str, quality: str) -> str:
    if quality == QUALITY_D:
        return TIER_EXCLUDE
    if quality == QUALITY_A and claim_type in _CLAIM_A_TYPES:
        return TIER_EXECUTIVE_KEY
    if quality in (QUALITY_A, QUALITY_B):
        return TIER_TECHNICAL
    return TIER_APPENDIX_ONLY


def assign_priority(claim_type: str, quality: str) -> str:
    if quality == QUALITY_A and claim_type in _CLAIM_A_TYPES:
        return PRIORITY_P0
    if quality == QUALITY_B and claim_type in _CLAIM_B_TYPES:
        return PRIORITY_P1
    if quality == QUALITY_C:
        return PRIORITY_P2
    return PRIORITY_P3


def timeline_eligible(
    quality: str,
    correlation_status: str,
    claim_type: str,
) -> bool:
    if quality not in (QUALITY_A, QUALITY_B):
        if claim_type in (CLAIM_LAUNCH_CONTEXT, CLAIM_FINAL_STATE, CLAIM_BENIGN_NEGATIVE_PROOF):
            return correlation_status in (
                CORRELATION_LINKED,
                CORRELATION_CAUSAL,
                CORRELATION_TEMPORAL,
            ) or claim_type in (
                CLAIM_LAUNCH_CONTEXT,
                CLAIM_FINAL_STATE,
            )
        return False
    if claim_type == CLAIM_INCONCLUSIVE_VISUAL and correlation_status == CORRELATION_UNRESOLVED:
        return False
    return True


def apply_executive_key_cap(records: List[Any]) -> None:
    """Downgrade report_tier to technical when more than MAX executive_key (metadata only)."""
    from sudarshan_core.visual_evidence.constants import MAX_EXECUTIVE_KEY_SCREENSHOTS

    exec_candidates = [
        r for r in records
        if getattr(r, "report_tier", "") == TIER_EXECUTIVE_KEY
    ]
    exec_candidates.sort(
        key=lambda r: (
            0 if getattr(r, "priority", "") == PRIORITY_P0 else 1,
            -int(getattr(r, "timestamp_ms", 0) or 0),
        )
    )
    for idx, rec in enumerate(exec_candidates):
        if idx >= MAX_EXECUTIVE_KEY_SCREENSHOTS:
            rec.report_tier = TIER_TECHNICAL
