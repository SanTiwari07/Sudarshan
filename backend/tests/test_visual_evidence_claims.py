"""Tests for deterministic visual evidence claim templates."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.visual_evidence.claim_templates import (
    ClaimTemplateError,
    lint_investigative_claim,
    render_investigative_claim,
)
from sudarshan_core.visual_evidence.constants import ALL_CLAIM_TYPES
from sudarshan_core.visual_evidence.quality import (
    apply_executive_key_cap,
    assign_quality,
    assign_report_tier,
)
from sudarshan_core.visual_evidence.constants import (
    CLAIM_INCONCLUSIVE_VISUAL,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_VISUAL_IMPERSONATION,
    CORRELATION_LINKED,
    CORRELATION_NOT_APPLICABLE,
    QUALITY_A,
    QUALITY_B,
    QUALITY_C,
    QUALITY_D,
    TIER_EXECUTIVE_KEY,
    TIER_EXCLUDE,
    TIER_TECHNICAL,
)
from sudarshan_core.visual_evidence.models import VisualEvidenceRecord


@pytest.mark.parametrize("claim_type", sorted(ALL_CLAIM_TYPES))
def test_every_claim_type_renders(claim_type):
    params = {}
    if claim_type == CLAIM_VISUAL_IMPERSONATION:
        params = {"baseline_name": "SBI", "rule_id": "VIDE-F001"}
    text = render_investigative_claim(claim_type, params)
    assert text
    lint_investigative_claim(text)


@pytest.mark.parametrize(
    "bad_claim",
    [
        "This proves malware behavior.",
        "The user was definitely hacked.",
        "User was compromised during analysis.",
        "Confirmed malware on screen.",
    ],
)
def test_forbidden_language_rejected(bad_claim):
    with pytest.raises(ClaimTemplateError):
        lint_investigative_claim(bad_claim)


def test_visual_impersonation_requires_params():
    with pytest.raises(ClaimTemplateError):
        render_investigative_claim(CLAIM_VISUAL_IMPERSONATION, {})


def test_claims_are_deterministic():
    a = render_investigative_claim(CLAIM_OVERLAY_OBSERVED)
    b = render_investigative_claim(CLAIM_OVERLAY_OBSERVED)
    assert a == b


def test_quality_a_requires_high_severity_or_vide():
    q = assign_quality(
        claim_type=CLAIM_OVERLAY_OBSERVED,
        correlation_status=CORRELATION_LINKED,
        linked_evidence_ids=["EVID-001"],
        evidence_by_finding_id={
            "EVID-001": {"severity": "CRITICAL", "finding_id": "EVID-001"},
        },
        static_flags={},
        vide_detected=False,
        is_duplicate=False,
        png_missing=False,
    )
    assert q == QUALITY_A


def test_quality_a_not_without_corroboration():
    q = assign_quality(
        claim_type=CLAIM_OVERLAY_OBSERVED,
        correlation_status=CORRELATION_LINKED,
        linked_evidence_ids=[],
        evidence_by_finding_id={},
        static_flags={},
        vide_detected=False,
        is_duplicate=False,
        png_missing=False,
    )
    assert q != QUALITY_A


def test_quality_c_launch_context():
    q = assign_quality(
        claim_type=CLAIM_LAUNCH_CONTEXT,
        correlation_status=CORRELATION_NOT_APPLICABLE,
        linked_evidence_ids=[],
        evidence_by_finding_id={},
        static_flags={},
        vide_detected=False,
        is_duplicate=False,
        png_missing=False,
    )
    assert q == QUALITY_C


def test_quality_d_duplicate():
    q = assign_quality(
        claim_type=CLAIM_INCONCLUSIVE_VISUAL,
        correlation_status=CORRELATION_LINKED,
        linked_evidence_ids=[],
        evidence_by_finding_id={},
        static_flags={},
        vide_detected=False,
        is_duplicate=True,
        png_missing=False,
    )
    assert q == QUALITY_D
    assert assign_report_tier(CLAIM_OVERLAY_OBSERVED, q) == TIER_EXCLUDE


def test_executive_key_cap():
    records = [
        VisualEvidenceRecord(
            screenshot_id=f"SCR-{i:03d}",
            filename=f"screenshots/{i}.png",
            png_sha256="a" * 64,
            timestamp_ms=i * 1000,
            capture_trigger="OVERLAY",
            claim_type=CLAIM_OVERLAY_OBSERVED,
            investigative_claim="overlay",
            quality=QUALITY_A,
            report_tier=TIER_EXECUTIVE_KEY,
            correlation_status=CORRELATION_LINKED,
            priority="P0",
        )
        for i in range(1, 5)
    ]
    apply_executive_key_cap(records)
    exec_count = sum(1 for r in records if r.report_tier == TIER_EXECUTIVE_KEY)
    assert exec_count == 2
    assert sum(1 for r in records if r.report_tier == TIER_TECHNICAL) == 2
