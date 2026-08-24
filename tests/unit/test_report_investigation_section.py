"""
Rendering the investigation in the HTML report.

The dynamic section already answered "which hooks fired". It could not answer
"what did we look for, what did we grant, and did any of it work", so a reader
could not tell a sample that requested nothing from one whose permission grants
silently failed.

The load-bearing case is the precondition split. A stage recording that the
SANDBOX enabled accessibility, rendered under "Reconstructed Fraud Workflow" at
100% confidence, reads as something the application did - the opposite of what
it means.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.report_generator import _render_investigation  # noqa: E402


class _Idx:
    """Minimal stand-in for the report's finding-id allocator."""

    def __init__(self):
        self.n = 0

    def next(self, prefix, _desc=""):
        self.n += 1
        return f"{prefix}-{self.n:03d}"


def _render(report):
    return _render_investigation(report, _Idx())


# ── renders nothing when there is nothing to say ─────────────────────────────

def test_a_static_only_report_is_unchanged():
    assert _render({}) == ""


def test_empty_investigation_data_renders_nothing():
    assert _render({
        "investigation": {"transitions": []},
        "permission_findings": {"records": []},
        "crashes": [],
    }) == ""


# ── stage transitions ────────────────────────────────────────────────────────

def test_stage_transitions_are_rendered_with_elapsed_time():
    html = _render({"investigation": {"transitions": [
        {"from": "BOOTSTRAP", "to": "APP_LAUNCH",
         "reason": "launched", "elapsed_seconds": 5.0},
        {"from": "APP_LAUNCH", "to": "PERMISSION_ANALYSIS",
         "reason": "observed SYSTEM_PERMISSION", "elapsed_seconds": 73.0},
    ]}})
    assert "BOOTSTRAP" in html and "APP_LAUNCH" in html
    assert "00:05" in html
    assert "01:13" in html          # 73s
    assert "observed SYSTEM_PERMISSION" in html


def test_a_malformed_elapsed_time_does_not_break_rendering():
    html = _render({"investigation": {"transitions": [
        {"from": "A", "to": "B", "reason": "x", "elapsed_seconds": "nonsense"},
    ]}})
    assert "--:--" in html


# ── permission findings ──────────────────────────────────────────────────────

def _perm(**kw):
    base = {
        "permission": "android.permission.READ_SMS", "severity": "CRITICAL",
        "classification": "UNEXPECTED_PERMISSION", "declared": True,
        "requested_at_runtime": False, "granted": True,
    }
    base.update(kw)
    return {"permission_findings": {"records": [base]}}


def test_a_notable_permission_is_rendered_with_its_four_facts():
    """The facts are what make it a finding rather than a list entry."""
    html = _render(_perm())
    assert "READ_SMS" in html
    assert "UNEXPECTED_PERMISSION" in html
    assert "declared" in html
    assert "granted" in html


def test_the_android_permission_prefix_is_stripped_for_readability():
    assert "android.permission.READ_SMS" not in _render(_perm())


def test_an_ungranted_permission_says_so_rather_than_omitting_it():
    html = _render(_perm(granted=False))
    assert "not granted" in html


def test_info_severity_permissions_are_not_rendered_as_findings():
    """
    Otherwise every ordinary permission becomes a finding and the section is
    noise. GRANTED_WITHOUT_REQUEST on an expected permission is INFO.
    """
    assert _render(_perm(severity="INFO")) == ""


def test_the_assessed_category_is_shown_with_its_reasoning():
    html = _render({
        "permission_findings": {
            "profile": {"category": "CALCULATOR", "confidence": "HIGH",
                        "signals": ["app label matched calculator"]},
            "records": [],
        },
    })
    assert "CALCULATOR" in html
    assert "app label matched calculator" in html


def test_an_unknown_category_is_not_asserted():
    """Reporting a category we never established would be a claim, not a fact."""
    html = _render({
        "permission_findings": {
            "profile": {"category": "UNKNOWN", "confidence": "LOW"},
            "records": [{"permission": "android.permission.CAMERA",
                         "severity": "HIGH", "classification": "X"}],
        },
    })
    assert "UNKNOWN" not in html


def test_the_section_says_unexpected_is_not_a_verdict():
    html = _render({
        "permission_findings": {
            "profile": {"category": "CALCULATOR", "confidence": "HIGH", "signals": []},
            "records": [],
        },
    })
    assert "not a verdict" in html.lower()


# ── crashes ──────────────────────────────────────────────────────────────────

def test_a_classified_crash_is_rendered_with_its_confidence():
    html = _render({"crashes": [{
        "crash_type": "INSTRUMENTATION_SENSITIVE_CRASH", "confidence": "HIGH",
        "severity": "MEDIUM", "summary": "died with our own instrumentation on the stack",
    }]})
    assert "INSTRUMENTATION_SENSITIVE_CRASH" in html
    assert "HIGH" in html
    assert "instrumentation" in html


def test_a_crash_with_missing_fields_still_renders():
    html = _render({"crashes": [{}]})
    assert "UNKNOWN_CRASH" in html


# ── the precondition split ───────────────────────────────────────────────────

def test_precondition_stages_are_rendered_apart_from_the_fraud_workflow():
    """
    A sandbox-granted capability shown as a fraud-workflow stage would read as
    application behaviour.
    """
    from sudarshan_core.engines.report_generator import _build_dynamic

    report = {
        "fraud_workflow": {"stages": [
            {"label": "Runtime Permissions Granted by Sandbox",
             "technique_id": "T1401", "description": "harness action",
             "confidence": 1.0, "evidence_ids": [], "is_precondition": True},
            {"label": "SMS / OTP Interception", "technique_id": "T1412",
             "description": "read incoming SMS", "confidence": 0.9,
             "evidence_ids": ["EVID-1"], "is_precondition": False},
        ]},
    }
    html = _build_dynamic(report, {"records": []}, _Idx())

    assert "Sandbox Preconditions" in html
    assert "Reconstructed Fraud Workflow" in html
    # The precondition must be under the harness heading, ahead of the fraud one.
    assert html.index("Sandbox Preconditions") < html.index("Reconstructed Fraud Workflow")
    assert "harness actions, not application behaviour" in html


def test_a_workflow_of_only_preconditions_shows_no_fraud_heading():
    from sudarshan_core.engines.report_generator import _build_dynamic

    html = _build_dynamic(
        {"fraud_workflow": {"stages": [
            {"label": "Accessibility Enabled by Sandbox", "technique_id": "T1417",
             "description": "harness action", "confidence": 1.0,
             "evidence_ids": [], "is_precondition": True},
        ]}},
        {"records": []}, _Idx(),
    )
    assert "Sandbox Preconditions" in html
    assert "Reconstructed Fraud Workflow" not in html


def test_legacy_stages_without_the_flag_render_as_behaviour():
    """Older workflow.json files have no is_precondition key."""
    from sudarshan_core.engines.report_generator import _build_dynamic

    html = _build_dynamic(
        {"fraud_workflow": {"stages": [
            {"label": "SMS / OTP Interception", "technique_id": "T1412",
             "description": "read SMS", "confidence": 0.9, "evidence_ids": []},
        ]}},
        {"records": []}, _Idx(),
    )
    assert "Reconstructed Fraud Workflow" in html
    assert "Sandbox Preconditions" not in html


# ── output safety ────────────────────────────────────────────────────────────

def test_app_controlled_text_is_escaped():
    """Permission and crash text can carry attacker-chosen strings."""
    html = _render({"crashes": [{
        "crash_type": "UNKNOWN_CRASH",
        "summary": "<script>alert('xss')</script>",
    }]})
    assert "<script>" not in html
