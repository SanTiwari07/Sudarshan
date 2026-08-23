"""
Tests for permissions-as-investigation.

The point of these is the gaps between four facts - declared, requested,
granted, expected - because the gaps are where the findings are. A permission
list on its own says almost nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.permission_investigator import (  # noqa: E402
    Classification,
    PermissionClass,
    PermissionInvestigator,
    investigate_permissions,
    permission_class,
)

P = "android.permission."
CAMERA = P + "CAMERA"
READ_SMS = P + "READ_SMS"
INTERNET = P + "INTERNET"
ACCESSIBILITY = P + "BIND_ACCESSIBILITY_SERVICE"
OVERLAY = P + "SYSTEM_ALERT_WINDOW"


# ── permission classes ───────────────────────────────────────────────────────

def test_runtime_dialog_permissions_are_dangerous():
    assert permission_class(CAMERA) is PermissionClass.DANGEROUS
    assert permission_class(READ_SMS) is PermissionClass.DANGEROUS


def test_settings_gated_permissions_are_special():
    assert permission_class(ACCESSIBILITY) is PermissionClass.SPECIAL
    assert permission_class(OVERLAY) is PermissionClass.SPECIAL


def test_install_time_permissions_are_normal():
    assert permission_class(INTERNET) is PermissionClass.NORMAL


def test_an_unmodelled_permission_is_unknown_not_normal():
    assert permission_class(P + "SET_WALLPAPER") is PermissionClass.UNKNOWN


# ── the brief's calculator case ──────────────────────────────────────────────

def _calculator(**kw):
    return investigate_permissions(
        package_name="com.example.calculator", app_label="Calculator", **kw
    )


def test_unexpected_and_granted_is_the_headline_finding():
    inv = _calculator(declared=[CAMERA], granted=[CAMERA])
    rec = inv.records()[0]
    assert rec.permission == CAMERA
    assert rec.declared and rec.granted
    assert rec.expected_for_app is False
    assert rec.classification == Classification.UNEXPECTED_PERMISSION.value
    assert rec.severity == "MEDIUM"


def test_sms_on_a_calculator_outranks_camera():
    """Severity has to separate 'odd' from 'this is how OTP theft works'."""
    inv = _calculator(declared=[READ_SMS], granted=[READ_SMS])
    assert inv.records()[0].severity == "CRITICAL"


def test_accessibility_on_a_calculator_is_critical():
    inv = _calculator(declared=[ACCESSIBILITY], granted=[ACCESSIBILITY])
    assert inv.records()[0].severity == "CRITICAL"


def test_an_unexpected_permission_never_granted_is_reported_one_step_down():
    """Capability the app asked for and did not get still deserves reporting."""
    inv = _calculator(declared=[READ_SMS])
    rec = inv.records()[0]
    assert rec.classification == Classification.UNEXPECTED_PERMISSION.value
    assert rec.severity == "HIGH"      # de-escalated from CRITICAL


def test_expected_permissions_are_not_findings():
    inv = _calculator(declared=[INTERNET], granted=[INTERNET])
    rec = inv.records()[0]
    assert rec.expected_for_app is True
    assert rec.severity == "INFO"


# ── the four-fact gaps ───────────────────────────────────────────────────────

def test_declared_but_never_exercised_is_dormant_capability():
    inv = investigate_permissions(
        package_name="com.example.cam", app_label="Camera", declared=[CAMERA]
    )
    assert inv.records()[0].classification == Classification.DORMANT_CAPABILITY.value


def test_granted_without_a_runtime_request_is_flagged():
    """
    This is how our own pre-granting shows up: the dialog never appeared
    because we suppressed it. It is a finding about the harness, not the app.
    """
    inv = investigate_permissions(
        package_name="com.example.cam", app_label="Camera",
        declared=[CAMERA], granted=[CAMERA],
    )
    rec = inv.records()[0]
    assert rec.classification == Classification.GRANTED_WITHOUT_REQUEST.value
    assert rec.severity == "INFO"


def test_requested_without_being_declared_is_flagged():
    inv = investigate_permissions(
        package_name="com.example.cam", app_label="Camera", requested=[CAMERA]
    )
    rec = inv.records()[0]
    assert rec.classification == Classification.UNDECLARED_REQUEST.value
    assert rec.severity == "MEDIUM"


def test_the_actionable_reading_wins_when_several_apply():
    """
    An unexpected permission that fired is also technically 'granted without
    request'. The analyst needs to hear the first one.
    """
    inv = _calculator(declared=[READ_SMS], granted=[READ_SMS])
    assert inv.records()[0].classification == Classification.UNEXPECTED_PERMISSION.value


# ── unknown apps stay quiet ──────────────────────────────────────────────────

def test_an_uncategorised_app_produces_no_unexpected_findings():
    inv = investigate_permissions(
        package_name="com.a.b", declared=[READ_SMS, CAMERA, ACCESSIBILITY],
        granted=[READ_SMS],
    )
    assert inv.unexpected() == []


# ── incremental recording ────────────────────────────────────────────────────

def test_the_three_facts_accumulate_independently():
    inv = PermissionInvestigator("com.example.calculator", "Calculator")
    inv.record_declared([CAMERA])
    assert inv.records()[0].requested_at_runtime is False

    inv.record_runtime_request(CAMERA, evidence_id="EVID-004", screenshot_id="SCR-002")
    inv.record_granted(CAMERA, True, evidence_id="EVID-005")
    inv.classify_all()

    rec = inv.records()[0]
    assert (rec.declared, rec.requested_at_runtime, rec.granted) == (True, True, True)
    assert rec.evidence_ids == ["EVID-004", "EVID-005"]
    assert rec.screenshot_ids == ["SCR-002"]


def test_a_failed_grant_is_recorded_rather_than_ignored():
    """The case the action verifier exists to catch must be representable."""
    inv = PermissionInvestigator("com.example.calculator", "Calculator")
    inv.record_declared([CAMERA])
    inv.record_granted(CAMERA, granted=False)
    inv.classify_all()
    assert inv.records()[0].granted is False


def test_declared_is_idempotent():
    inv = PermissionInvestigator("com.x")
    assert inv.record_declared([CAMERA, CAMERA]) == 1
    assert inv.record_declared([CAMERA]) == 0
    assert len(inv.records()) == 1


def test_linking_evidence_to_an_unknown_permission_returns_none():
    inv = PermissionInvestigator("com.x")
    assert inv.link_evidence(CAMERA, evidence_id="EVID-1") is None


def test_evidence_links_are_deduped():
    inv = PermissionInvestigator("com.x")
    inv.record_declared([CAMERA])
    inv.link_evidence(CAMERA, evidence_id="EVID-1")
    inv.link_evidence(CAMERA, evidence_id="EVID-1")
    assert inv.records()[0].evidence_ids == ["EVID-1"]


# ── special permissions ──────────────────────────────────────────────────────

def test_special_permissions_are_separated_from_dialog_permissions():
    inv = investigate_permissions(
        package_name="com.example.calculator", app_label="Calculator",
        declared=[CAMERA, ACCESSIBILITY, OVERLAY],
    )
    names = {r.permission for r in inv.special_permissions()}
    assert names == {ACCESSIBILITY, OVERLAY}


def test_each_special_permission_has_a_deterministic_settings_route():
    """Navigation to a Settings toggle must not be a Gemini guess."""
    inv = PermissionInvestigator("com.x")
    assert inv.settings_action_for(ACCESSIBILITY) == "android.settings.ACCESSIBILITY_SETTINGS"
    assert "OVERLAY" in inv.settings_action_for(OVERLAY).upper()


def test_a_dialog_permission_has_no_settings_route():
    assert PermissionInvestigator("com.x").settings_action_for(CAMERA) == ""


# ── ordering and summary ─────────────────────────────────────────────────────

def test_records_are_ordered_most_severe_first():
    inv = _calculator(
        declared=[INTERNET, CAMERA, READ_SMS], granted=[INTERNET, CAMERA, READ_SMS]
    )
    severities = [r.severity for r in inv.records()]
    assert severities == sorted(
        severities, key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(s)
    )
    assert inv.records()[0].permission == READ_SMS


def test_summary_counts_each_fact_separately():
    inv = _calculator(declared=[CAMERA, READ_SMS], granted=[CAMERA], requested=[CAMERA])
    summary = inv.summary()
    assert summary["declared"] == 2
    assert summary["requested_at_runtime"] == 1
    assert summary["granted"] == 1
    assert summary["unexpected"] == 2
    assert summary["profile"]["category"] == "CALCULATOR"


def test_summary_is_json_serialisable():
    import json
    inv = _calculator(declared=[CAMERA], granted=[CAMERA])
    json.dumps(inv.summary())


def test_no_classification_is_a_malware_verdict():
    """
    The strongest thing this module may say is REQUIRES_REVIEW. Anything
    stronger belongs to the risk engine.
    """
    values = {c.value for c in Classification}
    for word in ("MALICIOUS", "MALWARE", "TROJAN", "CONFIRMED"):
        assert not any(word in v for v in values)
