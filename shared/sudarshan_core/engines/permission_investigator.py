"""
Permissions as an investigation, not a list.

The engine already reports what an APK declares. That is one of four facts an
analyst needs, and on its own it is the least interesting:

    DECLARED    the manifest asks for it
    REQUESTED   Android actually put a dialog in front of the user at runtime
    GRANTED     the permission is really held, confirmed by querying the device
    EXPECTED    an app of this apparent kind would plausibly need it

The gaps between them are where the findings live. A permission declared but
never requested is dormant capability. One granted without ever being requested
is what our own pre-granting does. One requested and granted that the app has no
business needing is the calculator-asking-for-SMS case.

This module owns those four facts per permission and the classification that
falls out of comparing them. It does not decide whether the app is malware -
`classification` tops out at REQUIRES_REVIEW, and the verdict stays in
risk_engine.

Relationship to `permission_orchestrator`: that module *performs* grants over
ADB. This one *reasons* about them. They are deliberately separate - the
orchestrator currently grants blindly and records nothing, and mixing the
decision into the mechanism is why that went unnoticed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sudarshan_core.engines.capability_profile import (
    CapabilityProfile,
    Expectation,
    build_profile,
    group_of,
    is_special,
)

logger = logging.getLogger(__name__)


class PermissionClass(str, Enum):
    """How Android itself gates the permission."""

    NORMAL = "normal"          # granted at install, no dialog
    DANGEROUS = "dangerous"    # runtime dialog
    SPECIAL = "special"        # Settings toggle, no dialog
    UNKNOWN = "unknown"


class Classification(str, Enum):
    """
    The investigative reading of one permission.

    None of these is a malware verdict. The strongest, REQUIRES_REVIEW, means
    "an analyst should look at this", which is the most a permission on its own
    can ever justify.
    """

    EXPECTED = "EXPECTED"
    UNEXPECTED_PERMISSION = "UNEXPECTED_PERMISSION"
    DORMANT_CAPABILITY = "DORMANT_CAPABILITY"
    GRANTED_WITHOUT_REQUEST = "GRANTED_WITHOUT_REQUEST"
    UNDECLARED_REQUEST = "UNDECLARED_REQUEST"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


#: Runtime-dialog permissions. Anything in a group Android gates at runtime.
_DANGEROUS_GROUPS = frozenset({
    "SMS", "CALL", "CONTACTS", "CAMERA", "MICROPHONE",
    "LOCATION", "STORAGE", "CALENDAR",
})

#: Special permissions and the Settings action that reaches them. Used by the
#: special-permission flow so navigation is deterministic rather than a Gemini
#: guess at where a toggle lives.
SPECIAL_PERMISSION_FLOWS: Dict[str, str] = {
    "ACCESSIBILITY": "android.settings.ACCESSIBILITY_SETTINGS",
    "OVERLAY": "android.settings.action.MANAGE_OVERLAY_PERMISSION",
    "DEVICE_ADMIN": "android.app.action.ADD_DEVICE_ADMIN",
    "NOTIFICATION_ACCESS": "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS",
    "VPN": "android.net.vpn.SETTINGS",
    "PACKAGE_CONTROL": "android.settings.MANAGE_UNKNOWN_APP_SOURCES",
}

#: Severity for an unexpected permission, by group. A calculator holding SMS or
#: Accessibility is a different order of concern from one holding STORAGE.
_UNEXPECTED_SEVERITY: Dict[str, str] = {
    "ACCESSIBILITY": "CRITICAL",
    "SMS": "CRITICAL",
    "DEVICE_ADMIN": "HIGH",
    "OVERLAY": "HIGH",
    "NOTIFICATION_ACCESS": "HIGH",
    "PACKAGE_CONTROL": "HIGH",
    "VPN": "HIGH",
    "CALL": "HIGH",
    "MICROPHONE": "HIGH",
    "CAMERA": "MEDIUM",
    "CONTACTS": "MEDIUM",
    "LOCATION": "MEDIUM",
    "CALENDAR": "LOW",
    "STORAGE": "LOW",
}


def permission_class(permission: str) -> PermissionClass:
    """Which Android gating mechanism applies to this permission."""
    group = group_of(permission)
    if not group:
        return PermissionClass.UNKNOWN
    if is_special(permission):
        return PermissionClass.SPECIAL
    if group in _DANGEROUS_GROUPS:
        return PermissionClass.DANGEROUS
    return PermissionClass.NORMAL


@dataclass
class PermissionRecord:
    """The four facts about one permission, plus what they add up to."""

    permission: str
    declared: bool = False
    requested_at_runtime: bool = False
    granted: bool = False
    permission_class: str = PermissionClass.UNKNOWN.value
    expected_for_app: bool = True
    expectation: str = Expectation.PLAUSIBLE.value
    classification: str = Classification.EXPECTED.value
    severity: str = "INFO"
    group: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    screenshot_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permission": self.permission,
            "declared": self.declared,
            "requested_at_runtime": self.requested_at_runtime,
            "granted": self.granted,
            "permission_class": self.permission_class,
            "expected_for_app": self.expected_for_app,
            "expectation": self.expectation,
            "classification": self.classification,
            "severity": self.severity,
            "group": self.group,
            "evidence_ids": list(self.evidence_ids),
            "screenshot_ids": list(self.screenshot_ids),
        }


def classify_record(record: PermissionRecord) -> PermissionRecord:
    """
    Fill in ``classification`` and ``severity`` from the four facts.

    Ordering matters. An unexpected permission that was actually exercised is
    reported as UNEXPECTED_PERMISSION even though it is also, say, dormant -
    the more actionable reading wins, so an analyst is not told "dormant" about
    the one permission that fired.
    """
    unexpected = not record.expected_for_app

    if unexpected and record.granted:
        record.classification = Classification.UNEXPECTED_PERMISSION.value
        record.severity = _UNEXPECTED_SEVERITY.get(record.group, "MEDIUM")
        return record

    if unexpected:
        # Declared but never granted: still worth reporting, one step down -
        # capability the app asked for and did not get in this run.
        record.classification = Classification.UNEXPECTED_PERMISSION.value
        base = _UNEXPECTED_SEVERITY.get(record.group, "MEDIUM")
        record.severity = {"CRITICAL": "HIGH", "HIGH": "MEDIUM"}.get(base, "LOW")
        return record

    if record.requested_at_runtime and not record.declared:
        # Android cannot grant this, so it signals a manifest we misparsed or a
        # dynamically-loaded component asking on its own behalf.
        record.classification = Classification.UNDECLARED_REQUEST.value
        record.severity = "MEDIUM"
        return record

    if record.granted and not record.requested_at_runtime:
        # Expected for this app, so not a finding about the sample. It is
        # usually a finding about US: pre-granting suppresses the dialog.
        record.classification = Classification.GRANTED_WITHOUT_REQUEST.value
        record.severity = "INFO"
        return record

    if record.declared and not record.granted and not record.requested_at_runtime:
        record.classification = Classification.DORMANT_CAPABILITY.value
        record.severity = "INFO"
        return record

    record.classification = Classification.EXPECTED.value
    record.severity = "INFO"
    return record


class PermissionInvestigator:
    """
    Tracks declared / requested / granted per permission for one investigation.

    Deliberately holds no device handle. Callers feed it observations - the
    manifest list, a runtime dialog the perception layer classified, the result
    of a `pm list permissions` query - and it answers what those add up to.
    That keeps it fully unit-testable with no emulator, which is the difference
    between this logic being verified and being hoped about.
    """

    def __init__(
        self,
        package_name: str = "",
        app_label: str = "",
        profile: Optional[CapabilityProfile] = None,
    ) -> None:
        self.package_name = package_name
        self._records: Dict[str, PermissionRecord] = {}
        self.profile = profile or build_profile(package_name, app_label)

    # ── ingest ───────────────────────────────────────────────────────────────

    def _record_for(self, permission: str) -> PermissionRecord:
        name = (permission or "").strip()
        if name not in self._records:
            self._records[name] = PermissionRecord(
                permission=name,
                permission_class=permission_class(name).value,
                group=group_of(name),
            )
        return self._records[name]

    def record_declared(self, permissions: Iterable[str]) -> int:
        """Take the manifest's permission list. Returns how many were new."""
        added = 0
        for perm in permissions or []:
            record = self._record_for(perm)
            if not record.declared:
                added += 1
            record.declared = True
        return added

    def record_runtime_request(
        self,
        permission: str,
        evidence_id: str = "",
        screenshot_id: str = "",
    ) -> PermissionRecord:
        """Android put a permission dialog in front of the user."""
        record = self._record_for(permission)
        record.requested_at_runtime = True
        self._link(record, evidence_id, screenshot_id)
        return record

    def record_granted(
        self,
        permission: str,
        granted: bool = True,
        evidence_id: str = "",
        screenshot_id: str = "",
    ) -> PermissionRecord:
        """
        The verified permission state, from querying the device.

        ``granted=False`` is meaningful and is recorded rather than ignored: a
        grant we attempted and did not get is exactly the case the action
        verifier exists to catch.
        """
        record = self._record_for(permission)
        record.granted = bool(granted)
        self._link(record, evidence_id, screenshot_id)
        return record

    @staticmethod
    def _link(record: PermissionRecord, evidence_id: str, screenshot_id: str) -> None:
        if evidence_id and evidence_id not in record.evidence_ids:
            record.evidence_ids.append(evidence_id)
        if screenshot_id and screenshot_id not in record.screenshot_ids:
            record.screenshot_ids.append(screenshot_id)

    def link_evidence(
        self, permission: str, evidence_id: str = "", screenshot_id: str = ""
    ) -> Optional[PermissionRecord]:
        """Attach evidence to an already-known permission; None if unknown."""
        name = (permission or "").strip()
        if name not in self._records:
            return None
        record = self._records[name]
        self._link(record, evidence_id, screenshot_id)
        return record

    # ── read ─────────────────────────────────────────────────────────────────

    def classify_all(self) -> List[PermissionRecord]:
        """Apply the capability profile and classification to every record."""
        for record in self._records.values():
            expectation = self.profile.expectation(record.permission)
            record.expectation = expectation.value
            record.expected_for_app = expectation is not Expectation.UNEXPECTED
            classify_record(record)
        return self.records()

    def records(self) -> List[PermissionRecord]:
        """Every record, ordered by severity then name so output is stable."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(
            self._records.values(),
            key=lambda r: (order.get(r.severity, 5), r.permission),
        )

    def unexpected(self) -> List[PermissionRecord]:
        return [r for r in self.records() if not r.expected_for_app]

    def special_permissions(self) -> List[PermissionRecord]:
        """Declared permissions that need a Settings workflow to investigate."""
        return [
            r for r in self.records()
            if r.permission_class == PermissionClass.SPECIAL.value
        ]

    def settings_action_for(self, permission: str) -> str:
        """The Settings intent that reaches this permission's toggle, or ""."""
        return SPECIAL_PERMISSION_FLOWS.get(group_of(permission), "")

    def summary(self) -> Dict[str, Any]:
        records = self.classify_all()
        return {
            "package_name": self.package_name,
            "profile": self.profile.to_dict(),
            "total": len(records),
            "declared": sum(1 for r in records if r.declared),
            "requested_at_runtime": sum(1 for r in records if r.requested_at_runtime),
            "granted": sum(1 for r in records if r.granted),
            "unexpected": sum(1 for r in records if not r.expected_for_app),
            "special": len(self.special_permissions()),
            "records": [r.to_dict() for r in records],
        }


def investigate_permissions(
    package_name: str = "",
    app_label: str = "",
    declared: Optional[Sequence[str]] = None,
    granted: Optional[Sequence[str]] = None,
    requested: Optional[Sequence[str]] = None,
) -> PermissionInvestigator:
    """Convenience constructor for the common one-shot case."""
    investigator = PermissionInvestigator(package_name, app_label)
    investigator.record_declared(declared or [])
    for perm in requested or []:
        investigator.record_runtime_request(perm)
    for perm in granted or []:
        investigator.record_granted(perm)
    investigator.classify_all()
    return investigator
