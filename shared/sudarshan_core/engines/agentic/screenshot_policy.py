"""
SUDARSHAN - Central Screenshot Policy
=====================================
State/event-aware screenshot decision engine.

Separates screenshot deduplication from event deduplication and evidence
deduplication.  Every capture request is evaluated before adb screencap runs.

Philosophy:
    MANY runtime events  →  FEW meaningful screenshots
    NOT EVERY POLL IS AN EVENT
    NOT EVERY EVENT NEEDS A SCREENSHOT
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─── Decision outcomes ─────────────────────────────────────────────────────────

class ScreenshotDecision(str, Enum):
    CAPTURE = "CAPTURE"
    DEDUPLICATED = "DEDUPLICATED"
    SUPPRESSED = "SUPPRESSED"
    BLOCKED = "BLOCKED"
    REUSE = "REUSE"


class ScreenshotTriggerPriority(str, Enum):
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"


class ScreenOwnership(str, Enum):
    """Who owns the foreground screen relative to the target APK."""
    TARGET_APP = "TARGET_APP"
    SYSTEM_PERMISSION = "SYSTEM_PERMISSION"
    SYSTEM_INSTALLER = "SYSTEM_INSTALLER"
    SYSTEM_SETTINGS = "SYSTEM_SETTINGS"
    EXTERNAL_APP = "EXTERNAL_APP"
    WEBVIEW = "WEBVIEW"
    HOME_LAUNCHER = "HOME_LAUNCHER"
    CRASH_STATE = "CRASH_STATE"
    APP_NOT_RESPONDING = "APP_NOT_RESPONDING"
    TRANSITION = "TRANSITION"
    UNKNOWN = "UNKNOWN"


# ─── Known launcher / system packages ─────────────────────────────────────────

LAUNCHER_PACKAGES: frozenset[str] = frozenset({
    "com.android.launcher",
    "com.android.launcher3",
    "com.google.android.apps.nexuslauncher",
    "com.miui.home",
    "com.sec.android.app.launcher",
    "com.huawei.android.launcher",
    "com.oppo.launcher",
    "com.oneplus.launcher",
    "com.tcl.android.launcher",
    "com.android.launcher2",
    "com.google.android.launcher",
    "com.samsung.android.app.launcher",
})

INSTALLER_PACKAGES: frozenset[str] = frozenset({
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
})

SETTINGS_PACKAGES: frozenset[str] = frozenset({
    "com.android.settings",
})

SYSTEM_UI_PACKAGES: frozenset[str] = frozenset({
    "com.android.systemui",
})

CRASH_ACTIVITY_MARKERS: tuple[str, ...] = (
    "has stopped",
    "android.process.acore",
    "com.android.systemui.anr",
    "crashactivity",
    "anractivity",
    "erroractivity",
)

# Trigger → priority mapping
_TRIGGER_PRIORITY: Dict[str, ScreenshotTriggerPriority] = {
    "PERMISSION_DIALOG": ScreenshotTriggerPriority.HIGH,
    "ACCESSIBILITY": ScreenshotTriggerPriority.HIGH,
    "OVERLAY": ScreenshotTriggerPriority.HIGH,
    "EXTERNAL_APK": ScreenshotTriggerPriority.HIGH,
    "PACKAGE_INSTALLER": ScreenshotTriggerPriority.HIGH,
    "VPN_REQUEST": ScreenshotTriggerPriority.HIGH,
    "UPDATE_PROMPT": ScreenshotTriggerPriority.HIGH,
    "DOWNLOAD_PROMPT": ScreenshotTriggerPriority.HIGH,
    "APP_CRASH": ScreenshotTriggerPriority.HIGH,
    "AUTO_CRITICAL": ScreenshotTriggerPriority.HIGH,
    "HOOK_TRIGGER": ScreenshotTriggerPriority.HIGH,
    "EVIDENCE_MOMENT": ScreenshotTriggerPriority.HIGH,
    "SUSPICIOUS_UI": ScreenshotTriggerPriority.NORMAL,
    "EXPLORER_ACTION": ScreenshotTriggerPriority.NORMAL,
    "APP_LAUNCH": ScreenshotTriggerPriority.NORMAL,
    "LIFECYCLE": ScreenshotTriggerPriority.NORMAL,
    "FINAL_STATE": ScreenshotTriggerPriority.LOW,
    "OTHER": ScreenshotTriggerPriority.LOW,
}


def resolve_screen_ownership(
    foreground_package: str,
    target_package: str,
    activity: str = "",
    semantic_type: str = "",
) -> ScreenOwnership:
    """
    Determine screen ownership using package/activity context.

    Package information takes priority over UI appearance classification.
    """
    fg = (foreground_package or "").strip()
    target = (target_package or "").strip()
    act_lower = (activity or "").lower()

  # Crash / ANR signals
    if any(m in act_lower for m in CRASH_ACTIVITY_MARKERS):
        if "anr" in act_lower:
            return ScreenOwnership.APP_NOT_RESPONDING
        return ScreenOwnership.CRASH_STATE

    if not fg:
        return ScreenOwnership.UNKNOWN

    # Home / launcher
    if fg in LAUNCHER_PACKAGES or "launcher" in act_lower:
        if target and fg != target:
            return ScreenOwnership.HOME_LAUNCHER
        # Target app IS the launcher (launcher-replacement malware)
        return ScreenOwnership.TARGET_APP

    if target and fg == target:
        if semantic_type == "WEBVIEW":
            return ScreenOwnership.WEBVIEW
        return ScreenOwnership.TARGET_APP

    if fg in INSTALLER_PACKAGES:
        if semantic_type in ("EXTERNAL_APK", "PACKAGE_INSTALLER"):
            return ScreenOwnership.SYSTEM_INSTALLER
        if semantic_type == "SYSTEM_PERMISSION":
            return ScreenOwnership.SYSTEM_PERMISSION
        return ScreenOwnership.SYSTEM_INSTALLER

    if fg in SETTINGS_PACKAGES:
        if semantic_type in ("ACCESSIBILITY_DIALOG", "SETTINGS"):
            return ScreenOwnership.SYSTEM_SETTINGS
        return ScreenOwnership.SYSTEM_SETTINGS

    if fg in SYSTEM_UI_PACKAGES:
        if semantic_type == "SYSTEM_PERMISSION":
            return ScreenOwnership.SYSTEM_PERMISSION
        return ScreenOwnership.EXTERNAL_APP

    # Any other foreground package is external relative to target
    if target and fg != target:
        return ScreenOwnership.EXTERNAL_APP

    return ScreenOwnership.UNKNOWN


def trigger_priority(reason: str) -> ScreenshotTriggerPriority:
    return _TRIGGER_PRIORITY.get(reason or "", ScreenshotTriggerPriority.LOW)


@dataclass
class ScreenshotRequest:
    """Context for a screenshot decision."""
    trigger_type: str = ""
    reason: str = ""
    foreground_package: str = ""
    target_package: str = ""
    activity: str = ""
    state_id: str = ""
    action_id: str = ""
    evidence_moment_id: str = ""
    screen_hash: str = ""
    layout_hash: str = ""
    semantic_type: str = ""
    ownership: ScreenOwnership = ScreenOwnership.UNKNOWN
    force: bool = False
    label: str = ""
    transition_event: str = ""


@dataclass
class ScreenshotDecisionRecord:
    """Auditable record of every screenshot decision."""
    timestamp_ms: int
    decision: ScreenshotDecision
    reason: str
    trigger_type: str = ""
    ownership: str = ""
    foreground_package: str = ""
    state_id: str = ""
    screen_hash: str = ""
    reused_screenshot_id: str = ""
    observation_count: int = 1


@dataclass
class ScreenshotPolicyState:
    """Tracks deduplication state across an analysis session."""
    # Per ownership+hash: screenshot_id that was captured
    _captured_by_key: Dict[str, str] = field(default_factory=dict)
    # Per ownership: count of observations (for suppression stats)
    _observation_counts: Dict[str, int] = field(default_factory=dict)
    # Per ownership: count of captures
    _capture_counts: Dict[str, int] = field(default_factory=dict)
    # Per ownership: count of suppressions
    _suppression_counts: Dict[str, int] = field(default_factory=dict)
    # Transition events already recorded (one screenshot per transition)
    _recorded_transitions: Set[str] = field(default_factory=set)
    # Crash contexts already screenshotted
    _crash_screenshotted: Set[str] = field(default_factory=set)
    # Permission dialogs already screenshotted
    _permission_screenshotted: Set[str] = field(default_factory=set)
    # Decision audit log
    decisions: List[ScreenshotDecisionRecord] = field(default_factory=list)
    total_requests: int = 0

    def _dedup_key(
        self, ownership: ScreenOwnership, screen_hash: str, layout_hash: str = "",
    ) -> str:
        lh = layout_hash or screen_hash or "none"
        return f"{ownership.value}:{lh}"

    def record_observation(self, ownership: ScreenOwnership) -> int:
        key = ownership.value
        self._observation_counts[key] = self._observation_counts.get(key, 0) + 1
        return self._observation_counts[key]


class ScreenshotPolicy:
    """
    Central screenshot decision function.

    Usage::

        policy = ScreenshotPolicy(target_package="com.evil.app")
        req = ScreenshotRequest(...)
        decision, reason, reuse_id = policy.should_capture(req)
    """

    def __init__(self, target_package: str = "") -> None:
        self.target_package = target_package
        self.state = ScreenshotPolicyState()

    def should_capture(
        self, request: ScreenshotRequest,
    ) -> Tuple[ScreenshotDecision, str, Optional[str]]:
        """
        Evaluate whether a screenshot should be taken.

        Returns:
            (decision, reason_string, reused_screenshot_id_or_None)
        """
        self.state.total_requests += 1
        now_ms = int(time.time() * 1000)

        ownership = request.ownership
        if ownership == ScreenOwnership.UNKNOWN:
            ownership = resolve_screen_ownership(
                request.foreground_package,
                request.target_package or self.target_package,
                request.activity,
                request.semantic_type,
            )
            request.ownership = ownership

        obs_count = self.state.record_observation(ownership)
        priority = trigger_priority(request.reason)

        # ── Force override (lifecycle, explicit analyst request) ──────────
        if request.force and priority != ScreenshotTriggerPriority.LOW:
            decision = ScreenshotDecision.CAPTURE
            reason = "FORCE_REQUEST"
            self._record_decision(now_ms, decision, reason, request, ownership)
            return decision, reason, None

        # ── HOME_LAUNCHER policy ──────────────────────────────────────────
        if ownership == ScreenOwnership.HOME_LAUNCHER:
            return self._home_policy(request, ownership, now_ms, obs_count)

        # ── CRASH / ANR policy ────────────────────────────────────────────
        if ownership in (ScreenOwnership.CRASH_STATE, ScreenOwnership.APP_NOT_RESPONDING):
            return self._crash_policy(request, ownership, now_ms)

        # ── EXTERNAL / SYSTEM boundary policy ─────────────────────────────
        if ownership in (
            ScreenOwnership.EXTERNAL_APP,
            ScreenOwnership.SYSTEM_INSTALLER,
            ScreenOwnership.SYSTEM_SETTINGS,
        ):
            return self._external_policy(request, ownership, now_ms, obs_count)

        # ── PERMISSION dialog policy ──────────────────────────────────────
        if ownership == ScreenOwnership.SYSTEM_PERMISSION:
            return self._permission_policy(request, ownership, now_ms)

        # ── Standard state-aware deduplication ────────────────────────────
        dedup_key = self.state._dedup_key(
            ownership, request.screen_hash, request.layout_hash,
        )
        existing_id = self.state._captured_by_key.get(dedup_key)

        if existing_id and priority != ScreenshotTriggerPriority.HIGH:
            decision = ScreenshotDecision.REUSE
            reason = f"IDENTICAL_STATE:{ownership.value}"
            self._record_suppression(ownership)
            self._record_decision(
                now_ms, decision, reason, request, ownership, existing_id,
            )
            return decision, reason, existing_id

        if existing_id and priority == ScreenshotTriggerPriority.HIGH:
            # High-priority on same screen: still capture if new evidence moment
            if request.evidence_moment_id:
                decision = ScreenshotDecision.CAPTURE
                reason = "HIGH_PRIORITY_NEW_EVIDENCE"
                self._record_decision(now_ms, decision, reason, request, ownership)
                return decision, reason, None

        # ── LOW priority suppression ──────────────────────────────────────
        if priority == ScreenshotTriggerPriority.LOW and existing_id:
            decision = ScreenshotDecision.SUPPRESSED
            reason = "LOW_PRIORITY_IDENTICAL_STATE"
            self._record_suppression(ownership)
            self._record_decision(now_ms, decision, reason, request, ownership)
            return decision, reason, existing_id

        # ── Capture ───────────────────────────────────────────────────────
        decision = ScreenshotDecision.CAPTURE
        reason = "NEW_STATE_OR_HIGH_PRIORITY"
        self._record_decision(now_ms, decision, reason, request, ownership)
        return decision, reason, None

    def register_capture(
        self,
        screenshot_id: str,
        ownership: ScreenOwnership,
        screen_hash: str,
        layout_hash: str = "",
    ) -> None:
        """Record that a screenshot was successfully captured."""
        key = self.state._dedup_key(ownership, screen_hash, layout_hash)
        self.state._captured_by_key[key] = screenshot_id
        ow_key = ownership.value
        self.state._capture_counts[ow_key] = (
            self.state._capture_counts.get(ow_key, 0) + 1
        )

    def _home_policy(
        self,
        request: ScreenshotRequest,
        ownership: ScreenOwnership,
        now_ms: int,
        obs_count: int,
    ) -> Tuple[ScreenshotDecision, str, Optional[str]]:
        transition = request.transition_event or "TARGET_APP_EXITED_TO_HOME"
        transition_key = f"home:{transition}:{request.screen_hash}"

        if transition_key in self.state._recorded_transitions:
            decision = ScreenshotDecision.SUPPRESSED
            reason = "IDENTICAL_HOME_STATE"
            self._record_suppression(ownership)
            self._record_decision(now_ms, decision, reason, request, ownership)
            dedup_key = self.state._dedup_key(ownership, request.screen_hash)
            return decision, reason, self.state._captured_by_key.get(dedup_key)

        # First meaningful transition to home: one screenshot if high-priority
        priority = trigger_priority(request.reason)
        if priority == ScreenshotTriggerPriority.HIGH or request.transition_event:
            self.state._recorded_transitions.add(transition_key)
            decision = ScreenshotDecision.CAPTURE
            reason = f"HOME_TRANSITION:{transition}"
            self._record_decision(now_ms, decision, reason, request, ownership)
            return decision, reason, None

        # Repeated home observation without transition event
        decision = ScreenshotDecision.SUPPRESSED
        reason = "HOME_NO_NEW_TRANSITION"
        self._record_suppression(ownership)
        self._record_decision(now_ms, decision, reason, request, ownership)
        return decision, reason, None

    def _crash_policy(
        self,
        request: ScreenshotRequest,
        ownership: ScreenOwnership,
        now_ms: int,
    ) -> Tuple[ScreenshotDecision, str, Optional[str]]:
        crash_key = f"{request.state_id}:{request.action_id}:{request.activity}"
        if crash_key in self.state._crash_screenshotted:
            decision = ScreenshotDecision.SUPPRESSED
            reason = "CRASH_ALREADY_CAPTURED"
            self._record_suppression(ownership)
            self._record_decision(now_ms, decision, reason, request, ownership)
            return decision, reason, None

        self.state._crash_screenshotted.add(crash_key)
        decision = ScreenshotDecision.CAPTURE
        reason = "CRASH_CONTEXT"
        self._record_decision(now_ms, decision, reason, request, ownership)
        return decision, reason, None

    def _external_policy(
        self,
        request: ScreenshotRequest,
        ownership: ScreenOwnership,
        now_ms: int,
        obs_count: int,
    ) -> Tuple[ScreenshotDecision, str, Optional[str]]:
        transition = request.transition_event or ownership.value
        transition_key = f"ext:{ownership.value}:{request.foreground_package}:{request.screen_hash}"

        if transition_key in self.state._recorded_transitions:
            decision = ScreenshotDecision.SUPPRESSED
            reason = f"IDENTICAL_EXTERNAL_STATE:{ownership.value}"
            self._record_suppression(ownership)
            self._record_decision(now_ms, decision, reason, request, ownership)
            dedup_key = self.state._dedup_key(ownership, request.screen_hash)
            return decision, reason, self.state._captured_by_key.get(dedup_key)

        self.state._recorded_transitions.add(transition_key)
        decision = ScreenshotDecision.CAPTURE
        reason = f"EXTERNAL_BOUNDARY:{ownership.value}"
        self._record_decision(now_ms, decision, reason, request, ownership)
        return decision, reason, None

    def _permission_policy(
        self,
        request: ScreenshotRequest,
        ownership: ScreenOwnership,
        now_ms: int,
    ) -> Tuple[ScreenshotDecision, str, Optional[str]]:
        perm_key = f"perm:{request.screen_hash}:{request.semantic_type}"
        if perm_key in self.state._permission_screenshotted:
            decision = ScreenshotDecision.SUPPRESSED
            reason = "PERMISSION_DIALOG_ALREADY_CAPTURED"
            self._record_suppression(ownership)
            self._record_decision(now_ms, decision, reason, request, ownership)
            dedup_key = self.state._dedup_key(ownership, request.screen_hash)
            return decision, reason, self.state._captured_by_key.get(dedup_key)

        self.state._permission_screenshotted.add(perm_key)
        decision = ScreenshotDecision.CAPTURE
        reason = "PERMISSION_DIALOG"
        self._record_decision(now_ms, decision, reason, request, ownership)
        return decision, reason, None

    def _record_decision(
        self,
        now_ms: int,
        decision: ScreenshotDecision,
        reason: str,
        request: ScreenshotRequest,
        ownership: ScreenOwnership,
        reuse_id: str = "",
    ) -> None:
        self.state.decisions.append(ScreenshotDecisionRecord(
            timestamp_ms=now_ms,
            decision=decision,
            reason=reason,
            trigger_type=request.trigger_type or request.reason,
            ownership=ownership.value,
            foreground_package=request.foreground_package,
            state_id=request.state_id,
            screen_hash=request.screen_hash,
            reused_screenshot_id=reuse_id,
        ))

    def _record_suppression(self, ownership: ScreenOwnership) -> None:
        key = ownership.value
        self.state._suppression_counts[key] = (
            self.state._suppression_counts.get(key, 0) + 1
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Return suppression statistics for reports and dashboard."""
        captured = sum(1 for d in self.state.decisions
                       if d.decision == ScreenshotDecision.CAPTURE)
        deduplicated = sum(1 for d in self.state.decisions
                           if d.decision == ScreenshotDecision.DEDUPLICATED)
        suppressed = sum(1 for d in self.state.decisions
                         if d.decision == ScreenshotDecision.SUPPRESSED)
        reused = sum(1 for d in self.state.decisions
                     if d.decision == ScreenshotDecision.REUSE)
        blocked = sum(1 for d in self.state.decisions
                      if d.decision == ScreenshotDecision.BLOCKED)

        most_suppressed = ""
        max_sup = 0
        for key, count in self.state._suppression_counts.items():
            if count > max_sup:
                max_sup = count
                most_suppressed = key

        return {
            "total_requests": self.state.total_requests,
            "captured": captured,
            "deduplicated": deduplicated,
            "suppressed": suppressed,
            "reused": reused,
            "blocked": blocked,
            "observation_counts": dict(self.state._observation_counts),
            "capture_counts": dict(self.state._capture_counts),
            "suppression_counts": dict(self.state._suppression_counts),
            "most_suppressed_state": most_suppressed,
            "most_suppressed_count": max_sup,
        }

    def build_semantic_filename(
        self,
        index: int,
        reason: str,
        ownership: ScreenOwnership,
        label: str = "",
    ) -> str:
        """Build a semantic screenshot filename."""
        idx = f"{index:04d}"
        reason_slug = (reason or "screen").lower().replace("_", "_")[:30]
        ownership_slug = ownership.value.lower().replace("_", "_")[:20]
        label_slug = (label or "").replace(" ", "_").replace("/", "_")[:25]
        parts = [idx]
        if ownership_slug and ownership != ScreenOwnership.TARGET_APP:
            parts.append(ownership_slug)
        if label_slug:
            parts.append(label_slug)
        elif reason_slug:
            parts.append(reason_slug)
        return "_".join(parts)
