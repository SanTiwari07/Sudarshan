"""
SUDARSHAN - Agentic Goal Tracker
==================================
Implements the 15-stage fraud goal dependency graph defined in the Agentic
Explorer specification.

Design rules:
  - Goals are NOT independent: later stages depend on earlier ones completing.
  - The planner uses `next_priority_goal()` to always drive toward the most
    important incomplete goal.
  - Goals can be SKIPPED when Frida evidence proves they are not applicable
    (e.g., no SMS hooks fired after Stage 3 - accessibility - is complete).
  - Goal status is updated ONLY from observed device state - Frida events
    (`update_from_frida_events`) or the foreground window
    (`update_from_foreground`). The LLM cannot mark a goal complete; it can
    only choose actions and wait for the device to report the result.
  - This module NEVER makes malware verdicts - it only tracks exploration progress.

Usage::

    tracker = GoalTracker()
    tracker.update_from_frida_events(events)
    goal = tracker.next_priority_goal()
    if goal:
        print(goal.name, goal.description)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from sudarshan_core.engines.behavior_taxonomy import (
    Behavior,
    BehaviorObservation,
    BehaviorWeight,
    EvidenceStrength,
    classify_events,
    evaluate_behaviour_evidence,
)
from sudarshan_core.engines.dynamic_budget import TIMEOUT_REASON
from sudarshan_core.engines.runtime_event import (
    NormalizedEvent,
    normalize_collected_events,
    normalize_events,
)

logger = logging.getLogger(__name__)

# ─── Tunables ─────────────────────────────────────────────────────────────────

# Stage 1 is confirmed by observing the target package in the foreground for
# this many CONSECUTIVE observations. >1 rejects transient samples such as a
# splash screen or a launcher hand-off frame.
LAUNCH_CONFIRMATIONS_REQUIRED: int = 2

# How many times a FAILED goal may be retried before it is given up on.
MAX_GOAL_RETRIES: int = 1

# Actions a goal must have received ITSELF before it may be auto-skipped.
#
# The caller passes a GLOBAL Frida-silence streak, which keeps climbing while
# the app is quiet. Once it passes the threshold, every goal selected after
# that point would otherwise be skipped on its first pass without ever being
# genuinely tried - trading the old "never skipped" deadlock for a new "skipped
# on sight" one. A goal must have spent at least this many of its own actions
# before "we tried and nothing confirming happened" is a true statement.
MIN_ATTEMPTS_BEFORE_SKIP: int = 2

# Name of the stage-1 goal, referenced by the foreground completion path.
LAUNCH_GOAL_NAME: str = "Launch Application"


# ─── Goal Status ──────────────────────────────────────────────────────────────

class GoalStatus(str, Enum):
    """
    One goal's independent lifecycle state.

    Every goal owns its own state. There is deliberately NO global boolean
    derived from these - no ``dynamic_valid = all(goals_successful)`` - because
    a run in which nine goals produced evidence and six did not is a run with
    nine goals' worth of evidence in it. Coverage is computed from the
    distribution (see :meth:`GoalTracker.coverage_report`); VALIDITY is decided
    from observed evidence elsewhere and never from this enum.
    """

    PENDING     = "PENDING"       # Not yet started
    IN_PROGRESS = "IN_PROGRESS"   # Agent is actively working on this goal
    COMPLETED   = "COMPLETED"     # Evidence collected or goal satisfied
    #: The goal produced SOME evidence but was never confirmed - a login form
    #: filled but not submitted, an overlay permission screen answered with no
    #: overlay drawn afterwards. Distinct from FAILED, which produced nothing,
    #: and from COMPLETED, which produced confirmation. Counts half toward
    #: effective coverage; contributes only its ACTUAL evidence to scoring.
    PARTIAL     = "PARTIAL_SUCCESS"
    SKIPPED     = "SKIPPED"       # Evidence proves not applicable; skip safely
    FAILED      = "FAILED"        # Agent tried but could not trigger
    #: The run ended - budget, deadline or crash - before this goal was ever
    #: selected. Says nothing about the sample, and must never be reported as
    #: an absence of the behaviour. Assigned by :meth:`GoalTracker.finalize`.
    NOT_REACHED = "NOT_REACHED"
    #: This goal was being worked when the global wall-clock deadline arrived.
    #: Distinct from NOT_REACHED (never started) and from FAILED (tried and
    #: could not trigger): the attempt was cut off, not concluded.
    TIMEOUT     = "TIMEOUT"
    #: Something outside the sample stopped the investigation reaching this
    #: goal - an authentication wall with no obtainable account, a permission
    #: the sandbox will not grant, a device capability the emulator lacks, or
    #: the sample refusing to run. Deliberately NOT collapsed into NOT_REACHED:
    #: "we could not get there" and "we ran out of budget before trying" call
    #: for completely different remediation, and merging them was hiding the
    #: single most actionable fact a failed run produces.
    BLOCKED     = "BLOCKED"
    #: Static analysis proves this goal cannot apply to this sample - it
    #: declares no accessibility service, requests no SMS permission. Reporting
    #: such a goal as FAILED would penalise a sample for not doing something it
    #: was never built to do.
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"   # No instrument exists that could confirm this


#: Statuses that RESOLVE a goal for dependency purposes.
#:
#: FAILED is included, and that inclusion is the fix for a measured deadlock.
#: Previously only COMPLETED and SKIPPED counted, so a goal the agent genuinely
#: attempted and could not trigger held every dependent stage PENDING for the
#: rest of the run. Measured: one ordinary `dangerous_apis` event left stage 2
#: FAILED and 11 of 15 goals never attempted, while the tracker reported
#: "ALL GOALS COMPLETED OR SKIPPED".
#:
#: "Resolved" is deliberately NOT "satisfied". A dependent unblocked only
#: because its prerequisite failed records that fact in
#: ``ran_without_prerequisite`` so the report can say the chain was broken -
#: see :meth:`GoalTracker._unblock_reason`. Nothing here claims the
#: precondition held.
RESOLVED_STATES: frozenset = frozenset({
    GoalStatus.COMPLETED,
    GoalStatus.PARTIAL,
    GoalStatus.SKIPPED,
    GoalStatus.FAILED,
    GoalStatus.NOT_REACHED,
    GoalStatus.TIMEOUT,
    GoalStatus.BLOCKED,
    GoalStatus.NOT_APPLICABLE,
    GoalStatus.UNSUPPORTED,
})

#: Statuses that mean the goal was actually SATISFIED - the behaviour was
#: observed. Only COMPLETED. Used for coverage reporting, never for unblocking.
SATISFIED_STATES: frozenset = frozenset({GoalStatus.COMPLETED})

#: Statuses no further evidence may move a goal out of. PARTIAL is deliberately
#: NOT here: a goal that produced some evidence can still be confirmed by a
#: later hook, and demoting it to terminal would discard that upgrade.
TERMINAL_STATES: frozenset = frozenset({
    GoalStatus.COMPLETED,
    GoalStatus.SKIPPED,
    GoalStatus.NOT_APPLICABLE,
    GoalStatus.UNSUPPORTED,
})

#: Weight a PARTIAL_SUCCESS goal carries toward effective coverage.
#:
#: Half, and the number is a reporting convention rather than a measurement:
#: it exists so "9 confirmed + 2 partial of 15" reports as 66.7% instead of
#: either 60% (partial evidence discarded) or 73.3% (partial counted as
#: confirmed). It NEVER touches BFCI or FRS - scoring reads observed events,
#: not goal states. See §P13.
PARTIAL_GOAL_WEIGHT: float = 0.5


# ─── Confirmation modes ───────────────────────────────────────────────────────
#
# How a goal may be confirmed. Every goal MUST declare at least one, and
# tests/unit/test_goal_hook_contract.py fails the build if one does not: a goal
# with no confirmation route is unreachable by construction, which is the
# defect class this enum exists to make impossible.

class ConfirmationMode(str, Enum):
    #: Confirmed by a named Frida hook firing under an accepted category.
    FRIDA_HOOK = "FRIDA_HOOK"
    #: Confirmed by observed device state (foreground window, verified
    #: permission grant). Used where no hook CAN confirm the goal - stage 1
    #: precedes every hook, and a permission grant is a property of the
    #: package manager, not of a call the app makes.
    DEVICE_STATE = "DEVICE_STATE"
    #: Confirmed by a canonical BEHAVIOUR rather than by a named hook.
    #:
    #: The behaviour layer maps several hooks onto one meaning, so a goal in
    #: this mode survives the agent renaming a hook - which is the failure the
    #: hook-name contract exists to catch and which left four stages
    #: unreachable. A goal declaring this mode MUST declare
    #: `required_behaviors`; the contract test enforces that, so the mode
    #: cannot become a way to skip the guard.
    BEHAVIOR = "BEHAVIOR"
    #: The current Frida agent emits nothing that honestly demonstrates this
    #: goal. The goal resolves as UNSUPPORTED and says so, rather than sitting
    #: PENDING forever while the run reports itself finished.
    UNSUPPORTED = "UNSUPPORTED"


# ─── Goal Definition ──────────────────────────────────────────────────────────

@dataclass
class FraudGoal:
    """
    A single exploration goal in the 15-stage dependency graph.

    Attributes:
        name:               Short identifier (used in prompts and logs).
        stage:              Dependency order - lower stages must complete first.
        description:        What the agent should do to trigger this goal.
        frida_categories:   Frida event categories that signal this goal is ACTIVE.
                            Activity only - never completion. Every app emits
                            `network`, and most emit `dangerous_apis`.
        frida_hooks:        Hook names that CONFIRM completion. A hook only
                            confirms when it fires under one of
                            `completion_categories`; see `matches_completion`.
        completion_categories:
                            Categories under which `frida_hooks` count as
                            completion. Defaults to `frida_categories`.
                            Separate because the agent emits several hook names
                            under TWO categories - `SharedPreferences.getString`
                            goes to `banking` for a credential key and to
                            `app_telemetry` for a session key - and matching on
                            the name alone completed "Login Flow" on an
                            ordinary preferences read.
        depends_on:         Stage numbers that must be RESOLVED first
                            (see RESOLVED_STATES).
        skip_if_missing:    If True, auto-skip when no COMPLETION-relevant
                            evidence appears.
        confirmation:       How this goal can be confirmed at all.
        unsupported_reason: Required when confirmation is UNSUPPORTED. States
                            what instrument is missing, so the gap is a
                            documented fact rather than a silent stall.
        evidence_collected: Every event related to this goal, completion or not.
        completion_evidence:
                            The subset that could actually confirm it. The skip
                            predicate reads THIS, not the raw count.
        ran_without_prerequisite:
                            Stages this goal depended on that resolved WITHOUT
                            being satisfied. Non-empty means the goal ran on a
                            broken chain and the report must say so.
        status:             Current lifecycle status.
        attempts:           How many actions the agent has taken toward this goal.
    """
    name:             str
    stage:            int
    description:      str
    frida_categories: List[str]           = field(default_factory=list)
    frida_hooks:      List[str]           = field(default_factory=list)
    completion_categories: List[str]      = field(default_factory=list)
    depends_on:       List[int]           = field(default_factory=list)
    skip_if_missing:  bool                = False
    confirmation:     ConfirmationMode    = ConfirmationMode.FRIDA_HOOK
    unsupported_reason: str               = ""
    evidence_collected: List[Dict]        = field(default_factory=list)
    completion_evidence: List[Dict]       = field(default_factory=list)
    ran_without_prerequisite: List[int]   = field(default_factory=list)
    status:           GoalStatus          = GoalStatus.PENDING
    attempts:         int                 = 0
    retries_used:     int                 = 0
    #: Why this goal ended where it did, in one machine-readable token
    #: ("no_state_transition", "auth_flow_rejected", "time_budget_exhausted").
    #: Reported per goal so the analyst can tell a goal that was refused from
    #: one that was never tried. Never a verdict about the sample.
    failure_reason:   str                 = ""
    #: Verified, non-confirming progress this goal produced: a field populated,
    #: a screen transition proven by PRE/POST observation, a permission grant.
    #: This is what separates PARTIAL_SUCCESS from FAILED - the goal moved the
    #: device somewhere, it just never reached its own confirmation.
    progress_signals: List[str]           = field(default_factory=list)
    #: Wall-clock seconds this goal has consumed. Compared against the adaptive
    #: per-goal slice so one difficult goal cannot absorb the whole run.
    time_spent_seconds: float             = 0.0
    #: Planner (LLM) calls spent on this goal, capped per goal so a model that
    #: keeps returning the same unusable action cannot be asked forever.
    planner_calls:    int                 = 0
    #: Canonical behaviours that CONFIRM this goal. Declared instead of raw
    #: hook names, which is the fix for a defect the contract tests have been
    #: reporting since they were written: a goal naming a hook the agent does
    #: not emit is unreachable by construction, and four stages were.
    #:
    #: Confirmation strength is decided by
    #: behavior_taxonomy.evaluate_behaviour_evidence, so a single ubiquitous
    #: observation can never complete a goal however many times it fires.
    required_behaviors: List[Behavior]  = field(default_factory=list)
    #: Behaviours consistent with this goal that are never sufficient alone.
    #: They produce PARTIAL and are named in the report.
    supporting_behaviors: List[Behavior] = field(default_factory=list)
    #: What a behaviour proves FOR THIS GOAL, where that differs from what it
    #: proves in general. Weight is a property of the (behaviour, claim) pair:
    #: lifecycle callbacks are ubiquitous evidence of code loading and decisive
    #: evidence that the app launched at all.
    behavior_weights: Dict[Behavior, BehaviorWeight] = field(default_factory=dict)
    #: The evidence verdict from the last reconciliation, kept so the report can
    #: say WHAT was proven rather than only that something was.
    evidence_verdict: Optional[Any]     = None
    #: What stopped this goal, when the answer is "something outside the
    #: sample". One of the BLOCKED_* tokens.
    blocked_reason:   str               = ""

    def __post_init__(self) -> None:
        if not self.completion_categories:
            self.completion_categories = list(self.frida_categories)

    def accepts_completion_category(self, category: str) -> bool:
        """
        Whether a hook firing under `category` may complete this goal.

        An empty `completion_categories` accepts any category. That is the
        permissive case and is only correct for goals whose hooks are emitted
        under exactly one category anyway; the contract test pins which.
        """
        if not self.completion_categories:
            return True
        return category in self.completion_categories

    def matches_completion(self, hook: str, category: str) -> bool:
        """
        Whether this event confirms the goal.

        BOTH conditions must hold. Name alone is not enough - the agent
        deliberately routes the same hook to a scored or an unscored category
        depending on what it saw, and honouring that routing is the difference
        between "the app read a credential" and "the app read a preference".
        """
        if self.confirmation is not ConfirmationMode.FRIDA_HOOK:
            return False
        if not hook or not self.frida_hooks:
            return False
        if not self.accepts_completion_category(category):
            return False
        return any(h in hook for h in self.frida_hooks)

    def is_unblocked(self, resolved_stages: Set[int]) -> bool:
        """True when every dependency stage has RESOLVED (see RESOLVED_STATES)."""
        return all(d in resolved_stages for d in self.depends_on)

    def to_prompt_context(self) -> str:
        """Compact string representation for inclusion in agent prompts."""
        broken = (
            f", prerequisite(s) {self.ran_without_prerequisite} unmet"
            if self.ran_without_prerequisite else ""
        )
        return (
            f"[Stage {self.stage}] {self.name} - {self.status.value} "
            f"(evidence: {len(self.evidence_collected)}, "
            f"confirming: {len(self.completion_evidence)}, "
            f"attempts: {self.attempts}{broken}): {self.description}"
        )


# ─── Goal Dependency Graph Definition ─────────────────────────────────────────

def _build_default_goals() -> List[FraudGoal]:
    """
    Constructs the canonical 15-stage fraud exploration goal graph.

    Each goal specifies:
      - Which Frida event categories signal it is firing.
      - Which specific hook names definitively confirm completion.
      - Which earlier stages must finish before this goal is unblocked.
    """
    return [
        FraudGoal(
            name="Launch Application",
            stage=1,
            description=(
                "Confirm the target application has launched and is in the foreground. "
                "Dismiss any splash screen. Verify the package is the active window."
            ),
            frida_categories=[],
            frida_hooks=[],
            # Stage 1 precedes every hook - hooks cannot fire before the process
            # they are attached to is running - so it is confirmed by observing
            # the foreground window instead. See update_from_foreground().
            confirmation=ConfirmationMode.DEVICE_STATE,
            # Lifecycle callbacks from the instrumented process are
            # DIRECT proof the application started and ran its own code -
            # strictly stronger than the foreground poll this stage used
            # to rely on, which any loader that hands off to a dropped
            # package defeats. Measured on Anubis: the sample launched,
            # handed the journey to a package it had just installed, and
            # stage 1 never confirmed because the foreground was no
            # longer the target. The override is what makes lifecycle
            # decisive HERE and nowhere else.
            required_behaviors=[Behavior.APP_LIFECYCLE],
            behavior_weights={Behavior.APP_LIFECYCLE: BehaviorWeight.DECISIVE},
            depends_on=[],
            skip_if_missing=False,
        ),
        FraudGoal(
            name="Grant Runtime Permissions",
            stage=2,
            description=(
                "Accept all runtime permission dialogs (Contacts, SMS, Camera, Location, "
                "Microphone, Storage). Use `grant_permission` tool for each. "
                "Tap 'Allow' on any dialog boxes."
            ),
            frida_categories=["dangerous_apis"],
            # No hook. This goal previously declared ContextImpl.checkPermission
            # and PackageManager.checkPermission; the agent emits NEITHER, so
            # stage 2 could never complete - and stages 3, 4 and 5 all depend on
            # it, which is how one event stalled the whole graph.
            #
            # The dead names are not replaced by a firing hook, because no hook
            # would be honest: whether a permission is HELD is a property of the
            # package manager, not of any call the app makes. A checkPermission
            # hook would only prove the app ASKED, and every app asks.
            #
            # It is confirmed by the same device read the ActionVerifier already
            # performs - `dumpsys package <pkg>` -> runtime permissions granted.
            # See update_from_permission_state().
            frida_hooks=[],
            confirmation=ConfirmationMode.DEVICE_STATE,
            # No behaviour confirms a permission GRANT - whether a
            # permission is held is a property of the package manager,
            # not of any call the app makes. Confirmed by device state.
            required_behaviors=[],
            depends_on=[1],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Accessibility Abuse",
            stage=3,
            description=(
                "Navigate to Accessibility Settings and enable the target app's Accessibility "
                "Service. Look for 'Accessibility', 'Accessibility Service', 'Enable' UI elements. "
                "Use `start_activity` with android.settings.ACCESSIBILITY_SETTINGS."
            ),
            frida_categories=["accessibility"],
            # Removed: AccessibilityManager.isEnabled and
            # Settings.Secure.getString/accessibility - neither is emitted, and
            # neither has an equivalent. Both are CAPABILITY CHECKS in any case:
            # they would prove the app asked whether it had accessibility, not
            # that it used it.
            #
            # Deliberately NOT substituted with the agent's
            # AccessibilityManager.sendAccessibilityEvent, which IS emitted but
            # fires on every UI change in every app - the exact false-completion
            # this reconciliation exists to avoid (see INCIDENTAL_CATEGORIES in
            # investigation_controller, which documents a legitimate file
            # manager tripping it).
            #
            # Added instead: performAction and dispatchGesture, both already
            # emitted, and both evidence of the service ACTING rather than
            # merely existing.
            frida_hooks=[
                "AccessibilityService.onAccessibilityEvent",
                "AccessibilityNodeInfo.performAction",
                "AccessibilityService.dispatchGesture",
            ],
            required_behaviors=[
                Behavior.ACCESSIBILITY_NODE_HARVEST,
                Behavior.ACCESSIBILITY_GESTURE_INJECTION,
            ],
            supporting_behaviors=[Behavior.ACCESSIBILITY_SERVICE_ACTIVE],
            depends_on=[1, 2],
            skip_if_missing=False,
        ),
        FraudGoal(
            name="Overlay Detection",
            stage=4,
            description=(
                "Trigger the app to draw overlay windows. Navigate to 'Draw over other apps' or "
                "'Appear on top' settings. Grant SYSTEM_ALERT_WINDOW permission. "
                "Use `start_activity` with android.settings.action.MANAGE_OVERLAY_PERMISSION."
            ),
            frida_categories=["overlay"],
            # Removed: View.setType/TYPE_APPLICATION_OVERLAY and
            # Settings.canDrawOverlays - neither emitted, no equivalent, and
            # canDrawOverlays is a capability check rather than an overlay.
            #
            # updateViewLayout and removeView ARE emitted and the agent scopes
            # them correctly (overlay only for a view it saw added as an
            # overlay, app_telemetry otherwise). They are added here because
            # completion is now category-gated: under `overlay` they mean a live
            # overlay was manipulated, and the app_telemetry emission of the
            # same name can no longer complete this goal.
            frida_hooks=[
                "WindowManager.addView",
                "WindowManager.updateViewLayout",
                "WindowManager.removeView",
            ],
            completion_categories=["overlay"],
            required_behaviors=[Behavior.OVERLAY_WINDOW_ADDED],
            supporting_behaviors=[Behavior.OVERLAY_WINDOW_MANIPULATED],
            depends_on=[1, 2],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Login Flow",
            stage=5,
            description=(
                "Complete the application's login or registration flow. Fill username/email "
                "and password fields. Submit credentials. Reach the authenticated state. "
                "If no login UI is present after 8 actions, this stage is auto-skipped."
            ),
            # app_telemetry carries Cipher.doFinal and Activity.onResume, which
            # moved out of 'banking' when the BFCI categories were de-contaminated.
            # Goal COMPLETION is hook-driven and unaffected; this keeps the
            # IN_PROGRESS transition firing as it did before.
            frida_categories=["banking", "dangerous_apis", "app_telemetry"],
            # Removed: the four "Activity.onResume/<suffix>" triggers. The agent
            # emits a bare `Activity.onResume` and has never emitted a suffixed
            # form, so all four were dead. They are NOT replaced by bare
            # Activity.onResume: that fires on every screen of every app and
            # would complete "Login Flow" on the splash screen.
            #
            # Also removed: Cipher.doFinal. It IS emitted, so it was not dead -
            # but it is emitted ONLY to `app_telemetry`, and the agent's own
            # note beside it says it "fires on ANY encryption ... is not
            # evidence of banking-credential theft on its own" and is "retained
            # as unscored context". Completing Login Flow on it was a false
            # completion; removing it is not a substitution, it is deleting a
            # trigger that never demonstrated the goal.
            #
            # The survivor is category-gated to `banking`, where the agent emits
            # it only for a credential-shaped preference key ("App read
            # credential material from SharedPreferences"). The same hook name
            # under `app_telemetry` is an ordinary session read and can no
            # longer complete this goal.
            frida_hooks=[
                "SharedPreferences.getString",
            ],
            completion_categories=["banking"],
            required_behaviors=[Behavior.CREDENTIAL_STORE_ACCESS],
            supporting_behaviors=[Behavior.KEYSTORE_ACCESS,
                                  Behavior.KEYBOARD_ACTIVITY],
            depends_on=[1, 2],
            # skip_if_missing=True allows auto-skip after MAX_ATTEMPTS_PER_GOAL
            # when the app has no conventional login screen (most banking trojans).
            skip_if_missing=True,
        ),
        FraudGoal(
            name="SMS / OTP Interception",
            stage=6,
            description=(
                "Trigger SMS read/receive hooks. Look for OTP input fields and fill them. "
                "Navigate to screens that mention OTP, verification, or mobile number. "
                "Monitor for SmsManager or SMS ContentProvider access."
            ),
            frida_categories=["sms"],
            # Removed: ContentResolver.query/sms - the agent emits a bare
            # `ContentResolver.query`, but it fires for sms OR mms OR CONTACTS.
            # A contacts read does not demonstrate OTP interception, so the bare
            # name is not an honest substitute for the /sms-scoped trigger.
            #
            # Removed: BroadcastReceiver.onReceive/SMS_RECEIVED - the agent has
            # no BroadcastReceiver hook at all and no equivalent.
            #
            # Added: SmsMessage.getMessageBody, already emitted, severity
            # CRITICAL, described by the agent as "OTP interception confirmed".
            # This is the exact behaviour the goal is named for.
            frida_hooks=[
                "SmsManager.sendTextMessage",
                "SmsManager.sendMultipartTextMessage",
                "SmsMessage.getMessageBody",
            ],
            required_behaviors=[Behavior.SMS_READ, Behavior.SMS_SEND],
            supporting_behaviors=[Behavior.NOTIFICATION_INTERCEPTION,
                                  Behavior.CONTENT_PROVIDER_QUERY],
            depends_on=[1, 2, 5],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Banking Application Detection",
            stage=7,
            description=(
                "Confirm the app scans for installed banking applications. "
                "Trigger `getInstalledPackages()` or `queryIntentActivities()` hooks. "
                "Look for list screens showing bank names or payment apps."
            ),
            # PackageManager enumeration moved to device_fingerprint when the
            # BFCI categories were de-contaminated - enumeration alone is
            # reconnaissance, not proof of banking targeting. Completion is still
            # hook-driven; this preserves the IN_PROGRESS transition.
            frida_categories=["banking", "device_fingerprint"],
            # Removed: PackageManager.queryIntentActivities - not emitted, no
            # equivalent. The two survivors are emitted under
            # `device_fingerprint` and already cover package enumeration.
            frida_hooks=[
                "PackageManager.getInstalledPackages",
                "PackageManager.getInstalledApplications",
            ],
            required_behaviors=[Behavior.INSTALLED_PACKAGE_ENUMERATION],
            supporting_behaviors=[Behavior.FOREGROUND_APP_MONITORING],
            depends_on=[1, 5],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Network / C2 Communication",
            stage=8,
            description=(
                "Trigger the app's network communication. Navigate to any sync, update, "
                "or registration screen. Perform actions that result in API calls. "
                "Monitor for HTTP/HTTPS connections to non-CDN endpoints."
            ),
            frida_categories=["network"],
            # Substituted, both to the agent's real name for the same event:
            #   HttpURLConnection.connect -> HttpURLConnection.getInputStream
            #   OkHttpClient.newCall      -> OkHttp.RealCall.execute / .enqueue
            # Each names the moment an HTTP request is actually issued, which is
            # what the dead name meant. These are renames, not widenings.
            #
            # completion_categories pins `network`, excluding the `smoke`
            # emission of URL.openConnection - that one is the agent's own
            # start-up liveness probe, not the sample reaching a C2.
            frida_hooks=[
                "URL.openConnection",
                "HttpURLConnection.getInputStream",
                "OkHttp.RealCall.execute",
                "OkHttp.RealCall.enqueue",
                "Socket.connect",
            ],
            completion_categories=["network"],
            required_behaviors=[Behavior.HTTP_REQUEST,
                                Behavior.TLS_PAYLOAD_CAPTURE],
            supporting_behaviors=[Behavior.SOCKET_CONNECTION],
            depends_on=[1, 5],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Persistence Mechanisms",
            stage=9,
            description=(
                "Trigger persistence hooks: Device Admin activation, boot receivers, "
                "AlarmManager scheduling, or JobScheduler registration. "
                "Navigate to 'Device Admin' settings if prompted."
            ),
            frida_categories=["persistence"],
            # Substituted:
            #   AlarmManager.setRepeating -> AlarmManager.setExact. Both mean
            #     "the app scheduled a future wake-up"; the agent describes its
            #     hook as "scheduled exact alarm for persistence/wakeup".
            #   PackageInstaller.createSession -> Intent.installPackageRequest.
            #     Both mean "the app asked Android to install a package"; the
            #     agent scopes its hook to the package-archive MIME type.
            #
            # Removed: DevicePolicyManager.setActiveAdmin - not emitted. The
            # agent has isAdminActive, but that is a CHECK, not an activation,
            # and completing a persistence goal on it would claim device-admin
            # abuse from a query any app may make.
            #
            # Added: DevicePolicyManager.lockNow - emitted, CRITICAL, described
            # by the agent as "RANSOMWARE/EXTORTION BEHAVIOR CONFIRMED". That is
            # device-admin power being exercised, which is what the dead name
            # was reaching for.
            frida_hooks=[
                "AlarmManager.setExact",
                "JobScheduler.schedule",
                "Intent.installPackageRequest",
                "DevicePolicyManager.lockNow",
            ],
            required_behaviors=[Behavior.SCHEDULED_EXECUTION,
                                Behavior.DEVICE_ADMIN_ABUSE,
                                Behavior.PACKAGE_INSTALL_REQUEST],
            # isAdminActive is a QUERY. It supports the goal and can
            # never complete it, which is why it sits here rather than
            # above - the distinction a hook-name match could not make.
            supporting_behaviors=[Behavior.DEVICE_ADMIN_QUERY],
            depends_on=[1, 3],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Dynamic Code Loading",
            stage=10,
            description=(
                "Trigger DexClassLoader or PathClassLoader to load external DEX. "
                "Navigate to any update or plugin screens. Monitor for DexClassLoader "
                "instantiation with external file paths."
            ),
            frida_categories=["code_execution", "dangerous_apis"],
            # Removed: Runtime.load - not emitted. No substitute needed: native
            # library loading is already covered by System.loadLibrary below,
            # which IS emitted, so the goal loses no reachable behaviour.
            #
            # completion_categories pins `dangerous_apis`; System.loadLibrary is
            # also emitted under `smoke` as a start-up probe, and the agent
            # loading its own library is not the sample loading code.
            frida_hooks=[
                # These two now complete the goal, and only these two.
                # `code_execution` was split out of `dangerous_apis` so it could
                # carry a BFCI weight: PathClassLoader and System.loadLibrary
                # stayed behind because EVERY app loads its own APK through the
                # first and any app with native code triggers the second.
                # Keeping them as completion triggers would let a calculator
                # complete "Dynamic Code Loading".
                "DexClassLoader.<init>",
                "InMemoryDexClassLoader.<init>",
            ],
            completion_categories=["code_execution"],
            # Both are code the process was not statically linked to
            # run. The engine already treats them as one axis - the
            # agent files both under `code_execution` and BFCI weights
            # that bucket - but the goal graph could only name the Dex
            # half, so a sample that shells out scored zero goals while
            # BFCI scored it 10.0 from the same events.
            required_behaviors=[Behavior.DYNAMIC_DEX_LOADING,
                                Behavior.COMMAND_EXECUTION],
            supporting_behaviors=[Behavior.NATIVE_METHOD_REGISTRATION,
                                  Behavior.NATIVE_LIBRARY_LOAD],
            depends_on=[1, 5],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Runtime Reflection",
            stage=11,
            description=(
                "Trigger Java Reflection API calls. Navigate through menus and settings "
                "that invoke obscured functionality. Monitor for Method.invoke and "
                "Class.forName calls with suspicious class names."
            ),
            frida_categories=["dangerous_apis"],
            # Method.invoke, Class.forName and Constructor.newInstance are all
            # dead - the agent has no reflection hooks - and none was replaced.
            #
            # Adding them would be worse than leaving them out. The Android
            # framework itself reflects constantly (resource loading, Parcelable
            # creators, every androidx initialiser), so a Method.invoke hook
            # fires thousands of times for a calculator and would complete this
            # goal for every sample ever run.
            #
            # Reflection IS detected statically - apk_analyzer.REFLECTION_APIS
            # feeds the OB axis of STEI. This goal is the DYNAMIC confirmation,
            # and the instrument for it does not exist. Saying so is the honest
            # outcome; sitting PENDING while the run reports itself complete is
            # not.
            frida_hooks=[],
            confirmation=ConfirmationMode.UNSUPPORTED,
            unsupported_reason=(
                "The Frida agent emits no reflection hook. Method.invoke / "
                "Class.forName cannot be hooked usefully - the Android "
                "framework reflects on every app, so the signal would complete "
                "for every sample. Reflection is reported from static analysis "
                "(apk_analyzer.REFLECTION_APIS) instead."
            ),
            required_behaviors=[],
            depends_on=[1, 10],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Deep Links",
            stage=12,
            description=(
                "Trigger deep link handling. Use `broadcast_intent` or `start_activity` "
                "with custom URI schemes found in the manifest. Look for intent filter "
                "URLs in static analysis findings."
            ),
            frida_categories=["dangerous_apis"],
            # Activity.getIntent, Uri.parse and Intent.getData are all dead, and
            # none was replaced for the same reason as stage 11: every Android
            # app parses URIs and reads its own Intent on every Activity start.
            # A hook on those would confirm this goal for a calculator.
            #
            # Deep-link HANDLING is observable in principle (an Activity started
            # by a VIEW intent with a custom scheme), but the agent emits no
            # such event today, and inventing one from Activity.onCreate would
            # not distinguish a deep link from an ordinary launch.
            frida_hooks=[],
            confirmation=ConfirmationMode.UNSUPPORTED,
            unsupported_reason=(
                "The Frida agent emits no deep-link event. Uri.parse / "
                "Intent.getData fire for every app on every launch and cannot "
                "distinguish a deep link from ordinary navigation. Declared "
                "intent-filter URIs are reported from the manifest instead."
            ),
            required_behaviors=[],
            supporting_behaviors=[Behavior.WEBVIEW_NAVIGATION],
            depends_on=[1],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Broadcast Receivers",
            stage=13,
            description=(
                "Fire implicit broadcasts and exported receiver intents. Use "
                "`broadcast_intent` tool with action strings from static findings "
                "(BOOT_COMPLETED, SMS_RECEIVED, PACKAGE_REPLACED, etc.)."
            ),
            frida_categories=["persistence", "dangerous_apis"],
            # BroadcastReceiver.onReceive and IntentFilter.addAction are both
            # dead and neither was replaced. The agent hooks no receiver.
            #
            # This one is genuinely ADDABLE - a BroadcastReceiver.onReceive hook
            # carrying the action string would be a real, scoped signal, unlike
            # stages 11 and 12. It is left UNSUPPORTED rather than added here
            # because adding a hook means editing the agent and rebuilding the
            # 685 KB bundle, which cannot be verified without an emulator, and
            # shipping an unverified hook is how the original contract broke.
            # Recorded as future work rather than silently attempted.
            frida_hooks=[],
            confirmation=ConfirmationMode.UNSUPPORTED,
            unsupported_reason=(
                "The Frida agent hooks no BroadcastReceiver. This IS a "
                "hookable signal (onReceive carrying the action string) and is "
                "the best candidate for closing a real gap - see the agent "
                "hook backlog. Not added blind: it needs an emulator run to "
                "verify before it can be a completion trigger."
            ),
            required_behaviors=[],
            depends_on=[1, 9],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Exported Components",
            stage=14,
            description=(
                "Invoke exported Activities, Services, and ContentProviders directly via "
                "ADB intent injection. Use `start_activity` with component names from "
                "static analysis. Enumerate ContentProvider URIs."
            ),
            frida_categories=["dangerous_apis"],
            # Removed: ContentProvider.query, ContentProvider.insert and
            # Service.onStartCommand - none is emitted and none has an
            # equivalent. (ContentResolver.query exists but is the CALLER side,
            # scoped to sms/mms/contacts; it does not show a provider of THIS
            # app being invoked.)
            #
            # Activity.onCreate survives, category-gated to `smoke`, which is
            # the only category it is emitted under. It is a weak trigger - it
            # fires for any Activity start, not only an externally injected one
            # - and it is retained rather than strengthened because this goal's
            # method is ADB intent injection: the explorer knows it launched the
            # component, so an Activity actually starting is the confirmation
            # that the injection landed.
            frida_hooks=[
                "Activity.onCreate",
            ],
            completion_categories=["smoke"],
            required_behaviors=[],
            supporting_behaviors=[Behavior.APP_LIFECYCLE],
            depends_on=[1],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Background Services",
            stage=15,
            description=(
                "Confirm the app registers long-running background services. "
                "Press Home to background the app and monitor for continued Frida "
                "hook activity (network, SMS, accessibility events in background)."
            ),
            frida_categories=["persistence", "network", "accessibility"],
            # Removed: Service.onStartCommand, Service.onCreate,
            # NotificationManager.notify and WorkManager.enqueue - all four
            # dead, no Service or WorkManager hooks exist.
            #
            # Added: JobScheduler.schedule, which IS emitted and which the agent
            # describes as "scheduled background JobScheduler job". That is
            # precisely "the app arranged to run in the background".
            #
            # Note this trigger is shared with stage 9 (Persistence). That is
            # intentional and not double-counting: the goal graph tracks
            # exploration coverage, not score. Scheduling background work is
            # honestly evidence for both questions, and neither goal feeds BFCI
            # or FRS.
            frida_hooks=[
                "JobScheduler.schedule",
            ],
            completion_categories=["persistence"],
            required_behaviors=[Behavior.SCHEDULED_EXECUTION],
            supporting_behaviors=[Behavior.FOREGROUND_APP_MONITORING],
            depends_on=[1, 9],
            skip_if_missing=True,
        ),
        FraudGoal(
            name="Anti-Analysis Resistance",
            stage=16,
            description=(
                "Determine whether the sample resists observation: probing for a "
                "debugger, reading emulator-identifying system properties, calling "
                "ptrace, or terminating its own process once instrumentation is "
                "detected. No navigation is required - this stage is confirmed by "
                "what the sample does to US."
            ),
            # ── Why this stage exists ────────────────────────────────────────
            #
            # The engine could already SEE this. The agent files it under
            # `anti_analysis`, risk_engine scores substantive evasion at
            # _EVASION_RESISTANCE_SCORE, and dynamic_exclusion_reason treats
            # self-termination as an explanation for a silent run. The goal
            # graph was the only layer with no way to say it.
            #
            # Measured on Cerberus: Process.killProcess and System.exit both
            # observed and attributed to the sample - the single most
            # diagnostic thing that run produced - while the graph reported
            # zero successful and zero partial goals, because refusing to be
            # analysed matched no stage.
            #
            # Confirmed by behaviour rather than by hook name, and deliberately
            # not skippable: a sample that does NOT resist resolves this stage
            # as attempted-and-nothing-observed, which is itself a finding.
            frida_categories=["anti_analysis"],
            frida_hooks=[],
            confirmation=ConfirmationMode.BEHAVIOR,
            required_behaviors=[
                Behavior.SELF_TERMINATION,
                Behavior.PTRACE_CHECK,
            ],
            supporting_behaviors=[
                Behavior.DEBUGGER_CHECK,
                Behavior.SYSTEM_PROPERTY_PROBE,
            ],
            # Depends on nothing. A sample that kills itself inside
            # Application.onCreate never reaches stage 1's foreground
            # confirmation, and gating the observation of that refusal behind
            # the launch it prevented would guarantee it could never be
            # reported.
            depends_on=[],
            skip_if_missing=False,
        ),
    ]


# ─── Goal Tracker ─────────────────────────────────────────────────────────────

class GoalTracker:
    """
    Manages the 15-stage fraud goal dependency graph for the Agentic Explorer.

    The tracker:
      1. Maintains ordered goal list with dependency awareness.
      2. Updates goal evidence from Frida event streams (deterministic).
      3. Exposes `next_priority_goal()` to drive the planner.
      4. Tracks which stages are unblocked based on completion state.

    This class NEVER makes malware verdicts. It only tracks exploration coverage.
    """

    def __init__(self) -> None:
        self._goals: List[FraudGoal] = _build_default_goals()
        # Map stage → goal for fast lookup
        self._by_stage: Dict[int, FraudGoal] = {g.stage: g for g in self._goals}
        # Consecutive observations of the target package in the foreground.
        # Reset whenever the reading is unavailable or shows another package.
        self._launch_confirmations: int = 0
        #: Canonical behaviours from the most recent reconcile().
        self._last_behaviors: Dict[Any, Any] = {}
        # Goals whose instrument does not exist are resolved once, up front,
        # rather than left PENDING to block their dependents. Doing it in the
        # constructor means the gap is visible in the very first status dump.
        self._resolve_unsupported_goals()

    def _resolve_unsupported_goals(self) -> None:
        """
        Settle goals that no instrument can confirm, loudly.

        UNSUPPORTED is a claim about the ENGINE, not about the sample: it says
        Sudarshan cannot answer this question, which is why it is logged at
        WARNING and carried into the report by audit_unfulfilled_goals(). It is
        never reported as an absence of the behaviour.
        """
        for goal in self._goals:
            if goal.confirmation is not ConfirmationMode.UNSUPPORTED:
                continue
            goal.status = GoalStatus.UNSUPPORTED
            logger.warning(
                "[GoalTracker] '%s' (stage %d) is UNSUPPORTED - %s",
                goal.name, goal.stage,
                goal.unsupported_reason or "no confirmation route declared",
            )

    # ── Public read API ────────────────────────────────────────────────────────

    @property
    def goals(self) -> List[FraudGoal]:
        return self._goals

    def get_goal(self, stage: int) -> Optional[FraudGoal]:
        return self._by_stage.get(stage)

    def get_goal_by_name(self, name: str) -> Optional[FraudGoal]:
        return next((g for g in self._goals if g.name == name), None)

    def _resolved_stages(self) -> Set[int]:
        """
        Stage numbers that have RESOLVED - see :data:`RESOLVED_STATES`.

        Includes FAILED and UNSUPPORTED, which is the deadlock fix. A goal the
        agent genuinely attempted and could not trigger, or one no instrument
        can confirm, must not hold every dependent stage PENDING for the rest
        of the run.
        """
        return {g.stage for g in self._goals if g.status in RESOLVED_STATES}

    def _satisfied_stages(self) -> Set[int]:
        """Stage numbers actually CONFIRMED. Used for reporting, not unblocking."""
        return {g.stage for g in self._goals if g.status in SATISFIED_STATES}

    def _completed_stages(self) -> Set[int]:
        """
        Deprecated alias for :meth:`_resolved_stages`.

        Kept because external callers and tests reference it. The name is now
        misleading - "completed" no longer describes what unblocks a dependent
        - so new code should say which of the two it means.
        """
        return self._resolved_stages()

    def _mark_broken_chain(self, goal: FraudGoal) -> None:
        """
        Record that this goal is running without a satisfied prerequisite.

        Called at selection time, because that is the moment the graph decides
        to proceed on an unmet precondition. Without this the report could not
        distinguish "SMS interception found nothing" from "SMS interception ran
        without ever having been granted permissions", and those are different
        findings.
        """
        satisfied = self._satisfied_stages()
        unmet = [d for d in goal.depends_on if d not in satisfied]
        for stage in unmet:
            if stage in goal.ran_without_prerequisite:
                continue
            goal.ran_without_prerequisite.append(stage)
            dep = self._by_stage.get(stage)
            logger.warning(
                "[GoalTracker] '%s' (stage %d) is proceeding WITHOUT its "
                "prerequisite stage %d ('%s', %s) - results from this stage "
                "must be read as unconditioned.",
                goal.name, goal.stage, stage,
                dep.name if dep else "unknown",
                dep.status.value if dep else "MISSING",
            )

    def next_priority_goal(self) -> Optional[FraudGoal]:
        """
        Return the highest-priority unblocked, unfinished goal.

        Priority order:
          1. IN_PROGRESS goals first (resume interrupted work).
          2. PENDING goals in stage order (lower stage = higher priority).
          3. FAILED goals last (retry once before giving up).

        Returns None only when nothing is left that could be progressed.
        "Unblocked" now means every dependency has RESOLVED, not that every
        dependency succeeded - a goal selected on a broken chain is marked via
        _mark_broken_chain() so the report can say the precondition was unmet.
        """
        resolved = self._resolved_stages()

        in_progress = [
            g for g in self._goals
            if g.status == GoalStatus.IN_PROGRESS and g.is_unblocked(resolved)
        ]
        if in_progress:
            self._mark_broken_chain(in_progress[0])
            return in_progress[0]

        pending = [
            g for g in self._goals
            if g.status == GoalStatus.PENDING and g.is_unblocked(resolved)
        ]
        if pending:
            self._mark_broken_chain(pending[0])
            return pending[0]

        # FAILED goals get exactly one retry before being given up on. Without
        # this branch a transient failure permanently removed a goal from the
        # graph, which is what the docstring above always promised but the code
        # did not previously do.
        # PARTIAL_SUCCESS is retryable on the same budget as FAILED. A goal that
        # got a form filled but never submitted is the single most likely one to
        # succeed on a second pass, and excluding it would mean the state that
        # exists to record "nearly there" was the one state that never got
        # another try. NOT_REACHED and TIMEOUT are NOT retried here: the first
        # is only ever assigned by finalize() at the end of the run, and the
        # second means the wall-clock deadline has already arrived.
        retryable = [
            g for g in self._goals
            if g.status in (GoalStatus.FAILED, GoalStatus.PARTIAL)
            and g.is_unblocked(resolved)
            and g.retries_used < MAX_GOAL_RETRIES
        ]
        if retryable:
            goal = retryable[0]
            goal.retries_used += 1
            goal.status = GoalStatus.IN_PROGRESS
            logger.info(
                f"[GoalTracker] '{goal.name}' → IN_PROGRESS "
                f"(retry {goal.retries_used}/{MAX_GOAL_RETRIES})"
            )
            return goal

        return None

    def all_done(self) -> bool:
        """Return True when no further goals can be progressed."""
        return self.next_priority_goal() is None

    def completion_summary(self) -> Dict[str, str]:
        """Return {goal_name: status} for the audit log."""
        return {g.name: g.status.value for g in self._goals}

    def active_goal_context(self) -> str:
        """
        Build a compact multi-line string for the agent's system prompt.
        Shows completed goals (summarized) and the next active goal in detail.
        """
        lines = ["=== FRAUD EXPLORATION GOALS ==="]
        for g in self._goals:
            lines.append(g.to_prompt_context())
        lines.append("")
        next_goal = self.next_priority_goal()
        if next_goal:
            lines.append(f">>> CURRENT PRIORITY GOAL: [{next_goal.name}]")
            lines.append(f"    Description: {next_goal.description}")
            if next_goal.ran_without_prerequisite:
                lines.append(
                    f"    NOTE: prerequisite stage(s) "
                    f"{next_goal.ran_without_prerequisite} were NOT satisfied. "
                    f"This stage is proceeding on an incomplete chain."
                )
        else:
            # Never claim completion the run did not achieve.
            #
            # This line previously read ">>> ALL GOALS COMPLETED OR SKIPPED"
            # whenever next_priority_goal() returned None - which it does when
            # goals are merely blocked, failed or unsupported. A measured run
            # printed it into the planner prompt with 11 of 15 goals never
            # attempted. Stating a false summary to the model is the same
            # defect class as reporting one to the analyst.
            lines.append(">>> NO FURTHER GOALS CAN BE PROGRESSED")
            lines.append(f"    {self.disposition_line()}")
        return "\n".join(lines)

    # ── Evidence ingestion (deterministic - no AI involved) ───────────────────

    def update_from_frida_events(self, events: List[Dict]) -> List[str]:
        """
        Scan a batch of Frida events and update goal evidence + status.

        This is the ONLY deterministic path into goal state - the LLM never
        directly marks a goal as complete. Frida evidence does.

        Returns list of goal names whose status changed this cycle.
        """
        changed: List[str] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            category = event.get("category", "")
            data = event.get("data")
            hook = (data or {}).get("hook", "") if isinstance(data, dict) else ""

            for goal in self._goals:
                # UNSUPPORTED goals are terminal: no event can confirm a goal
                # whose instrument does not exist, and letting one drift back
                # into IN_PROGRESS would re-open the stall.
                # TERMINAL_STATES rather than a literal tuple: PARTIAL is
                # deliberately NOT terminal, so a goal that produced some
                # evidence can still be CONFIRMED by a later hook. FAILED,
                # NOT_REACHED and TIMEOUT are likewise re-openable by evidence
                # - a goal the UI could not drive may still fire from a
                # background thread, and discarding that would be discarding
                # observed behaviour.
                if goal.status in TERMINAL_STATES:
                    continue

                # ── Activity: this goal's subject matter is happening ────────
                # Category alone. Deliberately weak - `network` fires for every
                # app - so it only ever moves PENDING -> IN_PROGRESS.
                if category in goal.frida_categories:
                    goal.evidence_collected.append(event)
                    # NOT_REACHED and TIMEOUT re-open alongside PENDING.
                    #
                    # Both are assigned by finalize() to goals the WALK never
                    # got to, and neither is a claim about the sample - so an
                    # event arriving afterwards (from a background thread, or
                    # from the post-run reconciliation against the full
                    # collected set) is new information and must be able to
                    # move the goal.
                    #
                    # Measured on Drinik: the session collected 49
                    # `code_execution` events, BFCI scored 10.0 from them, and
                    # stage 10 stayed NOT_REACHED with 0% coverage because only
                    # PENDING re-opened. The evidence was there and the graph
                    # would not look at it.
                    if goal.status in (
                        GoalStatus.PENDING,
                        GoalStatus.NOT_REACHED,
                        GoalStatus.TIMEOUT,
                    ):
                        goal.status = GoalStatus.IN_PROGRESS
                        changed.append(goal.name)
                        logger.info(
                            f"[GoalTracker] Goal '{goal.name}' → IN_PROGRESS "
                            f"(Frida category: {category})"
                        )

                # ── Completion: this goal's specific behaviour was observed ──
                # Name AND category. The category half is the fix for a false
                # completion: the agent routes several hook names to a scored
                # or an unscored category depending on what it saw, and the old
                # name-only match ignored that, completing "Login Flow" on an
                # ordinary preferences read.
                if goal.matches_completion(hook, category):
                    goal.completion_evidence.append(event)
                    if goal.status != GoalStatus.COMPLETED:
                        goal.status = GoalStatus.COMPLETED
                        changed.append(goal.name)
                        logger.info(
                            f"[GoalTracker] Goal '{goal.name}' → COMPLETED "
                            f"(hook: {hook} category: {category})"
                        )
        return changed

    # ── Explicit state mutations (called by agent loop) ────────────────────────

    def mark_in_progress(self, goal_name: str) -> None:
        """Called when the agent begins working on a goal."""
        goal = self.get_goal_by_name(goal_name)
        if goal and goal.status == GoalStatus.PENDING:
            goal.status = GoalStatus.IN_PROGRESS
            logger.debug(f"[GoalTracker] '{goal_name}' → IN_PROGRESS (agent action)")

    def update_from_foreground(
        self,
        foreground_package: str,
        target_package:     str,
    ) -> List[str]:
        """
        Deterministic completion path for Stage 1 ("Launch Application").

        Stage 1 cannot be confirmed by a Frida hook - it is the precondition for
        hooks firing at all - so it is confirmed by observing that the target
        package owns the foreground window for LAUNCH_CONFIRMATIONS_REQUIRED
        consecutive observations. Requiring consecutive readings prevents a
        single transient sample (splash screen, launcher hand-off) from
        completing the goal.

        This is observed device state, not LLM output: the agent cannot assert
        the app launched, it can only act until the device reports that it did.

        Returns list of goal names whose status changed.
        """
        changed: List[str] = []
        goal = self.get_goal_by_name(LAUNCH_GOAL_NAME)
        if goal is None or goal.status in (GoalStatus.COMPLETED, GoalStatus.SKIPPED):
            return changed

        # An unreadable foreground or unknown target is not evidence of failure
        # OR success - it breaks the streak rather than counting toward it.
        if not foreground_package or not target_package:
            self._launch_confirmations = 0
            return changed

        if foreground_package != target_package:
            self._launch_confirmations = 0
            return changed

        self._launch_confirmations += 1
        if self._launch_confirmations >= LAUNCH_CONFIRMATIONS_REQUIRED:
            goal.status = GoalStatus.COMPLETED
            goal.evidence_collected.append({
                "category": "foreground",
                "data": {
                    "hook": "foreground_package_confirmed",
                    "package": foreground_package,
                    "consecutive_observations": self._launch_confirmations,
                },
            })
            goal.completion_evidence.append(goal.evidence_collected[-1])
            changed.append(goal.name)
            logger.info(
                f"[GoalTracker] '{goal.name}' → COMPLETED "
                f"(foreground package confirmed {self._launch_confirmations}x)"
            )
        return changed

    def update_from_permission_state(
        self,
        granted_permissions: Any = (),
        runtime_declared: Any = (),
    ) -> List[str]:
        """
        Deterministic completion path for Stage 2 ("Grant Runtime Permissions").

        Stage 2 has no Frida hook, and deliberately so: whether a permission is
        HELD is a property of the package manager, not of any call the app
        makes. The old declaration named ContextImpl.checkPermission, which the
        agent never emitted - and because stages 3, 4 and 5 all depend on stage
        2, that one dead contract stalled the entire graph.

        The confirming observation is the same device read the ActionVerifier
        already performs: ``dumpsys package <pkg>`` -> runtime permissions
        granted. Pass the verified grant set here.

        ``runtime_declared`` is optional. When supplied and EMPTY it means the
        manifest requests no runtime permission at all, so there is nothing to
        grant and the goal is SKIPPED rather than left hanging - a calculator
        must not sit forever on a stage that cannot apply to it.

        This is observed device state, not LLM output.
        """
        changed: List[str] = []
        goal = self.get_goal(2)
        if goal is None or goal.status in (
            GoalStatus.COMPLETED, GoalStatus.SKIPPED, GoalStatus.UNSUPPORTED,
        ):
            return changed

        granted = {str(p) for p in (granted_permissions or ()) if p}
        declared = {str(p) for p in (runtime_declared or ()) if p}

        if not granted:
            # Nothing granted yet. If we KNOW the manifest asks for no runtime
            # permission, settle the goal now instead of retrying an impossible
            # grant; otherwise leave it for a later observation.
            if runtime_declared is not None and not declared and runtime_declared != ():
                goal.status = GoalStatus.SKIPPED
                changed.append(goal.name)
                logger.info(
                    "[GoalTracker] '%s' → SKIPPED (manifest declares no "
                    "runtime permissions - nothing to grant)", goal.name,
                )
            return changed

        goal.status = GoalStatus.COMPLETED
        evidence = {
            "category": "device_state",
            "data": {
                "hook": "runtime_permission_granted_verified",
                "granted": sorted(granted),
                "granted_count": len(granted),
            },
        }
        goal.evidence_collected.append(evidence)
        goal.completion_evidence.append(evidence)
        changed.append(goal.name)
        logger.info(
            "[GoalTracker] '%s' → COMPLETED (%d runtime permission(s) verified "
            "held on device: %s)",
            goal.name, len(granted), ", ".join(sorted(granted)[:4]),
        )
        return changed

    def record_progress_signal(self, goal_name: str, signal: str) -> None:
        """
        Note verified, non-confirming progress toward a goal.

        This is the input that lets :meth:`resolve_goal` choose PARTIAL_SUCCESS
        over FAILED. It must only be called for progress that was VERIFIED - a
        field the population verifier read back, a screen transition proven by
        PRE/POST observation, a permission the device reported held. An ADB exit
        code is not a progress signal (see the action ladder, §P5).
        """
        goal = self.get_goal_by_name(goal_name)
        if goal is None or not signal:
            return
        if signal not in goal.progress_signals:
            goal.progress_signals.append(signal)

    def record_planner_call(self, goal_name: str) -> int:
        """Count one planner consultation against this goal. Returns the total."""
        goal = self.get_goal_by_name(goal_name)
        if goal is None:
            return 0
        goal.planner_calls += 1
        return goal.planner_calls

    def add_time_spent(self, goal_name: str, seconds: float) -> float:
        """Accumulate wall-clock time against a goal. Returns the total."""
        goal = self.get_goal_by_name(goal_name)
        if goal is None:
            return 0.0
        goal.time_spent_seconds += max(0.0, float(seconds))
        return goal.time_spent_seconds

    def resolve_goal(self, goal_name: str, reason: str = "") -> Optional[GoalStatus]:
        """
        Settle a goal the agent has given up on, as PARTIAL_SUCCESS or FAILED.

        The choice is made from what the goal DEMONSTRABLY produced, never from
        the agent's opinion of how it went:

          * any confirming evidence -> COMPLETED (already set by the event path;
            re-asserted here so a race cannot demote a confirmed goal);
          * verified progress signals, or related evidence that could not
            confirm it -> PARTIAL_SUCCESS;
          * nothing at all -> FAILED.

        Returns the resulting status, or None when the goal is already terminal.

        This is the ONLY place a goal is given up on, and the decision is
        goal-scoped by construction: a goal ending FAILED is a statement about
        that goal. What the RUN achieved is :meth:`coverage_report`, which reads
        the whole distribution and never a single goal's outcome.
        """
        goal = self.get_goal_by_name(goal_name)
        if goal is None or goal.status in TERMINAL_STATES:
            return None

        if goal.completion_evidence:
            goal.status = GoalStatus.COMPLETED
            return goal.status

        if reason:
            goal.failure_reason = reason

        if goal.progress_signals or goal.evidence_collected:
            goal.status = GoalStatus.PARTIAL
            logger.info(
                "[GoalTracker] '%s' → PARTIAL_SUCCESS (%d verified progress "
                "signal(s), %d related event(s), no confirming evidence)%s",
                goal.name, len(goal.progress_signals),
                len(goal.evidence_collected),
                f" reason={reason}" if reason else "",
            )
        else:
            goal.status = GoalStatus.FAILED
            logger.warning(
                "[GoalTracker] '%s' → FAILED (nothing observed)%s",
                goal.name, f" reason={reason}" if reason else "",
            )
        return goal.status

    def mark_failed(self, goal_name: str, reason: str = "") -> None:
        """
        Called when the agent exhausts retries on a goal.

        Kept under its original name and one-argument contract because existing
        callers and tests use it. It now routes through :meth:`resolve_goal`, so
        a goal that DID produce verified progress lands on PARTIAL_SUCCESS
        instead of having that progress erased by a blanket FAILED - which is
        the §P4 rule restated: an action failure is not an evidence failure.
        """
        self.resolve_goal(goal_name, reason=reason or "max_attempts")

    def mark_timed_out(self, goal_name: str) -> None:
        """
        The global wall-clock deadline arrived while this goal was being worked.

        Distinct from FAILED: the attempt was cut off, not concluded. A goal
        that had already produced confirming evidence stays COMPLETED - a
        deadline does not retract an observation.
        """
        goal = self.get_goal_by_name(goal_name)
        if goal is None or goal.status in TERMINAL_STATES:
            return
        if goal.completion_evidence:
            goal.status = GoalStatus.COMPLETED
            return
        goal.status = GoalStatus.TIMEOUT
        goal.failure_reason = TIMEOUT_REASON
        logger.warning(
            "[GoalTracker] '%s' → TIMEOUT (global deadline reached mid-goal; "
            "%d related event(s) retained)",
            goal.name, len(goal.evidence_collected),
        )

    def mark_blocked(self, goal_name: str, blocker: str, detail: str = "") -> None:
        """
        Something outside the sample stopped this goal being reached.

        BLOCKED is deliberately not NOT_REACHED. "The login wall wants an
        account we cannot obtain" and "the budget ran out before we tried" are
        different findings with different remediation, and collapsing them hid
        the single most actionable fact a failed run produces. It is also not
        FAILED: the sample was never given the chance to exhibit the behaviour,
        so nothing about the sample has been established.

        A goal that already produced confirming evidence stays COMPLETED - a
        blocker discovered later does not retract an observation.
        """
        goal = self.get_goal_by_name(goal_name)
        if goal is None or goal.status in TERMINAL_STATES:
            return
        if goal.completion_evidence:
            goal.status = GoalStatus.COMPLETED
            return
        goal.status = GoalStatus.BLOCKED
        goal.blocked_reason = blocker
        goal.failure_reason = detail or blocker
        logger.info(
            "[GoalTracker] '%s' → BLOCKED (%s)%s",
            goal.name, blocker, f": {detail}" if detail else "",
        )

    def mark_not_applicable(self, goal_name: str, reason: str) -> None:
        """
        Static analysis proves this goal cannot apply to this sample.

        A calculator that declares no accessibility service has not FAILED to
        abuse accessibility; the question does not arise. Reporting it as
        failed penalises a sample for not doing something it was never built to
        do, and pollutes coverage with stages that were never in play.
        """
        goal = self.get_goal_by_name(goal_name)
        if goal is None or goal.status in TERMINAL_STATES:
            return
        if goal.completion_evidence:
            goal.status = GoalStatus.COMPLETED
            return
        goal.status = GoalStatus.NOT_APPLICABLE
        goal.failure_reason = reason
        logger.info("[GoalTracker] '%s' → NOT_APPLICABLE (%s)", goal.name, reason)

    # ── Whole-evidence reconciliation ─────────────────────────────────────────

    def reconcile(
        self,
        collected_events: Optional[Dict[str, Any]] = None,
        *,
        normalized: Optional[List[NormalizedEvent]] = None,
    ) -> Dict[str, Any]:
        """
        Re-evaluate EVERY goal against the COMPLETE evidence set.

        This is the answer to a failure mode the per-event path cannot avoid:
        the tracker only ever saw events the explorer drained from the bus
        while it was walking, so anything that fired before the walk started,
        after it stopped, or on a background thread it never observed was
        invisible to the goal graph - while being counted correctly by BFCI,
        by the evidence store and by the report.

        Measured on Drinik: 50 `code_execution` events collected, BFCI 10.0
        scored from them, goal graph reporting zero successful and zero
        partial. The evidence existed and the graph never looked at it.

        Confirmation is by canonical BEHAVIOUR, never by raw hook name, so a
        hook the agent renames breaks one table entry in behavior_taxonomy
        instead of silently disabling a stage - which is the defect the four
        red `test_goal_hook_contract` tests have been reporting all along.

        Strength decides the state, deterministically:

            CONCLUSIVE -> COMPLETED
            MODERATE   -> PARTIAL
            WEAK       -> PARTIAL only if nothing better is known
            NONE       -> left as it is

        A goal is never DEMOTED here. Reconciliation can only add what the walk
        missed; it cannot retract what the walk proved.
        """
        events = normalized
        if events is None:
            events = normalize_collected_events(collected_events or {})

        observed = classify_events(events)
        self._last_behaviors = observed

        changed: List[str] = []
        for goal in self._goals:
            if goal.status in TERMINAL_STATES and goal.status != GoalStatus.COMPLETED:
                # SKIPPED / NOT_APPLICABLE / UNSUPPORTED are settled questions.
                continue
            if not goal.required_behaviors and not goal.supporting_behaviors:
                continue

            verdict = evaluate_behaviour_evidence(
                observed,
                goal.required_behaviors,
                goal.supporting_behaviors,
                weight_overrides=goal.behavior_weights,
            )
            goal.evidence_verdict = verdict
            if verdict.strength is EvidenceStrength.NONE:
                continue

            # Attach the supporting events so the report can cite them, and so
            # resolve_goal() can tell a goal that produced something from one
            # that produced nothing.
            for event in verdict.evidence_events():
                raw = dict(event.raw)
                if raw not in goal.evidence_collected:
                    goal.evidence_collected.append(raw)

            if verdict.conclusive:
                if goal.status != GoalStatus.COMPLETED:
                    goal.status = GoalStatus.COMPLETED
                    changed.append(goal.name)
                    logger.info(
                        "[GoalTracker] '%s' → COMPLETED via behaviour evidence: %s",
                        goal.name, verdict.reason,
                    )
                for event in verdict.evidence_events():
                    raw = dict(event.raw)
                    if raw not in goal.completion_evidence:
                        goal.completion_evidence.append(raw)
            elif goal.status not in (GoalStatus.COMPLETED, GoalStatus.PARTIAL):
                goal.status = GoalStatus.PARTIAL
                goal.failure_reason = goal.failure_reason or "evidence_below_completion_threshold"
                changed.append(goal.name)
                logger.info(
                    "[GoalTracker] '%s' → PARTIAL_SUCCESS via behaviour evidence: %s",
                    goal.name, verdict.reason,
                )

        return {
            "events_considered": len(events),
            "behaviors_observed": {
                b.value: o.count for b, o in observed.items()
            },
            "goals_changed": changed,
        }

    @property
    def observed_behaviors(self) -> Dict[Any, Any]:
        """Canonical behaviours from the last reconcile(), for the report."""
        return dict(getattr(self, "_last_behaviors", {}) or {})

    def finalize(self, *, timed_out: bool = False, reason: str = "") -> Dict[str, int]:
        """
        Settle every goal the run never concluded, once, at the end.

        This is what makes NOT_REACHED a real state rather than a euphemism for
        PENDING. A goal that was never selected says nothing about the sample,
        and leaving it PENDING in a finished run invites the reader to treat it
        as an absence of the behaviour.

        Rules, in order:

          * IN_PROGRESS -> TIMEOUT when the deadline ended the run, otherwise
            resolved as PARTIAL/FAILED from what it produced. The goal was
            genuinely being worked, so it gets the same evidence-driven
            treatment any attempted goal gets.
          * PENDING -> NOT_REACHED. Never selected; there is nothing to judge.

        Idempotent, so a second call after a late event changes nothing.
        Returns a count of goals moved into each state.
        """
        moved: Dict[str, int] = {}
        for goal in self._goals:
            if goal.status in TERMINAL_STATES or goal.status in (
                GoalStatus.PARTIAL, GoalStatus.FAILED,
                GoalStatus.NOT_REACHED, GoalStatus.TIMEOUT,
            ):
                continue
            if goal.status == GoalStatus.IN_PROGRESS:
                if timed_out:
                    self.mark_timed_out(goal.name)
                else:
                    self.resolve_goal(goal.name, reason=reason or "run_ended")
            elif goal.status == GoalStatus.PENDING:
                goal.status = GoalStatus.NOT_REACHED
                goal.failure_reason = (
                    TIMEOUT_REASON if timed_out
                    else (reason or "run_ended_before_selection")
                )
            else:
                continue
            moved[goal.status.value] = moved.get(goal.status.value, 0) + 1
        if moved:
            logger.info(
                "[GoalTracker] finalize(timed_out=%s): %s", timed_out, moved,
            )
        return moved

    def auto_skip_if_applicable(self, consecutive_empty_actions: int, threshold: int = 5) -> None:
        """
        Skip a `skip_if_missing` goal that has produced no CONFIRMING evidence.

        The predicate reads ``completion_evidence``, not ``evidence_collected``,
        and that distinction is the fix for a measured deadlock. The old test
        was ``len(evidence_collected) == 0``, but a category match appends to
        that list, and stage 2's category is `dangerous_apis` - emitted by 8
        hook sites. So a single ordinary ``Runtime.exec`` gave stage 2 one piece
        of category evidence, permanently disqualifying it from being skipped,
        while its (dead) completion hooks meant it could never complete either.
        Stages 3, 4 and 5 depend on stage 2, so the whole graph stalled.

        Ordering alone would not have fixed it: the goal legitimately HAS
        same-category evidence, and forever. What matters is that none of that
        evidence could ever CONFIRM the goal, and only completion_evidence
        answers that question.

        Called by the agent loop after each iteration.
        """
        next_goal = self.next_priority_goal()
        if next_goal and next_goal.skip_if_missing:
            if (
                next_goal.status == GoalStatus.IN_PROGRESS
                and len(next_goal.completion_evidence) == 0
                and consecutive_empty_actions >= threshold
                # The goal's OWN budget, not just the global silence streak.
                # Without this, a long-quiet run skips every subsequent goal on
                # first sight - see MIN_ATTEMPTS_BEFORE_SKIP.
                and next_goal.attempts >= MIN_ATTEMPTS_BEFORE_SKIP
            ):
                next_goal.status = GoalStatus.SKIPPED
                logger.info(
                    "[GoalTracker] '%s' → SKIPPED (no confirming evidence after "
                    "%d of its own actions and %d quiet actions overall; %d "
                    "same-category event(s) seen but none could complete it)",
                    next_goal.name, next_goal.attempts, consecutive_empty_actions,
                    len(next_goal.evidence_collected),
                )

    def record_attempt(self, goal_name: str) -> None:
        """Increment attempt counter for a goal."""
        goal = self.get_goal_by_name(goal_name)
        if goal:
            goal.attempts += 1

    # ── Post-run gap audit ─────────────────────────────────────────────────────

    def audit_unfulfilled_goals(self) -> List[Dict[str, Any]]:
        """
        Which fraud goals finished the run without evidence, and why.

        This is the forensic counterpart to :meth:`completion_summary`. That
        method reports *what* happened; this one reports what did **not**, and
        distinguishes the three reasons a goal can end unfulfilled - because
        they call for different remediation:

        ``blocked``
            A dependency stage never completed, so the agent could not legally
            attempt this goal. Fixing the dependency fixes this one for free.
        ``attempted``
            The agent tried and could not trigger the behaviour. This is the
            interesting case: it may be evasion, or a missing precondition.
        ``never_attempted``
            The run ended - budget, timeout or crash - before the goal came up.
            Says nothing about the sample at all.

        ``unsupported``
            No instrument in this engine could confirm the goal. A statement
            about Sudarshan, not about the sample, and never an absence of the
            behaviour.

        Ordered by stage so the earliest unmet goal, which usually unblocks the
        rest, is first.
        """
        resolved = self._resolved_stages()
        satisfied = self._satisfied_stages()
        audit: List[Dict[str, Any]] = []

        for goal in sorted(self._goals, key=lambda g: g.stage):
            if goal.status == GoalStatus.COMPLETED:
                continue
            # A goal with CONFIRMING evidence is not a gap. Previously any
            # same-category event suppressed the audit entry, which hid exactly
            # the goals that had noise but no confirmation - the stalled ones.
            if goal.completion_evidence:
                continue

            if goal.status == GoalStatus.UNSUPPORTED:
                reason = "unsupported"
            elif not goal.is_unblocked(resolved):
                reason = "blocked"
            elif goal.attempts > 0 or goal.status == GoalStatus.FAILED:
                reason = "attempted"
            else:
                reason = "never_attempted"

            blocking_stages = [s for s in goal.depends_on if s not in resolved]
            unsatisfied_deps = [s for s in goal.depends_on if s not in satisfied]
            audit.append(
                {
                    "goal_name": goal.name,
                    "stage": goal.stage,
                    "status": goal.status.value,
                    "description": goal.description,
                    "reason": reason,
                    "attempts": goal.attempts,
                    "retries_used": goal.retries_used,
                    # Split so a reader can tell "nothing happened" from
                    # "things happened but none of them confirmed this".
                    "evidence_count": len(goal.evidence_collected),
                    "confirming_evidence_count": 0,
                    "blocked_by_stages": blocking_stages,
                    "blocked_by_goals": [
                        g.name for g in self._goals if g.stage in blocking_stages
                    ],
                    "unsatisfied_prerequisites": unsatisfied_deps,
                    "ran_without_prerequisite": list(goal.ran_without_prerequisite),
                    "confirmation_mode": goal.confirmation.value,
                    "unsupported_reason": goal.unsupported_reason,
                    "frida_categories": list(goal.frida_categories),
                    "skippable": goal.skip_if_missing,
                }
            )
        return audit

    def disposition_line(self) -> str:
        """
        One self-describing sentence about where the goal graph ended up.

        Exists because "1/15" meant three different things and said none of
        them. Used in the planner prompt and in the report header.
        """
        counts: Dict[str, int] = {}
        for goal in self._goals:
            counts[goal.status.value] = counts.get(goal.status.value, 0) + 1
        parts = [
            f"{counts[status]} {status.lower()}"
            for status in (
                GoalStatus.COMPLETED.value, GoalStatus.PARTIAL.value,
                GoalStatus.SKIPPED.value, GoalStatus.FAILED.value,
                GoalStatus.NOT_REACHED.value, GoalStatus.TIMEOUT.value,
                GoalStatus.BLOCKED.value, GoalStatus.NOT_APPLICABLE.value,
                GoalStatus.UNSUPPORTED.value,
                GoalStatus.IN_PROGRESS.value, GoalStatus.PENDING.value,
            )
            if counts.get(status)
        ]
        return f"{len(self._goals)} goals: " + ", ".join(parts)

    def coverage_report(self) -> Dict[str, Any]:
        """
        Goal-graph coverage for the report's gap-analysis section.

        Reports TWO ratios, because one number could not honestly carry the
        question. The old single `coverage_ratio` counted COMPLETED over all 15
        goals, so a run that legitimately skipped nine inapplicable stages and
        confirmed all six that applied scored 0.40 and read as poor coverage -
        the same number as a run that stalled.

          ``confirmed_ratio``   satisfied / all goals. What was PROVEN.
          ``assessed_ratio``    resolved / all goals. What was actually
                                ADJUDICATED - completed, skipped, failed or
                                unsupported - as opposed to left hanging.

        `coverage_ratio` is retained as an alias of `confirmed_ratio` so
        existing consumers keep their meaning rather than silently shifting.
        """
        total = len(self._goals)
        by_status: Dict[str, int] = {}
        for goal in self._goals:
            by_status[goal.status.value] = by_status.get(goal.status.value, 0) + 1

        satisfied = by_status.get(GoalStatus.COMPLETED.value, 0)
        partial = by_status.get(GoalStatus.PARTIAL.value, 0)
        failed = by_status.get(GoalStatus.FAILED.value, 0)
        skipped = by_status.get(GoalStatus.SKIPPED.value, 0)
        not_reached = by_status.get(GoalStatus.NOT_REACHED.value, 0)
        timed_out = by_status.get(GoalStatus.TIMEOUT.value, 0)
        unsupported_count = by_status.get(GoalStatus.UNSUPPORTED.value, 0)
        resolved = sum(
            1 for g in self._goals if g.status in RESOLVED_STATES
        )
        # Effective coverage: confirmed goals in full, partial goals at half.
        # A REPORTING convention, not a measurement, and deliberately kept out
        # of every scoring path - BFCI and FRS read observed events, never goal
        # states (§P13/§P17). It exists so "9 confirmed + 2 partial of 15"
        # reports 66.7% rather than 60% (partial evidence silently discarded)
        # or 73.3% (partial counted as proof).
        effective = satisfied + partial * PARTIAL_GOAL_WEIGHT
        unattempted = [
            g.stage for g in self._goals
            if g.attempts == 0 and g.status not in RESOLVED_STATES
        ]
        broken_chain = [
            {"stage": g.stage, "goal_name": g.name,
             "unsatisfied_prerequisites": list(g.ran_without_prerequisite)}
            for g in self._goals if g.ran_without_prerequisite
        ]
        unsupported = [
            {"stage": g.stage, "goal_name": g.name, "reason": g.unsupported_reason}
            for g in self._goals if g.status == GoalStatus.UNSUPPORTED
        ]

        return {
            "total_goals": total,
            "satisfied_goals": satisfied,
            "resolved_goals": resolved,
            # Per-state counts, flat, because this is the shape the dynamic
            # result contract and the analyst-facing coverage panel consume.
            "goals_total": total,
            "goals_successful": satisfied,
            "goals_partial": partial,
            "goals_failed": failed,
            "goals_skipped": skipped,
            "goals_not_reached": not_reached,
            "goals_timed_out": timed_out,
            "goals_unsupported": unsupported_count,
            "effective_goal_count": round(effective, 4),
            "effective_coverage_ratio": round(effective / total, 4) if total else 0.0,
            "confirmed_ratio": round(satisfied / total, 4) if total else 0.0,
            "assessed_ratio": round(resolved / total, 4) if total else 0.0,
            # Alias, kept so existing readers do not silently change meaning.
            # The §P12 contract's `coverage_ratio` is the EFFECTIVE one and is
            # published by dynamic_coverage.build_dynamic_coverage(); this one
            # keeps meaning "what was proven", as its docstring has promised.
            "coverage_ratio": round(satisfied / total, 4) if total else 0.0,
            "disposition": self.disposition_line(),
            "by_status": by_status,
            # Per-goal outcome detail, so the report can name which goals
            # succeeded, which were partial and which failed - and why - rather
            # than printing three integers.
            "goal_states": [
                {
                    "stage": g.stage,
                    "goal_name": g.name,
                    "status": g.status.value,
                    "attempts": g.attempts,
                    "planner_calls": g.planner_calls,
                    "time_spent_seconds": round(g.time_spent_seconds, 1),
                    "confirming_evidence_count": len(g.completion_evidence),
                    "related_evidence_count": len(g.evidence_collected),
                    "progress_signals": list(g.progress_signals),
                    "failure_reason": g.failure_reason,
                }
                for g in sorted(self._goals, key=lambda g: g.stage)
            ],
            "successful_goals": [
                g.name for g in self._goals if g.status == GoalStatus.COMPLETED
            ],
            "partial_goals": [
                g.name for g in self._goals if g.status == GoalStatus.PARTIAL
            ],
            "failed_goals": [
                g.name for g in self._goals if g.status == GoalStatus.FAILED
            ],
            "failure_reasons": sorted({
                g.failure_reason for g in self._goals if g.failure_reason
            }),
            # A non-empty list here means the graph stalled. It is the direct
            # regression signal for the deadlock this module was fixed for.
            "unattempted_stages": unattempted,
            "goals_run_without_prerequisite": broken_chain,
            "unsupported_goals": unsupported,
            "unfulfilled": self.audit_unfulfilled_goals(),
        }
