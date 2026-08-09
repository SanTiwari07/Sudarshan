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
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ─── Tunables ─────────────────────────────────────────────────────────────────

# Stage 1 is confirmed by observing the target package in the foreground for
# this many CONSECUTIVE observations. >1 rejects transient samples such as a
# splash screen or a launcher hand-off frame.
LAUNCH_CONFIRMATIONS_REQUIRED: int = 2

# How many times a FAILED goal may be retried before it is given up on.
MAX_GOAL_RETRIES: int = 1

# Name of the stage-1 goal, referenced by the foreground completion path.
LAUNCH_GOAL_NAME: str = "Launch Application"


# ─── Goal Status ──────────────────────────────────────────────────────────────

class GoalStatus(str, Enum):
    PENDING     = "PENDING"       # Not yet started
    IN_PROGRESS = "IN_PROGRESS"   # Agent is actively working on this goal
    COMPLETED   = "COMPLETED"     # Evidence collected or goal satisfied
    SKIPPED     = "SKIPPED"       # Evidence proves not applicable; skip safely
    FAILED      = "FAILED"        # Agent tried but could not trigger


# ─── Goal Definition ──────────────────────────────────────────────────────────

@dataclass
class FraudGoal:
    """
    A single exploration goal in the 15-stage dependency graph.

    Attributes:
        name:               Short identifier (used in prompts and logs).
        stage:              Dependency order - lower stages must complete first.
        description:        What the agent should do to trigger this goal.
        frida_categories:   Frida event categories that signal this goal is active.
        frida_hooks:        Specific hook names that confirm goal completion.
        depends_on:         Stage numbers that must be COMPLETED or SKIPPED first.
        skip_if_missing:    If True, auto-skip when no relevant Frida signals appear.
        evidence_collected: Frida events observed that relate to this goal.
        status:             Current lifecycle status.
        attempts:           How many actions the agent has taken toward this goal.
    """
    name:             str
    stage:            int
    description:      str
    frida_categories: List[str]           = field(default_factory=list)
    frida_hooks:      List[str]           = field(default_factory=list)
    depends_on:       List[int]           = field(default_factory=list)
    skip_if_missing:  bool                = False
    evidence_collected: List[Dict]        = field(default_factory=list)
    status:           GoalStatus          = GoalStatus.PENDING
    attempts:         int                 = 0
    retries_used:     int                 = 0

    def is_unblocked(self, completed_stages: Set[int]) -> bool:
        """Return True if all dependency stages are done (completed or skipped)."""
        return all(d in completed_stages for d in self.depends_on)

    def to_prompt_context(self) -> str:
        """Compact string representation for inclusion in agent prompts."""
        evidence_count = len(self.evidence_collected)
        return (
            f"[Stage {self.stage}] {self.name} - {self.status.value} "
            f"(evidence: {evidence_count}, attempts: {self.attempts}): {self.description}"
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
            frida_hooks=["ContextImpl.checkPermission", "PackageManager.checkPermission"],
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
            frida_hooks=[
                "AccessibilityService.onAccessibilityEvent",
                "AccessibilityManager.isEnabled",
                "Settings.Secure.getString/accessibility",
            ],
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
            frida_hooks=[
                "WindowManager.addView",
                "View.setType/TYPE_APPLICATION_OVERLAY",
                "Settings.canDrawOverlays",
            ],
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
            frida_hooks=[
                "SharedPreferences.getString",
                "Cipher.doFinal",
                # Banking trojans often skip login and go straight to a dashboard.
                # Activity.onResume for any 'home', 'main', 'dashboard', or 'wallet'
                # activity is a reliable signal that the post-auth state is reached.
                "Activity.onResume/home",
                "Activity.onResume/main",
                "Activity.onResume/dashboard",
                "Activity.onResume/wallet",
            ],
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
            frida_hooks=[
                "SmsManager.sendTextMessage",
                "SmsManager.sendMultipartTextMessage",
                "ContentResolver.query/sms",
                "BroadcastReceiver.onReceive/SMS_RECEIVED",
            ],
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
            frida_hooks=[
                "PackageManager.getInstalledPackages",
                "PackageManager.getInstalledApplications",
                "PackageManager.queryIntentActivities",
            ],
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
            frida_hooks=[
                "URL.openConnection",
                "HttpURLConnection.connect",
                "OkHttpClient.newCall",
                "Socket.connect",
            ],
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
            frida_hooks=[
                "DevicePolicyManager.setActiveAdmin",
                "AlarmManager.setRepeating",
                "JobScheduler.schedule",
                "PackageInstaller.createSession",
            ],
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
            frida_categories=["dangerous_apis"],
            frida_hooks=[
                "DexClassLoader.<init>",
                "PathClassLoader.<init>",
                "InMemoryDexClassLoader.<init>",
                "Runtime.load",
                "System.loadLibrary",
            ],
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
            frida_hooks=[
                "Method.invoke",
                "Class.forName",
                "Constructor.newInstance",
            ],
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
            frida_hooks=[
                "Activity.getIntent",
                "Uri.parse",
                "Intent.getData",
            ],
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
            frida_hooks=[
                "BroadcastReceiver.onReceive",
                "IntentFilter.addAction",
            ],
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
            frida_hooks=[
                "ContentProvider.query",
                "ContentProvider.insert",
                "Service.onStartCommand",
                "Activity.onCreate",
            ],
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
            frida_hooks=[
                "Service.onStartCommand",
                "Service.onCreate",
                "NotificationManager.notify",
                "WorkManager.enqueue",
            ],
            depends_on=[1, 9],
            skip_if_missing=True,
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

    # ── Public read API ────────────────────────────────────────────────────────

    @property
    def goals(self) -> List[FraudGoal]:
        return self._goals

    def get_goal(self, stage: int) -> Optional[FraudGoal]:
        return self._by_stage.get(stage)

    def get_goal_by_name(self, name: str) -> Optional[FraudGoal]:
        return next((g for g in self._goals if g.name == name), None)

    def _completed_stages(self) -> Set[int]:
        """Return set of stage numbers that are COMPLETED or SKIPPED."""
        return {
            g.stage for g in self._goals
            if g.status in (GoalStatus.COMPLETED, GoalStatus.SKIPPED)
        }

    def next_priority_goal(self) -> Optional[FraudGoal]:
        """
        Return the highest-priority unblocked, unfinished goal.

        Priority order:
          1. IN_PROGRESS goals first (resume interrupted work).
          2. PENDING goals in stage order (lower stage = higher priority).
          3. FAILED goals last (retry once before giving up).
        Returns None when all goals are COMPLETED, SKIPPED, or permanently FAILED.
        """
        completed = self._completed_stages()

        in_progress = [
            g for g in self._goals
            if g.status == GoalStatus.IN_PROGRESS and g.is_unblocked(completed)
        ]
        if in_progress:
            return in_progress[0]

        pending = [
            g for g in self._goals
            if g.status == GoalStatus.PENDING and g.is_unblocked(completed)
        ]
        if pending:
            return pending[0]

        # FAILED goals get exactly one retry before being given up on. Without
        # this branch a transient failure permanently removed a goal from the
        # graph, which is what the docstring above always promised but the code
        # did not previously do.
        retryable = [
            g for g in self._goals
            if g.status == GoalStatus.FAILED
            and g.is_unblocked(completed)
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
        else:
            lines.append(">>> ALL GOALS COMPLETED OR SKIPPED")
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
            category = event.get("category", "")
            hook = event.get("data", {}).get("hook", "")

            for goal in self._goals:
                if goal.status in (GoalStatus.COMPLETED, GoalStatus.SKIPPED):
                    continue
                # Match by category
                if category in goal.frida_categories:
                    goal.evidence_collected.append(event)
                    if goal.status == GoalStatus.PENDING:
                        goal.status = GoalStatus.IN_PROGRESS
                        changed.append(goal.name)
                        logger.info(
                            f"[GoalTracker] Goal '{goal.name}' → IN_PROGRESS "
                            f"(Frida category: {category})"
                        )
                # Check specific hook completion
                if any(h in hook for h in goal.frida_hooks):
                    if goal.status != GoalStatus.COMPLETED:
                        goal.status = GoalStatus.COMPLETED
                        changed.append(goal.name)
                        logger.info(
                            f"[GoalTracker] Goal '{goal.name}' → COMPLETED "
                            f"(hook: {hook})"
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
            changed.append(goal.name)
            logger.info(
                f"[GoalTracker] '{goal.name}' → COMPLETED "
                f"(foreground package confirmed {self._launch_confirmations}x)"
            )
        return changed

    def mark_failed(self, goal_name: str) -> None:
        """Called when the agent exhausts retries on a goal."""
        goal = self.get_goal_by_name(goal_name)
        if goal and goal.status != GoalStatus.COMPLETED:
            goal.status = GoalStatus.FAILED
            logger.warning(f"[GoalTracker] '{goal_name}' → FAILED (max attempts)")

    def auto_skip_if_applicable(self, consecutive_empty_actions: int, threshold: int = 5) -> None:
        """
        Auto-skip goals flagged with `skip_if_missing=True` if they have
        received no Frida evidence after `threshold` consecutive empty actions.
        Called by the agent loop after each iteration.
        """
        next_goal = self.next_priority_goal()
        if next_goal and next_goal.skip_if_missing:
            if (
                next_goal.status == GoalStatus.IN_PROGRESS
                and len(next_goal.evidence_collected) == 0
                and consecutive_empty_actions >= threshold
            ):
                next_goal.status = GoalStatus.SKIPPED
                logger.info(
                    f"[GoalTracker] '{next_goal.name}' → SKIPPED "
                    f"(no Frida evidence after {consecutive_empty_actions} actions)"
                )

    def record_attempt(self, goal_name: str) -> None:
        """Increment attempt counter for a goal."""
        goal = self.get_goal_by_name(goal_name)
        if goal:
            goal.attempts += 1
