"""
SUDARSHAN - Agentic Dynamic Analysis Explorer
==============================================
Orchestrates the full Observe → Think → Act → Execute agent loop for
dynamic analysis of Android applications.

Drop-in replacement for UIExplorer with the same public interface:
    start(duration_seconds: int) - async, runs the agent loop
    stop() - signals graceful termination
    get_reports() → Dict - returns all artifacts

Architecture principle:
    AI controls navigation. Deterministic engines control verdict.

    The AgenticExplorer NEVER:
      - Modifies BFCI scores.
      - Modifies STEI calculations.
      - Makes malware determinations.
      - Touches Threat Correlation logic.
      - Touches the Risk Engine.

    It ONLY explores the application and collects Frida evidence.
    All verdict logic remains in the existing deterministic pipeline.

Usage (same interface as UIExplorer)::

    explorer = AgenticExplorer(
        device_serial="emulator-5554",
        adb_path="adb",
        package_name="com.example.app",
        event_bus=event_bus,
    )
    await explorer.start(duration_seconds=60)
    reports = explorer.get_reports()
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.audit_log import AuditLog
from sudarshan_core.engines.agentic.benchmark import BenchmarkCollector
from sudarshan_core.engines.agentic.goal_tracker import GoalStatus, GoalTracker
from sudarshan_core.engines.agentic.action_verifier import (
    DeviceStateProbe,
    FieldSnapshot,
    StateSnapshot,
    VerificationResult,
    verify_action,
    verify_field_population,
)
from sudarshan_core.engines.agentic.adaptive_budget import (
    MAX_EXPLORATION_BUDGET_SECONDS,
    AdaptiveBudget,
)
from sudarshan_core.engines.agentic.field_classifier import (
    ClassificationSource,
    classify_field,
    classify_field_with_gemini,
    needs_escalation,
)
from sudarshan_core.engines.agentic.field_taxonomy import FieldType
from sudarshan_core.engines.agentic.auth_state import AuthState, AuthStateMachine
from sudarshan_core.engines.agentic.progress_tracker import ProgressTracker
from sudarshan_core.engines.agentic.perception import (
    PerceptionPipeline,
    in_investigation_scope,
    package_of,
)
from sudarshan_core.engines.agentic.screenshot_policy import is_safe_interactive_boundary
from sudarshan_core.engines.agentic.planner import AgentPlanner
from sudarshan_core.engines.agentic.action_dispatch import (
    ActionDispatcher,
    MAX_ACTION_SECONDS,
    MAX_EXECUTION_ATTEMPTS,
    pipeline_log,
    select_canonical_action,
)
from sudarshan_core.engines.dynamic_budget import (
    TIMEOUT_REASON,
    get_active_deadline,
)
from sudarshan_core.engines.dynamic_coverage import build_dynamic_coverage
from sudarshan_core.engines.agentic.tool_executor import (
    NAVIGATIONAL_TOOLS,
    ToolExecutor,
)
from sudarshan_core.engines.agentic.crash_classifier import (
    CrashContext,
    classify_crash,
    crash_event,
)
from sudarshan_core.engines.agentic.screen_classifier import (
    classify_screen,
    classify_screen_with_ownership,
    is_explorable_screen_type,
    should_invoke_planner,
    ScreenType,
)
from sudarshan_core.engines.agentic.secondary_payload import (
    SecondaryPayloadTracker,
)
from sudarshan_core.engines.agentic.form_recovery import (
    SOURCE as FORM_RECOVERY_SOURCE,
    STAGNATION_THRESHOLD as FORM_STAGNATION_THRESHOLD,
    FormRecoveryLadder,
    describe_form_screen,
)
from sudarshan_core.engines.agentic.ui_observation import describe_screen
from sudarshan_core.engines.event_bus import RuntimeEventBus
from sudarshan_core.engines.screenshot_manager import ScreenshotReason
from sudarshan_core.engines.investigation_controller import (
    InvestigationController,
    InvestigationState,
    score_progress,
)
from sudarshan_core.engines.permission_investigator import PermissionInvestigator
from sudarshan_core.engines.agentic.exploration_engine import (
    ExplorationGraph,
    ExplorationBudget,
    StopReason,
    EvidenceMomentType,
    _is_submit_label,
)

logger = logging.getLogger(__name__)

#: Screens where entering data IS entering credentials, so a submit on them
#: advances the authentication state and may be retried with a fresh identity.
#: DATA_ENTRY_FORM is deliberately absent - see its definition in
#: :mod:`~sudarshan_core.engines.agentic.screen_classifier`.
_CREDENTIAL_SCREEN_TYPES: frozenset = frozenset({
    "BANK_LOGIN",
    "OTP_SCREEN",
})

# ─── Configuration (env overrides) ────────────────────────────────────────────

# Maximum actions the agent may take before stopping.
#
# Raised with the analysis window and the per-stage budget, because it binds
# first: at 25 actions and 4 per stage the walk stops after ~6 stages no matter
# how long the window is, so raising the window alone changed nothing.
#
# Sized for the WORST case rather than the sample that prompted it: the fullest
# trojan plan is 14 stages, which needs 56 actions at 4 each. 60 leaves margin
# and costs ~252s at the measured 4.2s per action, inside the 300s window.
ACTION_BUDGET: int = ExplorationBudget.MAX_ACTIONS

# Per-action evidence frames route through ScreenshotPolicy instead of
# force=True bypass. Set SUDARSHAN_ACTION_EVIDENCE_FRAMES=0 to disable.
ACTION_EVIDENCE_FRAMES: bool = os.getenv(
    "SUDARSHAN_ACTION_EVIDENCE_FRAMES", "1"
).strip().lower() not in ("0", "false", "no")

# Frida-silence threshold: stop if no new events for this many consecutive actions.
FRIDA_SILENCE_THRESHOLD: int = ExplorationBudget.FRIDA_SILENCE_THRESHOLD

# Maximum actions the agent may take on a single goal before marking it failed.
# Prevents the agent from looping forever on goals that cannot be reached
# (e.g. Stage 5 Login Flow when the app has no conventional login screen).
# This activates mark_failed → retry branch in next_priority_goal().
MAX_ATTEMPTS_PER_GOAL: int = int(os.getenv("SUDARSHAN_MAX_ATTEMPTS_PER_GOAL", "8"))

# ── Per-goal time budget ──────────────────────────────────────────────────────
#
# The 30-minute wall clock is NOT divided equally across fifteen goals. Most
# goals resolve in a handful of actions and would waste a fixed slice; the ones
# that do not are precisely the ones that must be cut off. So each goal gets an
# upper bound rather than an allocation, and whatever it does not use is
# available to the goals that follow it.
#
# 90s is roughly a dozen actions at the measured per-iteration cost - enough to
# fill and submit a four-field form, which is the longest legitimate single-goal
# sequence in the corpus. A goal still working after that is looping, and the
# right answer is to record what it achieved and move on.
MAX_GOAL_SECONDS: float = float(os.getenv("SUDARSHAN_MAX_GOAL_SECONDS", "90"))

#: Times the walk will answer the SAME permission dialog on the SAME screen
#: before it stops trying and explores elsewhere.
#:
#: A permission screen the sandbox cannot satisfy re-renders identically after
#: every tap, which makes it the most effective trap on the device: a walk that
#: answers it on sight answers it forever and never reaches the sample's own
#: screens. Three is enough for a genuine two-step grant (Allow -> While using
#: the app) plus one retry, and few enough that a loop is caught within seconds.
MAX_PERMISSION_SCREEN_ATTEMPTS: int = int(
    os.getenv("SUDARSHAN_MAX_PERMISSION_SCREEN_ATTEMPTS", "3")
)

#: Recorded on the Login Flow goal when the app has explicitly refused the
#: synthetic credentials.
#:
#: This is a STOPPING condition, not a failure to report: an app that shows
#: "Invalid credentials" has answered the question, and no further synthetic
#: identity will be accepted. Retrying only spends budget the other
#: investigation branches need - accessibility abuse, overlay draw, SMS
#: interception, WebView phishing, dynamic code loading, C2 traffic - which is
#: what the run is actually here to observe.
AUTH_FLOW_REJECTED: str = "AUTH_FLOW_REJECTED"

#: The smallest slice worth starting a goal with. A goal begun with two seconds
#: left produces one half-verified action and a misleading FAILED; refusing it
#: and recording TIMEOUT is the honest outcome.
MIN_GOAL_SLICE_SECONDS: float = float(
    os.getenv("SUDARSHAN_MIN_GOAL_SLICE_SECONDS", "10")
)

#: Planner (LLM) calls one goal may consume. Measured at ~12s each, so an
#: unbounded budget is how a single stubborn screen eats the window. Small on
#: purpose: after this the deterministic planner drives the goal, which is the
#: §P19 fallback and not a degraded mode.
MAX_PLANNER_CALLS_PER_GOAL: int = int(
    os.getenv("SUDARSHAN_MAX_PLANNER_CALLS_PER_GOAL", "4")
)

#: What one planner call is assumed to cost when deciding whether to start it.
#: Measured on gemini-2.5-flash with the explorer's real prompt: 7.9s, 13.8s,
#: 15.1s and 11.2s on consecutive iterations.
PLANNER_CALL_COST_SECONDS: float = float(
    os.getenv("SUDARSHAN_PLANNER_CALL_COST_SECONDS", "15")
)

# ── Planner budget ────────────────────────────────────────────────────────────
#
# How many consecutive graph-led iterations may pass before the planner is
# consulted anyway. The graph cannot propose device-state work - granting a
# permission, injecting a test SMS, warping the clock - so the model has to get
# a turn even when the graph always has a tap to offer.
#
# Four is a deliberate trade: at ~12s per call it costs ~3s per iteration
# amortised, against ~12s when every iteration paid for one.
PLANNER_CONSULT_EVERY: int = int(os.getenv("SUDARSHAN_PLANNER_CONSULT_EVERY", "4"))

#: Tools the graph wins outright in select_canonical_action. When the graph
#: offers one of these, the planner's answer is discarded - so computing it is
#: pure latency. Kept in sync with that function by the test in
#: test_planner_budget.py, which fails if the two lists drift apart.
_GRAPH_WINS_TOOLS = frozenset({
    "click_text", "tap", "tap_sequence", "type_text", "check",
})


def _planner_could_change_outcome(graph_action: Optional[Dict[str, Any]]) -> bool:
    """
    Whether consulting the planner can still affect what happens this iteration.

    False only when the graph already holds an action that select_canonical_action
    will pick over anything the planner returns. The one exception it keeps is
    the narrow hint-substitution path: a `type_text` whose field the graph could
    not name is exactly where a model that can read the screen earns its cost.
    """
    if not graph_action:
        return True
    tool = graph_action.get("tool", "")
    if tool not in _GRAPH_WINS_TOOLS:
        return True
    if tool == "type_text":
        # The graph knows WHERE to type; the planner may know WHAT. Only worth
        # asking when the graph could not work the field out for itself.
        return str(graph_action.get("field_type", "")) in ("", "UNKNOWN")
    return False


# Attempts after which a demonstrably inert control stops being retried.
# Applies ONLY when ADB reported success, the window settled, and the screen is
# unchanged - see the no-op short circuit in _execute_with_bounded_retries().
# The full MAX_EXECUTION_ATTEMPTS ladder still runs for anything ambiguous.
NOOP_RETRY_ATTEMPTS: int = int(os.getenv("SUDARSHAN_NOOP_RETRY_ATTEMPTS", "2"))

# In-app view hierarchies retained for VIDE, one per distinct screen. Each is
# capped at 120 KB, so 40 bounds the report contribution at ~5 MB worst case.
MAX_STATE_HIERARCHIES: int = int(
    os.getenv("SUDARSHAN_MAX_STATE_HIERARCHIES", "40")
)


# ─── Crash recovery pacing ────────────────────────────────────────────────────
# A crash screen used to be followed by a flat 1.5 s sleep and an immediate
# re-observe, which frequently caught the app still starting, produced another
# crash screen, and burned the entire action budget in a relaunch loop.
CRASH_RECOVERY_TIMEOUT_SECONDS: float = float(
    os.getenv("SUDARSHAN_CRASH_RECOVERY_TIMEOUT", "10.0")
)
CRASH_RECOVERY_BASE_SECONDS: float = float(
    os.getenv("SUDARSHAN_CRASH_RECOVERY_BASE", "2.0")
)
CRASH_RECOVERY_MAX_SECONDS: float = float(
    os.getenv("SUDARSHAN_CRASH_RECOVERY_MAX", "8.0")
)
# An app that dies this many times running is not going to be explored. Stop and
# keep what was collected rather than spending the budget on relaunches.
MAX_CONSECUTIVE_CRASHES: int = int(
    os.getenv("SUDARSHAN_MAX_CONSECUTIVE_CRASHES", "3")
)
# An ANR whose process is still alive is not a crash, and must not spend the
# crash budget at the same rate.
#
# Attaching Frida and installing ~70 hooks runs on the app's main thread, so the
# app misses the window-focus event and Android reports
# "Input dispatching timed out ... Waited 5002ms for FocusEvent(hasFocus=true)".
# Measured on the e-challan payload: the dialog appears once per attach, "Wait"
# clears it, and the app then behaves normally. Counting each one as a crash
# retired the 3-crash budget before the walk had taken an action - exploration
# stopped at 2 actions on 0 screens with the form never reached.
#
# A separate, larger budget: a genuinely wedged app still terminates the run,
# but a startup stall the walk can wait out no longer does.
MAX_SURVIVABLE_ANRS: int = int(
    os.getenv("SUDARSHAN_MAX_SURVIVABLE_ANRS", "8")
)

# ─── In-content settle delay ──────────────────────────────────────────────────
# wait_for_idle() uses `dumpsys window | grep mCurrentFocus` to detect when the
# foreground Activity has stopped changing.  This is accurate for cold Activity
# starts and explicit window transitions, but it fires almost immediately for
# in-app dialogs, progress spinners, and partial-screen overlays — the entire
# class of UI that appears AFTER clicking INSTALL / OK / Allow on a prompt
# screen that stays in the same Activity.
#
# This additional sleep runs after the window-focus signal clears, giving the
# in-content layout a moment to stabilise before the post-action observe runs.
# It is applied only to click_text/tap actions sourced from the exploration
# graph (not the planner), because those are the interactive CTAs most likely
# to trigger an in-app transition that the focus probe cannot see.
#
# Default: 1.5 s.  Raise on a slow emulator:
#   SUDARSHAN_CONTENT_SETTLE_SECONDS=3.0   docker compose up
CONTENT_SETTLE_SECONDS: float = float(
    os.getenv("SUDARSHAN_CONTENT_SETTLE_SECONDS", "1.5")
)

# ─── Out-of-scope navigation recovery ─────────────────────────────────────────
# A tap on "Phone", a share sheet or an ACTION_VIEW intent hands the foreground
# to another app. Observed on InsecureBankv2: the agent tapped through to the
# system Contacts app and spent 12 of its 16 actions there pressing back, so the
# sample's own login screen - the credential-entry surface the run exists to
# exercise - was never reached, and the screenshots in the report were of AOSP.
#
# The first departure is treated as a dialog or chooser that Back will close,
# which preserves the app's task stack. If the agent is still outside the scope
# on the next observation, Back is not working and the app is relaunched
# outright.
BACK_BEFORE_RELAUNCH: int = int(
    os.getenv("SUDARSHAN_OUT_OF_SCOPE_BACK_ATTEMPTS", "1")
)
# An app that keeps throwing the agent out - a launcher-replacement, or a sample
# that re-fires its intent on resume - will not be explored by trying harder.
# Past this many consecutive recovery attempts the guard stops spending budget
# and lets the loop's own stopping conditions end the run.
MAX_OUT_OF_SCOPE_RECOVERIES: int = int(
    os.getenv("SUDARSHAN_MAX_OUT_OF_SCOPE_RECOVERIES", "6")
)

from sudarshan_core.ai.gemini_provider import gemini_is_configured


#: Android's reply when `am start -n` names a component that no longer resolves.
#: Matched on the message rather than the exit code because `am` exits 0 while
#: printing this to stdout.
_MISSING_COMPONENT_MARKERS = (
    "does not exist",
    "activity class",
    "unable to resolve intent",
)


def _launcher_component_missing(result: Any) -> bool:
    """
    Whether a relaunch failed because the target component is gone.

    Distinguishes "the app hid itself" from an ordinary transient failure, so
    the first conclusive answer ends the retry loop instead of the sixth.
    """
    if result is None:
        return False
    text = f"{getattr(result, 'output', '') or ''} {getattr(result, 'error', '') or ''}".lower()
    if not text.strip():
        return False
    return any(marker in text for marker in _MISSING_COMPONENT_MARKERS)


class AgenticExplorer:
    """
    Goal-driven AI explorer implementing the full Observe→Think→Act→Execute loop.

    Public interface is identical to UIExplorer to ensure zero changes are
    needed in frida_sandbox.py beyond the import swap.
    """

    def __init__(
        self,
        device_serial: str,
        adb_path:      str              = "adb",
        package_name:  str              = "",
        event_bus:     Optional[RuntimeEventBus] = None,
        screenshot_manager: Optional[Any] = None,
        static_findings: Optional[Dict[str, Any]] = None,
        accessibility_service_class: Optional[str] = None,
        main_activity: Optional[str] = None,
        pregranted_permissions: Optional[List[str]] = None,
    ) -> None:
        self.device_serial   = device_serial
        self.adb_path        = adb_path
        self.package_name    = package_name
        self.event_bus       = event_bus
        self.screenshot_manager = screenshot_manager
        self.static_findings = static_findings or {}
        # The launchable component, as "<package>/<activity>", used to put the
        # app back in the foreground after a crash or after the agent is thrown
        # into another app.
        #
        # This attribute was read in the crash-recovery path but never assigned,
        # so every relaunch raised AttributeError into the `except Exception`
        # around it: recovery silently did nothing and the run burned its budget
        # re-observing a dead app. Defaulting to "" keeps that path honest - the
        # callers that cannot resolve a launcher fall back to press_home rather
        # than issuing `am start` with a missing component.
        self.main_activity: str = main_activity or ""

        # Secondary payloads (§19/§20): the second APK a dropper fetches.
        # Fed from _on_frida_event so it sees the whole runtime stream.
        self._payloads = SecondaryPayloadTracker(parent_package=package_name)

        # Permission investigation.
        #
        # Seeded from the manifest permissions that now arrive over the static
        # bridge. When static_findings is empty - a validation harness, a
        # recovery re-run - the investigator still works: it simply has no
        # declared set to compare against, and says so rather than inventing one.
        self.permissions = PermissionInvestigator(
            package_name=package_name,
            app_label=str(self.static_findings.get("app_label") or ""),
        )
        # Capability handed to the sample by the harness before it ran. Recorded
        # as granted-but-never-requested, which classifies as
        # GRANTED_WITHOUT_REQUEST: a finding about our own setup, not about the
        # app. Without it the report shows a sample holding SMS access with no
        # account of how it got there.
        pregranted = list(pregranted_permissions or [])

        declared = self.static_findings.get("permissions") or []
        if declared:
            self.permissions.record_declared(declared)
            logger.info(
                "[AgenticExplorer] Static bridge: %d declared permission(s); "
                "app category inferred as %s (%s)",
                len(declared),
                self.permissions.profile.category.value,
                self.permissions.profile.inference.confidence,
            )
        if pregranted:
            for perm in pregranted:
                self.permissions.record_granted(perm, True)
            logger.info(
                "[AgenticExplorer] %d permission(s) were pre-granted before "
                "launch - no runtime dialog will appear for them, so what the "
                "sample would have requested cannot be observed this run.",
                len(pregranted),
            )
        else:
            logger.info(
                "[AgenticExplorer] No static findings supplied - permission "
                "expectations cannot be evaluated for this run."
            )

        # Investigation lifecycle: which stage, what is allowed here, what next.
        # Seeded from the static signals that now arrive over the bridge, so a
        # calculator and a banking trojan get different plans rather than the
        # same flat loop.
        self.investigation = InvestigationController(
            package_name=package_name,
            category=self.permissions.profile.category,
            static_flags=self.static_findings.get("flags") or {},
            special_permissions=[
                r.permission for r in self.permissions.special_permissions()
            ],
            max_actions=ACTION_BUDGET,
        )
        logger.info(
            "[Investigation] Plan for %s (%s): %s",
            package_name or "?",
            self.permissions.profile.category.value,
            " -> ".join(st.value for st in self.investigation.plan),
        )

        # Subsystems
        self.goals      = GoalTracker()
        #: Which goal the current iteration is being charged to, and when that
        #: charge started. Kept on the explorer rather than in GoalTracker
        #: because the tracker is a pure state machine with no clock of its own.
        self._current_goal_name: str = ""
        self._current_goal_started: float = 0.0
        #: Permission screens answered this run, keyed by (permission,
        #: screen_hash). See _note_permission_screen - this is what stops the
        #: walk answering the same dialog forever (§P7).
        self._permission_attempts: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.memory     = AgentMemory()
        self.audit_log  = AuditLog()
        self.benchmark  = BenchmarkCollector(package_name=package_name)
        self.perception = PerceptionPipeline(
            device_serial=device_serial,
            package_name=package_name,
            adb_path=adb_path,
            screenshot_manager=screenshot_manager,
        )
        self.executor   = ToolExecutor(
            device_serial=device_serial,
            package_name=package_name,
            adb_path=adb_path,
            accessibility_service_class=accessibility_service_class,
            screenshot_manager=screenshot_manager,
        )
        # Verification reads device state through the executor's ADB channel,
        # which routes via the policy-enforcing SandboxProvider. The probe must
        # never open its own transport or it would bypass those controls.
        self._probe = DeviceStateProbe(
            self.executor._adb,
            package_name,
            # The persistent device channel, injected the same way: the probe
            # still owns no transport, it is just handed a hierarchy read that
            # does not cost a subprocess. Falls back to ADB on its own when the
            # channel is unavailable.
            dump_hierarchy=self.executor._channel.dump_hierarchy,
        )
        # A screen-changing action awaiting judgement by the next observation.
        self._pending_verification = None
        # Every crash this run, classified. Reported rather than summed: three
        # crashes of three different kinds is a different story from three of
        # the same kind.
        self.crash_findings: List[Any] = []
        # Stages whose deterministic procedure has already run, so returning to
        # a stage does not repeat work that is not idempotent on the device.
        self._procedures_run: set = set()

        # Deep exploration state graph (deterministic coverage engine)
        self.exploration = ExplorationGraph(package_name=package_name)

        planner_mode = os.getenv("SUDARSHAN_PLANNER_MODE", "").lower()
        
        agent_planner = AgentPlanner(
            api_key="configured" if gemini_is_configured() else None,
            device_serial=device_serial,
            package_name=package_name,
            action_budget=ACTION_BUDGET,
            benchmark=self.benchmark,
            adb_path=adb_path,
        )

        if planner_mode == "jev":
            from sudarshan_core.engines.agentic.jev_planner import JevPlanner
            self.planner = JevPlanner(
                api_key=os.getenv("TYPESAFE_JEV_API_KEY", ""),
                device_serial=device_serial,
                package_name=package_name,
                action_budget=ACTION_BUDGET,
                benchmark=self.benchmark,
                adb_path=adb_path,
                exploration=self.exploration
            )
        elif planner_mode == "laya":
            from sudarshan_core.engines.agentic.laya_planner import LayaPlanner
            self.planner = LayaPlanner(
                device_serial=device_serial,
                package_name=package_name,
                action_budget=ACTION_BUDGET,
                benchmark=self.benchmark,
                adb_path=adb_path,
                exploration=self.exploration
            )
        elif planner_mode == "hybrid":
            from sudarshan_core.engines.agentic.jev_planner import JevPlanner
            from sudarshan_core.engines.agentic.hybrid_planner import HybridPlanner
            jev_planner = JevPlanner(
                api_key=os.getenv("TYPESAFE_JEV_API_KEY", ""),
                device_serial=device_serial,
                package_name=package_name,
                action_budget=ACTION_BUDGET,
                benchmark=self.benchmark,
                adb_path=adb_path,
                exploration=self.exploration
            )
            self.planner = HybridPlanner(jev_planner, agent_planner)
        elif planner_mode == "laya_hybrid":
            from sudarshan_core.engines.agentic.laya_planner import LayaPlanner
            from sudarshan_core.engines.agentic.jev_planner import JevPlanner
            from sudarshan_core.engines.agentic.decision_provider import create_decision_provider
            
            laya_planner = LayaPlanner(
                device_serial=device_serial,
                package_name=package_name,
                action_budget=ACTION_BUDGET,
                benchmark=self.benchmark,
                adb_path=adb_path,
                exploration=self.exploration
            )
            jev_planner = JevPlanner(
                api_key=os.getenv("TYPESAFE_JEV_API_KEY", ""),
                device_serial=device_serial,
                package_name=package_name,
                action_budget=ACTION_BUDGET,
                benchmark=self.benchmark,
                adb_path=adb_path,
                exploration=self.exploration
            )
            self.planner = create_decision_provider(
                "laya_hybrid",
                laya_planner=laya_planner,
                jev_planner=jev_planner,
                agent_planner=agent_planner,
                exploration=self.exploration,
            )
        else:
            self.planner = agent_planner
        self.dispatcher = ActionDispatcher()
        self._stop_reason: Optional[StopReason] = None

        # Target process identity. Re-resolved when the walk comes back from a
        # system boundary, because an installer or a self-restart replaces the
        # process without ending the investigation.
        self._target_pid: int = 0
        self._target_pid_changes: int = 0
        self._pre_action_state_id: str = ""
        self._pre_action_screen_hash: str = ""
        # Whether the retry ladder already waited for the window to settle for
        # the action currently in flight, so the loop's SETTLE step can skip a
        # duplicate wait_for_idle.
        self._settled_during_execute: bool = False
        # Set when the action just dispatched submits a credential form, so the
        # post-action observation is judged as a login outcome.
        self._submitted_credentials: bool = False
        # Explicit authentication workflow position. `login_outcome` on the
        # exploration graph keeps its old four values and is derived from this,
        # so nothing that already reads it has to change.
        self.auth: AuthStateMachine = AuthStateMachine()
        # Shared answer to "is the walk still learning anything?", used by the
        # adaptive budget and loop recovery instead of each deriving its own.
        self.progress: ProgressTracker = ProgressTracker(
            stagnation_limit=ExplorationBudget.FRIDA_SILENCE_THRESHOLD,
        )
        # Populated in start(), where the caller's duration is known.
        self.budget: Optional[AdaptiveBudget] = None
        # Child applications already explored, so a package that keeps coming
        # back to the foreground is not explored twice.
        self._explored_children: set = set()
        #: package -> "was this installed onto the device, or shipped with the
        #: image?". Answered once per package; see _is_third_party_package.
        self._third_party_cache: Dict[str, bool] = {}
        #: Third-party packages present before the walk started, filled in by
        #: run(). None until then, which reads as "no baseline, prove nothing".
        self._baseline_third_party: Optional[Set[str]] = None
        # State ids that already contributed an in-app evidence frame.
        self._state_frames_captured: set = set()
        # ── Form stagnation ───────────────────────────────────────────────────
        # Consecutive actions after which the screen was unchanged, and the
        # per-screen escalation ladder that answers it. A form the walk has
        # stopped being able to move is not a planning failure - the action was
        # aimed at a control the keyboard was standing in front of - so it needs
        # a different answer than re-planning or backtracking. See
        # form_recovery.
        self._unchanged_action_streak: int = 0
        self._form_recovery: FormRecoveryLadder = FormRecoveryLadder()
        self._form_recoveries_issued: int = 0
        # One view hierarchy per distinct in-app screen, keyed by state id.
        # VIDE compares view structure to decide whether a sample is a clone,
        # and a single hierarchy of the login form - the one screen a clone and
        # its target look alike on - is the weakest evidence available.
        self.state_ui_hierarchies: Dict[str, str] = {}

        # ── State ─────────────────────────────────────────────────────────────
        self._is_running:    bool              = False
        self._cancel_task:   bool              = False
        self._start_time:    float             = 0.0
        self._duration:      int               = 0

        # ── Frida event buffer (filled by EventBus callback) ──────────────────
        self._pending_frida_events: List[Dict] = []
        self._events_lock = threading.Lock()
        self.last_ui_hierarchy_xml: str = ""

        # ── Coverage artifacts (matches UIExplorer.get_reports() shape) ───────
        self.attack_timeline: List[Dict]        = []
        self.exploration_graph: List[Dict]      = []
        self.coverage_metrics: Dict[str, Any]   = {
            "screens": 0,
            "buttons_found": 0,
            "buttons_clicked": 0,
            "forms_found": 0,
            "forms_completed": 0,
            "permissions_granted": 0,
            "dialogs_dismissed": 0,
            "navigation_depth": 0,
            "coverage_percent": 0,
        }

        # Record application launch in victim journey
        self.exploration._journey.add_launch("00:00")

        # Subscribe to EventBus
        if self.event_bus:
            self.event_bus.subscribe(self._on_frida_event)

    # ── EventBus callback ──────────────────────────────────────────────────────

    def _launch_component(self) -> str:
        """
        The "<package>/<activity>" component `am start -n` needs, or "".

        Callers pass the main activity in either form - androguard returns a
        bare class name, while `cmd package resolve-activity` returns a full
        component - so both are accepted rather than requiring the caller to
        know which one it holds.
        """
        activity = (self.main_activity or "").strip()
        if not activity:
            return ""
        if "/" in activity:
            return activity
        if not self.package_name:
            return ""
        return f"{self.package_name}/{activity}"

    def _resolve_target_pid(self) -> int:
        """
        Current pid of the target package, or 0 when it is not running.

        Uses the sandbox provider's adb - never a private path to the device -
        and never raises: a pid reading that fails is a missing fact, not a
        reason to end an investigation.
        """
        try:
            from sudarshan_core.sandbox import get_sandbox_provider

            provider = get_sandbox_provider()
            args = ["-s", self.device_serial] if self.device_serial else []
            ok, out = provider.adb(
                *args, "shell", "pidof", self.package_name, timeout=10,
            )
        except Exception:  # noqa: BLE001
            return 0
        if not ok or not isinstance(out, str):
            return 0
        # `pidof` prints every matching pid, newest last on AOSP. The first is
        # the main process; the sample's :remote services are not the target.
        match = re.search(r"\d+", out)
        return int(match.group(0)) if match else 0

    async def _target_process_is_alive(self) -> bool:
        """
        Whether the sample (or a package it handed the journey to) is still up.

        This is what separates an ANR from a crash. Android puts the same style
        of dialog over both, but a process that is merely stalled can be waited
        out and explored afterwards, while one that has died cannot. Asked over
        the sandbox provider's adb, like every other device question here.
        """
        loop = asyncio.get_running_loop()

        def _alive() -> bool:
            if self._resolve_target_pid():
                return True
            # The companion is the app the victim is actually looking at, so an
            # ANR over IT is still a survivable stall for this investigation.
            companions = getattr(
                getattr(self, "exploration", None), "companion_packages", None,
            ) or []
            for package in companions:
                try:
                    from sudarshan_core.sandbox import get_sandbox_provider

                    provider = get_sandbox_provider()
                    args = ["-s", self.device_serial] if self.device_serial else []
                    ok, out = provider.adb(
                        *args, "shell", "pidof", package, timeout=10,
                    )
                except Exception:  # noqa: BLE001
                    continue
                if ok and isinstance(out, str) and re.search(r"\d+", out):
                    return True
            return False

        try:
            return await loop.run_in_executor(None, _alive)
        except Exception:  # noqa: BLE001
            # Unknown means "do not escalate": treat it as survivable and let
            # the ordinary budget end the run if the app really is gone.
            return True

    def _check_target_pid(self) -> None:
        """
        Notice that the sample restarted, and keep exploring it.

        A dropper that goes through the package installer or the VPN consent
        dialog frequently comes back as a NEW process: the installer replaced
        the package, or the app restarted itself after being granted what it
        asked for. The old pid is then dead, and everything keyed to it - a
        Frida session, a process-scoped hook - is talking to nothing.

        This is a process change, not a sandbox failure. Treating it as one
        ended runs at the exact moment the second stage began, which is the
        only moment that mattered. So: re-resolve, record, carry on.
        """
        current = self._resolve_target_pid()
        if not current:
            return
        if not self._target_pid:
            self._target_pid = current
            return
        if current == self._target_pid:
            return

        old, self._target_pid = self._target_pid, current
        self._target_pid_changes += 1
        logger.info(
            "[VSE] Target PID changed: old=%d new=%d. Resuming exploration.",
            old, current,
        )
        self.audit_log.record_system_event(
            "target_process_changed",
            f"{self.package_name} pid {old} -> {current} "
            f"(change #{self._target_pid_changes})",
        )
        if self.event_bus:
            try:
                self.event_bus.publish({
                    "type": "event",
                    "category": "persistence",
                    "severity": "MEDIUM",
                    "data": {
                        # Named for the observation - a pid that changed - not
                        # for a cause we did not hook.
                        "hook": "process.target_pid_changed",
                        "description": (
                            f"Target process restarted under a new pid "
                            f"({old} -> {current}); exploration continued"
                        ),
                        "package": self.package_name,
                        "old_pid": old,
                        "new_pid": current,
                    },
                })
            except Exception:  # noqa: BLE001
                pass

    #: Actions whose effect lives in device state rather than on screen. Only
    #: these justify the four ADB queries a full probe costs; everything else is
    #: judged from perception data the loop already holds.
    _DEVICE_STATE_ACTIONS = frozenset({
        "grant_permission", "deny_permission", "start_activity",
    })

    @staticmethod
    def _screen_text(obs: Any) -> str:
        """All visible text on a screen, for outcome detection."""
        parts: List[str] = []
        for n in getattr(obs, "ui_nodes", []) or []:
            for attr in ("text", "desc"):
                v = getattr(n, attr, "") or ""
                if v:
                    parts.append(v)
        # The hierarchy XML carries text the node filter drops - an inline error
        # label under a field is rarely clickable, and "Invalid credentials" is
        # exactly that kind of node.
        raw = getattr(obs, "ui_xml_raw", "") or ""
        if raw:
            parts.extend(re.findall(r'text="([^"]+)"', raw))
            parts.extend(re.findall(r'content-desc="([^"]+)"', raw))
        return " ".join(parts)

    async def _form_recovery_action(
        self,
        state: Any,
        classification: Any,
    ) -> Optional[Dict[str, Any]]:
        """
        Something to try when a form has stopped responding, or None.

        Engages only after FORM_STAGNATION_THRESHOLD consecutive actions left
        the screen unchanged, and only on a screen that actually has input
        fields. One unchanged screen is not stagnation - typing into a field is
        SUPPOSED to leave the hash where it was - and reacting to it would fire
        the ladder on every well-behaved form.

        The IME probe is the one device call this makes, and it only happens
        once stagnation is established, so a healthy walk never pays for it.
        """
        if self._unchanged_action_streak < FORM_STAGNATION_THRESHOLD:
            return None

        screen_type = str(getattr(classification, "screen_type", "") or "")
        form = describe_form_screen(state, screen_type)
        if not form.is_form:
            return None

        try:
            form.keyboard_visible = await self.executor.is_keyboard_visible()
        except Exception as exc:
            logger.debug("[AgenticExplorer] IME probe failed: %s", exc)
            form.keyboard_visible = None

        action = self._form_recovery.plan(form)
        if action is None:
            return None

        self._form_recoveries_issued += 1
        logger.info(
            "[AgenticExplorer] FORM_STAGNATION state=%s streak=%d step=%s "
            "inputs=%d unfilled=%d keyboard=%s",
            form.state_id, self._unchanged_action_streak,
            action.get("_recovery_step"), form.input_count,
            form.unfilled_input_count, form.keyboard_visible,
        )
        self.audit_log.record_system_event(
            "form_stagnation_recovery",
            f"state={form.state_id} step={action.get('_recovery_step')} "
            f"streak={self._unchanged_action_streak} "
            f"inputs={form.input_count} unfilled={form.unfilled_input_count}",
        )
        return action

    def _screen_observation(self, obs: Any, classification: Any) -> Any:
        """
        A perceptual description of what is on screen right now.

        Attached to every frame this explorer captures so the Screenshot
        Appendix and the evidence modal can say what a picture SHOWS rather
        than repeating why it was taken. Never raises: a description that
        cannot be built costs a sentence, not a frame.
        """
        try:
            return describe_screen(
                activity=getattr(obs, "activity", "") or "",
                ui_nodes=getattr(obs, "ui_nodes", None) or None,
                ui_xml=getattr(obs, "ui_xml_raw", "") or "",
                screen_type=str(getattr(classification, "screen_type", "") or ""),
                app_label=str(self.static_findings.get("app_label") or ""),
            )
        except Exception as exc:
            logger.debug("[AgenticExplorer] screen description failed: %s", exc)
            return None

    def _capture_state_frame(
        self,
        obs: Any,
        state: Any,
        classification: Any,
        reason: str = "",
        label: str = "",
    ) -> None:
        """
        One evidence frame per distinct in-app screen.

        The report used to show the launch screen and whatever the per-action
        capture happened to catch, which for a login-gated app is a picture of
        the login form and nothing else. VIDE compares a sample's screens
        against a known-good baseline to judge whether it is a clone, so the
        screens BEHIND the login are the ones that carry the signal.

        Deduplicated by state id, so a screen visited twenty times contributes
        one frame, and skipped entirely for anything that is not the sample.
        """
        if self.screenshot_manager is None:
            return
        state_id = getattr(state, "state_id", "") or ""
        ownership = str(getattr(classification, "ownership", "") or "")
        if not state_id or state_id.startswith("PLACEHOLDER-"):
            return
        if "TARGET_APP" not in ownership and ownership:
            return
        if state_id in self._state_frames_captured:
            return
        self._state_frames_captured.add(state_id)
        # Keep this screen's hierarchy alongside its frame. Bounded so a walk
        # through a large app cannot grow the report without limit.
        raw_xml = getattr(obs, "ui_xml_raw", "") or ""
        if raw_xml and len(self.state_ui_hierarchies) < MAX_STATE_HIERARCHIES:
            self.state_ui_hierarchies[state_id] = raw_xml[:120_000]
        semantic = str(getattr(classification, "screen_type", "") or "")
        # What this frame SHOWS, read from the hierarchy that produced it. The
        # capture reason says why the shutter fired and describes no picture;
        # this travels with the frame into the manifest so the appendix and the
        # evidence modal have something screen-specific to print.
        observation = self._screen_observation(obs, classification)
        try:
            self.screenshot_manager.capture_async(
                label=label or f"state_{state_id}_{semantic}".lower(),
                category="explorer_state",
                source="explorer",
                reason=reason or ScreenshotReason.SUSPICIOUS_UI.value,
                force=True,
                activity=getattr(obs, "activity", ""),
                state_id=state_id,
                foreground_package=package_of(getattr(obs, "activity", "")),
                layout_hash=getattr(obs, "screen_hash", ""),
                semantic_type=semantic,
                explorer_action=f"state:{state_id}",
                screen_observation=observation,
            )
            logger.info(
                "[AgenticExplorer] IN_APP_FRAME state=%s semantic=%s activity=%s",
                state_id, semantic, getattr(obs, "activity", ""),
            )
        except Exception as exc:
            logger.debug("[AgenticExplorer] state frame capture failed: %s", exc)

    async def _reusable_observation(self, carried: Any) -> Optional[Any]:
        """
        The carried post-action observation, if it still describes the screen.

        The loop used to read the device twice per iteration: once after an
        action settled, and again at the top of the next iteration, with nothing
        touching the device in between. Measured, that second read cost ~2.36s
        of `uiautomator dump` plus a ~1.61s `wait_for_idle` - together 43% and
        26% of a 310s run - to re-derive an answer already in hand.

        Reuse is not unconditional. A screen can change on its own: a delayed
        dialog, a network reply, an overlay a sample raises on a timer. So the
        cheap focus probe (one `dumpsys window` line, ~0.3s) is re-read and the
        carried observation is trusted only if the foreground window is exactly
        where it was. Anything else - a probe failure, a changed window, a
        missing signature - falls through to a full observation.
        """
        if not carried:
            return None
        obs, captured_sig = carried
        if obs is None or not captured_sig:
            return None
        try:
            current_sig = await self.executor._focus_signature()
        except Exception as exc:
            logger.debug("[AgenticExplorer] Focus probe failed, re-observing: %s", exc)
            return None
        if current_sig is None or current_sig != captured_sig:
            logger.debug(
                "[AgenticExplorer] Screen moved since post-action observe "
                "(%s -> %s) - re-observing",
                captured_sig, current_sig,
            )
            return None
        return obs

    async def _carry_observation(self, obs: Any) -> Optional[Tuple[Any, str]]:
        """Pair an observation with the focus signature it was taken under."""
        if obs is None:
            return None
        try:
            sig = await self.executor._focus_signature()
        except Exception:
            return None
        if not sig:
            return None
        return (obs, sig)

    async def _verification_snapshot(
        self, action: Dict[str, Any], obs: Any
    ) -> StateSnapshot:
        """Device state before an action, probed only when the action needs it."""
        if action.get("tool", "") in self._DEVICE_STATE_ACTIONS:
            try:
                return await self._probe.snapshot(
                    screen_hash=getattr(obs, "screen_hash", ""),
                    activity=getattr(obs, "activity", ""),
                )
            except Exception as exc:
                # A probe failure must leave the action UNVERIFIED, never
                # abort the investigation.
                logger.debug("[AgenticExplorer] State probe failed: %s", exc)
                return StateSnapshot()
        return StateSnapshot(
            screen_hash=getattr(obs, "screen_hash", ""),
            activity=getattr(obs, "activity", ""),
            foreground_package=package_of(getattr(obs, "activity", "")),
        )

    async def _verify_action(
        self, action: Dict[str, Any], before: StateSnapshot, obs: Any
    ) -> VerificationResult:
        """
        Decide whether the action did its job.

        Device-state actions are probed immediately, because their effect is
        already final once the command returns. Screen-changing actions are
        deferred to :meth:`_resolve_pending_verification`: the next OBSERVE
        reads the settled screen anyway, so verifying here would mean a second
        `uiautomator dump` per action for a worse answer.
        """
        if action.get("tool", "") not in self._DEVICE_STATE_ACTIONS:
            self._pending_verification = (dict(action), before)
            return VerificationResult(
                action=str(action.get("tool") or "unknown"),
                outcome="UNVERIFIED",
                detail="deferred to the next observation",
            )
        try:
            after = await self._probe.snapshot()
            return verify_action(action, before, after, self.package_name)
        except Exception as exc:
            logger.debug("[AgenticExplorer] Verification failed: %s", exc)
            return VerificationResult(
                action=str(action.get("tool") or "unknown"),
                detail=f"verification could not run: {exc}",
            )

    def _resolve_pending_verification(self, obs: Any) -> Optional[VerificationResult]:
        """
        Judge the previous screen-changing action against the screen we just read.

        Returns None when nothing was pending.
        """
        pending = self._pending_verification
        self._pending_verification = None
        if pending is None:
            return None
        action, before = pending
        after = StateSnapshot(
            screen_hash=getattr(obs, "screen_hash", ""),
            activity=getattr(obs, "activity", ""),
            foreground_package=package_of(getattr(obs, "activity", "")),
        )
        result = verify_action(action, before, after, self.package_name)
        if result.failed and before.screen_hash:
            # The action did not do what it claimed, so the cached choice for
            # the screen it was taken on must not be replayed.
            self.planner.invalidate_cache_for_screen(before.screen_hash)
        return result

    async def _resolve_ambiguous_fields(
        self, obs: Any, screen_type: str = "",
    ) -> Dict[str, Any]:
        """
        Name the input fields the local patterns could not.

        A registration / KYC / personal-details form rendered in a WebView
        gives its fields no caption, no resource-id and no content-desc, so
        every one of them falls through to the positional guess: the first is
        assumed to be the identifier and the rest resolve to UNKNOWN. They then
        all receive the same generic string, no email or phone validator
        accepts it, the form can never be submitted, and the walk eventually
        abandons a screen it never had a chance on.

        The deterministic pass still leads and still decides the ordinary
        captioned field. Only fields it could not name, on a screen that looks
        like a form, cost a model round trip.

        Returns {node_id: FieldClassification}, empty when nothing needed
        resolving. Never raises: an unavailable model degrades the
        classification, it does not stop the walk.
        """
        inputs = [n for n in (getattr(obs, "ui_nodes", None) or [])
                  if getattr(n, "is_input", False)]
        if not inputs:
            return {}

        deterministic: List[tuple] = []
        for index, node in enumerate(inputs):
            deterministic.append((node, classify_field(
                field_label=getattr(node, "field_label", "") or "",
                resource_id=getattr(node, "resource_id", "") or "",
                content_desc=getattr(node, "desc", "") or "",
                class_name=getattr(node, "class_name", "") or "",
                text=getattr(node, "text", "") or "",
                hint=getattr(node, "hint", "") or "",
                input_type=getattr(node, "input_type", "") or "",
                is_password=bool(getattr(node, "is_password", False)),
                index=index,
                screen_type=screen_type,
            )))

        is_webview = bool(getattr(obs, "is_webview", False))
        pending = [
            (node, c) for node, c in deterministic
            if needs_escalation(
                c, screen_type=screen_type, is_webview=is_webview,
            )
        ]
        if not pending:
            return {}

        unnamed = sum(
            1 for _, c in deterministic
            if c.source == ClassificationSource.POSITIONAL
        )
        logger.info(
            "[AgenticExplorer] FIELD_ESCALATION screen_type=%s inputs=%d "
            "unnamed=%d escalating=%d",
            screen_type or "UNKNOWN", len(inputs), unnamed, len(pending),
        )

        resolved: Dict[str, Any] = {}
        for node, det in pending:
            try:
                answer = await classify_field_with_gemini(
                    det,
                    field_label=getattr(node, "field_label", "") or "",
                    hint=getattr(node, "hint", "") or "",
                    resource_id=getattr(node, "resource_id", "") or "",
                    content_desc=getattr(node, "desc", "") or "",
                    class_name=getattr(node, "class_name", "") or "",
                    input_type=getattr(node, "input_type", "") or "",
                    is_password=bool(getattr(node, "is_password", False)),
                    screen_type=screen_type,
                    package=self.package_name,
                    activity=getattr(obs, "activity", "") or "",
                    ocr_text=self._screen_text(obs)[:400],
                )
            except Exception as exc:
                logger.debug(
                    "[AgenticExplorer] Field escalation failed: %s", exc,
                )
                continue
            if answer is not None and answer.field_type is not FieldType.UNKNOWN:
                resolved[getattr(node, "node_id", "")] = answer
        return resolved

    @staticmethod
    def _field_snapshot_from_obs(
        obs: Any, action: Dict[str, Any],
    ) -> Optional[FieldSnapshot]:
        """
        Find the field we typed into among the nodes of an observation.

        Built from the observation the loop has ALREADY taken rather than from
        a fresh `uiautomator dump`: a second dump costs ~700ms per typed field
        and would roughly double the cost of filling a login form, for the same
        answer.

        Matching is by resource-id, then by the tapped point falling inside a
        field's bounds. The coordinate route is what works on the WebView forms
        in the corpus, where no field carries an id.
        """
        nodes = [n for n in (getattr(obs, "ui_nodes", None) or [])
                 if getattr(n, "is_input", False)]
        if not nodes:
            return None

        wanted_id = str(action.get("resource_id") or "")
        match = None
        if wanted_id:
            for n in nodes:
                if (getattr(n, "resource_id", "") or "") == wanted_id:
                    match = n
                    break

        if match is None:
            x, y = action.get("x"), action.get("y")
            if isinstance(x, int) and isinstance(y, int):
                for n in nodes:
                    m = re.match(
                        r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                        getattr(n, "bounds", "") or "",
                    )
                    if not m:
                        continue
                    x1, y1, x2, y2 = map(int, m.groups())
                    if x1 <= x <= x2 and y1 <= y <= y2:
                        match = n
                        break

        if match is None:
            return None

        text = getattr(match, "text", "") or ""
        stripped = text.strip()
        return FieldSnapshot(
            found=True,
            text=text,
            text_read=True,
            text_length=len(stripped),
            is_password=bool(getattr(match, "is_password", False)),
            # uiautomator exposes focus, but the perception parser does not
            # carry it on UINode. None means "not reported", which the verifier
            # treats as no evidence either way rather than as unfocused.
            focused=None,
            enabled=bool(getattr(match, "enabled", True)),
            resource_id=getattr(match, "resource_id", "") or "",
            node_id=getattr(match, "node_id", "") or "",
            content_desc=getattr(match, "desc", "") or "",
        )

    def _verify_typed_field(
        self, action: Dict[str, Any], result: Any, post_obs: Any,
    ) -> Optional[VerificationResult]:
        """
        Verify that a type_text actually populated the field it aimed at.

        The screen-change rule cannot answer this: typing rarely changes the
        screen hash, so every type_text came back INCONCLUSIVE and a tap that
        missed the field was indistinguishable from a successful one. The walk
        then pressed Login on an empty form and read the resulting error as
        "credentials refused" - a wrong conclusion about the sample, drawn from
        a mechanical failure of our own.

        Returns None when the action was not a type_text or the field could not
        be located, which is INCONCLUSIVE rather than a failure.
        """
        if action.get("tool") != "type_text":
            return None

        snapshot = self._field_snapshot_from_obs(post_obs, action)
        if snapshot is None:
            return None

        data = getattr(result, "data", None) or {}
        expected_length = data.get("typed_length")

        verification = verify_field_population(
            action, snapshot, expected_length=expected_length,
        )
        # The value is never in this line - only its length and the field's
        # identity, both of which are already visible on the screen itself.
        logger.info("[AgenticExplorer] %s", verification.log_line())
        # §P28 / §P34: the forensic record of an input is (field_type,
        # value_source, result). The VALUE is deliberately absent: it is a
        # synthetic secret, and a persistent report carrying it in plaintext is
        # the thing §P28 exists to prevent. `value_source` names where the
        # value came from, which is what an analyst actually needs to know when
        # reading a screenshot of the filled form.
        logger.info(
            "[DAE][INPUT] field=%s source=%s result=%s",
            data.get("field_type") or action.get("field_hint") or "UNKNOWN",
            action.get("value_source") or "SYNTHETIC_PERSONA",
            "SUCCESS" if verification.succeeded else verification.outcome,
        )
        self.audit_log.record_system_event(
            "field_population_verified",
            f"field_hint={action.get('field_hint', '')} "
            f"field_type={data.get('field_type', '')} "
            f"outcome={verification.outcome}",
        )

        if verification.succeeded:
            # Only a VERIFIED population advances the authentication state. An
            # action that did not fill a field did not fill a field, whatever
            # ADB returned.
            self.auth.on_field_filled(
                str(data.get("field_type") or action.get("field_hint") or ""),
                verified=True,
                elapsed=self._elapsed_ts(),
            )
        return verification

    def _action_retry_variants(
        self,
        action: Dict[str, Any],
        attempt: int,
        tried: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        The next rung of the deterministic action ladder, or None when spent.

        The remaining wall-clock comes from the ONE global deadline, so a rung
        that cannot finish before it is never started (§P9/§P25).
        """
        return self.dispatcher.retry_payload(
            action,
            attempt,
            tried=tried,
            remaining_seconds=self._remaining_budget_seconds(),
        )

    def _remaining_budget_seconds(self) -> Optional[float]:
        """
        Seconds left in the WHOLE dynamic analysis, not in this stage.

        Reads the one shared deadline. Returns None only when no deadline is
        armed - a unit test or a replay - in which case callers keep their
        previous unbounded behaviour rather than inventing a second clock.
        """
        deadline = get_active_deadline()
        return deadline.remaining() if deadline is not None else None

    def _budget_allows(self, cost_seconds: float, stage: str) -> bool:
        """Whether an operation costing `cost_seconds` may start. See §P9."""
        deadline = get_active_deadline()
        if deadline is None:
            return True
        return deadline.allows(cost_seconds, stage=stage)

    async def _execute_with_bounded_retries(
        self,
        action: Dict[str, Any],
        obs: Any,
    ) -> Tuple[Any, VerificationResult, int]:
        """
        Execute one semantic action, walking the deterministic ladder.

        ADB exit code zero is not verification and never has been: a
        `click_text` that matched nothing, a `pm grant` Android refused and a
        relaunch of an Activity that died immediately all return success. Every
        rung is therefore judged by comparing device state PRE and POST (see
        action_verifier), and the ladder escalates only on a verdict, never on
        a return value.

        The ladder itself lives in ActionDispatcher.retry_payload - resource-id,
        node, text, bounds-centre, normalised coordinates, vision, then a
        re-aimed tap for an obstructed control - and is bounded three ways:
        MAX_EXECUTION_ATTEMPTS rungs, MAX_ACTION_SECONDS of wall clock, and the
        global deadline underneath both.

        Returns (result, verification, attempts). A FAILED verification here is
        an ACTION failure. It is not a goal failure and it is emphatically not
        a dynamic-analysis failure - see _resolve_goal_outcome and §P18.
        """
        from sudarshan_core.engines.agentic.semantic_action import (
            validate_coordinates_for_screen,
        )
        from sudarshan_core.engines.agentic.device_properties import get_screen_size

        sw, sh = get_screen_size(self.adb_path, self.device_serial)
        fg = package_of(getattr(obs, "activity", ""))
        x, y = action.get("x"), action.get("y")
        coord_ok = ""
        if x is not None and y is not None:
            ok, reason = validate_coordinates_for_screen(
                int(x), int(y),
                screen_width=sw,
                screen_height=sh,
                package=fg,
                expected_package="",
            )
            coord_ok = "PASS" if ok else "FAIL"
            action["_pipeline_debug"] = {
                **(action.get("_pipeline_debug") or {}),
                "coordinate_valid": ok,
                "coordinate_reason": reason,
            }
            if not ok:
                logger.warning(
                    "[AgenticExplorer] Coordinate validation failed: %s", reason
                )
                self.audit_log.record_system_event(
                    "coordinate_validation_failed", reason,
                )

        # Fresh per action; never inherit the previous action's settle result.
        self._settled_during_execute = False

        trace = self.dispatcher.begin_trace(action)
        trace.coordinate_validation = coord_ok
        trace.foreground_package_before = fg
        trace.state_before = getattr(obs, "screen_hash", "")
        pipeline_log(
            "ACTION_SELECTED",
            action_id=trace.action_id,
            priority=trace.prioritization_score,
            selected_by=trace.selected_by,
            semantic_role=trace.semantic_role,
            text=trace.text,
        )

        before = await self._verification_snapshot(action, obs)
        current = dict(action)
        result = None
        verification = VerificationResult(
            action=str(action.get("tool") or "unknown"),
            outcome="UNVERIFIED",
        )
        attempts = 0
        # The ladder's only state: which resolutions have been spent. Carried
        # here rather than on the payload so every rung is built from the
        # ORIGINAL action - rung 1 rewrites `text` to the resource-id, and
        # building the "resolve by visible text" rung on top of that would make
        # it a second resource-id lookup.
        strategies_tried: List[str] = []
        action_started = time.monotonic()

        for attempt_index in range(MAX_EXECUTION_ATTEMPTS):
            attempts = attempt_index + 1
            if attempt_index > 0:
                # Per-action wall clock, checked BEFORE the rung is built. One
                # action may not absorb the run: MAX_ACTION_SECONDS bounds the
                # whole ladder, and the global deadline bounds that in turn.
                spent = time.monotonic() - action_started
                if spent >= MAX_ACTION_SECONDS:
                    pipeline_log(
                        "ACTION_LADDER_TIME_EXHAUSTED",
                        action_id=trace.action_id,
                        spent=f"{spent:.1f}s",
                        budget=f"{MAX_ACTION_SECONDS:.0f}s",
                    )
                    break
                retry = self._action_retry_variants(
                    action, attempt_index, strategies_tried,
                )
                if retry is None:
                    break
                strategies_tried = list(retry.get("_strategies_tried") or [])
                current = retry
                pipeline_log(
                    "ACTION_RETRY",
                    attempt=attempts,
                    strategy=(current.get("_pipeline_debug") or {}).get("retry_strategy"),
                )

            pipeline_log(
                "ACTION_DISPATCHED",
                action_id=trace.action_id,
                tool=current.get("tool"),
                attempt=attempts,
            )
            trace.mark("ACTION_DISPATCHED")
            trace.executor_received = True
            trace.executor_method = str(current.get("tool") or "")
            pipeline_log("EXECUTOR", method=trace.executor_method, attempt=attempts)

            result = await self.executor.execute(current)
            data = getattr(result, "data", None) or {}
            trace.adb_command_generated = bool(data.get("adb_command_generated") or result.success)
            trace.adb_command_executed = bool(data.get("adb_command_executed") or result.success)
            trace.adb_return_code = data.get("adb_return_code", 0 if result.success else 1)
            trace.adb_stdout = str(data.get("adb_stdout") or result.output or "")
            if result.success:
                trace.mark("ACTION_EXECUTED")
                pipeline_log(
                    "ACTION_EXECUTED",
                    action_id=trace.action_id,
                    adb_rc=trace.adb_return_code,
                    x=data.get("x", current.get("x")),
                    y=data.get("y", current.get("y")),
                )
            else:
                pipeline_log(
                    "ACTION_EXECUTE_FAILED",
                    action_id=trace.action_id,
                    error=result.error,
                    attempt=attempts,
                )

            if current.get("tool", "") in NAVIGATIONAL_TOOLS:
                # Recorded so the SETTLE step in the main loop does not repeat
                # this wait. Both fired for every click_text, costing a measured
                # ~1.6s per iteration for a signal already read here.
                self._settled_during_execute = await self.executor.wait_for_idle(
                    timeout=2.0
                )

            # Text entry is done when ADB accepted it. The screen deliberately
            # does not change - a field's value is not part of screen identity -
            # so the verifier can only ever report "unchanged", and escalating
            # turns each filled field into three attempts: type, tap, tap. A
            # measured run spent them on every field and never reached the
            # submit button with a filled form.
            if result.success and current.get("tool", "") == "type_text":
                pipeline_log(
                    "ACTION_TEXT_ENTERED",
                    action_id=trace.action_id,
                    field_hint=current.get("field_hint", ""),
                )
                trace.action_verification = "PASS"
                trace.mark("ACTION_VERIFIED")
                return result, verification, attempts

            verification = await self._verify_action(current, before, obs)
            if result.success and verification.outcome != "FAILED":
                # Screen-changing tools stay UNVERIFIED until post-observe.
                if verification.outcome != "UNVERIFIED" and not verification.failed:
                    trace.action_verification = "PASS"
                    trace.mark("ACTION_VERIFIED")
                    return result, verification, attempts
                if verification.outcome == "UNVERIFIED":
                    return result, verification, attempts

            # ── No-op short circuit ───────────────────────────────────────────
            # A retry earns its cost when the UI might still be transitioning.
            # It earns nothing when ADB reported success, the window has been
            # observed to settle, and the screen is demonstrably where it was:
            # that combination says the control did nothing, and doing it a
            # third time will not change the answer. Measured, each extra
            # attempt costs ~7s, and 7 of 21 iterations in a 310s run spent the
            # full ladder on controls that were genuinely inert (an ActionBar
            # title, a Login button with empty credentials).
            #
            # Deliberately narrow: if wait_for_idle could NOT confirm the window
            # settled, the screen may still be moving and the ladder runs in
            # full, preserving the timing-race protection that already exists.
            screen_unchanged = "unchanged" in str(
                getattr(verification, "observed", "") or ""
            ).lower()
            if (
                result.success
                and self._settled_during_execute
                and screen_unchanged
                and attempts >= NOOP_RETRY_ATTEMPTS
            ):
                pipeline_log(
                    "ACTION_NOOP_SHORT_CIRCUIT",
                    action_id=trace.action_id,
                    attempts=attempts,
                    observed=str(getattr(verification, "observed", "")),
                )
                logger.debug(
                    "[AgenticExplorer] '%s' is inert (adb ok, window settled, "
                    "screen unchanged) after %d attempts - not escalating",
                    action.get("text") or action.get("tool"), attempts,
                )
                break

        if result is None:
            result = await self.executor.execute(action)
            attempts = max(attempts, 1)
        if verification.failed or not result.success:
            self.audit_log.record_system_event(
                "action_execution_failed",
                f"tool={action.get('tool')} attempts={attempts}",
            )
            pipeline_log(
                "ACTION_EXECUTION_FAILED",
                action_id=trace.action_id,
                attempts=attempts,
            )
        return result, verification, attempts

    async def _run_stage_procedure(self) -> None:
        """
        Run the deterministic procedure a stage owns, once per stage.

        §10 is explicit that Gemini must not be responsible for blindly
        navigating Android Settings. Accessibility is the case that matters: the
        capability is behind a Settings toggle, a banking trojan's payload is
        usually gated on it, and hoping the planner finds the right row is how
        Cerberus ran for 90 seconds without its payload ever starting.

        Idempotent - a stage that has already run its procedure does not repeat
        it, so returning to the stage later costs nothing.
        """
        state = self.investigation.state
        if state in self._procedures_run:
            return
        if state is not InvestigationState.ACCESSIBILITY_ANALYSIS:
            return
        self._procedures_run.add(state)

        service_class = getattr(self.executor, "accessibility_service_class", None)
        if not service_class:
            logger.info(
                "[Investigation] ACCESSIBILITY_ANALYSIS: no accessibility service "
                "declared in the manifest - nothing to enable. That absence is "
                "itself a finding about the sample."
            )
            return

        try:
            from sudarshan_core.engines.permission_orchestrator import (
                PermissionOrchestrator,
            )

            orch = PermissionOrchestrator(
                device_serial=self.device_serial,
                adb_path=self.adb_path,
                event_bus=self.event_bus,
            )
            label = str(self.static_findings.get("app_label") or self.package_name)
            logger.info(
                "[Investigation] ACCESSIBILITY_ANALYSIS: enabling '%s' for %s",
                service_class, self.package_name,
            )
            granted = await asyncio.to_thread(
                orch.grant_accessibility, self.package_name, label, service_class
            )
            # grant_accessibility already re-reads device state; record what it
            # found rather than what we asked for.
            self.permissions.record_granted(
                "android.permission.BIND_ACCESSIBILITY_SERVICE", bool(granted)
            )
            self.audit_log.record_system_event(
                "accessibility_procedure",
                f"component={service_class} verified_enabled={bool(granted)}",
            )
            if granted:
                logger.info(
                    "[Investigation] Accessibility VERIFIED enabled - the sample's "
                    "accessibility-gated behaviour can now be observed."
                )
                # Put the sample back in front; the grant leaves Settings up.
                component = self._launch_component()
                if component:
                    await self.executor.execute(
                        {"tool": "start_activity", "component": component}
                    )
                    await self.executor.wait_for_idle()
            else:
                logger.warning(
                    "[Investigation] Accessibility grant did not take effect - "
                    "accessibility-gated behaviour will NOT be observable, so a "
                    "quiet run cannot be read as the sample having none."
                )
        except Exception as exc:
            logger.warning(
                "[Investigation] Accessibility procedure failed: %s", exc
            )

    def _capture_evidence_moment_screenshot(
        self,
        moment_type: str,
        label: str,
        obs: Any,
        state_id: str = "",
        action_id: str = "",
        moment_id: str = "",
    ) -> Optional[str]:
        """Capture screenshot for a security-relevant evidence moment."""
        if self.screenshot_manager is None:
            return None
        reason_map = {
            EvidenceMomentType.UPDATE_REQUEST.value: "UPDATE_PROMPT",
            EvidenceMomentType.VPN_REQUEST.value: "VPN_REQUEST",
            EvidenceMomentType.EXTERNAL_APK_INSTALL_REQUEST.value: "EXTERNAL_APK",
            EvidenceMomentType.SUSPICIOUS_PERMISSION.value: "PERMISSION_DIALOG",
            EvidenceMomentType.ACCESSIBILITY_REQUEST.value: "ACCESSIBILITY",
            EvidenceMomentType.DOWNLOAD_PROMPT.value: "DOWNLOAD_PROMPT",
        }
        reason = reason_map.get(moment_type, "EVIDENCE_MOMENT")
        try:
            path = self.screenshot_manager.capture(
                label=label[:40].replace(" ", "_"),
                category="evidence_moment",
                source="explorer",
                reason=reason,
                activity=getattr(obs, "activity", ""),
                state_id=state_id,
                action_id=action_id,
                evidence_moment_id=moment_id,
                foreground_package=package_of(getattr(obs, "activity", "")),
                layout_hash=getattr(obs, "screen_hash", ""),
                semantic_type=moment_type,
            )
            return path
        except Exception as exc:
            logger.debug("[AgenticExplorer] evidence screenshot failed: %s", exc)
            return None

    def _log_goal_header(self, goal: Any) -> None:
        """
        The `[DYNAMIC][GOAL n/15]` block the observability spec asks for.

        Emitted once when a goal becomes current, so a log reader can see where
        one goal's actions end and the next one's begin without correlating
        timestamps.
        """
        deadline = get_active_deadline()
        budget = ""
        if deadline is not None:
            budget = (
                f" | budget remaining {deadline.remaining():.0f}s of "
                f"{deadline.total_seconds:.0f}s"
            )
        logger.info(
            "[DYNAMIC][GOAL %d/%d] %s%s",
            goal.stage, len(self.goals.goals), goal.name, budget,
        )

    def _set_permission_screen_result(
        self, permission: str, screen_hash: str, result: str,
    ) -> None:
        """Stamp the outcome on a ledger entry created by _note_permission_screen."""
        entry = self._permission_attempts.get(
            (permission or "unknown", screen_hash or "")
        )
        if entry is not None:
            entry["result"] = result

    def _note_permission_screen(
        self, permission: str, screen_hash: str, result: str = "seen",
    ) -> int:
        """
        Record one encounter with a permission screen and return the attempt count.

        Exists because a permission dialog the walk cannot satisfy is the single
        most effective trap on the device: it re-renders identically after every
        tap, so a walk that answers it on sight answers it forever and the
        sample's own screens are never reached.

        The ledger is keyed by (permission, screen_hash) rather than by
        permission alone: Android shows genuinely different dialogs for the same
        permission (the first request, the "don't ask again" variant, the
        Settings page), and collapsing them would stop the walk answering a
        dialog it had never actually seen.
        """
        key = (permission or "unknown", screen_hash or "")
        entry = self._permission_attempts.setdefault(
            key,
            {
                "permission": permission or "unknown",
                "screen_hash": screen_hash or "",
                "attempt_count": 0,
                "result": "",
                "timestamp": self._elapsed_ts(),
            },
        )
        entry["attempt_count"] += 1
        entry["result"] = result
        entry["timestamp"] = self._elapsed_ts()
        return int(entry["attempt_count"])

    def permission_screen_ledger(self) -> List[Dict[str, Any]]:
        """Every permission screen this run met, with how often and how it ended."""
        return [dict(v) for v in self._permission_attempts.values()]

    def _record_permission_from_screen(self, obs: Any, classification: Any) -> None:
        """Record runtime permission observation from screen classification."""
        if classification.screen_type not in (
            "SYSTEM_PERMISSION", "ACCESSIBILITY_DIALOG", "OVERLAY_ATTACK",
        ):
            return
        combined = " ".join(
            (getattr(n, "text", "") or "") + " " + (getattr(n, "desc", "") or "")
            for n in getattr(obs, "ui_nodes", [])
        ).lower()
        perm_map = {
            "microphone": "android.permission.RECORD_AUDIO",
            "camera": "android.permission.CAMERA",
            "location": "android.permission.ACCESS_FINE_LOCATION",
            "contacts": "android.permission.READ_CONTACTS",
            "sms": "android.permission.READ_SMS",
            "phone": "android.permission.READ_PHONE_STATE",
            "storage": "android.permission.READ_EXTERNAL_STORAGE",
            "accessibility": "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "overlay": "android.permission.SYSTEM_ALERT_WINDOW",
        }
        matched_permission = ""
        for keyword, perm in perm_map.items():
            if keyword in combined or keyword in classification.screen_type.lower():
                self.permissions.record_runtime_request(perm)
                matched_permission = perm
                break
        if classification.screen_type == "ACCESSIBILITY_DIALOG":
            self.permissions.record_runtime_request(
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            )
            matched_permission = (
                matched_permission
                or "android.permission.BIND_ACCESSIBILITY_SERVICE"
            )

        # Ledger the encounter. This is what makes "the same permission screen
        # keeps coming back" a bounded, reportable fact instead of a loop: the
        # count is consulted by the boundary budget and surfaced in the report
        # so an analyst can see the sample was demanding a grant the sandbox
        # would not give it.
        permission_label = matched_permission or classification.screen_type
        screen_hash = getattr(obs, "screen_hash", "")
        attempts = self._note_permission_screen(permission_label, screen_hash)
        self._set_permission_screen_result(
            permission_label, screen_hash,
            "answered" if attempts <= MAX_PERMISSION_SCREEN_ATTEMPTS
            else "abandoned_repeat",
        )
        if attempts > MAX_PERMISSION_SCREEN_ATTEMPTS:
            logger.info(
                "[AgenticExplorer] Permission screen for %s has been answered "
                "%d times and keeps returning - not answering it again this "
                "run; exploring other branches instead.",
                matched_permission or classification.screen_type, attempts,
            )
            self.audit_log.record_system_event(
                "permission_screen_repeat",
                f"{matched_permission or classification.screen_type}: "
                f"{attempts} encounters",
            )

    async def _handle_home_launcher(
        self,
        obs: Any,
        foreground_package: str,
        classification: Any,
        actions_taken: int,
    ) -> None:
        """
        Handle HOME_LAUNCHER observation without normal target-app exploration.

        Records transition event, captures ONE screenshot if policy allows,
        attempts relaunch of target app. Does NOT explore launcher UI.
        """
        home_count = self.exploration._home_observation_count
        logger.info(
            "[AgenticExplorer] HOME_LAUNCHER detected (fg=%s, observation #%d) - "
            "not exploring launcher",
            foreground_package, home_count,
        )
        self.audit_log.record_system_event(
            "home_launcher_detected",
            f"fg={foreground_package} count={home_count}",
        )
        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source": "SYSTEM",
            "action": "HOME_LAUNCHER",
            "target": foreground_package,
            "details": (
                f"Target app not foreground (observation #{home_count}). "
                "Screenshot suppressed if unchanged."
            ),
            "success": True,
        })

        # One transition screenshot if policy allows
        if self.screenshot_manager and home_count <= 1:
            scr = self.screenshot_manager.capture(
                label="home_transition",
                category="home_launcher",
                source="explorer",
                reason="APP_CRASH",
                activity=obs.activity,
                foreground_package=foreground_package,
                layout_hash=obs.screen_hash,
                semantic_type=ScreenType.HOME_LAUNCHER,
                transition_event="TARGET_APP_EXITED_TO_HOME",
            )
            if scr:
                self.exploration._home_screenshot_count += 1

        # Attempt relaunch
        component = self._launch_component()
        if component:
            try:
                await self.executor.execute({
                    "tool": "start_activity", "component": component,
                })
            except Exception as exc:
                logger.debug("[AgenticExplorer] Home recovery relaunch failed: %s", exc)

    async def _handle_crash_state(
        self,
        obs: Any,
        classification: Any,
        actions_taken: int,
    ) -> None:
        """Handle CRASH_STATE: record crash, one screenshot, attempt recovery."""
        fg = package_of(obs.activity)
        logger.warning(
            "[AgenticExplorer] CRASH_STATE detected: %s (fg=%s)",
            classification.screen_type, fg,
        )
        finding = classify_crash(CrashContext(
            last_action="",
            stage=self.investigation.state.value,
            actions_before_crash=actions_taken,
            crash_index=len(self.crash_findings) + 1,
            instrumented=True,
            logcat=obs.logcat or "",
            activity=obs.activity,
        ))
        self.crash_findings.append(finding)
        self.audit_log.record_system_event(
            "crash_state_detected",
            f"{finding.crash_type}: {finding.summary}",
        )
        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source": "SYSTEM",
            "action": "APP_CRASH",
            "target": obs.activity,
            "details": finding.summary,
            "success": False,
        })

        if self.event_bus:
            try:
                self.event_bus.publish(crash_event(finding, self.package_name))
            except Exception:
                pass

        if self.screenshot_manager:
            self.screenshot_manager.capture(
                label="crash_context",
                category="crash",
                source="explorer",
                reason="APP_CRASH",
                activity=obs.activity,
                foreground_package=fg,
                layout_hash=obs.screen_hash,
                semantic_type=classification.screen_type,
                state_id="",
                transition_event="APP_CRASH",
            )

        # An ANR is not a crash: the process is alive and merely slow, which on
        # an emulator that has just deoptimized the boot image for Frida is the
        # ordinary case. "Wait" keeps it alive and often lets the screen the
        # walk was mid-way through finish rendering, whereas relaunching throws
        # away whatever had already been filled in. Tried first, once, and only
        # when the dialog actually offers it; relaunch remains the fallback.
        if classification.screen_type == ScreenType.APP_NOT_RESPONDING:
            from sudarshan_core.engines.agentic.semantic_action import (
                is_anr_wait_control,
            )

            wait_label = next(
                (
                    (getattr(n, "text", "") or getattr(n, "desc", "") or "").strip()
                    for n in (obs.ui_nodes or [])
                    if is_anr_wait_control(
                        getattr(n, "text", "") or getattr(n, "desc", "") or ""
                    )
                ),
                "",
            )
            if wait_label:
                logger.info(
                    "[AgenticExplorer] ANR dialog: pressing %r to keep the "
                    "sample alive rather than relaunching it", wait_label,
                )
                try:
                    await self.executor.execute({
                        "tool": "click_text", "text": wait_label,
                    })
                    await self.executor.wait_for_idle(
                        timeout=CRASH_RECOVERY_TIMEOUT_SECONDS,
                    )
                    # The dialog does not always go away the instant "Wait" is
                    # pressed - the app is, after all, still stalled. Observing
                    # immediately re-reads the same dialog and books a second
                    # ANR for the same event, which is how a single startup
                    # stall used to retire the whole budget. Give it a bounded
                    # chance to clear before handing back.
                    await asyncio.sleep(CRASH_RECOVERY_BASE_SECONDS)
                    return
                except Exception as exc:
                    logger.debug(
                        "[AgenticExplorer] ANR wait-press failed, "
                        "falling through to relaunch: %s", exc,
                    )

        component = self._launch_component()
        if component:
            try:
                await self.executor.execute({
                    "tool": "start_activity", "component": component,
                })
            except Exception as exc:
                logger.debug("[AgenticExplorer] Crash recovery relaunch failed: %s", exc)
        await self.executor.wait_for_idle(timeout=CRASH_RECOVERY_TIMEOUT_SECONDS)
        await asyncio.sleep(CRASH_RECOVERY_BASE_SECONDS)

    def _on_frida_event(self, event: Dict[str, Any]) -> None:
        """Receive Frida events from the bus and buffer them for the agent loop."""
        with self._events_lock:
            self._pending_frida_events.append(event)
        # A dropper's second APK is only visible in the runtime stream, so the
        # tracker has to see every event rather than the ones the agent loop
        # happens to drain. Never allowed to break event delivery.
        try:
            self._payloads.observe_event(event)
        except Exception:  # noqa: BLE001
            logger.debug("[AgenticExplorer] payload tracker declined an event",
                         exc_info=True)
        # Also append to timeline (same as UIExplorer)
        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source":    "Frida",
            "category":  event.get("category", "unknown"),
            "data":      event.get("data", {}),
        })

    def _is_third_party_package(self, package: str) -> bool:
        """
        Whether `package` was installed onto this device rather than shipped
        with the image.

        Asked of the device instead of matched against a denylist, because a
        denylist of "apps that are not payloads" cannot be written: the whole
        point is that the payload's package name is unknown and often random.
        Chrome, Settings and the launcher are system packages on every image we
        run, so this single question excludes them all without naming any.

        Cached per package - the answer cannot change during a run - and a
        failed query answers False, so an unreadable device narrows scope
        rather than widening it.
        """
        cached = self._third_party_cache.get(package)
        if cached is not None:
            return cached
        answer = False
        try:
            out = subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell",
                 "pm", "list", "packages", "-3"],
                capture_output=True, text=True, timeout=20,
            ).stdout
            answer = f"package:{package}" in (out or "")
        except Exception as exc:                      # noqa: BLE001
            logger.debug(
                "[AgenticExplorer] Could not classify '%s' as third-party: %s",
                package, exc,
            )
        self._third_party_cache[package] = answer
        return answer

    def _snapshot_third_party_packages(self) -> Set[str]:
        """
        Every third-party package present right now, as a set.

        Taken once at the start of the walk. A failed query returns an empty
        set, and the caller treats "no baseline" as "cannot prove anything was
        installed" - so an unreadable device narrows scope rather than
        adopting every foreign package it meets.
        """
        try:
            out = subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell",
                 "pm", "list", "packages", "-3"],
                capture_output=True, text=True, timeout=20,
            ).stdout or ""
        except Exception as exc:                      # noqa: BLE001
            logger.warning(
                "[AgenticExplorer] Could not snapshot installed packages (%s) - "
                "a payload installed during this run will not be recognised as "
                "the sample's own.", exc,
            )
            return set()
        packages = {
            line.split("package:", 1)[1].strip()
            for line in out.splitlines()
            if line.strip().startswith("package:")
        }
        logger.info(
            "[AgenticExplorer] Baseline: %d third-party package(s) on device "
            "before the walk.", len(packages),
        )
        return packages

    def _installed_during_this_run(self, package: str) -> bool:
        """
        Whether `package` arrived on the device after the walk started.

        The baseline is the whole test. A package that was not there when we
        started and is there now was put there during the session, and the
        sample is the only thing installing packages inside the sandbox.
        """
        if not package or self._baseline_third_party is None:
            return False
        if package in self._baseline_third_party:
            return False
        return self._is_third_party_package(package)

    def _detect_launch_handoff(self, foreground_package: str, obs: Any) -> bool:
        """
        Adopt a package the SAMPLE launched to render its own UI.

        Four conditions, all required, and each one removes a specific way this
        could go wrong:

        1. The victim has taken no action yet. A foreign app that appears after
           a tap was reached BY that tap - that is a departure, and §P24 owns
           it. Only a foreground that appears as a consequence of launching the
           target can be a hand-off.
        2. The sample's process is still alive. A sample that died and left
           something else on screen did not hand off to it.
        3. The foreground is a third-party package. Excludes the launcher,
           Settings, Chrome and every other system surface without naming them.
        4. It is not already a known boundary surface.

        Returns True when a hand-off was adopted, and is idempotent afterwards.
        """
        if not foreground_package or foreground_package == self.package_name:
            return False
        if foreground_package in self.exploration.companion_packages:
            return True

        # (0) A package that was installed DURING this run is the sample's own
        # second stage, whatever the victim did in between.
        #
        # Condition (1) below restricts adoption to a foreground that appears
        # before any victim action, on the reasoning that a foreign app which
        # shows up after a tap was reached BY that tap and is therefore a
        # departure. That is right for navigation - tapping a link that opens
        # Chrome IS leaving - and exactly wrong for a dropper, where the taps
        # are the install: measured on Anubis (com.tjmonh.android, posing as
        # "RTO eChallan"), the walk clicked Install -> OK -> Allow from this
        # source -> Install, Android installed com.hsjjsjs.android, and its
        # phishing form - Full Name, Mobile Number, Mother Name, Date Of Birth -
        # took the screen. Ten actions had been attempted by then, so (1)
        # rejected it, the scope guard called the payload a departure, and the
        # run spent its remaining budget pressing back towards the inert
        # dropper. forms_found: 0, forms_completed: 0, login_outcome:
        # not_attempted - on a screen built for nothing but credential theft.
        #
        # SecondaryPayloadTracker.child_packages() was supposed to cover this
        # (its own comment: "a foreground package that is a KNOWN CHILD is in
        # scope"), and the scope guard at G8 already honours it. But that set is
        # fed by confirm_installed(), which nothing in the production path ever
        # calls - the same "the API existed, the producer did not" gap that
        # module's docstring describes for record_secondary_apk(). This is the
        # producer, and it asks the device rather than depending on the install
        # hooks firing.
        if self._installed_during_this_run(foreground_package):
            logger.info(
                "[DAE][HANDOFF] %s was not on the device when this run started "
                "- the sample installed it. Adopting the payload as a surface "
                "of this investigation.", foreground_package,
            )
            self._payloads.confirm_installed(foreground_package)
            return self.adopt_companion_package(
                foreground_package,
                activity=getattr(obs, "activity", ""),
                evidence=(
                    f"absent from the device at session start and in the "
                    f"foreground now - installed by {self.package_name} "
                    f"during this run"
                ),
            )

        # (1) nothing the victim did can explain this foreground.
        if self.exploration.actions_attempted > 0:
            return False
        # (4) a system boundary is a boundary, however early it appears.
        if in_investigation_scope(
            foreground_package, self.package_name, activity=obs.activity,
        ):
            return False
        from sudarshan_core.engines.agentic.screenshot_policy import (
            LAUNCHER_PACKAGES,
        )
        if foreground_package in LAUNCHER_PACKAGES:
            return False
        # (2) the sample is still running behind whatever is on screen.
        if self._resolve_target_pid() <= 0:
            logger.info(
                "[DAE][HANDOFF] rejected foreground=%s - target process is not "
                "running, so the sample did not hand off to it",
                foreground_package,
            )
            return False
        # (3) shipped with the image, or installed onto it?
        if not self._is_third_party_package(foreground_package):
            return False

        return self.adopt_companion_package(
            foreground_package,
            activity=getattr(obs, "activity", ""),
            evidence=(
                f"foreground before any victim action while {self.package_name} "
                f"(pid {self._target_pid}) was still running"
            ),
        )

    def adopt_companion_package(
        self,
        package: str,
        *,
        activity: str = "",
        evidence: str = "",
    ) -> bool:
        """
        Take ownership of a package the sample launched to render its journey.

        Public because the SANDBOX detects this first. The hand-off completes
        milliseconds after launch, long before the explorer starts, so
        frida_sandbox sees it while deciding which processes to instrument -
        and it must not have to be rediscovered here, where the "before any
        victim action" test could already have expired.

        Idempotent, so the sandbox seeding it and the explorer observing it
        independently cannot produce two adoptions.
        """
        if not package or package == self.package_name:
            return False
        if package in self.exploration.companion_packages:
            return True

        record = self._payloads.register_launch_handoff(
            package,
            activity=activity,
            detected_at_ms=int(time.time() * 1000),
            evidence=evidence,
        )
        if not record:
            return False
        foreground_package = package
        self.exploration.companion_packages.add(foreground_package)
        logger.info(
            "[DAE][HANDOFF] target=%s companion=%s activity=%s "
            "- adopted as a target surface",
            self.package_name, foreground_package, activity,
        )
        self.audit_log.record_system_event(
            "launch_handoff_detected",
            f"{self.package_name} -> {foreground_package} (activity={activity})",
        )
        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source":    "System",
            "action":    "Launch Hand-off",
            "details":   (
                f"{self.package_name} launched {foreground_package}, which "
                f"renders the user-facing journey"
            ),
        })
        if self.event_bus:
            try:
                self.event_bus.publish({
                    "type": "event",
                    "category": "multi_stage",
                    "severity": "MEDIUM",
                    "data": {
                        # Named for what was OBSERVED - a foreground change
                        # while the sample was running - not for an API we did
                        # not hook.
                        "hook": "activity.launch_handoff",
                        "description": (
                            f"{self.package_name} put {foreground_package} in "
                            f"front of the user immediately after launch; the "
                            f"app's journey is rendered by a second package"
                        ),
                        "package": self.package_name,
                        "child_package": foreground_package,
                    },
                })
            except Exception:
                pass
        return True

    def _drain_frida_events(self) -> List[Dict]:
        """Drain and return all buffered Frida events since the last drain."""
        with self._events_lock:
            events = list(self._pending_frida_events)
            self._pending_frida_events.clear()
        # The Smart Investigator's tally. Counted on the drain rather than in
        # the graph because the event stream belongs to the explorer, and
        # counted even when a branch is blocked: a sample that keeps calling
        # hooked APIs while the victim is stuck at a boundary is exactly the
        # case §P29 asks to keep observing.
        if events:
            self.exploration.runtime_events_observed += len(events)
        return events

    # ── Main agent loop ────────────────────────────────────────────────────────

    async def start(self, duration_seconds: int) -> None:
        """
        Run the Observe → Think → Act → Execute agent loop.

        Stopping conditions (first hit wins):
          SC1: All fraud goals completed.
          SC2: No new Frida evidence for FRIDA_SILENCE_THRESHOLD consecutive actions.
          SC3: Action budget exceeded (ACTION_BUDGET).
          SC4: Time budget exceeded (duration_seconds).
          SC5: Application crashes (detected by activity name).
          SC6: Planner returns None (FallbackPlanner signals no progress).
          SC7: _cancel_task set by stop().
        """
        self._is_running   = True
        self._cancel_task  = False
        self._start_time   = time.monotonic()
        self._duration     = duration_seconds

        # Everything third-party already on the device, before the walk touches
        # anything. Any third-party package that appears in the foreground later
        # and is NOT in this set was installed DURING the session - and the only
        # thing installing packages in here is the sample. See
        # _detect_launch_handoff for what that buys.
        self._baseline_third_party = self._snapshot_third_party_packages()

        # The caller's duration is the STARTING budget, not the whole story.
        # frida_sandbox passes FRIDA_ANALYSIS_DURATION (300s by default) to
        # every sample alike, which cuts off an app that is mid-login and
        # idles for four minutes on one that finished at t=40. The deadline now
        # follows the walk, within a hard maximum that nothing can move.
        # The exploration window is a CHILD of the one global deadline, never a
        # peer of it. Both the starting budget and the adaptive ceiling are
        # clamped to what the whole dynamic analysis has left, so no amount of
        # measured progress can extend the walk past the 30-minute wall clock -
        # which is the §P25 rule that there is exactly one deadline and every
        # child inherits it.
        _global = get_active_deadline()
        _initial = float(duration_seconds)
        _ceiling = float(MAX_EXPLORATION_BUDGET_SECONDS)
        if _global is not None:
            _initial = _global.budget_for(_initial)
            _ceiling = _global.budget_for(_ceiling)
            logger.info(
                "[DYNAMIC][BUDGET] exploration window clamped to the global "
                "deadline: start %.0fs, ceiling %.0fs, global remaining %.0fs",
                _initial, _ceiling, _global.remaining(),
            )
        self.budget = AdaptiveBudget(
            initial_seconds=_initial,
            max_seconds=max(_initial, _ceiling),
            started_monotonic=self._start_time,
        )

        self.audit_log.record_system_event(
            "exploration_start",
            f"AgenticExplorer started. Budget={ACTION_BUDGET}, "
            f"Duration={duration_seconds}s (adaptive max "
            f"{self.budget.max_seconds:.0f}s, enabled={self.budget.enabled}), "
            f"Package={self.package_name}"
        )
        self.attack_timeline.append({
            "timestamp": "00:00",
            "source":    "System",
            "action":    "AgenticExplorer Started",
            "details":   f"ActionBudget={ACTION_BUDGET}",
        })

        # FridaSession launches the target before the explorer starts. BOOTSTRAP
        # and APP_LAUNCH only permit read-only tools, so every UI tap (including
        # affirmative controls on update/permission dialogs) was rejected until
        # INITIAL_OBSERVATION - the simulated user never acted on the real screen.
        if self.investigation.state in (
            InvestigationState.BOOTSTRAP,
            InvestigationState.APP_LAUNCH,
        ):
            self.investigation.transition_to(
                InvestigationState.INITIAL_OBSERVATION,
                "target app launched by Frida session before explorer start",
            )
            from sudarshan_core.engines.runtime_lifecycle import record_lifecycle_event
            record_lifecycle_event(
                "explorer_started",
                "RUNNING",
                "AgenticExplorer",
                f"interactive stage={self.investigation.state.value}",
            )

        actions_taken         = 0
        frida_silence_streak  = 0
        last_action_failed    = False
        last_screen_hash      = ""
        consecutive_crashes   = 0
        survivable_anrs       = 0
        out_of_scope_streak   = 0
        # Whether the previous iteration was outside the sample. Distinct from
        # the streak, which the recovery path resets: this survives long enough
        # for the return-to-target branch to know a boundary was crossed and
        # that the process may have been replaced while the walk was away.
        was_out_of_scope      = False
        # Set once the sample will not come back to the foreground. Navigation
        # stops; observation does not.
        navigation_abandoned  = False
        # The last action the planner chose, kept so a departure discovered on
        # the next observation can be attributed back to the control that
        # caused it. Recovery actions issued by the guard itself deliberately
        # do not overwrite these.
        last_action_tool      = ""
        last_action_target    = ""
        self._first_screen_logged = False
        # The post-action observation from the previous iteration, handed
        # forward so the loop does not dump the same unchanged screen twice.
        # Consumed (and cleared) by the OBSERVE step below. See
        # _reusable_observation() for the conditions under which it is trusted.
        carried_obs: Optional[Any] = None

        # ── Mark Stage 1 goal in-progress immediately ─────────────────────────
        self.goals.mark_in_progress("Launch Application")

        try:
            while self._is_running and not self._cancel_task:
                elapsed = time.monotonic() - self._start_time

                # ── SC4: Time budget (adaptive, hard-capped) ───────────────────
                # Two ways to stop: the deadline arrived, or the walk stopped
                # learning and has nothing left to try. The first is
                # unconditional - that is what guarantees no run is unbounded.
                _work_remaining = bool(self.exploration.coverage_metrics().get(
                    "actionable_elements_unresolved", 0
                ))
                # ── The one global deadline outranks everything ───────────────
                # Checked FIRST and unconditionally. The adaptive budget below
                # can extend itself while the walk is still learning; this
                # cannot be extended by anything, which is what makes 30 minutes
                # a wall-clock guarantee rather than a starting position.
                _global = get_active_deadline()
                if _global is not None and _global.expired:
                    _global.note_expiry("exploration_loop")
                    logger.warning(
                        "[DYNAMIC][TIMEOUT] Global %.0f-second deadline reached "
                        "at elapsed=%.0fs after %d actions. Stopping "
                        "exploration and finalizing partial result.",
                        _global.total_seconds, _global.elapsed(), actions_taken,
                    )
                    self.audit_log.record_system_event(
                        "stop_global_deadline",
                        f"elapsed={_global.elapsed():.0f}s "
                        f"budget={_global.total_seconds:.0f}s "
                        f"actions={actions_taken}",
                    )
                    self._stop_reason = StopReason.TIME_BUDGET_EXHAUSTED
                    break
                if self.budget.should_finish(
                    stagnant_streak=self.progress.stagnant_streak,
                    recovery_exhausted=(frida_silence_streak >= FRIDA_SILENCE_THRESHOLD),
                    work_remaining=_work_remaining,
                ):
                    _exp_cov = self.exploration.coverage_metrics()
                    logger.info(
                        "[AgenticExplorer] STOP reason=TIME_BUDGET_EXHAUSTED "
                        "elapsed=%.1fs deadline=%.0fs extensions=%d finish=%s "
                        "states=%d actions_taken=%d "
                        "unexplored_actions=%d current_state=%s",
                        elapsed,
                        self.budget.deadline_seconds,
                        self.budget.extensions,
                        self.budget.finish_reason,
                        _exp_cov.get("states_discovered", 0),
                        actions_taken,
                        _exp_cov.get("actionable_elements_unresolved", 0),
                        self.exploration._current_state_id or "none",
                    )
                    self.audit_log.record_system_event(
                        "stop_time_budget",
                        f"elapsed={elapsed:.1f}s reason={self.budget.finish_reason} "
                        f"extensions={self.budget.extensions}",
                    )
                    self._stop_reason = StopReason.TIME_BUDGET_EXHAUSTED
                    break

                # ── SC3: Action budget ─────────────────────────────────────────
                if actions_taken >= ACTION_BUDGET:
                    _exp_cov = self.exploration.coverage_metrics()
                    logger.info(
                        "[AgenticExplorer] STOP reason=EXPLORATION_BUDGET_EXHAUSTED "
                        "actions_taken=%d budget=%d states=%d "
                        "unexplored_actions=%d current_state=%s",
                        actions_taken, ACTION_BUDGET,
                        _exp_cov.get("states_discovered", 0),
                        _exp_cov.get("actionable_elements_unresolved", 0),
                        self.exploration._current_state_id or "none",
                    )
                    self.audit_log.record_system_event("stop_action_budget", f"actions={actions_taken}")
                    self._stop_reason = StopReason.EXPLORATION_BUDGET_EXHAUSTED
                    break

                # SC1: Fraud goals complete is a PRIORITIZATION signal only.
                # Deep exploration continues until the state graph is exhausted.
                if self.goals.all_done():
                    logger.debug(
                        "[AgenticExplorer] All fraud goals completed - "
                        "continuing deep exploration of remaining branches"
                    )

                self.memory.advance_iteration()

                # ── OBSERVE ───────────────────────────────────────────────────
                frida_events_this_cycle = self._drain_frida_events()
                reused_obs = await self._reusable_observation(carried_obs)
                carried_obs = None
                if reused_obs is not None:
                    # The previous iteration already read this screen AFTER its
                    # action settled, and nothing has touched the device since.
                    # Re-dumping costs a measured ~2.36s plus a ~1.61s
                    # wait_for_idle for an answer we are holding.
                    obs = reused_obs
                    obs.frida_events = frida_events_this_cycle
                    pipeline_log(
                        "OBSERVATION_REUSED",
                        activity=obs.activity,
                        nodes=len(obs.ui_nodes or []),
                    )
                else:
                    obs = await self.perception.observe(
                        frida_events=frida_events_this_cycle,
                        last_action_failed=last_action_failed,
                        static_findings=self.static_findings,
                    )
                if obs.ui_xml_raw:
                    self.last_ui_hierarchy_xml = obs.ui_xml_raw[:120_000]

                if not self._first_screen_logged and obs.screen_hash:
                    self._first_screen_logged = True
                    from sudarshan_core.engines.runtime_lifecycle import record_lifecycle_event
                    record_lifecycle_event(
                        "first_screen_observed",
                        "OK",
                        "AgenticExplorer",
                        f"activity={obs.activity} nodes={obs.ui_node_count}",
                    )

                # Stage 1 is confirmed by observed foreground state, not by a
                # Frida hook (hooks cannot fire before the app is running) and
                # not by the LLM. Without this the whole dependency graph stays
                # blocked on stage 1 forever.
                foreground_package = package_of(obs.activity)
                # Adoption runs BEFORE classification so the payload's very
                # first screen - usually its most interesting - is classified
                # as the sample's own rather than as EXTERNAL_APP. It needs
                # only the foreground package and the observation, so there is
                # nothing to wait for.
                self._detect_launch_handoff(foreground_package, obs)
                # Classified here rather than after the scope guard: the guard
                # needs the screen type to distinguish a consent prompt hosted
                # by Settings from an ordinary Settings screen. Reused verbatim
                # by the INVESTIGATION STATE step below - not recomputed.
                classification = classify_screen_with_ownership(
                    obs.activity, obs.ui_nodes, obs.ui_xml_raw,
                    self.package_name, foreground_package,
                    companion_packages=self.exploration.companion_packages,
                )
                self.goals.update_from_foreground(
                    foreground_package=foreground_package,
                    target_package=self.package_name,
                )

                # ── SCOPE GUARD ───────────────────────────────────────────────
                # Runs before the screen is registered: a Contacts screen is not
                # a screen of the sample, and counting it inflates both the
                # screen graph the planner reasons over and the coverage figure
                # the report presents.
                # The UI text is a real signal for boundary detection - an OEM
                # installer is confirmed by its package fragment PLUS an
                # install marker on screen, and passing nothing here left that
                # second signal permanently unavailable, so every OEM installer
                # scored one signal and failed the two-signal rule.
                screen_text = self._screen_text(obs)
                # ── G8: a child application is IN scope ───────────────────────
                # An APK the sample downloaded and installed is not a foreign
                # app that the walk wandered into - it is the payload, and it is
                # usually where the interesting behaviour lives. Treating its
                # foreground as a departure made the guard navigate straight
                # back out of the one surface worth looking at. The parent
                # investigation still owns it: evidence stays attached here and
                # the original APK context is never replaced.
                # A package the sample launched to render its own journey was
                # adopted above, before classification. See
                # _detect_launch_handoff.
                _is_child = self._payloads.is_child_package(foreground_package)
                if _is_child and foreground_package not in self._explored_children:
                    self._explored_children.add(foreground_package)
                    relationship = self._payloads.relationship_for(foreground_package)
                    self._payloads.mark_child_exploration(
                        foreground_package,
                        state="exploring",
                        launched_at_ms=int(time.time() * 1000),
                    )
                    logger.info(
                        "[AgenticExplorer] CHILD_APP_FOREGROUND parent=%s child=%s "
                        "trigger=%s - exploring as a surface of this investigation",
                        self.package_name, foreground_package,
                        (relationship or {}).get("trigger", "unknown"),
                    )
                    self.audit_log.record_system_event(
                        "child_application_entered",
                        f"parent={self.package_name} child={foreground_package}",
                    )
                    self.attack_timeline.append({
                        "timestamp": self._elapsed_ts(),
                        "source":    "System",
                        "action":    "Child Application Explored",
                        "details":   (
                            f"{foreground_package} installed by "
                            f"{self.package_name}"
                        ),
                    })

                if not _is_child and not in_investigation_scope(
                    foreground_package, self.package_name,
                    activity=obs.activity,
                    ui_text=screen_text,
                    screen_type=classification.screen_type,
                    companion_packages=self.exploration.companion_packages,
                ):
                    out_of_scope_streak += 1
                    was_out_of_scope = True

                    # Blame the action that did it, once, on the first
                    # observation of the departure. memory.current_screen_hash
                    # still points at the in-app screen the tap was made from,
                    # because out-of-scope screens are never registered below.
                    if out_of_scope_streak == 1 and last_action_tool:
                        # SAFE BOUNDARY: do NOT record as escaping when the
                        # destination is a recognised safe system boundary role
                        # (e.g. OEM package installer, permission controller).
                        # Recording it would permanently block the same button
                        # text (e.g. "INSTALL") from being selected again on
                        # the source screen after recovery.
                        fg_is_safe_boundary = is_safe_interactive_boundary(
                            foreground_package, obs.activity, screen_text,
                        )
                        if not fg_is_safe_boundary:
                            self.memory.record_escaping_action(
                                last_action_tool, last_action_target
                            )
                            self.planner.invalidate_cache_for_screen(
                                self.memory.current_screen_hash
                            )
                            logger.info(
                                "[AgenticExplorer] '%s(%s)' leads out of the app - "
                                "it will not be chosen again on this screen.",
                                last_action_tool, last_action_target,
                            )
                            self.audit_log.record_system_event(
                                "escaping_action_recorded",
                                f"{last_action_tool}({last_action_target}) "
                                f"-> {foreground_package}",
                            )
                        else:
                            logger.info(
                                "[VSE] BOUNDARY_TRANSITION to safe system "
                                "boundary: fg=%s screen=%s (from %s via '%s(%s)') "
                                "- not recorded as an escaping action",
                                foreground_package, classification.screen_type,
                                self.package_name,
                                last_action_tool, last_action_target,
                            )
                            self.audit_log.record_system_event(
                                "boundary_transition_safe",
                                f"{last_action_tool}({last_action_target}) "
                                f"-> {foreground_package} (safe boundary)",
                            )
                        last_action_tool = last_action_target = ""
                    # `navigation_abandoned` is checked here, not only the
                    # streak cap. Detecting a missing launcher component set the
                    # flag but left this condition looking at the counter alone,
                    # so the guard announced "cannot be relaunched" and then
                    # tried again anyway - once per iteration until the cap.
                    if (
                        navigation_abandoned
                        or out_of_scope_streak > MAX_OUT_OF_SCOPE_RECOVERIES
                    ):
                        # Stop NAVIGATING, but keep OBSERVING.
                        #
                        # This used to `break`, ending the investigation. That is
                        # exactly backwards for a sample that hides itself:
                        # measured on Cerberus, which backgrounds itself and
                        # disables its launcher activity (every relaunch returned
                        # "Activity class ... does not exist"). Six failed
                        # recoveries then terminated the run at 6 actions and 4
                        # evidence records - while the trojan was still
                        # instrumented and still firing hooks. A backgrounded
                        # process is not a finished one, and self-hiding is the
                        # behaviour we are there to observe, not a reason to
                        # stop watching.
                        if not navigation_abandoned:
                            navigation_abandoned = True
                            logger.warning(
                                "[AgenticExplorer] '%s' will not return to the "
                                "foreground after %d attempts (now showing '%s'). "
                                "Its launcher component may be disabled - "
                                "self-hiding is itself a finding. Continuing to "
                                "observe runtime events without further "
                                "navigation.",
                                self.package_name, out_of_scope_streak - 1,
                                foreground_package,
                            )
                            self.audit_log.record_system_event(
                                "out_of_scope_unrecoverable",
                                f"foreground={foreground_package} "
                                f"attempts={out_of_scope_streak - 1} - "
                                f"observation continues",
                            )
                        # No recovery action - but the plan keeps moving. A
                        # stage procedure like the accessibility grant works
                        # through Settings and does not need the sample in the
                        # foreground, so a self-hiding app must not freeze the
                        # investigation in whatever stage it happened to be in.
                        self.investigation.record_action()
                        advance_now, why_now = self.investigation.should_advance()
                        if advance_now:
                            self.investigation.advance(why_now)
                        await self._run_stage_procedure()

                        frida_silence_streak += 1
                        actions_taken += 1
                        await self.executor.wait_for_idle()
                        continue

                    component = self._launch_component()
                    use_back = out_of_scope_streak <= BACK_BEFORE_RELAUNCH
                    if use_back:
                        recovery = {"tool": "press_back"}
                    elif component:
                        recovery = {"tool": "start_activity", "component": component}
                    else:
                        # No resolvable component is NOT a reason to keep
                        # pressing back. It used to be: the ladder fell through
                        # to press_back on every attempt, and once the agent was
                        # on the launcher, back did nothing. A measured run spent
                        # six recoveries pressing back at the launcher, set
                        # navigation_abandoned, and then idled for 190s of a 300s
                        # window with 8 unexplored actions still in the graph.
                        #
                        # Launching by package resolves the entry Activity on the
                        # device instead of guessing it here.
                        recovery = {
                            "tool": "start_activity",
                            "package": self.package_name,
                        }
                    logger.info(
                        "[AgenticExplorer] Out of scope: foreground is '%s', "
                        "target is '%s' - recovering with %s (attempt %d)",
                        foreground_package, self.package_name,
                        recovery["tool"], out_of_scope_streak,
                    )
                    self.audit_log.record_system_event(
                        "out_of_scope_recovery",
                        f"foreground={foreground_package} tool={recovery['tool']} "
                        f"attempt={out_of_scope_streak}",
                    )
                    try:
                        recovery_result = await self.executor.execute(recovery)
                        # A relaunch that fails because the component is gone is
                        # CONCLUSIVE on the first attempt - retrying an activity
                        # Android says does not exist cannot succeed. Measured on
                        # Cerberus, which disables its own launcher activity:
                        # every one of six attempts returned "Activity class ...
                        # does not exist", and those six actions were the run.
                        if (
                            recovery["tool"] == "start_activity"
                            and _launcher_component_missing(recovery_result)
                        ):
                            navigation_abandoned = True
                            logger.warning(
                                "[AgenticExplorer] '%s' cannot be relaunched - "
                                "Android reports its launcher component does not "
                                "exist. The sample has disabled its own launcher, "
                                "which is self-hiding behaviour and a finding in "
                                "its own right. Navigation stops here; observation "
                                "and the investigation plan continue.",
                                self.package_name,
                            )
                            self.audit_log.record_system_event(
                                "self_hiding_detected",
                                f"{self.package_name} launcher component missing "
                                f"after {out_of_scope_streak} attempt(s)",
                            )
                            if self.event_bus:
                                try:
                                    self.event_bus.publish({
                                        "type": "event",
                                        "category": "persistence",
                                        "severity": "HIGH",
                                        "data": {
                                            # Named for what we OBSERVED, not
                                            # for the API we suppose caused it.
                                            # The agent does not hook
                                            # setComponentEnabledSetting; this is
                                            # inferred from Android refusing to
                                            # relaunch the component, and calling
                                            # it a hooked call would overstate
                                            # the evidence.
                                            "hook": "launcher.component_unresolvable",
                                            "description": (
                                                "Application's launcher component "
                                                "no longer resolves - the app has "
                                                "removed itself from the launcher "
                                                "(inferred from a refused relaunch, "
                                                "not from a hooked API call)"
                                            ),
                                            "package": self.package_name,
                                        },
                                    })
                                except Exception:
                                    pass
                    except Exception as exc:
                        # A failed recovery is not fatal; the next iteration
                        # re-observes and escalates from press_back to am_start.
                        logger.warning(
                            "[AgenticExplorer] Out-of-scope recovery failed: %s", exc
                        )
                    await self.executor.wait_for_idle()

                    # Counted as an action: it is a real interaction with the
                    # device, and hiding it would let a sample that repeatedly
                    # ejects the agent run past its budget.
                    actions_taken += 1
                    last_action_failed = False
                    continue

                # Coming back into scope is the one moment a pid change is
                # both likely and cheap to detect - one adb call per boundary
                # crossing, not one per iteration.
                if was_out_of_scope and foreground_package == self.package_name:
                    self._check_target_pid()
                was_out_of_scope = False
                out_of_scope_streak = 0

                # Judge the previous screen-changing action now that the settled
                # screen has been read. Deferring costs nothing and is more
                # accurate than dumping the UI a second time right after acting.
                deferred = self._resolve_pending_verification(obs)
                if deferred is not None and deferred.outcome != "UNVERIFIED":
                    logger.info("[AgenticExplorer] %s", deferred.log_line())

                # ── INVESTIGATION STATE ───────────────────────────────────────
                # `classification` was computed before the scope guard above,
                # which needs the screen type to tell a consent prompt hosted by
                # Settings from the rest of the Settings app.
                self.investigation.observe(
                    screen_type=classification.screen_type,
                    frida_categories=[
                        e.get("category", "") for e in frida_events_this_cycle
                        if isinstance(e, dict)
                    ],
                )


                # ── DEEP EXPLORATION: update state graph ─────────────────────
                # Name any input the local patterns could not, before the
                # inventory is built from them. Done here because this is the
                # async side: the graph's build is synchronous and cannot
                # await a model call.
                field_overrides = await self._resolve_ambiguous_fields(
                    obs, screen_type=classification.screen_type,
                )

                graph_state = self.exploration.observe(
                    obs,
                    semantic_type=classification.screen_type,
                    foreground_package=foreground_package,
                    ownership=classification.ownership,
                    elapsed_ts=self._elapsed_ts(),
                    field_overrides=field_overrides,
                )
                self._record_permission_from_screen(obs, classification)

                # ── G5: authentication position ───────────────────────────────
                # Fed from the same observation the investigation controller
                # sees, so the two cannot describe different screens. The
                # required-field set comes from the classified inputs on this
                # screen, which is what makes "partially filled" a fact rather
                # than a guess about how many boxes a login form usually has.
                self.auth.on_screen(
                    screen_type=classification.screen_type,
                    required_fields={
                        a.field_type
                        for a in getattr(graph_state, "actionable_elements", [])
                        if getattr(a, "is_input", False)
                        and getattr(a, "field_type", "UNKNOWN") != "UNKNOWN"
                    },
                    screen_text=screen_text,
                    elapsed=self._elapsed_ts(),
                )

                # ── HOME_LAUNCHER handling ────────────────────────────────────
                if classification.screen_type == ScreenType.HOME_LAUNCHER:
                    await self._handle_home_launcher(
                        obs, foreground_package, classification, actions_taken,
                    )
                    actions_taken += 1
                    await self.executor.wait_for_idle()
                    continue

                # ── CRASH_STATE handling (launcher may show after crash) ────────
                if classification.screen_type in (
                    ScreenType.CRASH_STATE, ScreenType.APP_NOT_RESPONDING,
                ):
                    await self._handle_crash_state(obs, classification, actions_taken)
                    # An ANR whose process is still running is a stall, not a
                    # death, and gets its own larger budget - see
                    # MAX_SURVIVABLE_ANRS. A crash, or an ANR the app did not
                    # survive, still spends the crash budget.
                    survivable_anr = (
                        classification.screen_type == ScreenType.APP_NOT_RESPONDING
                        and await self._target_process_is_alive()
                    )
                    if survivable_anr:
                        survivable_anrs += 1
                        logger.info(
                            "[AgenticExplorer] ANR %d/%d - process still alive, "
                            "not counting it against the crash budget",
                            survivable_anrs, MAX_SURVIVABLE_ANRS,
                        )
                        if survivable_anrs >= MAX_SURVIVABLE_ANRS:
                            self._stop_reason = StopReason.APPLICATION_CRASH_LOOP
                            break
                    else:
                        consecutive_crashes += 1
                        if consecutive_crashes >= MAX_CONSECUTIVE_CRASHES:
                            self._stop_reason = StopReason.APPLICATION_CRASH_LOOP
                            break
                    actions_taken += 1
                    continue

                # Capture evidence-moment screenshots for newly detected moments
                for moment in self.exploration.evidence_moments:
                    if not moment.screenshot_ids:
                        scr = self._capture_evidence_moment_screenshot(
                            moment.moment_type,
                            moment.title,
                            obs,
                            state_id=moment.state_id,
                            moment_id=moment.evidence_moment_id,
                        )
                        if scr and self.screenshot_manager:
                            recs = self.screenshot_manager.get_manifest()
                            if recs:
                                moment.screenshot_ids.append(recs[-1].screenshot_id)
                # Walk the plan.
                #
                # This used to be `if stuck(): abandon()`, so the only way to
                # leave a stage was to fail in it. A sample that kept producing
                # events was never stuck and therefore never walked the plan it
                # was given - measured on Cerberus, which had
                # ACCESSIBILITY_ANALYSIS planned, visited only BOOTSTRAP and
                # PERSISTENCE_ANALYSIS, and never reached the stage that would
                # have unlocked its payload.
                #
                # A stuck stage is abandoned (never re-entered); a stage that
                # merely spent its budget is advanced past but may be returned
                # to if evidence warrants.
                advance, why = self.investigation.should_advance()
                if advance:
                    if self.investigation.stuck():
                        self.investigation.abandon(why)
                    else:
                        self.investigation.advance(why)

                # Stages with a deterministic procedure run it on entry rather
                # than hoping the planner clicks the right things in Settings.
                await self._run_stage_procedure()
                logger.info(
                    "[Investigation] Stage: %s  Screen: %s  Goal: %s",
                    self.investigation.state.value,
                    classification.screen_type,
                    (self.goals.next_priority_goal().name
                     if self.goals.next_priority_goal() else "none"),
                )

                self.memory.register_screen(obs.screen_hash, obs.activity)
                self.benchmark.record_screen(obs.screen_hash)

                # Update coverage metrics (UIExplorer compatibility)
                self.coverage_metrics["screens"] = len(self.memory.visited_screens)
                self.coverage_metrics["buttons_found"] = max(
                    self.coverage_metrics["buttons_found"],
                    sum(1 for n in obs.ui_nodes if not n.is_input)
                )
                self.coverage_metrics["forms_found"] = max(
                    self.coverage_metrics["forms_found"],
                    sum(1 for n in obs.ui_nodes if n.is_input)
                )

                # Feed Frida events to goal tracker (deterministic)
                if frida_events_this_cycle:
                    changed_goals = self.goals.update_from_frida_events(frida_events_this_cycle)
                    self.memory.record_frida_events(
                        frida_events_this_cycle,
                        goal_name=self.goals.next_priority_goal().name
                        if self.goals.next_priority_goal() else "general"
                    )
                    # Count EVERY event against its OWN hook. This previously
                    # iterated the set of categories, so a category was counted
                    # once per cycle regardless of how many events arrived, and
                    # the first event's hook was attributed to every category - # corrupting both the per-category counts and
                    # frida_unique_hook_types.
                    for event in frida_events_this_cycle:
                        self.benchmark.record_frida_event(
                            event.get("category", ""),
                            event.get("data", {}).get("hook", ""),
                        )
                    frida_silence_streak = 0
                else:
                    frida_silence_streak += 1

                # SC2: Frida silence - only stop if ALSO no unexplored graph work
                if frida_silence_streak >= FRIDA_SILENCE_THRESHOLD:
                    self.goals.auto_skip_if_applicable(frida_silence_streak)
                    if not self.exploration.has_unexplored_work():
                        _exp_cov = self.exploration.coverage_metrics()
                        logger.info(
                            "[AgenticExplorer] STOP reason=NO_UNEXPLORED_ACTIONS "
                            "frida_silence=%d states=%d actions_taken=%d "
                            "unexplored_actions=%d failed_actions=%d "
                            "current_state=%s",
                            frida_silence_streak,
                            _exp_cov.get("states_discovered", 0),
                            actions_taken,
                            _exp_cov.get("actionable_elements_unresolved", 0),
                            _exp_cov.get("actionable_elements_failed", 0),
                            self.exploration._current_state_id or "none",
                        )
                        self.audit_log.record_system_event(
                            "stop_frida_silence",
                            f"streak={frida_silence_streak}"
                        )
                        self._stop_reason = StopReason.NO_UNEXPLORED_ACTIONS
                        break
                    logger.debug(
                        "[AgenticExplorer] Frida silent but %d states have "
                        "unexplored actions - continuing",
                        sum(1 for s in self.exploration.states.values()
                            if s.unexplored_actions()),
                    )

                # SC5: Crash detection & auto-recovery
                if self._is_crash_screen(obs.activity):
                    logger.warning(f"[AgenticExplorer] SC5: App crash/ANR screen detected ({obs.activity}) - attempting relaunch and recovery")
                    self.audit_log.record_system_event("crash_detected_relaunching", obs.activity)

                    # Name the crash before recovering from it. Every death used
                    # to read the same in the report; the distinction between
                    # "died because our own agent is on the stack" and "died
                    # after we granted accessibility" is what an analyst acts on.
                    finding = classify_crash(CrashContext(
                        last_action=last_action_tool,
                        stage=self.investigation.state.value,
                        actions_before_crash=actions_taken,
                        crash_index=consecutive_crashes + 1,
                        instrumented=True,
                        logcat=obs.logcat or "",
                        activity=obs.activity,
                    ))
                    self.crash_findings.append(finding)
                    logger.warning(
                        "[Investigation] Crash classified: %s (%s) - %s",
                        finding.crash_type, finding.confidence, finding.summary,
                    )
                    self.audit_log.record_system_event(
                        "crash_classified",
                        f"{finding.crash_type} ({finding.confidence}): "
                        f"{'; '.join(finding.signals)}",
                    )
                    # Published through the existing bus and schema, so
                    # EvidenceStore records it without any change (§23).
                    if self.event_bus:
                        try:
                            self.event_bus.publish(
                                crash_event(finding, self.package_name)
                            )
                        except Exception as exc:
                            logger.debug("[AgenticExplorer] Crash event publish failed: %s", exc)
                    try:
                        crash_component = self._launch_component()
                        if crash_component:
                            await self.executor.execute({
                                "tool": "start_activity",
                                "component": crash_component,
                            })
                        else:
                            await self.executor.execute({"tool": "press_home"})
                    except Exception as _r_err:
                        logger.warning(f"[AgenticExplorer] Relaunch attempt warning: {_r_err}")

                    # A cold Activity start on an emulator is routinely 2-4 s.
                    # The old flat 1.5 s meant the very next OBSERVE ran against
                    # a half-started process, which frequently produced a second
                    # crash screen and a relaunch loop that burned the whole
                    # action budget without exploring anything.
                    consecutive_crashes += 1
                    await self.executor.wait_for_idle(
                        timeout=CRASH_RECOVERY_TIMEOUT_SECONDS
                    )
                    # Back off further each time: a sample that crashes
                    # repeatedly will not be fixed by retrying faster.
                    await asyncio.sleep(
                        min(CRASH_RECOVERY_BASE_SECONDS * consecutive_crashes,
                            CRASH_RECOVERY_MAX_SECONDS)
                    )

                    if consecutive_crashes >= MAX_CONSECUTIVE_CRASHES:
                        logger.error(
                            "[AgenticExplorer] App crashed %d times in a row - "
                            "stopping exploration. Evidence collected so far is "
                            "retained; the run is NOT reported as clean.",
                            consecutive_crashes,
                        )
                        self.audit_log.record_system_event(
                            "stop_repeated_crashes",
                            f"consecutive_crashes={consecutive_crashes}",
                        )
                        self._stop_reason = StopReason.APPLICATION_CRASH_LOOP
                        break
                    continue

                # Reached a normal screen - the app recovered, so the crash
                # streak must not carry over and trip MAX_CONSECUTIVE_CRASHES
                # later in the run.
                consecutive_crashes = 0

                # ── THINK ─────────────────────────────────────────────────────
                next_goal = self.goals.next_priority_goal()
                if next_goal:
                    self.goals.mark_in_progress(next_goal.name)
                    self.goals.record_attempt(next_goal.name)
                    # Wall clock charged to whichever goal was current for the
                    # PREVIOUS iteration, so a goal that keeps being selected
                    # accumulates its own cost and can be cut off on it. Charged
                    # here, at selection, because that is the one point every
                    # iteration passes through exactly once.
                    now = time.monotonic()
                    if self._current_goal_name:
                        self.goals.add_time_spent(
                            self._current_goal_name,
                            now - (self._current_goal_started or now),
                        )
                    if self._current_goal_name != next_goal.name:
                        self._log_goal_header(next_goal)
                    self._current_goal_name = next_goal.name
                    self._current_goal_started = now

                    # ── Give up on this goal, and ONLY on this goal ───────────
                    # Three independent bounds, whichever comes first:
                    #   * attempts   - MAX_ATTEMPTS_PER_GOAL selections
                    #   * wall clock - MAX_GOAL_SECONDS, so one difficult goal
                    #     cannot absorb the analysis (§P10)
                    #   * the global deadline underneath both
                    #
                    # The outcome is decided from what the goal DEMONSTRABLY
                    # produced: verified progress makes it PARTIAL_SUCCESS,
                    # nothing at all makes it FAILED. Either way the run
                    # continues to the next goal - a goal outcome is never a
                    # run outcome (§P18).
                    _give_up_reason = ""
                    if next_goal.attempts >= MAX_ATTEMPTS_PER_GOAL:
                        _give_up_reason = "max_attempts"
                    elif next_goal.time_spent_seconds >= MAX_GOAL_SECONDS:
                        _give_up_reason = "goal_time_budget_exhausted"
                    elif not self._budget_allows(
                        MIN_GOAL_SLICE_SECONDS, stage=f"goal:{next_goal.name}"
                    ):
                        _give_up_reason = TIMEOUT_REASON

                    if _give_up_reason:
                        if _give_up_reason == TIMEOUT_REASON:
                            self.goals.mark_timed_out(next_goal.name)
                        else:
                            self.goals.resolve_goal(
                                next_goal.name, reason=_give_up_reason,
                            )
                        logger.info(
                            "[DYNAMIC][GOAL] '%s' resolved as %s "
                            "(attempts=%d/%d, %.0fs/%.0fs, reason=%s). "
                            "Continuing to the next goal.",
                            next_goal.name, next_goal.status.value,
                            next_goal.attempts, MAX_ATTEMPTS_PER_GOAL,
                            next_goal.time_spent_seconds, MAX_GOAL_SECONDS,
                            _give_up_reason,
                        )
                        self.audit_log.record_system_event(
                            "goal_resolved",
                            f"{next_goal.name}: {next_goal.status.value} "
                            f"({_give_up_reason})",
                        )
                        # Re-evaluate next goal after state change
                        next_goal = self.goals.next_priority_goal()
                        self._current_goal_name = (
                            next_goal.name if next_goal else ""
                        )
                        self._current_goal_started = time.monotonic()

                # ── Form stagnation outranks planning ─────────────────────────
                # When the screen has stopped moving on a form, neither planner
                # has anything new to say: the graph re-offers the action it
                # already chose and the LLM re-derives it, because the action
                # was never wrong - the keyboard was standing in front of the
                # control it aimed at. Recovery is tried FIRST, and only for as
                # many rungs as its ladder has, after which selection returns
                # to normal.
                action = await self._form_recovery_action(
                    graph_state, classification,
                )
                selected_by = "form_recovery"

                planner_action = None
                if action is None:
                    # ── Ask the graph first, and only pay for the model when
                    #    its answer can still change the outcome ─────────────
                    #
                    # This used to call the planner BEFORE looking at the graph,
                    # every iteration. But select_canonical_action gives the
                    # graph priority for click_text / tap / tap_sequence /
                    # type_text / check, so on those iterations the model's
                    # answer was computed and then discarded.
                    #
                    # Measured on a live Anubis run: Gemini took 7.9s, 13.8s,
                    # 15.1s and 11.2s on consecutive iterations - ~12s average
                    # against ~10s for all of perception, execution and
                    # verification combined. Twenty calls consumed roughly 240s
                    # of a 300s window, which is why a four-field form could not
                    # be filled inside one run: each field cost a round trip
                    # whose result was thrown away.
                    #
                    # The planner is still consulted whenever it could matter:
                    #   * the graph has nothing to offer
                    #   * the graph's action is not one the graph wins with
                    #   * the graph wants to type but cannot name the field, so
                    #     the planner's hint would be substituted in
                    #   * periodically regardless, so privileged device-state
                    #     moves (grant_permission, inject_test_sms, ...) still
                    #     get their turn - those can never come from the graph
                    planner_mode = os.getenv("SUDARSHAN_PLANNER_MODE", "").lower()
                    is_jev = planner_mode == "jev"
                    is_laya = planner_mode == "laya"
                    is_hybrid = planner_mode in ("hybrid", "laya_hybrid")
                    
                    graph_action = None if (is_jev or is_laya) else self.exploration.get_next_action(
                        state_id=graph_state.state_id, memory=self.memory,
                    )
                    self._planner_skips = getattr(self, "_planner_skips", 0)
                    force_planner = self._planner_skips >= PLANNER_CONSULT_EVERY or is_jev or is_laya or is_hybrid

                    # Two further gates, both of which fall back to the
                    # deterministic path rather than blocking (§P9/§P19):
                    #
                    #   * the per-goal planner budget - a model that keeps
                    #     returning the same unusable action for one goal must
                    #     not be asked about it forever;
                    #   * the ONE global deadline - a call started with less
                    #     than its own latency remaining costs that latency and
                    #     produces nothing usable.

                    _goal_name = next_goal.name if next_goal else ""
                    _planner_budget_left = (
                        not _goal_name
                        or next_goal.planner_calls < MAX_PLANNER_CALLS_PER_GOAL
                    )
                    if not _planner_budget_left:
                        logger.debug(
                            "[AgenticExplorer] Planner budget for goal '%s' is "
                            "spent (%d/%d) - deterministic planning only",
                            _goal_name, next_goal.planner_calls,
                            MAX_PLANNER_CALLS_PER_GOAL,
                        )
                    if (
                        should_invoke_planner(classification.screen_type)
                        and (force_planner or _planner_could_change_outcome(graph_action))
                        and _planner_budget_left
                        and self._budget_allows(
                            PLANNER_CALL_COST_SECONDS, stage="planner",
                        )
                    ):
                        if _goal_name:
                            self.goals.record_planner_call(_goal_name)
                        planner_action = await self.planner.decide(
                            obs, self.memory, self.goals,
                            deadline_seconds=self._remaining_budget_seconds(),
                        )
                        self._planner_skips = 0
                    else:
                        self._planner_skips += 1

                    if is_jev:
                        action = planner_action
                        selected_by = "jev_planner" if action else "none"
                    elif is_laya:
                        action = planner_action
                        selected_by = "laya_planner" if action else "none"
                    elif planner_action and planner_action.get("_selected_by") in ("jev_planner", "laya_planner"):
                        action = planner_action
                        selected_by = planner_action.get("_selected_by")
                    else:
                        action, selected_by = select_canonical_action(graph_action, planner_action)
                if action is not None:
                    action["_selected_by"] = selected_by
                    pipeline_log(
                        "ACTION_SELECTED",
                        state=graph_state.state_id,
                        action=action.get("text") or action.get("tool", ""),
                        tool=action.get("tool", ""),
                        source=selected_by,
                    )

                if action is None and not self.exploration.has_unexplored_work():
                    _exp_cov = self.exploration.coverage_metrics()
                    logger.info(
                        "[AgenticExplorer] STOP reason=EXPLORATION_COMPLETE "
                        "states=%d actions_taken=%d "
                        "explored=%d failed=%d pending=%d "
                        "current_state=%s",
                        _exp_cov.get("states_discovered", 0),
                        actions_taken,
                        _exp_cov.get("actionable_elements_explored", 0),
                        _exp_cov.get("actionable_elements_failed", 0),
                        _exp_cov.get("actionable_elements_unresolved", 0),
                        self.exploration._current_state_id or "none",
                    )
                    self.audit_log.record_system_event(
                        "stop_exploration_complete",
                        "All reachable branches explored or blocked"
                    )
                    self._stop_reason = StopReason.EXPLORATION_COMPLETE
                    break
                if action is None:
                    # graph has unexplored work somewhere but get_next_action returned None —
                    # this should not happen if backtracking is working; log it to aid debug.
                    _exp_cov = self.exploration.coverage_metrics()
                    logger.warning(
                        "[AgenticExplorer] NO_UNEXPLORED_ACTIONS in current state but "
                        "graph still has %d pending action(s) — "
                        "current_state=%s actionable_elements=%d. "
                        "Applying fallback scroll.",
                        _exp_cov.get("actionable_elements_unresolved", 0),
                        self.exploration._current_state_id or "none",
                        _exp_cov.get("actionable_elements_discovered", 0),
                    )
                    # Backtrack attempted but failed - try scroll on current screen
                    action = {
                        "tool": "scroll",
                        "direction": "down",
                        "goal": "DEEP_EXPLORATION",
                        "reasoning": "Fallback scroll when planner exhausted",
                        "_source": "exploration_fallback",
                    }

                reasoning = action.get("reasoning", "")
                self.memory.record_reasoning(reasoning)
                if action.get("_source") == "fallback":
                    self.benchmark.record_fallback_activation()

                # NOTE: LLM calls are counted inside AgentPlanner, at the actual
                # request site - a schema retry issues a second API call that is
                # invisible from here.


                # ── ENFORCE THE STAGE ALLOWLIST (§34) ─────────────────────────
                # The planner proposes; the controller disposes. Exploration-graph
                # actions bypass stage gates — deep exploration must not stall
                # because the investigation stage has not advanced yet.
                chosen_tool = action.get("tool", "")
                _exploration_sources = frozenset({
                    "exploration_engine", "backtrack", "exploration_fallback",
                    # Recovery answers a screen that has stopped responding.
                    # Gating it on the investigation stage would leave the walk
                    # stuck on exactly the form whose completion advances that
                    # stage in the first place.
                    FORM_RECOVERY_SOURCE,
                })
                if (
                    not self.investigation.is_action_allowed(chosen_tool)
                    and action.get("_source") not in _exploration_sources
                ):
                    logger.warning(
                        "[Investigation] Rejected '%s' - not permitted in %s "
                        "(allowed: %s)",
                        chosen_tool, self.investigation.state.value,
                        ", ".join(sorted(self.investigation.allowed_actions())) or "none",
                    )
                    self.audit_log.record_system_event(
                        "action_rejected_by_stage",
                        f"{chosen_tool} not allowed in {self.investigation.state.value}",
                    )
                    self.planner.invalidate_cache_for_screen(obs.screen_hash)
                    # Counted so a planner that keeps proposing the same
                    # disallowed action trips `stuck()` and moves the stage on,
                    # rather than spinning until the budget runs out.
                    self.investigation.record_action(failed=True)
                    last_action_failed = True
                    continue

                # ── ACT ───────────────────────────────────────────────────────
                # Remembered before execution so the scope guard can name the
                # control responsible if the next observation lands outside the
                # app. Matches the (tool, target) shape the planners score with.
                last_action_tool   = action.get("tool", "")
                last_action_target = action.get("text") or str(action.get("x", ""))

                # Is this the submit of a credential form? Only counts when the
                # screen actually holds a password box - a "Continue" on an
                # onboarding carousel is not a login attempt, and treating it as
                # one would spend the credential-retry budget on the wrong
                # screen.
                # `press_enter` counts too: the IME's action key commits the
                # form exactly as its button would, and recovery reaches for it
                # precisely when that button is unreachable. Leaving it out
                # would have the walk submit credentials the auth state machine
                # never hears about, so the app's answer is read as an
                # unexplained screen change.
                # A CREDENTIAL screen, not merely a screen with boxes on it.
                #
                # ScreenType.DATA_ENTRY_FORM is documented as deliberately not
                # driving the authentication state - it is data entry, not
                # credential entry - but this site did not honour that, and the
                # `press_enter` branch fires on the IME action after ANY field.
                # Measured on an e-challan form whose four boxes are a name, a
                # phone, a mother's name and a date: typing them raised seven
                # LOGIN_ATTEMPTs and three LOGIN_ATTEMPTS_EXHAUSTED, and each
                # "rejection" rotated the vault to a fresh identity. The form
                # was then re-filled with one persona's name beside another
                # persona's phone number - incoherent data that the app itself
                # would be right to reject.
                _auth_screen = classification.screen_type in _CREDENTIAL_SCREEN_TYPES or any(
                    getattr(n, "is_password", False)
                    for n in (getattr(obs, "ui_nodes", []) or [])
                )
                self._submitted_credentials = bool(
                    _auth_screen
                    and (
                        (
                            last_action_tool in ("click_text", "tap")
                            and _is_submit_label(last_action_target)
                        )
                        or last_action_tool == "press_enter"
                    )
                    and any(
                        getattr(n, "is_password", False)
                        or getattr(n, "is_input", False)
                        for n in (getattr(obs, "ui_nodes", []) or [])
                    )
                )
                if self._submitted_credentials:
                    self.exploration.note_login_attempt(graph_state.state_id)

                # Capture pre-action state for graph edge recording
                self._pre_action_state_id = graph_state.state_id
                self._pre_action_screen_hash = obs.screen_hash

                # State before the action, for the verifier to compare against.
                # Only actions whose effect lives in device state pay for a
                # device probe; screen-changing actions are judged from the
                # perception data we already hold, which costs nothing.
                before = await self._verification_snapshot(action, obs)

                result, verification, retry_attempts = await self._execute_with_bounded_retries(
                    action, obs,
                )
                actions_taken += retry_attempts
                last_action_failed = not result.success or verification.failed
                if verification.outcome != "UNVERIFIED":
                    logger.info("[AgenticExplorer] %s", verification.log_line())
                    self.audit_log.record_system_event(
                        "action_verification",
                        f"{verification.action} expected={verification.expected} "
                        f"observed={verification.observed} -> {verification.outcome}",
                    )
                if verification.failed and verification.detail:
                    logger.warning(
                        "[AgenticExplorer] Action reported success but did not "
                        "take effect: %s", verification.detail,
                    )

                # ── Credit VERIFIED progress to the goal being worked ─────────
                # This is the input that lets a goal end PARTIAL_SUCCESS rather
                # than FAILED, and it is fed only from a positive verification -
                # PRE/POST device state, never an ADB exit code (§P5). A goal
                # that moved the device somewhere real but never reached its own
                # confirming hook is a goal with evidence in it, and recording
                # that is what stops the failure of one action erasing it (§P4).
                if verification.succeeded and self._current_goal_name:
                    self.goals.record_progress_signal(
                        self._current_goal_name,
                        f"{verification.action}:{verification.observed or 'verified'}",
                    )
                # The per-goal [DYNAMIC][GOAL] action line from the
                # observability spec. One line per action, naming the goal it
                # was spent on, so a reader can attribute every action.
                if self._current_goal_name:
                    logger.info(
                        "[DYNAMIC][GOAL] goal=%s action=%s status=%s%s",
                        self._current_goal_name,
                        action.get("text") or action.get("tool", ""),
                        "SUCCESS" if verification.succeeded else verification.outcome,
                        f" reason={verification.detail}"
                        if verification.failed and verification.detail else "",
                    )

                # ── SETTLE ────────────────────────────────────────────────────
                # Nothing used to happen here: the loop went straight back to
                # OBSERVE, so the only gap between one action and reading the
                # next screen was the tool's own fixed sleep. With the
                # deterministic FallbackPlanner there is no LLM round trip to
                # absorb the difference either, so input was dispatched into
                # activity transitions - tapping views mid-teardown and running
                # `uiautomator dump` against a window that was still animating.
                # On a slower emulator that crashed the app under analysis, and
                # a harness-induced crash is indistinguishable in the report
                # from a sample that genuinely did nothing.
                #
                # Waiting for the window to stop moving is bounded (see
                # wait_for_idle) and only applied to actions that can actually
                # change the screen.
                if action.get("tool", "") in NAVIGATIONAL_TOOLS:
                    if self._settled_during_execute:
                        # Already waited, inside the retry ladder, for this same
                        # action. Waiting again reads the same settled window.
                        logger.debug(
                            "[AgenticExplorer] UI already settled during execute "
                            "- skipping duplicate wait_for_idle"
                        )
                    else:
                        settled = await self.executor.wait_for_idle()
                        if not settled:
                            logger.debug(
                                "[AgenticExplorer] UI did not settle after '%s' - "
                                "observing anyway", action.get("tool", "")
                            )

                # ── IN-CONTENT SETTLE ─────────────────────────────────────────
                # wait_for_idle tracks the foreground Activity only.  In-app
                # transitions (spinners, download overlays, progress dialogs)
                # remain in the same Activity window so the focus signal clears
                # immediately.  A small extra sleep lets the content finish
                # rendering before the post-action observe runs, preventing a
                # false ui_changed=False when the screen is mid-transition.
                if (
                    action.get("tool", "") in ("click_text", "tap")
                    and action.get("_source") in (
                        "exploration_engine", "exploration_graph", "backtrack",
                    )
                ):
                    await asyncio.sleep(CONTENT_SETTLE_SECONDS)

                # ── POST-ACTION RE-OBSERVE ─────────────────────────────────────
                # Read the settled screen after action to record accurate
                # state transitions in the exploration graph.
                post_frida = self._drain_frida_events()
                post_obs = await self.perception.observe(
                    frida_events=post_frida,
                    last_action_failed=last_action_failed,
                    static_findings=self.static_findings,
                )
                post_classification = classify_screen_with_ownership(
                    post_obs.activity, post_obs.ui_nodes,
                    post_obs.ui_xml_raw, self.package_name,
                    package_of(post_obs.activity),
                    companion_packages=self.exploration.companion_packages,
                )
                post_state = self.exploration.observe(
                    post_obs,
                    semantic_type=post_classification.screen_type,
                    foreground_package=package_of(post_obs.activity),
                    ownership=post_classification.ownership,
                    parent_state_id=self._pre_action_state_id,
                    entry_action=f"{last_action_tool}:{last_action_target}",
                    elapsed_ts=self._elapsed_ts(),
                )
                ui_changed = (
                    post_obs.screen_hash != self._pre_action_screen_hash
                    or package_of(post_obs.activity) != package_of(obs.activity)
                    or post_obs.activity != getattr(obs, "activity", "")
                )
                # If ADB "succeeded" but the UI did not change, climb the retry
                # ladder - EXCEPT for text entry, which is not supposed to change
                # the screen. Typing into a field leaves the hash where it was by
                # design, so this ladder re-tapped every filled field twice more
                # and cost three actions per field on every login form.
                remaining = max(0, MAX_EXECUTION_ATTEMPTS - retry_attempts)
                if last_action_tool == "type_text" and result.success:
                    remaining = 0
                if (
                    not ui_changed
                    and remaining
                    and last_action_tool in ("click_text", "tap", "type_text")
                ):
                    pipeline_log(
                        "POST_ACTION_UNCHANGED",
                        action_id=action.get("_action_id"),
                        remaining=remaining,
                    )
                    for step in range(remaining):
                        retry = self.dispatcher.retry_payload(action, retry_attempts)
                        if retry is None:
                            break
                        retry_attempts += 1
                        actions_taken += 1
                        pipeline_log(
                            "ACTION_DISPATCHED",
                            attempt=retry_attempts,
                            strategy=(retry.get("_pipeline_debug") or {}).get("retry_strategy"),
                        )
                        result = await self.executor.execute(retry)
                        if retry.get("tool", "") in NAVIGATIONAL_TOOLS:
                            await self.executor.wait_for_idle()
                        post_frida = self._drain_frida_events()
                        post_obs = await self.perception.observe(
                            frida_events=post_frida,
                            last_action_failed=not result.success,
                            static_findings=self.static_findings,
                        )
                        post_classification = classify_screen_with_ownership(
                            post_obs.activity, post_obs.ui_nodes,
                            post_obs.ui_xml_raw, self.package_name,
                            package_of(post_obs.activity),
                            companion_packages=self.exploration.companion_packages,
                        )
                        post_state = self.exploration.observe(
                            post_obs,
                            semantic_type=post_classification.screen_type,
                            foreground_package=package_of(post_obs.activity),
                            ownership=post_classification.ownership,
                            parent_state_id=self._pre_action_state_id,
                            entry_action=f"{last_action_tool}:{last_action_target}",
                            elapsed_ts=self._elapsed_ts(),
                        )
                        ui_changed = (
                            post_obs.screen_hash != self._pre_action_screen_hash
                            or package_of(post_obs.activity) != package_of(obs.activity)
                        )
                        if ui_changed:
                            pipeline_log(
                                "STATE_CHANGED",
                                old_state=self._pre_action_state_id,
                                new_state=post_state.state_id,
                            )
                            break

                # ── ever_ui_changed: track UI change across ALL retry attempts ─
                # The retry loop above updates `ui_changed` on each attempt but
                # overwrites it, so the final value reflects only the LAST retry.
                # `ever_ui_changed` is set True the first time any attempt sees
                # a changed hash, and it is never cleared.  This is what we pass
                # to record_action() so the graph correctly marks the action as
                # explored even when the last retry caught the hash mid-transition.
                ever_ui_changed: bool = ui_changed  # initialised from first post-obs

                # ── Credential form outcome ───────────────────────────────────
                # A submit pressed on a screen that had a password box is a
                # login attempt, and the app's answer decides what happens next.
                # Silence is not an answer: the vault issues a new identity and
                # the form is offered again, up to MAX_LOGIN_ATTEMPTS. An
                # explicit "invalid credentials" closes the branch immediately.
                # ── G9: did the typed text actually reach the field? ──────────
                # Runs before the login-outcome judgement below, so a submit is
                # judged against a form we know was filled rather than one we
                # assumed was.
                field_verification = self._verify_typed_field(
                    action, result, post_obs,
                )
                # Tri-state, and the distinction carries the whole fix:
                #   None  - not a type_text, or the field could not be re-read.
                #   True  - the value is in the field.
                #   False - the field was READ and our value is not in it.
                # Only False resolves differently. An INCONCLUSIVE read (a
                # masked field exposing neither text nor length) stays None and
                # resolves as it always did, so password boxes cannot loop.
                input_verified: Optional[bool] = None
                if field_verification is not None:
                    if field_verification.failed:
                        input_verified = False
                        last_action_failed = True
                    elif field_verification.succeeded:
                        input_verified = True

                if self._submitted_credentials:
                    self._submitted_credentials = False
                    self.auth.on_submit(elapsed=self._elapsed_ts())
                    outcome = self.exploration.note_login_outcome(
                        screen_text=self._screen_text(post_obs),
                        current_state_id=post_state.state_id,
                        activity_changed=(
                            post_obs.activity != getattr(obs, "activity", "")
                        ),
                    )
                    # The state machine judges the same evidence, but does not
                    # accept an activity change as authentication: an error
                    # screen is a new activity too. That is why `accepted`
                    # below and AuthState.AUTHENTICATED can legitimately
                    # disagree, and the stricter one is the one reported.
                    self.auth.on_submit_result(
                        rejected=(outcome == "rejected"),
                        activity_changed=(
                            post_obs.activity != getattr(obs, "activity", "")
                        ),
                        screen_type=post_classification.screen_type,
                        screen_text=self._screen_text(post_obs),
                        elapsed=self._elapsed_ts(),
                    )
                    self.audit_log.record_system_event(
                        "login_outcome",
                        f"{outcome} attempt={self.exploration.login_attempts} "
                        f"auth_state={self.auth.state.value}",
                    )
                    if outcome == "accepted":
                        self._capture_state_frame(
                            post_obs, post_state, post_classification,
                            reason=ScreenshotReason.LOGIN.value,
                            label="authenticated_session",
                        )
                    elif self.auth.is_terminal:
                        # ── The app has answered, so stop asking ─────────────
                        #
                        # An explicit "invalid credentials" settles the
                        # question: no further synthetic identity will be
                        # accepted, and retrying only spends budget the other
                        # investigation branches need. The purpose of filling a
                        # login form during analysis is to get PAST it and
                        # observe what the sample does next - accessibility
                        # abuse, overlay draw, SMS interception, C2 traffic -
                        # not to succeed at authenticating.
                        #
                        # The goal is resolved as PARTIAL rather than FAILED
                        # whenever the form was actually filled and submitted:
                        # that is verified progress, and it stays in the record
                        # even though the credentials were refused.
                        self.goals.record_progress_signal(
                            "Login Flow", "credentials_submitted",
                        )
                        self.goals.resolve_goal(
                            "Login Flow", reason=AUTH_FLOW_REJECTED,
                        )
                        logger.info(
                            "[DYNAMIC][GOAL] goal=Login Flow status=%s "
                            "reason=%s auth_state=%s - moving to another "
                            "investigation branch",
                            (self.goals.get_goal_by_name("Login Flow").status.value
                             if self.goals.get_goal_by_name("Login Flow") else "?"),
                            AUTH_FLOW_REJECTED, self.auth.state.value,
                        )
                        self.audit_log.record_system_event(
                            "auth_flow_rejected",
                            f"auth_state={self.auth.state.value} "
                            f"attempts={self.exploration.login_attempts}",
                        )

                pipeline_log("POST_ACTION_OBSERVE", state_id=post_state.state_id)
                # Every distinct in-app screen gets a frame of its own, so the
                # report and VIDE see what the sample actually looks like from
                # the inside rather than only its launch screen.
                self._capture_state_frame(
                    post_obs, post_state, post_classification,
                )
                if ui_changed:
                    ever_ui_changed = True
                    pipeline_log(
                        "STATE_CHANGED",
                        old_state=self._pre_action_state_id,
                        new_state=post_state.state_id,
                        foreground_package=package_of(post_obs.activity),
                        ownership=post_classification.ownership,
                        semantic_type=post_classification.screen_type,
                        actions=len(post_state.actionable_elements),
                    )
                    pipeline_log("ACTION_VERIFIED", action_id=action.get("_action_id"))
                    self._log_consequences(obs, post_obs, post_classification)
                    # ── FIX 3: Advance current state in exploration graph ─────
                    # After a verified UI transition, the exploration graph must
                    # know we are now in the NEW state so that get_next_action()
                    # on the next iteration returns actions from STATE-002 and
                    # not from the already-exhausted STATE-001.
                    if post_state.state_id != self._pre_action_state_id:
                        self.exploration._current_state_id = post_state.state_id
                        logger.info(
                            "[AgenticExplorer] STATE_CHANGED old_state=%s "
                            "new_state=%s foreground_package=%s "
                            "ownership=%s semantic_type=%s actions=%d",
                            self._pre_action_state_id, post_state.state_id,
                            package_of(post_obs.activity),
                            post_classification.ownership,
                            post_classification.screen_type,
                            len(post_state.actionable_elements),
                        )
                elif retry_attempts >= MAX_EXECUTION_ATTEMPTS or not result.success:
                    pipeline_log(
                        "ACTION_EXECUTION_FAILED",
                        action_id=action.get("_action_id"),
                        attempts=retry_attempts,
                    )

                # Update ever_ui_changed from the retry loop outcomes too.
                # Each retry's ui_changed is evaluated inside the retry loop
                # (line 1681); if any retry returned True the loop broke early
                # and the final value of ui_changed reflects that.  However, if
                # the LAST retry saw False after an earlier True we need the flag
                # to survive.  Re-derive it here from state identity.
                if post_state.state_id != self._pre_action_state_id:
                    ever_ui_changed = True

                # ── Form stagnation streak ────────────────────────────────────
                # Counts actions that left the screen exactly where it was.
                # A screen that moved has nothing to recover from, so its ladder
                # is forgotten too: if the walk comes back to the same form
                # later - after a validation error, say - it gets the full set
                # of escapes again rather than an already-spent one.
                # ── Filling a field is progress, even on a still screen ───────
                #
                # The streak used to reset only on a state-id change. Populating
                # a WebView input does not change one: the hierarchy keeps the
                # same nodes and the same structure, only an attribute moves.
                # So every successful fill counted as stagnation.
                #
                # Measured on the Anubis payload's four-field form: Full Name
                # and Mobile Number were both filled and verified
                # (field_populated len=11, len=10), and the very next line was
                #   FORM_STAGNATION streak=2 ... inputs=4 unfilled=2
                # Recovery then took the loop - it runs BEFORE the graph, by
                # design - and walked its ladder to `tap_submit`, submitting the
                # form with two fields still empty. Mother Name and Date Of
                # Birth were never filled on a form the walk was actively
                # completing.
                #
                # A verified population is unambiguous evidence the screen is
                # responding to us, which is exactly what the streak is meant to
                # detect the absence of.
                _filled_a_field = (
                    (action or {}).get("tool") == "type_text"
                    and bool(result.success)
                    and bool((getattr(result, "data", None) or {}).get("typed_length"))
                )
                if ever_ui_changed or _filled_a_field:
                    self._unchanged_action_streak = 0
                    self._form_recovery.reset(self._pre_action_state_id)
                else:
                    self._unchanged_action_streak += 1

                adb_ok = bool(result.success)
                verified = bool(adb_ok and ui_changed)
                self.exploration.record_action(
                    source_state_id=self._pre_action_state_id,
                    target_state_id=post_state.state_id,
                    action_type=last_action_tool,
                    target_description=last_action_target,
                    success=adb_ok,
                    verified=verified,
                    dispatched=True,
                    executed=adb_ok,
                    attempts=retry_attempts,
                    action_id=action.get("_action_id", ""),
                    ui_changed=ui_changed,
                    ever_ui_changed=ever_ui_changed,
                    input_verified=input_verified,
                )
                if self.dispatcher.last_trace is not None:
                    tr = self.dispatcher.last_trace
                    tr.ui_changed = ui_changed
                    tr.action_verification = "PASS" if verified else "FAIL"
                    tr.state_after = post_obs.screen_hash
                    tr.foreground_package_after = package_of(post_obs.activity)
                    tr.attempts = retry_attempts
                    if verified:
                        tr.mark("ACTION_VERIFIED")
                last_action_failed = (not adb_ok) or (not verified)

                # ── PROGRESS (§13) ────────────────────────────────────────────
                # Score progress from post-action UI change, not pre-action obs.
                repeated = not ui_changed and bool(self._pre_action_screen_hash)
                progress = score_progress(
                    new_screen=ui_changed,
                    runtime_events=len(frida_events_this_cycle) + len(post_frida),
                    failed_action=last_action_failed,
                    repeated_screen=repeated,
                )
                self.investigation.record_action(
                    failed=last_action_failed, same_screen=repeated
                )
                if not progress.productive:
                    logger.debug(
                        "[Investigation] Unproductive action (%d): %s",
                        progress.score, "; ".join(progress.reasons) or "no change",
                    )

                # ── G6/G7: shared progress signal, and the adaptive budget ────
                # The same verdict feeds loop recovery and the deadline, so the
                # two can no longer disagree about whether the walk is moving.
                verdict = self.progress.record(
                    screen_hash=post_obs.screen_hash,
                    state_id=post_state.state_id,
                    activity=post_obs.activity,
                    package=package_of(post_obs.activity),
                    actionable_element_ids={
                        a.action_id for a in post_state.actionable_elements
                    },
                    runtime_events=len(frida_events_this_cycle) + len(post_frida),
                    workflow_stage=self.investigation.state.value,
                    auth_state=self.auth.state.value,
                    failed_action=last_action_failed,
                )
                if self.budget is not None:
                    self.budget.note_progress(
                        meaningful=verdict.meaningful,
                        detail="; ".join(verdict.novelty[:3]),
                    )
                last_screen_hash = post_obs.screen_hash

                if post_obs.screen_hash != self._pre_action_screen_hash:
                    self.coverage_metrics["navigation_depth"] += 1
                    self.exploration_graph.append({
                        "from":      self._pre_action_screen_hash,
                        "to":        post_obs.screen_hash,
                        "from_state": self._pre_action_state_id,
                        "to_state":  post_state.state_id,
                        "action":    last_action_tool,
                        "target":    last_action_target,
                        "goal":      action.get("goal", ""),
                        "timestamp": self._elapsed_ts(),
                        "source":    action.get("_source", "ai"),
                        "frida_events": post_frida,
                    })
                # Use post-action observation for remaining bookkeeping
                obs = post_obs
                if post_frida:
                    self.goals.update_from_frida_events(post_frida)
                    frida_silence_streak = 0

                # A cached choice that failed must not be replayed on this
                # screen - drop it so the next visit re-plans from scratch.
                if last_action_failed:
                    self.planner.invalidate_cache_for_screen(obs.screen_hash)

                # Record in memory
                tool   = action.get("tool", "")
                target = action.get("text") or str(action.get("x", ""))
                redundant = self.memory.is_action_loop(tool, target)

                # Credential key: only recorded if type_text tool was used
                cred_key = action.get("field_hint") if tool == "type_text" else None

                self.memory.record_action(
                    tool=tool,
                    target=target,
                    goal_name=action.get("goal", ""),
                    reasoning=reasoning,
                    success=result.success,
                    error=result.error,
                    credential_key=cred_key,
                )
                self.benchmark.record_action(obs.screen_hash, tool, target, redundant=redundant)

                # Update coverage metrics
                if tool in ("tap", "click_text"):
                    self.coverage_metrics["buttons_clicked"] += 1
                elif tool == "type_text":
                    self.coverage_metrics["forms_completed"] += 1
                elif tool == "grant_permission":
                    self.coverage_metrics["permissions_granted"] += 1
                    self.memory.record_permission_granted(action.get("permission", ""))

                if obs.screenshot_taken:
                    self.benchmark.record_screenshot()

                # ── Per-action evidence frame ──────────────────────────────────
                # Perception only screenshots when its 5-trigger tree fires and
                # the screen hash changed, so an analyst reading the report could
                # not see what each click actually did. Capture one frame per
                # executed action, forced past the perceptual-hash dedup: two
                # taps that look identical are still two distinct pieces of
                # evidence about what the app was asked to do.
                if self.screenshot_manager is not None and ACTION_EVIDENCE_FRAMES:
                    try:
                        self.screenshot_manager.capture_async(
                            label=f"action_{actions_taken:02d}_{tool}",
                            category="explorer_action",
                            source="explorer",
                            reason="EXPLORER_ACTION",
                            explorer_action=f"{tool}:{target}" if target else tool,
                            activity=obs.activity,
                            stage=action.get("goal", ""),
                            state_id=post_state.state_id,
                            action_id=action.get("_action_id", ""),
                            foreground_package=package_of(obs.activity),
                            layout_hash=obs.screen_hash,
                            semantic_type=post_classification.screen_type,
                            screen_observation=self._screen_observation(
                                post_obs, post_classification,
                            ),
                        )
                    except Exception as exc:
                        logger.debug(
                            "[AgenticExplorer] per-action capture failed: %s", exc
                        )

                # Log to attack_timeline
                self.attack_timeline.append({
                    "timestamp": self._elapsed_ts(),
                    "source":    action.get("_source", "ai").upper(),
                    "action":    tool,
                    "target":    target,
                    "goal":      action.get("goal", ""),
                    "details":   reasoning,
                    "success":   result.success,
                })

                # Log graph edge (legacy format - primary graph is in exploration.to_dict())
                # Edge already recorded above via post-action re-observe.

                # ── Audit log entry ────────────────────────────────────────────
                goal_snapshot = self.goals.completion_summary()
                self.audit_log.record(
                    iteration=self.memory.iteration,
                    activity=obs.activity,
                    screen_hash=obs.screen_hash,
                    ui_node_count=obs.ui_node_count,
                    screenshot_taken=obs.screenshot_taken,
                    vision_reason=obs.vision_reason,
                    goal_name=action.get("goal", ""),
                    goal_stage=next_goal.stage if next_goal else 0,
                    goal_status=next_goal.status.value if next_goal else "NONE",
                    reasoning=reasoning,
                    action=action,
                    result_success=result.success,
                    result_duration=result.duration,
                    result_retries=result.retries,
                    result_error=result.error,
                    frida_events=frida_events_this_cycle,
                    network_events=self.memory.network_events[-5:],
                    goal_status_snapshot=goal_snapshot,
                    action_budget_used=actions_taken,
                    action_budget_max=ACTION_BUDGET,
                    empty_action_streak=frida_silence_streak,
                    time_elapsed_s=time.monotonic() - self._start_time,
                    source=action.get("_source", "ai"),
                )

                last_screen_hash = obs.screen_hash

                # Hand this iteration's settled post-action read forward. The
                # next iteration re-checks the focus signature before trusting
                # it, so a screen that moves on its own still gets a fresh
                # observation. See _reusable_observation().
                carried_obs = await self._carry_observation(post_obs)

                logger.debug(f"[AgenticExplorer] Iteration {self.memory.iteration}: {result.to_log_line()}")

        except asyncio.CancelledError:
            logger.info("[AgenticExplorer] Task cancelled")
        except Exception as e:
            # Record unexpected crashes into explorer_error so they appear in
            # the result dict rather than being silently swallowed.
            err_msg = f"{type(e).__name__}: {e}"
            logger.error(f"[AgenticExplorer] Fatal loop error: {err_msg}")
            self.audit_log.record_system_event("fatal_error", err_msg)
            # Attach to the explorer so frida_sandbox.py can surface it.
            self.explorer_error = err_msg  # type: ignore[attr-defined]
        finally:
            await self._finalize(actions_taken)

    async def _finalize(self, actions_taken: int) -> None:
        """
        Cleanup and final metric recording.

        Runs on EVERY exit path, including the wall-clock deadline, and it is
        deliberately not gated on remaining time: flushing what was collected is
        bookkeeping, not exploration, and a run that stops without doing it has
        thrown away the evidence it spent its whole budget gathering (§P11).
        """
        # Charge the final iteration to whichever goal was current, so a goal
        # that was being worked when the run ended is not credited zero time.
        if self._current_goal_name and self._current_goal_started:
            self.goals.add_time_spent(
                self._current_goal_name,
                time.monotonic() - self._current_goal_started,
            )

        # ── Settle every goal the run never concluded ────────────────────────
        # PENDING in a finished run is not a state, it is an omission: it
        # invites the reader to treat "never selected" as "did not happen".
        # finalize() turns those into NOT_REACHED, and a goal that was mid-flight
        # when the deadline arrived into TIMEOUT.
        timed_out = self._stop_reason == StopReason.TIME_BUDGET_EXHAUSTED or (
            (deadline := get_active_deadline()) is not None and deadline.expired
        )
        self.goals.finalize(
            timed_out=timed_out,
            reason=TIMEOUT_REASON if timed_out else (
                self._stop_reason.value if self._stop_reason else "run_ended"
            ),
        )

        # Compute goal summary for benchmark
        completed = sum(1 for g in self.goals.goals if g.status == GoalStatus.COMPLETED)
        skipped   = sum(1 for g in self.goals.goals if g.status == GoalStatus.SKIPPED)
        failed    = sum(1 for g in self.goals.goals if g.status == GoalStatus.FAILED)
        self.benchmark.set_goal_summary(completed, skipped, failed)

        # Coverage percent - prefer exploration graph metrics when available
        exp_cov = self.exploration.coverage_metrics()
        if exp_cov.get("actionable_elements_discovered", 0) > 0:
            self.coverage_metrics["coverage_percent"] = int(
                exp_cov.get("exploration_coverage_percent", 0)
            )
        else:
            found   = self.coverage_metrics["buttons_found"]
            clicked = self.coverage_metrics["buttons_clicked"]
            if found > 0:
                self.coverage_metrics["coverage_percent"] = min(
                    100, int(clicked / found * 100)
                )

        if self._stop_reason:
            self.exploration.stop_reason = self._stop_reason

        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source":    "System",
            "action":    "AgenticExplorer Completed",
            "details":   (
                f"Actions={actions_taken}, "
                f"Goals: completed={completed} skipped={skipped} failed={failed}, "
                f"StopReason={self._stop_reason.value if self._stop_reason else 'unknown'}, "
                f"States={exp_cov.get('states_discovered', 0)}"
            ),
        })
        self.audit_log.record_system_event(
            "exploration_complete",
            f"actions={actions_taken}, goals_completed={completed}"
        )

        # Unsubscribe from EventBus
        if self.event_bus:
            self.event_bus.unsubscribe(self._on_frida_event)

        self._is_running = False
        logger.info(
            f"[AgenticExplorer] Completed. "
            f"Actions={actions_taken}, Screens={len(self.memory.visited_screens)}, "
            f"GoalsCompleted={completed}/{len(self.goals.goals)}"
        )

    # ── Stop signal ────────────────────────────────────────────────────────────

    def _log_consequences(
        self, before_obs: Any, after_obs: Any, classification: Any
    ) -> None:
        """Record generic post-action consequences. No APK-specific rules."""
        fg_before = package_of(getattr(before_obs, "activity", ""))
        fg_after = package_of(getattr(after_obs, "activity", ""))
        notes = []
        if fg_before and fg_after and fg_before != fg_after:
            notes.append(f"foreground {fg_before} -> {fg_after}")
        st = getattr(classification, "screen_type", "")
        if st:
            notes.append(f"screen_type={st}")
        own = getattr(classification, "ownership", "")
        if own:
            notes.append(f"ownership={own}")
        if getattr(after_obs, "is_webview", False):
            notes.append("webview_visible")
        moments = [
            m.moment_type for m in self.exploration.evidence_moments[-5:]
        ]
        pipeline_log(
            "CONSEQUENCE_OBSERVED",
            detail="; ".join(notes) or "ui_transition",
            evidence=",".join(moments[-3:]) if moments else "",
        )

    def stop(self) -> None:
        """Signal the agent loop to stop gracefully. Same interface as UIExplorer."""
        self._cancel_task = True

    # ── Report generation (same interface as UIExplorer.get_reports()) ─────────

    def get_reports(self) -> Dict[str, Any]:
        """
        Return all artifacts in the same structure as UIExplorer.get_reports().

        Adds:
            "audit_log" - full Explainable Exploration Log
            "benchmark" - per-run benchmark metrics
            "goal_summary" - final status of all 15 fraud goals
            "agent_memory" - memory summary (no credential values)
        """
        mem_summary = self.memory.get_summary()
        audit_entries = self.audit_log.get_entries()
        benchmark_report = self.benchmark.build_report()
        goal_summary = self.goals.completion_summary()
        # Added as new keys rather than reshaping the existing ones: every
        # current consumer of get_reports() keeps working unchanged (§23).
        investigation_summary = self.investigation.summary()
        permission_summary = self.permissions.summary()

        exploration_summary = {
            "duration_seconds":    self._duration,
            "screens_visited":     self.coverage_metrics["screens"],
            "buttons_clicked":     self.coverage_metrics["buttons_clicked"],
            "forms_completed":     self.coverage_metrics["forms_completed"],
            "permissions_granted": self.coverage_metrics["permissions_granted"],
            "dialogs_dismissed":   self.coverage_metrics["dialogs_dismissed"],
            "navigation_depth":    self.coverage_metrics["navigation_depth"],
            "coverage_percent":    self.coverage_metrics["coverage_percent"],
            "total_iterations":    self.memory.iteration,
            "llm_calls":           benchmark_report.get("llm_calls_made", 0),
            "fallback_activations":benchmark_report.get("fallback_activations", 0),
            "goals_completed":     benchmark_report.get("goals_completed", 0),
            "goals_skipped":       benchmark_report.get("goals_skipped", 0),
            "goals_failed":        benchmark_report.get("goals_failed", 0),
            "explorer_type":       "AgenticExplorer",
            "stop_reason":         self._stop_reason.value if self._stop_reason else "",
            **self.exploration.coverage_metrics(),
        }

        deep_exploration = self.exploration.to_dict()
        action_traces = [t.to_dict() for t in self.dispatcher.traces]

        # ── Dynamic status (§P25) ────────────────────────────────────────────
        # Instrumentation is judged by whether the run ever had a target
        # process to watch, not by whether the walk got far: a sample that was
        # launched, attached to and then blocked at a boundary produced real
        # evidence, and reporting that as INSTRUMENTATION_FAILED would let a
        # partial run be mistaken for an unobserved one.
        instrumentation_ok = bool(self._target_pid) or bool(
            self.exploration.states
        )
        dynamic_status = self.exploration.dynamic_status(
            instrumentation_ok=instrumentation_ok
        ).value
        exploration_summary["dynamic_status"] = dynamic_status

        # ── Goal coverage (§P2/§P12) ─────────────────────────────────────────
        # The 15-goal graph reports what it achieved as a DISTRIBUTION, and the
        # coverage contract is derived from that distribution plus the evidence
        # actually observed. Neither is a validity verdict on its own: coverage
        # says how much of the plan was exercised, validity says whether the
        # run produced trustworthy evidence, and 60% coverage is a valid
        # partial run, not an invalid one (§P14).
        goal_coverage = self.goals.coverage_report()
        deadline = get_active_deadline()
        timed_out = self._stop_reason == StopReason.TIME_BUDGET_EXHAUSTED or (
            deadline is not None and deadline.expired
        )
        # Verified transitions only: the exploration graph's edge count is what
        # PRE/POST observation actually proved, not what ADB accepted.
        meaningful_transitions = len(self.exploration.edges)
        dynamic_coverage = build_dynamic_coverage(
            goal_coverage,
            sandbox_available=True,
            instrumentation_ok=instrumentation_ok,
            # The explorer counts what IT observed. frida_sandbox recomputes
            # this from the full, harness-filtered event set before the result
            # is published - this value is the explorer's own view and is
            # deliberately the conservative one.
            evidence_event_count=int(
                getattr(self.exploration, "runtime_events_observed", 0)
            ),
            meaningful_transition_count=meaningful_transitions,
            budget_seconds=(
                deadline.total_seconds if deadline is not None
                else float(self._duration or 0)
            ),
            elapsed_seconds=(
                deadline.elapsed() if deadline is not None
                else (time.monotonic() - self._start_time if self._start_time else 0.0)
            ),
            timed_out=timed_out,
        )

        return {
            # One view hierarchy per distinct in-app screen, for VIDE. Consumed
            # by vide.pipeline._dynamic_ui_hierarchies(); the single
            # `ui_hierarchy_xml` remains the fallback for older runs.
            "ui_hierarchies": [
                {"state_id": sid, "xml": xml}
                for sid, xml in self.state_ui_hierarchies.items()
            ],
            "login_attempts": self.exploration.login_attempts,
            # Unchanged key, unchanged four values. The richer AuthState sits
            # beside it rather than replacing it, so existing report consumers
            # and frida_sandbox's session key are untouched.
            "login_outcome":  self.exploration.login_outcome,
            "auth_state":     self.auth.to_dict(),
            "progress":       self.progress.to_dict(),
            "time_budget":    self.budget.to_dict() if self.budget else {},
            "child_applications": [
                rel for rel in (
                    self._payloads.relationship_for(pkg)
                    for pkg in sorted(self._payloads.child_packages())
                ) if rel
            ],
            # ── UIExplorer-compatible keys (required by frida_sandbox.py) ──────
            "exploration_graph":   self.exploration_graph,
            "coverage":            self.coverage_metrics,
            "attack_timeline":     self.attack_timeline,
            "exploration_summary": exploration_summary,
            # ── New Agentic Explorer keys ─────────────────────────────────────
            "audit_log":           audit_entries,
            "benchmark":           benchmark_report,
            "goal_summary":        goal_summary,
            # Per-goal lifecycle states and the derived coverage contract. New
            # keys beside `goal_summary`, not a reshape of it, so every existing
            # consumer keeps working unchanged.
            "goal_coverage":       goal_coverage,
            "dynamic_coverage":    dynamic_coverage,
            "permission_screens":  self.permission_screen_ledger(),
            "agent_memory":        mem_summary,
            "investigation":       investigation_summary,
            "crashes":             [f.to_dict() for f in self.crash_findings],
            "permissions":         permission_summary,
            # ── Deep exploration artifacts ────────────────────────────────────
            "deep_exploration":    deep_exploration,
            "application_profile": deep_exploration.get("application_profile", {}),
            "evidence_moments":    deep_exploration.get("evidence_moments", []),
            "victim_journey":      deep_exploration.get("victim_journey", {}),
            "state_graph":         {
                "states": deep_exploration.get("states", []),
                "edges": deep_exploration.get("edges", []),
                "mermaid": self.exploration.to_mermaid(),
            },
            # The graph's own list stays first for compatibility, but the
            # tracker is what actually observes payloads at runtime - the
            # graph list had no producer in the production path.
            "secondary_apks":      (
                list(deep_exploration.get("secondary_apks", []))
                + self._payloads.to_records()
            ),
            "secondary_apk_summary": self._payloads.summary(),
            "action_traces":       action_traces,
            # ── Target-boundary and status reporting (§P24, §P25, §P26) ───────
            "dynamic_status":      dynamic_status,
            "boundary_events":     deep_exploration.get("boundary_events", []),
            "loop_events":         deep_exploration.get("loop_events", []),
        }

    def preserve_secondary_payloads(self, output_dir: Path) -> List[Dict[str, Any]]:
        """
        Pull and hash every secondary APK the run detected.

        Deferred to the end of the run rather than done at detection time: the
        app is usually still writing the file when the hook fires, so hashing
        it immediately would record the digest of a partial download.

        Uses the sandbox provider's own adb - never a private path to the
        device - and only ever reads. Failures are recorded on the payload and
        never abort artifact flushing.
        """
        payloads = self._payloads.payloads
        if not payloads:
            return []
        try:
            from sudarshan_core.sandbox import get_sandbox_provider

            adb = get_sandbox_provider().adb
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[AgenticExplorer] no sandbox provider; %d secondary payload(s) "
                "detected but not preserved: %s", len(payloads), exc,
            )
            return self._payloads.to_records()

        target = output_dir / "secondary_apks"
        for payload in payloads:
            try:
                self._payloads.preserve(
                    payload, target, adb, device_serial=self.device_serial,
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "[AgenticExplorer] could not preserve %s",
                    payload.device_path, exc_info=True,
                )
        logger.info(
            "[AgenticExplorer] SECONDARY_PAYLOADS %s",
            self._payloads.summary(),
        )
        return self._payloads.to_records()

    def flush_artifacts(self, output_dir: Path) -> None:
        """
        Write agentic artifacts to disk in the same directory as APK reports.
        Called by frida_sandbox.py after get_reports().
        """
        try:
            records = self.preserve_secondary_payloads(output_dir)
            if records:
                import json as _json

                with open(
                    output_dir / "secondary_apks.json", "w", encoding="utf-8"
                ) as f:
                    _json.dump(
                        {
                            "parent_package": self.package_name,
                            "summary": self._payloads.summary(),
                            "payloads": records,
                        },
                        f, indent=2, default=str,
                    )
        except Exception:  # noqa: BLE001
            logger.warning(
                "[AgenticExplorer] secondary payload flush failed", exc_info=True
            )
        try:
            self.audit_log.flush(output_dir / "audit_log.json")
            self.benchmark.flush(output_dir / "benchmark.json")
            # Deep exploration graph artifacts
            import json
            deep = self.exploration.to_dict()
            with open(output_dir / "deep_exploration.json", "w", encoding="utf-8") as f:
                json.dump(deep, f, indent=2, default=str)
            with open(output_dir / "state_graph.mmd", "w", encoding="utf-8") as f:
                f.write(self.exploration.to_mermaid())
            with open(output_dir / "victim_journey.json", "w", encoding="utf-8") as f:
                json.dump(deep.get("victim_journey", {}), f, indent=2)
            if self.dispatcher.traces:
                with open(output_dir / "action_pipeline.json", "w", encoding="utf-8") as f:
                    json.dump(
                        [t.to_dict() for t in self.dispatcher.traces],
                        f,
                        indent=2,
                        default=str,
                    )
            with open(output_dir / "exploration_graph.json", "w", encoding="utf-8") as f:
                json.dump(deep, f, indent=2, default=str)
            # In-app view hierarchies, one per screen, for VIDE and for anyone
            # re-running clone comparison against a stored run.
            if self.state_ui_hierarchies:
                with open(
                    output_dir / "ui_hierarchies.json", "w", encoding="utf-8"
                ) as f:
                    json.dump(
                        {
                            "package": self.package_name,
                            "login_attempts": self.exploration.login_attempts,
                            "login_outcome": self.exploration.login_outcome,
                            "hierarchies": [
                                {"state_id": sid, "xml": xml}
                                for sid, xml in self.state_ui_hierarchies.items()
                            ],
                        },
                        f, indent=2, default=str,
                    )
            if self.screenshot_manager is not None:
                from dataclasses import asdict
                manifest = [asdict(r) for r in self.screenshot_manager.get_manifest()]
                with open(output_dir / "screenshot_manifest.json", "w", encoding="utf-8") as f:
                    json.dump({"screenshots": manifest}, f, indent=2, default=str)
            timeline = []
            for moment in deep.get("evidence_moments", []):
                timeline.append({
                    "type": "evidence_moment",
                    "timestamp": moment.get("timestamp"),
                    "evidence_moment_id": moment.get("evidence_moment_id"),
                    "event_type": moment.get("moment_type"),
                    "state_id": moment.get("state_id"),
                    "screenshot_ids": moment.get("screenshot_ids", []),
                    "runtime_event_ids": moment.get("runtime_event_ids", []),
                })
            for trace in self.dispatcher.traces:
                timeline.append({
                    "type": "action",
                    "timestamp": trace.lifecycle[0] if trace.lifecycle else "",
                    "action_id": trace.action_id,
                    "state_id": trace.state_id,
                    "semantic_role": trace.semantic_role,
                    "verified": trace.action_verification == "PASS",
                })
            timeline.sort(key=lambda e: str(e.get("timestamp") or ""))
            with open(output_dir / "evidence_timeline.json", "w", encoding="utf-8") as f:
                json.dump(timeline, f, indent=2, default=str)
            logger.info(f"[AgenticExplorer] Artifacts flushed to {output_dir}")
        except Exception as e:
            logger.error(f"[AgenticExplorer] Failed to flush artifacts: {e}")

    # ── Utilities ──────────────────────────────────────────────────────────────

    def _elapsed_ts(self) -> str:
        """Return mm:ss elapsed time string from start."""
        elapsed = int(time.monotonic() - self._start_time) if self._start_time else 0
        return f"{elapsed // 60:02d}:{elapsed % 60:02d}"

    @staticmethod
    def _is_crash_screen(activity: str) -> bool:
        """
        Detect common crash/ANR/error activity patterns.
        Returns True if the current activity looks like a crash screen.
        """
        crash_signals = [
            "has stopped",
            "android.process.acore",
            "com.android.systemui.ANR",
            "CrashActivity",
            "ANRActivity",
            "ErrorActivity",
        ]
        act_lower = activity.lower()
        return any(s.lower() in act_lower for s in crash_signals)
