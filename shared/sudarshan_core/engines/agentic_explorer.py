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
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
from sudarshan_core.engines.agentic.adaptive_budget import AdaptiveBudget
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
    MAX_EXECUTION_ATTEMPTS,
    pipeline_log,
    select_canonical_action,
)
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
        self._probe = DeviceStateProbe(self.executor._adb, package_name)
        # A screen-changing action awaiting judgement by the next observation.
        self._pending_verification = None
        # Every crash this run, classified. Reported rather than summed: three
        # crashes of three different kinds is a different story from three of
        # the same kind.
        self.crash_findings: List[Any] = []
        # Stages whose deterministic procedure has already run, so returning to
        # a stage does not repeat work that is not idempotent on the device.
        self._procedures_run: set = set()

        self.planner    = AgentPlanner(
            api_key="configured" if gemini_is_configured() else None,
            device_serial=device_serial,
            package_name=package_name,
            action_budget=ACTION_BUDGET,
            benchmark=self.benchmark,
            adb_path=adb_path,
        )

        # Deep exploration state graph (deterministic coverage engine)
        self.exploration = ExplorationGraph(package_name=package_name)
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
        # State ids that already contributed an in-app evidence frame.
        self._state_frames_captured: set = set()
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
        self, action: Dict[str, Any], attempt: int
    ) -> Optional[Dict[str, Any]]:
        """Bounded retry ladder via ActionDispatcher (max 3 attempts)."""
        return self.dispatcher.retry_payload(action, attempt)

    async def _execute_with_bounded_retries(
        self,
        action: Dict[str, Any],
        obs: Any,
    ) -> Tuple[Any, VerificationResult, int]:
        """
        Execute with up to 3 attempts. ADB success is not verification.

        Attempt 1: structured click
        Attempt 2: geometry / parent tap
        Attempt 3: visual-grounded current-screen tap
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

        for attempt_index in range(MAX_EXECUTION_ATTEMPTS):
            attempts = attempt_index + 1
            if attempt_index > 0:
                retry = self._action_retry_variants(action, attempt_index)
                if retry is None:
                    break
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
        for keyword, perm in perm_map.items():
            if keyword in combined or keyword in classification.screen_type.lower():
                self.permissions.record_runtime_request(perm)
                break
        if classification.screen_type == "ACCESSIBILITY_DIALOG":
            self.permissions.record_runtime_request(
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
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

    def _drain_frida_events(self) -> List[Dict]:
        """Drain and return all buffered Frida events since the last drain."""
        with self._events_lock:
            events = list(self._pending_frida_events)
            self._pending_frida_events.clear()
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

        # The caller's duration is the STARTING budget, not the whole story.
        # frida_sandbox passes FRIDA_ANALYSIS_DURATION (300s by default) to
        # every sample alike, which cuts off an app that is mid-login and
        # idles for four minutes on one that finished at t=40. The deadline now
        # follows the walk, within a hard maximum that nothing can move.
        self.budget = AdaptiveBudget(
            initial_seconds=float(duration_seconds),
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
                # Classified here rather than after the scope guard: the guard
                # needs the screen type to distinguish a consent prompt hosted
                # by Settings from an ordinary Settings screen. Reused verbatim
                # by the INVESTIGATION STATE step below - not recomputed.
                classification = classify_screen_with_ownership(
                    obs.activity, obs.ui_nodes, obs.ui_xml_raw,
                    self.package_name, foreground_package,
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
                graph_state = self.exploration.observe(
                    obs,
                    semantic_type=classification.screen_type,
                    foreground_package=foreground_package,
                    ownership=classification.ownership,
                    elapsed_ts=self._elapsed_ts(),
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

                    # If this goal has accumulated too many attempts without
                    # completing, mark it FAILED so the retry branch can take
                    # over, or downstream goals can unblock via skip_if_missing.
                    if next_goal.attempts >= MAX_ATTEMPTS_PER_GOAL:
                        logger.warning(
                            f"[AgenticExplorer] Goal '{next_goal.name}' exhausted "
                            f"{next_goal.attempts} attempts - marking FAILED"
                        )
                        self.goals.mark_failed(next_goal.name)
                        self.audit_log.record_system_event(
                            "goal_max_attempts",
                            f"{next_goal.name}: {next_goal.attempts}/{MAX_ATTEMPTS_PER_GOAL}"
                        )
                        # Re-evaluate next goal after state change
                        next_goal = self.goals.next_priority_goal()

                planner_action = None
                if should_invoke_planner(classification.screen_type):
                    planner_action = await self.planner.decide(obs, self.memory, self.goals)

                graph_action = self.exploration.get_next_action(
                    state_id=graph_state.state_id, memory=self.memory,
                )
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
                self._submitted_credentials = bool(
                    last_action_tool in ("click_text", "tap")
                    and _is_submit_label(last_action_target)
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
        """Cleanup and final metric recording."""
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
