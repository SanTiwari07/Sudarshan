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
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.audit_log import AuditLog
from sudarshan_core.engines.agentic.benchmark import BenchmarkCollector
from sudarshan_core.engines.agentic.goal_tracker import GoalStatus, GoalTracker
from sudarshan_core.engines.agentic.action_verifier import (
    DeviceStateProbe,
    StateSnapshot,
    VerificationResult,
    verify_action,
)
from sudarshan_core.engines.agentic.perception import (
    PerceptionPipeline,
    in_investigation_scope,
    package_of,
)
from sudarshan_core.engines.agentic.planner import AgentPlanner
from sudarshan_core.engines.agentic.tool_executor import (
    NAVIGATIONAL_TOOLS,
    ToolExecutor,
)
from sudarshan_core.engines.agentic.crash_classifier import (
    CrashContext,
    classify_crash,
    crash_event,
)
from sudarshan_core.engines.agentic.screen_classifier import classify_screen
from sudarshan_core.engines.event_bus import RuntimeEventBus
from sudarshan_core.engines.investigation_controller import (
    InvestigationController,
    InvestigationState,
    score_progress,
)
from sudarshan_core.engines.permission_investigator import PermissionInvestigator

logger = logging.getLogger(__name__)

# ─── Configuration (env overrides) ────────────────────────────────────────────

# Maximum actions the agent may take before stopping.
ACTION_BUDGET: int = int(os.getenv("SUDARSHAN_AGENT_ACTION_BUDGET", "25"))

# Capture one screenshot per executed action so the report shows what every
# click did. Perception's own screenshots are conditional and hash-deduped, so
# without this a click that does not visibly change the screen leaves no trace.
# Set SUDARSHAN_ACTION_EVIDENCE_FRAMES=0 to fall back to conditional capture.
ACTION_EVIDENCE_FRAMES: bool = os.getenv(
    "SUDARSHAN_ACTION_EVIDENCE_FRAMES", "1"
).strip().lower() not in ("0", "false", "no")

# Frida-silence threshold: stop if no new events for this many consecutive actions.
FRIDA_SILENCE_THRESHOLD: int = int(os.getenv("SUDARSHAN_AGENT_SILENCE_THRESHOLD", "5"))

# Maximum actions the agent may take on a single goal before marking it failed.
# Prevents the agent from looping forever on goals that cannot be reached
# (e.g. Stage 5 Login Flow when the app has no conventional login screen).
# This activates mark_failed → retry branch in next_priority_goal().
MAX_ATTEMPTS_PER_GOAL: int = int(os.getenv("SUDARSHAN_MAX_ATTEMPTS_PER_GOAL", "8"))


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

# Gemini API key
GEMINI_API_KEY: Optional[str] = os.environ.get("GEMINI_API_KEY")


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
            api_key=GEMINI_API_KEY,
            device_serial=device_serial,
            package_name=package_name,
            action_budget=ACTION_BUDGET,
            benchmark=self.benchmark,
            adb_path=adb_path,
        )

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

    #: Actions whose effect lives in device state rather than on screen. Only
    #: these justify the four ADB queries a full probe costs; everything else is
    #: judged from perception data the loop already holds.
    _DEVICE_STATE_ACTIONS = frozenset({
        "grant_permission", "deny_permission", "start_activity",
    })

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

    def _on_frida_event(self, event: Dict[str, Any]) -> None:
        """Receive Frida events from the bus and buffer them for the agent loop."""
        with self._events_lock:
            self._pending_frida_events.append(event)
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

        self.audit_log.record_system_event(
            "exploration_start",
            f"AgenticExplorer started. Budget={ACTION_BUDGET}, "
            f"Duration={duration_seconds}s, Package={self.package_name}"
        )
        self.attack_timeline.append({
            "timestamp": "00:00",
            "source":    "System",
            "action":    "AgenticExplorer Started",
            "details":   f"ActionBudget={ACTION_BUDGET}",
        })

        actions_taken         = 0
        frida_silence_streak  = 0
        last_action_failed    = False
        last_screen_hash      = ""
        consecutive_crashes   = 0
        out_of_scope_streak   = 0
        # Set once the sample will not come back to the foreground. Navigation
        # stops; observation does not.
        navigation_abandoned  = False
        # The last action the planner chose, kept so a departure discovered on
        # the next observation can be attributed back to the control that
        # caused it. Recovery actions issued by the guard itself deliberately
        # do not overwrite these.
        last_action_tool      = ""
        last_action_target    = ""

        # ── Mark Stage 1 goal in-progress immediately ─────────────────────────
        self.goals.mark_in_progress("Launch Application")

        try:
            while self._is_running and not self._cancel_task:
                elapsed = time.monotonic() - self._start_time

                # ── SC4: Time budget ───────────────────────────────────────────
                if elapsed >= duration_seconds:
                    logger.info(f"[AgenticExplorer] SC4: Time budget exhausted ({elapsed:.1f}s)")
                    self.audit_log.record_system_event("stop_time_budget", f"elapsed={elapsed:.1f}s")
                    break

                # ── SC3: Action budget ─────────────────────────────────────────
                if actions_taken >= ACTION_BUDGET:
                    logger.info(f"[AgenticExplorer] SC3: Action budget exhausted ({actions_taken})")
                    self.audit_log.record_system_event("stop_action_budget", f"actions={actions_taken}")
                    break

                # ── SC1: All goals done ────────────────────────────────────────
                if self.goals.all_done():
                    logger.info("[AgenticExplorer] SC1: All fraud goals completed")
                    self.audit_log.record_system_event("stop_goals_complete", "All goals reached")
                    break

                self.memory.advance_iteration()

                # ── OBSERVE ───────────────────────────────────────────────────
                frida_events_this_cycle = self._drain_frida_events()
                obs = await self.perception.observe(
                    frida_events=frida_events_this_cycle,
                    last_action_failed=last_action_failed,
                    static_findings=self.static_findings,
                )
                if obs.ui_xml_raw:
                    self.last_ui_hierarchy_xml = obs.ui_xml_raw[:120_000]

                # Stage 1 is confirmed by observed foreground state, not by a
                # Frida hook (hooks cannot fire before the app is running) and
                # not by the LLM. Without this the whole dependency graph stays
                # blocked on stage 1 forever.
                foreground_package = package_of(obs.activity)
                self.goals.update_from_foreground(
                    foreground_package=foreground_package,
                    target_package=self.package_name,
                )

                # ── SCOPE GUARD ───────────────────────────────────────────────
                # Runs before the screen is registered: a Contacts screen is not
                # a screen of the sample, and counting it inflates both the
                # screen graph the planner reasons over and the coverage figure
                # the report presents.
                if not in_investigation_scope(foreground_package, self.package_name):
                    out_of_scope_streak += 1

                    # Blame the action that did it, once, on the first
                    # observation of the departure. memory.current_screen_hash
                    # still points at the in-app screen the tap was made from,
                    # because out-of-scope screens are never registered below.
                    if out_of_scope_streak == 1 and last_action_tool:
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
                    recovery = (
                        {"tool": "press_back"}
                        if use_back or not component
                        else {"tool": "start_activity", "component": component}
                    )
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
                                            "hook": "PackageManager.setComponentEnabledSetting",
                                            "description": (
                                                "Application's launcher component "
                                                "no longer resolves - the app "
                                                "removed itself from the launcher"
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

                out_of_scope_streak = 0

                # Judge the previous screen-changing action now that the settled
                # screen has been read. Deferring costs nothing and is more
                # accurate than dumping the UI a second time right after acting.
                deferred = self._resolve_pending_verification(obs)
                if deferred is not None and deferred.outcome != "UNVERIFIED":
                    logger.info("[AgenticExplorer] %s", deferred.log_line())

                # ── INVESTIGATION STATE ───────────────────────────────────────
                # Deterministic: the screen classifier is rule-based and the
                # Frida categories are facts, so the model has no say in which
                # stage the investigation is in.
                classification = classify_screen(
                    obs.activity, obs.ui_nodes, obs.ui_xml_raw, self.package_name
                )
                self.investigation.observe(
                    screen_type=classification.screen_type,
                    frida_categories=[
                        e.get("category", "") for e in frida_events_this_cycle
                        if isinstance(e, dict)
                    ],
                )
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

                # SC2: Frida silence threshold
                if frida_silence_streak >= FRIDA_SILENCE_THRESHOLD:
                    self.goals.auto_skip_if_applicable(frida_silence_streak)
                    if self.goals.all_done():
                        logger.info(
                            f"[AgenticExplorer] SC2: No Frida evidence for "
                            f"{frida_silence_streak} actions"
                        )
                        self.audit_log.record_system_event(
                            "stop_frida_silence",
                            f"streak={frida_silence_streak}"
                        )
                        break

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

                action = await self.planner.decide(obs, self.memory, self.goals)

                # SC6: Planner signals stop (FallbackPlanner exhausted)
                if action is None:
                    logger.info("[AgenticExplorer] SC6: Planner returned None - no progress possible")
                    self.audit_log.record_system_event(
                        "stop_planner_exhausted",
                        "FallbackPlanner consecutive failure limit reached"
                    )
                    break

                reasoning = action.get("reasoning", "")
                self.memory.record_reasoning(reasoning)
                if action.get("_source") == "fallback":
                    self.benchmark.record_fallback_activation()

                # NOTE: LLM calls are counted inside AgentPlanner, at the actual
                # request site - a schema retry issues a second API call that is
                # invisible from here.


                # ── ENFORCE THE STAGE ALLOWLIST (§34) ─────────────────────────
                # The planner proposes; the controller disposes. An action the
                # current stage does not permit never reaches the device, so a
                # model that hallucinates a tool - or is talked into one by the
                # analysed app's own UI text - cannot act on it.
                chosen_tool = action.get("tool", "")
                if not self.investigation.is_action_allowed(chosen_tool):
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

                # State before the action, for the verifier to compare against.
                # Only actions whose effect lives in device state pay for a
                # device probe; screen-changing actions are judged from the
                # perception data we already hold, which costs nothing.
                before = await self._verification_snapshot(action, obs)

                result = await self.executor.execute(action)
                actions_taken += 1

                # ── VERIFY ────────────────────────────────────────────────────
                # ToolResult.success only means the ADB command exited zero. It
                # is true for a click that matched nothing and for a grant of a
                # permission the manifest never declared. The device is asked
                # instead, and only a positive FAILED counts against the action.
                verification = await self._verify_action(action, before, obs)
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

                # ── PROGRESS (§13) ────────────────────────────────────────────
                # An orchestration signal only. It decides whether to keep
                # pushing on this stage; it never reaches BFCI or FRS, because
                # navigation luck must not move a verdict.
                repeated = obs.screen_hash == last_screen_hash and bool(obs.screen_hash)
                progress = score_progress(
                    new_screen=not repeated and bool(obs.screen_hash),
                    runtime_events=len(frida_events_this_cycle),
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
                last_screen_hash = obs.screen_hash

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
                    settled = await self.executor.wait_for_idle()
                    if not settled:
                        logger.debug(
                            "[AgenticExplorer] UI did not settle after '%s' - "
                            "observing anyway", action.get("tool", "")
                        )

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
                        # Async: capture() blocks on three adb round-trips, and
                        # stalling this loop while a Frida session is live drops
                        # the transport.
                        self.screenshot_manager.capture_async(
                            label=f"action_{actions_taken:02d}_{tool}",
                            category="explorer_action",
                            source="explorer",
                            reason="EXPLORER_ACTION",
                            explorer_action=f"{tool}:{target}" if target else tool,
                            activity=obs.activity,
                            stage=action.get("goal", ""),
                            force=True,
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

                # Log graph edge
                if last_screen_hash and obs.screen_hash != last_screen_hash:
                    self.coverage_metrics["navigation_depth"] += 1
                    self.exploration_graph.append({
                        "from":      last_screen_hash,
                        "to":        obs.screen_hash,
                        "action":    tool,
                        "target":    target,
                        "goal":      action.get("goal", ""),
                        "timestamp": self._elapsed_ts(),
                        "source":    action.get("_source", "ai"),
                        "frida_events": frida_events_this_cycle,
                    })

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

        # Coverage percent
        found   = self.coverage_metrics["buttons_found"]
        clicked = self.coverage_metrics["buttons_clicked"]
        if found > 0:
            self.coverage_metrics["coverage_percent"] = min(100, int(clicked / found * 100))

        self.attack_timeline.append({
            "timestamp": self._elapsed_ts(),
            "source":    "System",
            "action":    "AgenticExplorer Completed",
            "details":   (
                f"Actions={actions_taken}, "
                f"Goals: completed={completed} skipped={skipped} failed={failed}"
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
        }

        return {
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
        }

    def flush_artifacts(self, output_dir: Path) -> None:
        """
        Write agentic artifacts to disk in the same directory as APK reports.
        Called by frida_sandbox.py after get_reports().
        """
        try:
            self.audit_log.flush(output_dir / "audit_log.json")
            self.benchmark.flush(output_dir / "benchmark.json")
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
