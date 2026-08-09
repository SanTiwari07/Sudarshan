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
from sudarshan_core.engines.agentic.perception import PerceptionPipeline, package_of
from sudarshan_core.engines.agentic.planner import AgentPlanner
from sudarshan_core.engines.agentic.tool_executor import (
    NAVIGATIONAL_TOOLS,
    ToolExecutor,
)
from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

# ─── Configuration (env overrides) ────────────────────────────────────────────

# Maximum actions the agent may take before stopping.
ACTION_BUDGET: int = int(os.getenv("SUDARSHAN_AGENT_ACTION_BUDGET", "25"))

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

# Gemini API key
GEMINI_API_KEY: Optional[str] = os.environ.get("GEMINI_API_KEY")


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
    ) -> None:
        self.device_serial   = device_serial
        self.adb_path        = adb_path
        self.package_name    = package_name
        self.event_bus       = event_bus
        self.screenshot_manager = screenshot_manager
        self.static_findings = static_findings or {}

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
                self.memory.register_screen(obs.screen_hash, obs.activity)
                self.benchmark.record_screen(obs.screen_hash)

                # Stage 1 is confirmed by observed foreground state, not by a
                # Frida hook (hooks cannot fire before the app is running) and
                # not by the LLM. Without this the whole dependency graph stays
                # blocked on stage 1 forever.
                self.goals.update_from_foreground(
                    foreground_package=package_of(obs.activity),
                    target_package=self.package_name,
                )

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
                    try:
                        if self.main_activity:
                            await self.executor.execute({"tool": "am_start", "activity": self.main_activity})
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


                # ── ACT ───────────────────────────────────────────────────────
                result = await self.executor.execute(action)
                last_action_failed = not result.success
                actions_taken += 1

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
