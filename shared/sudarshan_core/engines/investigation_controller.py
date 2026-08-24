"""
Which stage of the investigation are we in, and what may be done here?

The explorer loop had no answer to either question. `AgenticExplorer.start()` is
a flat `while`: observe, plan, act, settle, repeat, bounded only by an action
budget, a time budget and Frida silence. Nothing tracks that permissions are
being investigated right now, so nothing can branch on it - a calculator and a
banking trojan get the identical treatment, and "what should we look at next"
is whatever the planner happens to pick.

This module supplies the missing state. It deliberately does NOT supply:

* **Goals.** `GoalTracker` already owns 15 fraud goals with a dependency graph
  and Frida-event completion rules. The controller maps a state to which of
  those goals are relevant and reads their status; it does not re-implement them.
* **A verdict.** The controller decides what to investigate next. The risk
  engine decides what the evidence means. Nothing here touches STEI, BFCI or
  FRS.
* **An action executor.** `TOOL_REGISTRY` is the action allowlist and
  `ToolExecutor` runs them. The controller narrows which registered tools are
  permitted in the current state; it cannot invent one.

The narrowing is the security-relevant part. Under §34 the model must never be
able to reach for an arbitrary action: `allowed_actions()` returns a subset of
the registry, and anything outside it is rejected before it reaches a device.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from sudarshan_core.engines.agentic.screen_classifier import ScreenType
from sudarshan_core.engines.capability_profile import AppCategory

logger = logging.getLogger(__name__)


# ─── Configuration (§33) ──────────────────────────────────────────────────────
# Every limit is named and overridable; none is written into a call site.

def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, "").strip() or default))
    except (TypeError, ValueError):
        return default


#: Total actions across the whole investigation.
#:
#: Kept in step with AgenticExplorer.ACTION_BUDGET, which is what the explorer
#: actually passes in. This default only applies to a controller constructed
#: directly, so a stale value here is quietly misleading rather than wrong.
INVESTIGATION_MAX_ACTIONS: int = _int_env("INVESTIGATION_MAX_ACTIONS", 120)
#: Actions one stage may spend before the investigation moves on.
#:
#: Lowered from 8 so the plan can actually be completed. A banking-trojan plan
#: runs to 11 stages; at 8 actions each that is 88 actions, far beyond any
#: sensible budget, so early stages consumed the run and the fraud-relevant
#: ones were never reached. Four is enough to open a screen, act on it and
#: judge the result, which is what a stage needs to be conclusive.
INVESTIGATION_MAX_ACTIONS_PER_GOAL: int = _int_env("INVESTIGATION_MAX_ACTIONS_PER_GOAL", 4)
#: Consecutive observations of the same screen before the state is forced on.
INVESTIGATION_MAX_SAME_SCREEN: int = _int_env("INVESTIGATION_MAX_SAME_SCREEN", 2)
#: Consecutive verified failures before the current stage is abandoned.
INVESTIGATION_MAX_CONSECUTIVE_FAILURES: int = _int_env(
    "INVESTIGATION_MAX_CONSECUTIVE_FAILURES", 3
)
#: Wall-clock ceiling for the whole investigation.
INVESTIGATION_TIMEOUT_SECONDS: int = _int_env("INVESTIGATION_TIMEOUT_SECONDS", 300)


class InvestigationState(str, Enum):
    """Stages an investigation can occupy."""

    BOOTSTRAP = "BOOTSTRAP"
    APP_LAUNCH = "APP_LAUNCH"
    INITIAL_OBSERVATION = "INITIAL_OBSERVATION"
    PERMISSION_ANALYSIS = "PERMISSION_ANALYSIS"
    PERMISSION_HANDLING = "PERMISSION_HANDLING"
    SPECIAL_PERMISSION_ANALYSIS = "SPECIAL_PERMISSION_ANALYSIS"
    ACCESSIBILITY_ANALYSIS = "ACCESSIBILITY_ANALYSIS"
    POST_PERMISSION_EXPLORATION = "POST_PERMISSION_EXPLORATION"
    AUTHENTICATION_ANALYSIS = "AUTHENTICATION_ANALYSIS"
    OTP_ANALYSIS = "OTP_ANALYSIS"
    BANKING_TARGET_ANALYSIS = "BANKING_TARGET_ANALYSIS"
    OVERLAY_ANALYSIS = "OVERLAY_ANALYSIS"
    NETWORK_ANALYSIS = "NETWORK_ANALYSIS"
    PERSISTENCE_ANALYSIS = "PERSISTENCE_ANALYSIS"
    DYNAMIC_CODE_ANALYSIS = "DYNAMIC_CODE_ANALYSIS"
    FINAL_OBSERVATION = "FINAL_OBSERVATION"
    COMPLETE = "COMPLETE"


# Every tool named below must exist in TOOL_REGISTRY - `unknown_actions()`
# asserts that, so a typo fails a test rather than silently narrowing the agent
# to nothing at runtime.

#: Read-only tools, permitted in every state except COMPLETE.
#:
#: They observe and change nothing, so forbidding them buys no safety and costs
#: real budget. Measured live: the planner proposed `dump_ui` during
#: AUTHENTICATION_ANALYSIS, the stage rejected it, and the action was spent on
#: the refusal - three of the run's actions went that way before the stage
#: advanced. The allowlist exists to stop the agent *acting* outside its remit,
#: not to stop it looking.
_READ_ONLY: FrozenSet[str] = frozenset({
    "dump_ui", "take_screenshot", "capture_logcat",
})

#: Permission handling. A runtime dialog can appear at any moment, and a goal
#: that needs a capability can come due in any exploration stage, so these are
#: permitted wherever the agent is actively exploring rather than only inside
#: PERMISSION_ANALYSIS. They remain excluded from the read-only stages.
_PERMISSION_TOOLS: FrozenSet[str] = frozenset({
    "grant_permission", "deny_permission",
})

_BASE_NAVIGATION: FrozenSet[str] = frozenset({
    "tap", "click_text", "swipe", "scroll", "press_back",
}) | _READ_ONLY

ALLOWED_ACTIONS: Dict[InvestigationState, FrozenSet[str]] = {
    InvestigationState.BOOTSTRAP: _READ_ONLY,
    InvestigationState.APP_LAUNCH: _READ_ONLY | {"start_activity", "press_back"},
    InvestigationState.INITIAL_OBSERVATION: _BASE_NAVIGATION,
    # A modal permission dialog: accept, refuse, or tap within it - plus the
    # read-only tools, so a blocked dialog can still be inspected. Navigation
    # is what stays out; letting the planner swipe or launch an activity here
    # is how a run wanders off mid-dialog and loses the grant it came for.
    InvestigationState.PERMISSION_ANALYSIS: _READ_ONLY | _PERMISSION_TOOLS | {"click_text"},
    InvestigationState.PERMISSION_HANDLING: _READ_ONLY | _PERMISSION_TOOLS | {"click_text"},
    InvestigationState.SPECIAL_PERMISSION_ANALYSIS: _READ_ONLY | _PERMISSION_TOOLS | {
        "start_activity", "click_text", "tap", "scroll", "press_back",
    },
    InvestigationState.ACCESSIBILITY_ANALYSIS: _READ_ONLY | _PERMISSION_TOOLS | {
        "start_activity", "click_text", "tap", "scroll", "press_back",
    },
    InvestigationState.POST_PERMISSION_EXPLORATION: _BASE_NAVIGATION | _PERMISSION_TOOLS | {"type_text"},
    InvestigationState.AUTHENTICATION_ANALYSIS: _BASE_NAVIGATION | _PERMISSION_TOOLS | {"type_text"},
    InvestigationState.OTP_ANALYSIS: _BASE_NAVIGATION | _PERMISSION_TOOLS | {"type_text", "inject_test_sms"},
    InvestigationState.BANKING_TARGET_ANALYSIS: _BASE_NAVIGATION | _PERMISSION_TOOLS | {"type_text", "list_packages"},
    InvestigationState.OVERLAY_ANALYSIS: _BASE_NAVIGATION | _PERMISSION_TOOLS,
    InvestigationState.NETWORK_ANALYSIS: _BASE_NAVIGATION | {
        "capture_logcat", "enable_wifi", "disable_wifi",
    },
    InvestigationState.PERSISTENCE_ANALYSIS: _BASE_NAVIGATION | {
        "broadcast_intent", "fast_forward_time", "capture_logcat",
    },
    InvestigationState.DYNAMIC_CODE_ANALYSIS: _BASE_NAVIGATION | {"capture_logcat"},
    # Safe guest UI must remain legal after the investigation plan walks past
    # the last named fraud stage; otherwise Install/OK on a still-live dialog
    # is rejected while the graph still has work.
    InvestigationState.FINAL_OBSERVATION: _BASE_NAVIGATION | _PERMISSION_TOOLS,
    InvestigationState.COMPLETE: frozenset(),
}


#: Observed screen -> the state that screen puts us in. Deterministic: the
#: classifier is rule-based, so this mapping is too, and the model has no say
#: in which stage the investigation is in.
SCREEN_TO_STATE: Dict[str, InvestigationState] = {
    ScreenType.SYSTEM_PERMISSION: InvestigationState.PERMISSION_ANALYSIS,
    ScreenType.ACCESSIBILITY_DIALOG: InvestigationState.ACCESSIBILITY_ANALYSIS,
    ScreenType.OTP_SCREEN: InvestigationState.OTP_ANALYSIS,
    ScreenType.BANK_LOGIN: InvestigationState.AUTHENTICATION_ANALYSIS,
    ScreenType.OVERLAY_ATTACK: InvestigationState.OVERLAY_ANALYSIS,
}

#: Categories ordinary apps emit incidentally, so seeing one is not by itself
#: reason to open a branch the static signals never suggested.
#:
#: Measured live: Amaze File Manager - a legitimate file manager - emitted
#: `AccessibilityManager.sendAccessibilityEvent`, which every app does whenever
#: the UI changes so screen readers can announce it. The bare `accessibility`
#: category pulled the run into ACCESSIBILITY_ANALYSIS, and the agent spent five
#: iterations walking Android Settings for an app with no accessibility service
#: at all. `network` is the same: every app talks to the network.
#:
#: These categories may still MOVE the investigation to a stage that is already
#: planned - the static signals put it there for a reason - they just cannot
#: open one on their own.
INCIDENTAL_CATEGORIES: FrozenSet[str] = frozenset({"accessibility", "network"})

#: Frida event category -> the state that evidence opens. Runtime evidence can
#: pull the investigation into a branch the static signals never suggested,
#: which is the point of §4's "observed runtime evidence determines the branch".
CATEGORY_TO_STATE: Dict[str, InvestigationState] = {
    "accessibility": InvestigationState.ACCESSIBILITY_ANALYSIS,
    "overlay": InvestigationState.OVERLAY_ANALYSIS,
    "sms": InvestigationState.OTP_ANALYSIS,
    "network": InvestigationState.NETWORK_ANALYSIS,
    "persistence": InvestigationState.PERSISTENCE_ANALYSIS,
    "banking": InvestigationState.BANKING_TARGET_ANALYSIS,
}

#: States every investigation runs, regardless of what the sample looks like.
_ALWAYS: Tuple[InvestigationState, ...] = (
    InvestigationState.BOOTSTRAP,
    InvestigationState.APP_LAUNCH,
    InvestigationState.INITIAL_OBSERVATION,
    InvestigationState.PERMISSION_ANALYSIS,
    InvestigationState.POST_PERMISSION_EXPLORATION,
    InvestigationState.NETWORK_ANALYSIS,
    InvestigationState.FINAL_OBSERVATION,
    InvestigationState.COMPLETE,
)


@dataclass
class StateTransition:
    """One move between states, with the reason that caused it."""

    from_state: str
    to_state: str
    reason: str
    action_index: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_state,
            "to": self.to_state,
            "reason": self.reason,
            "action_index": self.action_index,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }


@dataclass
class ProgressSignal:
    """
    Whether an action moved the investigation forward (§13).

    Explicitly an ORCHESTRATION signal. It never reaches BFCI or FRS - it only
    decides whether to keep pushing on the current stage or move on. Mixing it
    into the risk score would let navigation luck change a verdict.
    """

    score: int = 0
    reasons: List[str] = field(default_factory=list)

    def add(self, points: int, reason: str) -> None:
        self.score += points
        self.reasons.append(f"{reason} ({points:+d})")

    @property
    def productive(self) -> bool:
        return self.score > 0


#: Weights from §13. Named so they are tunable in one place.
PROGRESS_WEIGHTS: Dict[str, int] = {
    "new_screen": 3,
    "new_evidence": 3,
    "runtime_event": 3,
    "new_permission_state": 2,
    "new_activity": 2,
    "goal_completed": 5,
    "repeated_screen": -2,
    "failed_action": -3,
    "crash": -5,
}


def score_progress(
    *,
    new_screen: bool = False,
    new_activity: bool = False,
    runtime_events: int = 0,
    new_evidence: int = 0,
    new_permission_state: bool = False,
    goal_completed: bool = False,
    repeated_screen: bool = False,
    failed_action: bool = False,
    crashed: bool = False,
) -> ProgressSignal:
    """Turn what happened after one action into a progress signal."""
    signal = ProgressSignal()
    if new_screen:
        signal.add(PROGRESS_WEIGHTS["new_screen"], "new screen")
    if new_activity:
        signal.add(PROGRESS_WEIGHTS["new_activity"], "new activity")
    if runtime_events:
        signal.add(PROGRESS_WEIGHTS["runtime_event"], "runtime event")
    if new_evidence:
        signal.add(PROGRESS_WEIGHTS["new_evidence"], "new evidence")
    if new_permission_state:
        signal.add(PROGRESS_WEIGHTS["new_permission_state"], "permission state changed")
    if goal_completed:
        signal.add(PROGRESS_WEIGHTS["goal_completed"], "goal completed")
    if repeated_screen:
        signal.add(PROGRESS_WEIGHTS["repeated_screen"], "screen repeated")
    if failed_action:
        signal.add(PROGRESS_WEIGHTS["failed_action"], "action failed")
    if crashed:
        signal.add(PROGRESS_WEIGHTS["crash"], "application crashed")
    return signal


class InvestigationController:
    """
    Owns the investigation lifecycle: which stage, what is allowed, what next.

    Holds no device handle and performs no I/O. Callers feed it observations and
    it answers questions - which keeps every branching rule unit-testable
    without an emulator.
    """

    def __init__(
        self,
        package_name: str = "",
        category: AppCategory = AppCategory.UNKNOWN,
        static_flags: Optional[Dict[str, Any]] = None,
        special_permissions: Optional[Sequence[str]] = None,
        max_actions: int = INVESTIGATION_MAX_ACTIONS,
        timeout_seconds: int = INVESTIGATION_TIMEOUT_SECONDS,
    ) -> None:
        self.package_name = package_name
        self.category = category
        self.static_flags = dict(static_flags or {})
        self.special_permissions = list(special_permissions or [])
        self.max_actions = max_actions
        self.timeout_seconds = timeout_seconds

        self.state: InvestigationState = InvestigationState.BOOTSTRAP
        self.transitions: List[StateTransition] = []
        self.visited: List[InvestigationState] = [InvestigationState.BOOTSTRAP]
        # Stages abandoned for making no progress. Never re-entered from an
        # observation: the screen that stalled a stage is usually still on
        # display when it is abandoned, so without this the controller
        # oscillates - measured live, AUTHENTICATION_ANALYSIS and
        # BANKING_TARGET_ANALYSIS traded places three times on one BANK_LOGIN
        # screen, spending the budget on transitions instead of actions.
        self.abandoned: List[InvestigationState] = []
        self.actions_taken: int = 0
        #: Actions spent in the CURRENT stage. Reset on every transition, so a
        #: stage cannot quietly consume the whole run.
        self.actions_in_stage: int = 0
        self.consecutive_failures: int = 0
        self.same_screen_streak: int = 0
        self._started: float = time.monotonic()
        self._plan: Tuple[InvestigationState, ...] = self._build_plan()

    # ── planning ─────────────────────────────────────────────────────────────

    def _build_plan(self) -> Tuple[InvestigationState, ...]:
        """
        The states this sample warrants, from its static signals.

        §4 is explicit that not every APK runs every state. A calculator with no
        accessibility service should never spend budget in
        ACCESSIBILITY_ANALYSIS; a sample that declares one always should.
        """
        planned: List[InvestigationState] = list(_ALWAYS)
        flags = self.static_flags

        def _insert_before(state: InvestigationState, anchor: InvestigationState) -> None:
            if state in planned:
                return
            planned.insert(planned.index(anchor), state)

        if self.special_permissions:
            _insert_before(
                InvestigationState.SPECIAL_PERMISSION_ANALYSIS,
                InvestigationState.POST_PERMISSION_EXPLORATION,
            )
        if flags.get("has_accessibility_abuse"):
            _insert_before(
                InvestigationState.ACCESSIBILITY_ANALYSIS,
                InvestigationState.POST_PERMISSION_EXPLORATION,
            )
        if flags.get("has_system_alert_window"):
            _insert_before(
                InvestigationState.OVERLAY_ANALYSIS,
                InvestigationState.NETWORK_ANALYSIS,
            )
        if flags.get("has_sms_read_write"):
            _insert_before(
                InvestigationState.OTP_ANALYSIS,
                InvestigationState.NETWORK_ANALYSIS,
            )
        if flags.get("targets_indian_banks") or self.category is AppCategory.BANKING:
            _insert_before(
                InvestigationState.BANKING_TARGET_ANALYSIS,
                InvestigationState.NETWORK_ANALYSIS,
            )
            _insert_before(
                InvestigationState.AUTHENTICATION_ANALYSIS,
                InvestigationState.BANKING_TARGET_ANALYSIS,
            )
        if flags.get("has_concealed_payload"):
            _insert_before(
                InvestigationState.DYNAMIC_CODE_ANALYSIS,
                InvestigationState.NETWORK_ANALYSIS,
            )
        return tuple(planned)

    @property
    def plan(self) -> Tuple[InvestigationState, ...]:
        return self._plan

    def is_planned(self, state: InvestigationState) -> bool:
        return state in self._plan

    # ── the allowlist (§12, §34) ─────────────────────────────────────────────

    def allowed_actions(self, state: Optional[InvestigationState] = None) -> FrozenSet[str]:
        """Registered tools permitted in this state. Never a superset of the registry."""
        return ALLOWED_ACTIONS.get(state or self.state, _BASE_NAVIGATION)

    def is_action_allowed(self, tool: str, state: Optional[InvestigationState] = None) -> bool:
        return bool(tool) and tool in self.allowed_actions(state)

    # ── state selection ──────────────────────────────────────────────────────

    def state_for_observation(
        self,
        screen_type: str = "",
        frida_categories: Optional[Sequence[str]] = None,
    ) -> Optional[InvestigationState]:
        """
        The state this observation implies, or None to stay put.

        A permission dialog on screen outranks a Frida category: the dialog is
        in front of the user right now and will disappear if it is not handled,
        while a category can be revisited from evidence later.
        """
        mapped = SCREEN_TO_STATE.get(screen_type or "")
        if mapped is not None:
            return mapped
        for category in frida_categories or []:
            name = str(category).lower()
            candidate = CATEGORY_TO_STATE.get(name)
            if candidate is None:
                continue
            # An incidental category cannot open an unplanned branch. It can
            # still move us to one the static signals already asked for.
            if name in INCIDENTAL_CATEGORIES and not self.is_planned(candidate):
                logger.debug(
                    "[Investigation] Ignoring incidental '%s' evidence - %s is "
                    "not in this sample's plan", name, candidate.value,
                )
                continue
            return candidate
        return None

    def transition_to(self, state: InvestigationState, reason: str) -> StateTransition:
        """Move to a state and record why, with the §32 log line."""
        record = StateTransition(
            from_state=self.state.value,
            to_state=state.value,
            reason=reason,
            action_index=self.actions_taken,
            elapsed_seconds=time.monotonic() - self._started,
        )
        self.transitions.append(record)
        logger.info(
            "[Investigation] Transition: %s -> %s (%s)",
            self.state.value, state.value, reason,
        )
        self.state = state
        if state not in self.visited:
            self.visited.append(state)
        # A new stage starts with a clean failure count; carrying it over would
        # abandon a stage for the previous one's problems.
        self.consecutive_failures = 0
        self.actions_in_stage = 0
        return record

    def observe(
        self,
        screen_type: str = "",
        frida_categories: Optional[Sequence[str]] = None,
    ) -> Optional[StateTransition]:
        """Apply an observation; returns the transition it caused, if any."""
        target = self.state_for_observation(screen_type, frida_categories)
        if target is None or target is self.state:
            return None
        if target in self.abandoned:
            # Already tried and got nowhere. Staying put lets the current stage
            # finish or time out rather than bouncing back into a dead end.
            return None
        if not self.is_planned(target):
            # Runtime evidence outranks the static plan: a sample doing
            # something the manifest never advertised is exactly what dynamic
            # analysis is for, so the branch is opened rather than skipped.
            self._plan = tuple(list(self._plan) + [target])
            logger.info(
                "[Investigation] Opening unplanned stage %s - runtime evidence "
                "showed behaviour the static signals did not predict",
                target.value,
            )
        return self.transition_to(target, reason=f"observed {screen_type or 'runtime evidence'}")

    # ── bookkeeping ──────────────────────────────────────────────────────────

    def record_action(self, *, failed: bool = False, same_screen: bool = False) -> None:
        self.actions_taken += 1
        self.actions_in_stage += 1
        self.consecutive_failures = self.consecutive_failures + 1 if failed else 0
        self.same_screen_streak = self.same_screen_streak + 1 if same_screen else 0

    def stage_budget_exhausted(self) -> bool:
        """Whether the current stage has had its share of the action budget."""
        return self.actions_in_stage >= INVESTIGATION_MAX_ACTIONS_PER_GOAL

    def next_unvisited_planned(self) -> Optional[InvestigationState]:
        """
        The next stage in the plan that has neither been visited nor abandoned.

        Plan ORDER, not plan position. Evidence-driven transitions jump around -
        Cerberus went straight from BOOTSTRAP to PERSISTENCE_ANALYSIS - so
        advancing by index skipped everything in between. Walking to the next
        *unvisited* stage means an evidence jump forward does not silently
        discard the stages it leapt over.
        """
        for state in self._plan:
            if state is InvestigationState.COMPLETE:
                continue
            if state not in self.visited and state not in self.abandoned:
                return state
        return None

    def should_advance(self) -> Tuple[bool, str]:
        """
        Whether to move on from the current stage, and why.

        This is what makes the plan drive the run. Previously the only caller of
        advance() was the stuck() branch, so a sample that kept producing events
        was never stuck and never walked its plan: measured on Cerberus, which
        had ACCESSIBILITY_ANALYSIS planned, visited BOOTSTRAP and
        PERSISTENCE_ANALYSIS, and never reached the stage that would have
        unlocked its payload.
        """
        if self.state is InvestigationState.COMPLETE:
            return False, ""
        if self.stuck():
            return True, "stage made no progress"
        if self.stage_budget_exhausted():
            return True, (
                f"stage action budget spent "
                f"({self.actions_in_stage}/{INVESTIGATION_MAX_ACTIONS_PER_GOAL})"
            )
        return False, ""

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started

    def budget_exhausted(self) -> bool:
        return self.actions_taken >= self.max_actions

    def timed_out(self) -> bool:
        return self.elapsed_seconds >= self.timeout_seconds

    def stuck(self) -> bool:
        """Whether the current stage has stopped producing anything."""
        return (
            self.consecutive_failures >= INVESTIGATION_MAX_CONSECUTIVE_FAILURES
            or self.same_screen_streak >= INVESTIGATION_MAX_SAME_SCREEN
        )

    def should_stop(self) -> Tuple[bool, str]:
        """Whether the investigation is over, and why."""
        if self.state is InvestigationState.COMPLETE:
            return True, "investigation complete"
        if self.budget_exhausted():
            return True, f"action budget exhausted ({self.actions_taken})"
        if self.timed_out():
            return True, f"time budget exhausted ({self.elapsed_seconds:.0f}s)"
        return False, ""

    def abandon(self, reason: str = "stage made no progress") -> Optional[StateTransition]:
        """Give up on the current stage and move on, without returning to it."""
        if self.state not in self.abandoned:
            self.abandoned.append(self.state)
        return self.advance(reason)

    def advance(self, reason: str = "stage complete") -> Optional[StateTransition]:
        """
        Move to the next stage of the plan that has not been done yet.

        Returns None only when the plan is exhausted, at which point the caller
        is finished rather than merely between stages.
        """
        # COMPLETE is terminal. Without this the walk happily returns to any
        # stage the run never reached, so a finished investigation restarts
        # itself instead of stopping.
        if self.state is InvestigationState.COMPLETE:
            return None
        nxt = self.next_unvisited_planned()
        if nxt is None:
            return self.transition_to(InvestigationState.COMPLETE, reason)
        return self.transition_to(nxt, reason)

    # ── reporting ────────────────────────────────────────────────────────────

    def timeline(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.transitions]

    def summary(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "category": self.category.value,
            "state": self.state.value,
            "planned_states": [s.value for s in self._plan],
            "visited_states": [s.value for s in self.visited],
            "actions_taken": self.actions_taken,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "transitions": self.timeline(),
        }


def unknown_actions() -> FrozenSet[str]:
    """
    Any action named in ALLOWED_ACTIONS that TOOL_REGISTRY does not define.

    A typo here would silently narrow the agent rather than raise, so a test
    asserts this is empty. Imported lazily to keep this module importable
    without the executor's dependencies.
    """
    from sudarshan_core.engines.agentic.tool_registry import get_tool

    named = {tool for tools in ALLOWED_ACTIONS.values() for tool in tools}
    return frozenset(name for name in named if get_tool(name) is None)
