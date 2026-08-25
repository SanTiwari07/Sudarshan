"""
SUDARSHAN - Reusable progress tracking for the exploration loop.

``investigation_controller.score_progress`` already turns one action's outcome
into a number. What it cannot do is remember: each call is independent, so
"this action achieved nothing" and "the last nine actions achieved nothing"
look identical, and the loop had no shared answer to "are we still getting
anywhere?". Loop recovery, the adaptive time budget and the stop conditions
each need that answer, and each was deriving its own.

This is the memory around that function. `score_progress` is called unchanged
and its weights are untouched.

What counts as progress
-----------------------
A new screen, state, activity or package; a newly discovered actionable
element; a runtime event; new evidence; a workflow stage; an authentication
state change; a permission state change; a child application. Any one of them
means the walk learned something.

    STATE_A --click--> STATE_A   no progress
    STATE_A --click--> STATE_B   meaningful progress

Scope: orchestration only. Nothing here feeds BFCI or FRS - a run that
navigated well is not a more dangerous app, and letting navigation luck move a
risk score would be a scoring bug. The separation is deliberate and
``test_progress_tracker`` asserts it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

__all__ = [
    "ProgressKind",
    "ProgressTracker",
    "ProgressVerdict",
]


class ProgressKind(str, Enum):
    """The verdict on one action."""

    MEANINGFUL_PROGRESS = "MEANINGFUL_PROGRESS"
    NO_PROGRESS = "NO_PROGRESS"


@dataclass
class ProgressVerdict:
    """
    What one action achieved.

    `score` and `reasons` come straight from ``score_progress`` so callers that
    already log those keep working; `kind` and `novelty` are what the loop
    actually branches on.
    """

    kind: ProgressKind = ProgressKind.NO_PROGRESS
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    #: The specific novel things this action produced ("new_state:STATE-004").
    novelty: List[str] = field(default_factory=list)
    stagnant_streak: int = 0

    @property
    def meaningful(self) -> bool:
        return self.kind is ProgressKind.MEANINGFUL_PROGRESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "score": self.score,
            "reasons": list(self.reasons),
            "novelty": list(self.novelty),
            "stagnant_streak": self.stagnant_streak,
        }


class ProgressTracker:
    """
    Remembers what the walk has already seen, and judges whether it is moving.

    Holds no device handle and performs no I/O: the explorer feeds it the
    before/after facts of an action and it answers. That keeps every rule here
    unit-testable without an emulator.
    """

    def __init__(self, *, stagnation_limit: int = 8) -> None:
        #: Consecutive unproductive actions before :attr:`is_stagnant` trips.
        self.stagnation_limit = stagnation_limit

        self._seen_screens: Set[str] = set()
        self._seen_states: Set[str] = set()
        self._seen_activities: Set[str] = set()
        self._seen_packages: Set[str] = set()
        self._seen_elements: Set[str] = set()
        self._seen_workflows: Set[str] = set()
        self._seen_auth_states: Set[str] = set()
        self._seen_permission_states: Set[str] = set()
        self._seen_child_packages: Set[str] = set()

        self.total_actions: int = 0
        self.meaningful_actions: int = 0
        self.stagnant_streak: int = 0
        self.last_progress_monotonic: float = time.monotonic()
        self.history: List[ProgressVerdict] = []

    # ── Recording ───────────────────────────────────────────────────────────

    def record(
        self,
        *,
        screen_hash: str = "",
        state_id: str = "",
        activity: str = "",
        package: str = "",
        actionable_element_ids: Optional[Set[str]] = None,
        runtime_events: int = 0,
        new_evidence: int = 0,
        workflow_stage: str = "",
        auth_state: str = "",
        permission_state: str = "",
        child_package: str = "",
        goal_completed: bool = False,
        failed_action: bool = False,
        crashed: bool = False,
    ) -> ProgressVerdict:
        """
        Judge one action and fold it into the running picture.

        Everything is optional: the caller passes what it observed, and an
        argument it does not know about is simply not evidence either way.
        """
        from sudarshan_core.engines.investigation_controller import score_progress

        self.total_actions += 1
        novelty: List[str] = []

        new_screen = bool(screen_hash) and screen_hash not in self._seen_screens
        if new_screen:
            self._seen_screens.add(screen_hash)
            novelty.append(f"new_screen:{screen_hash[:12]}")

        new_state = bool(state_id) and state_id not in self._seen_states
        if new_state:
            self._seen_states.add(state_id)
            novelty.append(f"new_state:{state_id}")

        new_activity = bool(activity) and activity not in self._seen_activities
        if new_activity:
            self._seen_activities.add(activity)
            novelty.append(f"new_activity:{activity}")

        if package and package not in self._seen_packages:
            self._seen_packages.add(package)
            novelty.append(f"new_package:{package}")

        for element_id in (actionable_element_ids or set()):
            if element_id not in self._seen_elements:
                self._seen_elements.add(element_id)
                novelty.append(f"new_element:{element_id}")

        if runtime_events:
            novelty.append(f"runtime_events:{runtime_events}")
        if new_evidence:
            novelty.append(f"new_evidence:{new_evidence}")

        if workflow_stage and workflow_stage not in self._seen_workflows:
            self._seen_workflows.add(workflow_stage)
            novelty.append(f"new_workflow:{workflow_stage}")

        new_auth = bool(auth_state) and auth_state not in self._seen_auth_states
        if new_auth:
            self._seen_auth_states.add(auth_state)
            novelty.append(f"new_auth_state:{auth_state}")

        new_permission = (
            bool(permission_state) and permission_state not in self._seen_permission_states
        )
        if new_permission:
            self._seen_permission_states.add(permission_state)
            novelty.append(f"new_permission_state:{permission_state}")

        if child_package and child_package not in self._seen_child_packages:
            self._seen_child_packages.add(child_package)
            novelty.append(f"new_child_package:{child_package}")

        # A screen we have seen before, revisited, is the canonical no-progress
        # case: STATE_A -> click -> STATE_A.
        repeated_screen = bool(screen_hash) and not new_screen

        signal = score_progress(
            new_screen=new_screen,
            new_activity=new_activity,
            runtime_events=runtime_events,
            new_evidence=new_evidence,
            new_permission_state=new_permission,
            goal_completed=goal_completed,
            repeated_screen=repeated_screen,
            failed_action=failed_action,
            crashed=crashed,
        )

        # Novelty is the authority, not the score. `score_progress` weights a
        # repeated screen at -2, so an action that revealed a brand-new
        # actionable element or moved the auth state on a screen that looks the
        # same can come out negative; that is still something learned.
        meaningful = bool(novelty) and not crashed
        verdict = ProgressVerdict(
            kind=(
                ProgressKind.MEANINGFUL_PROGRESS if meaningful
                else ProgressKind.NO_PROGRESS
            ),
            score=signal.score,
            reasons=list(signal.reasons),
            novelty=novelty,
        )

        if meaningful:
            self.meaningful_actions += 1
            self.stagnant_streak = 0
            self.last_progress_monotonic = time.monotonic()
        else:
            self.stagnant_streak += 1

        verdict.stagnant_streak = self.stagnant_streak
        self.history.append(verdict)
        # Bounded: a long run must not grow this without limit.
        if len(self.history) > 500:
            del self.history[:-500]
        return verdict

    # ── Queries ─────────────────────────────────────────────────────────────

    @property
    def is_stagnant(self) -> bool:
        """Whether the walk has stopped learning anything."""
        return self.stagnant_streak >= self.stagnation_limit

    def seconds_since_progress(self) -> float:
        return max(0.0, time.monotonic() - self.last_progress_monotonic)

    @property
    def progress_rate(self) -> float:
        """Fraction of actions that achieved something. 0.0 with no actions."""
        if not self.total_actions:
            return 0.0
        return self.meaningful_actions / self.total_actions

    def coverage(self) -> Dict[str, int]:
        return {
            "screens": len(self._seen_screens),
            "states": len(self._seen_states),
            "activities": len(self._seen_activities),
            "packages": len(self._seen_packages),
            "actionable_elements": len(self._seen_elements),
            "workflows": len(self._seen_workflows),
            "auth_states": len(self._seen_auth_states),
            "permission_states": len(self._seen_permission_states),
            "child_packages": len(self._seen_child_packages),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_actions": self.total_actions,
            "meaningful_actions": self.meaningful_actions,
            "progress_rate": round(self.progress_rate, 4),
            "stagnant_streak": self.stagnant_streak,
            "is_stagnant": self.is_stagnant,
            "seconds_since_progress": round(self.seconds_since_progress(), 1),
            "coverage": self.coverage(),
        }
