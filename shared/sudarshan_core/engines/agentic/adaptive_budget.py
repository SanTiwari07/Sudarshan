"""
SUDARSHAN - Adaptive time budget for the exploration loop.

The 300 seconds every run gets originates in ``frida_sandbox``::

    ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "300"))
        -> FridaSession.run(duration_seconds=...)
            -> AgenticExplorer.start(duration_seconds)
                -> `if elapsed >= duration_seconds: break`   (SC4)

It is a single fixed number applied to every sample, and it is wrong in both
directions. An app that is mid-login at t=299 is cut off with the interesting
part unobserved. An app that reached a dead end at t=40 keeps the emulator for
another four minutes producing nothing.

This makes the deadline responsive to whether the walk is still learning:

  · start at INITIAL_EXPLORATION_BUDGET_SECONDS (the existing value, so
    behaviour is unchanged for a run that neither progresses nor stalls);
  · while meaningful progress keeps arriving, extend in increments;
  · never past MAX_EXPLORATION_BUDGET_SECONDS - the hard stop, which no amount
    of progress can move. There is no unbounded path;
  · when progress has stopped and recovery has not helped, finish early rather
    than idle out the clock.

Set ADAPTIVE_EXPLORATION_ENABLED=false to get exactly the old fixed-deadline
behaviour back.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "ADAPTIVE_EXPLORATION_ENABLED",
    "INITIAL_EXPLORATION_BUDGET_SECONDS",
    "MAX_EXPLORATION_BUDGET_SECONDS",
    "AdaptiveBudget",
]


def _env_int(name: str, default: int) -> int:
    """Tolerant int from the environment - a typo must not stop a run."""
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        logger.warning("[AdaptiveBudget] %s is not an integer; using %d", name, default)
        return default


#: Where every run starts. Defaults to FRIDA_ANALYSIS_DURATION so the existing
#: deployment knob keeps working and nothing has to be reconfigured.
INITIAL_EXPLORATION_BUDGET_SECONDS: int = _env_int(
    "INITIAL_EXPLORATION_BUDGET_SECONDS",
    _env_int("FRIDA_ANALYSIS_DURATION", 300),
)

#: The hard ceiling. Progress can extend the deadline up to here and no
#: further, whatever happens.
MAX_EXPLORATION_BUDGET_SECONDS: int = _env_int(
    "MAX_EXPLORATION_BUDGET_SECONDS",
    max(INITIAL_EXPLORATION_BUDGET_SECONDS * 3, 900),
)

ADAPTIVE_EXPLORATION_ENABLED: bool = (
    os.getenv("ADAPTIVE_EXPLORATION_ENABLED", "true").lower()
    not in {"0", "false", "no", "off"}
)

#: Seconds added per extension.
EXPLORATION_BUDGET_EXTENSION_SECONDS: int = _env_int(
    "EXPLORATION_BUDGET_EXTENSION_SECONDS", 60
)

#: Consecutive unproductive actions after which an idle run may finish early.
EXPLORATION_STAGNATION_LIMIT: int = _env_int("EXPLORATION_STAGNATION_LIMIT", 12)


@dataclass
class BudgetDecision:
    """Why the budget is what it is, for the audit log."""

    at_elapsed: float
    old_deadline: float
    new_deadline: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at_elapsed": round(self.at_elapsed, 1),
            "old_deadline": round(self.old_deadline, 1),
            "new_deadline": round(self.new_deadline, 1),
            "reason": self.reason,
        }


@dataclass
class AdaptiveBudget:
    """
    The run's deadline, and whether it has arrived.

    Monotonic clock throughout: a wall-clock jump during a long analysis must
    not extend or truncate a run.
    """

    initial_seconds: float = float(INITIAL_EXPLORATION_BUDGET_SECONDS)
    max_seconds: float = float(MAX_EXPLORATION_BUDGET_SECONDS)
    extension_seconds: float = float(EXPLORATION_BUDGET_EXTENSION_SECONDS)
    enabled: bool = ADAPTIVE_EXPLORATION_ENABLED
    stagnation_limit: int = EXPLORATION_STAGNATION_LIMIT

    started_monotonic: float = field(default_factory=time.monotonic)
    deadline_seconds: float = 0.0
    extensions: int = 0
    decisions: List[BudgetDecision] = field(default_factory=list)
    finish_reason: str = ""

    def __post_init__(self) -> None:
        # A caller that asks for more than the ceiling gets the ceiling: the
        # hard maximum outranks the starting value, not the other way round.
        self.max_seconds = max(float(self.max_seconds), float(self.initial_seconds))
        if not self.deadline_seconds:
            self.deadline_seconds = float(self.initial_seconds)

    # ── Clock ───────────────────────────────────────────────────────────────

    def elapsed(self) -> float:
        return time.monotonic() - self.started_monotonic

    def remaining(self) -> float:
        return max(0.0, self.deadline_seconds - self.elapsed())

    @property
    def at_hard_maximum(self) -> bool:
        return self.deadline_seconds >= self.max_seconds

    # ── Decisions ───────────────────────────────────────────────────────────

    def note_progress(self, *, meaningful: bool, detail: str = "") -> bool:
        """
        Fold one action's progress verdict into the deadline.

        Returns whether the deadline was extended. Extension only happens when
        the run is actually close to its deadline - extending at t=10 would
        just inflate the budget of a run that was never going to need it.
        """
        if not self.enabled or not meaningful:
            return False
        if self.at_hard_maximum:
            return False

        # Only top up inside the last extension-window of the current budget.
        if self.remaining() > self.extension_seconds:
            return False

        old = self.deadline_seconds
        self.deadline_seconds = min(
            self.max_seconds, self.deadline_seconds + self.extension_seconds,
        )
        if self.deadline_seconds <= old:
            return False

        self.extensions += 1
        decision = BudgetDecision(
            at_elapsed=self.elapsed(),
            old_deadline=old,
            new_deadline=self.deadline_seconds,
            reason=detail or "meaningful progress near deadline",
        )
        self.decisions.append(decision)
        logger.info(
            "[AdaptiveBudget] extended %.0fs -> %.0fs (max %.0fs) after %s",
            old, self.deadline_seconds, self.max_seconds, decision.reason,
        )
        return True

    def should_finish(
        self,
        *,
        stagnant_streak: int = 0,
        recovery_exhausted: bool = False,
        work_remaining: bool = True,
    ) -> bool:
        """
        Whether to stop now.

        Two independent reasons, and the time one is unconditional:

        1. The deadline has arrived. Always terminal - this is the guarantee
           that no run is unbounded.
        2. Progress has stopped, recovery has not restored it, and there is
           nothing left to try. Finishing early here frees the emulator instead
           of idling out the clock.
        """
        if self.elapsed() >= self.deadline_seconds:
            self.finish_reason = "time_budget_exhausted"
            return True

        if not self.enabled:
            return False

        if (
            stagnant_streak >= self.stagnation_limit
            and recovery_exhausted
            and not work_remaining
        ):
            self.finish_reason = "no_progress_and_no_work_remaining"
            logger.info(
                "[AdaptiveBudget] finishing early at %.0fs: stagnant for %d "
                "actions, recovery exhausted, no unexplored work",
                self.elapsed(), stagnant_streak,
            )
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_seconds": round(self.initial_seconds, 1),
            "max_seconds": round(self.max_seconds, 1),
            "deadline_seconds": round(self.deadline_seconds, 1),
            "elapsed_seconds": round(self.elapsed(), 1),
            "extensions": self.extensions,
            "adaptive_enabled": self.enabled,
            "finish_reason": self.finish_reason,
            "decisions": [d.to_dict() for d in self.decisions],
        }
