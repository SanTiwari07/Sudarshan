"""
SUDARSHAN - ONE wall-clock deadline for the whole dynamic analysis.

Why this module exists
----------------------
Before it, a dynamic run was bounded by five independent clocks that ADDED
rather than shared:

    ANALYSIS_TIMEOUT_SECONDS        300s   analysis-engine request timeout
    ANALYSIS_DURATION_SECONDS       130s   FridaSession.run window
    MAX_EXPLORATION_BUDGET_SECONDS  160s   AgenticExplorer adaptive ceiling
    EXPLORER_JOIN_GRACE_SECONDS      20s   thread wind-down
    (anti-evasion, teardown, reporting - no clock at all)

and the Gemini planner had NO timeout whatsoever: `_call_llm` dispatches to
`asyncio.to_thread` around a synchronous SDK call that retries three times with
exponential backoff and never sets an HTTP deadline. A hung request parks the
explorer thread for as long as the socket stays open, which is the path to a
multi-hour "analysis".

The contract here is deliberately narrow, because a budget that can be
re-derived in three places is not a budget:

  * exactly ONE deadline per dynamic analysis, created at the top of
    `run_frida_analysis` and stamped from a MONOTONIC clock;
  * every child - explorer, planner, action ladder, per-goal budget,
    anti-evasion, teardown - reads that same object and never invents its own;
  * `remaining()` is the only question anyone asks, and `allows(cost)` is how
    they decide not to START work that cannot finish.

Nothing here cancels anything. Cancellation is cooperative by design: a
subsystem told "0 seconds remain" stops at its next checkpoint and hands back
what it collected. Killing a thread mid-flush is how evidence is lost, and
preserving evidence outranks stopping promptly.

Thread-safe: the explorer runs on its own thread with its own event loop and
`FridaSession.run` runs in an executor, so the active deadline is stored behind
a lock and read from all three.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = [
    "DYNAMIC_MAX_WALL_TIME_SECONDS",
    "TIMEOUT_REASON",
    "DynamicDeadline",
    "clear_active_deadline",
    "get_active_deadline",
    "remaining_seconds",
    "set_active_deadline",
]


def _env_int(name: str, default: int) -> int:
    """Tolerant int from the environment - a typo must not unbound a run."""
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        logger.warning("[DynamicBudget] %s is not an integer; using %d", name, default)
        return default
    if value <= 0:
        logger.warning(
            "[DynamicBudget] %s=%d is not a usable deadline; using %d",
            name, value, default,
        )
        return default
    return value


#: The hard maximum wall-clock time for ONE complete dynamic analysis, measured
#: from the moment the dynamic pipeline is entered - not from the start of any
#: individual stage, call or retry.
#:
#: This is a CEILING, not a target. A typical run finishes in two to three
#: minutes; this is the point past which no further work may begin, whatever
#: the sample is doing and however much progress is still being made.
DYNAMIC_MAX_WALL_TIME_SECONDS: int = _env_int(
    "SUDARSHAN_DYNAMIC_MAX_WALL_SECONDS", 1800
)

#: The single string every subsystem reports when it stops for the deadline.
#: Pinned here rather than spelled at each site, because the risk engine, the
#: report and the frontend all branch on it and a typo would silently become a
#: third, unhandled status.
TIMEOUT_REASON: str = "TIME_BUDGET_EXHAUSTED"

#: Work that must always be affordable. Finalisation - flushing the evidence
#: store, draining the event bus, reconstructing the workflow, computing BFCI -
#: happens AFTER the deadline by definition, so it is never gated on remaining
#: time. `allows()` refuses to start new EXPLORATION, never new bookkeeping.
_MIN_USEFUL_SLICE_SECONDS: float = 1.0


@dataclass
class DynamicDeadline:
    """
    The one deadline. Monotonic, fixed in length, shared by reference.

    `total_seconds` is never extended after construction, and that is the whole
    guarantee: an adaptive sub-budget may shorten itself, and several do, but
    nothing anywhere may push this out - so no combination of retries, goals,
    planner calls or recovery attempts can multiply into a longer run.
    """

    total_seconds: float = float(DYNAMIC_MAX_WALL_TIME_SECONDS)
    started_monotonic: float = field(default_factory=time.monotonic)
    #: Set once, by whichever subsystem first observed the deadline pass. Kept
    #: so the finaliser can report WHERE the run ran out, not merely that it did.
    expired_at_stage: str = ""
    #: Stages that asked for time and were refused. Reported as limitations.
    refused_stages: List[str] = field(default_factory=list)

    # -- Clock ---------------------------------------------------------------

    def elapsed(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)

    def remaining(self) -> float:
        return max(0.0, self.total_seconds - self.elapsed())

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0.0

    # -- Admission control ---------------------------------------------------

    def allows(
        self,
        cost_seconds: float = _MIN_USEFUL_SLICE_SECONDS,
        *,
        stage: str = "",
    ) -> bool:
        """
        Whether an operation costing roughly `cost_seconds` may START.

        The point is to refuse work that cannot finish rather than to start it
        and abandon it half-done: a Gemini call begun with four seconds left
        costs its full latency and produces nothing usable, and an action
        dispatched into the last second leaves the device in a state the
        post-observation never reads.
        """
        remaining = self.remaining()
        ok = remaining > 0.0 and remaining >= max(float(cost_seconds), 0.0)
        if not ok and stage:
            if stage not in self.refused_stages:
                self.refused_stages.append(stage)
            if remaining <= 0.0:
                self.note_expiry(stage)
        return ok

    def budget_for(
        self,
        requested_seconds: float,
        *,
        minimum: float = 0.0,
    ) -> float:
        """
        Clamp a child's requested budget to what is actually left.

        Used wherever a sub-budget is constructed - the explorer's adaptive
        window, a per-goal slice, a per-call LLM timeout - so a child can never
        outlive its parent. `minimum` is honoured only while there is at least
        that much left; it can never manufacture time.
        """
        remaining = self.remaining()
        wanted = max(0.0, float(requested_seconds))
        clamped = min(wanted, remaining)
        if minimum > 0.0:
            clamped = min(max(clamped, min(float(minimum), remaining)), remaining)
        return max(0.0, clamped)

    def note_expiry(self, stage: str) -> None:
        """Record which stage first observed the deadline pass."""
        if not self.expired_at_stage:
            self.expired_at_stage = stage
            logger.warning(
                "[DYNAMIC][TIMEOUT] Global %.0f-second deadline reached at "
                "stage=%s. Stopping exploration and finalizing partial result.",
                self.total_seconds, stage,
            )

    def log_state(self, stage: str) -> None:
        """The [DYNAMIC][BUDGET] observability line."""
        logger.info(
            "[DYNAMIC][BUDGET] stage=%s elapsed=%.0fs remaining=%.0fs of %.0fs",
            stage, self.elapsed(), self.remaining(), self.total_seconds,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analysis_budget_seconds": round(self.total_seconds, 1),
            "analysis_elapsed_seconds": round(self.elapsed(), 1),
            "analysis_remaining_seconds": round(self.remaining(), 1),
            "budget_expired": self.expired,
            "expired_at_stage": self.expired_at_stage,
            "stages_refused_for_time": list(self.refused_stages),
        }


# --- Process-wide active deadline -------------------------------------------
#
# Passed explicitly wherever a call chain allows it. The global exists for the
# places where it does not: FridaSession.run() is synchronous and dispatched to
# an executor, the explorer runs on a third thread with its own event loop, and
# the planner is reached through two layers that predate this module. Rather
# than thread a parameter through every one of them - which is exactly where a
# second, divergent deadline gets introduced - they read the one that is active.

_ACTIVE_LOCK = threading.Lock()
_ACTIVE: Optional[DynamicDeadline] = None


def set_active_deadline(deadline: Optional[DynamicDeadline]) -> None:
    """Install the deadline for the dynamic analysis starting now."""
    global _ACTIVE
    with _ACTIVE_LOCK:
        _ACTIVE = deadline
    if deadline is not None:
        logger.info(
            "[DYNAMIC][BUDGET] Global deadline armed: %.0fs wall-clock maximum "
            "for the complete dynamic analysis.",
            deadline.total_seconds,
        )


def get_active_deadline() -> Optional[DynamicDeadline]:
    with _ACTIVE_LOCK:
        return _ACTIVE


def clear_active_deadline() -> None:
    set_active_deadline(None)


def remaining_seconds(default: float = float("inf")) -> float:
    """
    Time left in the active dynamic analysis.

    `default` is returned when no deadline is armed - a unit test, a replay, or
    a caller outside the dynamic pipeline. Callers that want to be bounded
    regardless pass a finite default; the dynamic pipeline always arms one.
    """
    deadline = get_active_deadline()
    return deadline.remaining() if deadline is not None else default
