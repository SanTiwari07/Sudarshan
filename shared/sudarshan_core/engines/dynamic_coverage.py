"""
SUDARSHAN - the dynamic result's coverage and validity contract.

The invariant this module exists to enforce
-------------------------------------------
**Dynamic analysis is evidence-accumulative, not all-or-nothing.**

The 15-stage fraud DAG is fifteen INVESTIGATION GOALS, not fifteen conditions
that must all hold. A run in which nine goals produced evidence, two produced
partial evidence and four produced nothing is a run with eleven goals' worth of
observation in it, and the correct thing to do with it is to report it - with
its coverage and its limitations stated - not to discard it.

So there is deliberately no expression anywhere of the form::

    dynamic_valid = all(goals_successful)      # forbidden

Coverage and validity are two different questions and are computed from two
different inputs:

``coverage``
    How much of the planned investigation was exercised. Computed from the goal
    state distribution: ``(successful + 0.5 * partial) / total``. Purely a
    reporting number.

``validity``
    Whether the run produced trustworthy runtime evidence at all. Computed from
    OBSERVED EVIDENCE - Frida attach, hook events, verified UI transitions,
    network interception - and never from goal states. 60% coverage does not
    mean ``dynamic_valid = False``; it means ``dynamic_valid = True,
    dynamic_status = PARTIAL, coverage = 60%``.

Nothing here scores anything. BFCI is computed from observed events by
``bfci_scorer``; FRS is computed deterministically by ``risk_engine``. This
module produces the metadata those two travel with, so a partial run can never
silently read as a complete one.

Pure by construction - no clock, no device, no I/O - so every case below is
unit-testable without an emulator.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional

from sudarshan_core.engines.dynamic_budget import TIMEOUT_REASON

logger = logging.getLogger(__name__)

__all__ = [
    "DYNAMIC_STATUSES",
    "DynamicCoverageStatus",
    "build_dynamic_coverage",
    "coverage_narrative",
]


class DynamicCoverageStatus:
    """
    What a dynamic run achieved, as a status rather than a boolean.

    A boolean cannot express the case this whole design exists for: a sample
    explored eight screens deep whose ninth branch ended at a boundary. That is
    a PARTIAL run with real evidence in it. Collapsing it to False loses the
    evidence; collapsing it to True overstates the coverage.

    None of these is a statement that a sample is safe. Scoring is the risk
    engine's job and it consumes these as one input among several.
    """

    #: Every planned investigation goal was adjudicated and confirmed.
    COMPLETE = "COMPLETE"
    #: Some goals produced evidence, some did not. Usable, and labelled.
    PARTIAL = "PARTIAL"
    #: Instrumentation worked and the sample did nothing observable. NOT a
    #: clean bill of health - the safety floors stay on.
    NO_BEHAVIOR_OBSERVED = "NO_BEHAVIOR_OBSERVED"
    #: Frida never attached, or the Java bridge never came up. Absence of
    #: evidence here is absence of OBSERVATION and carries no information
    #: about the sample.
    INSTRUMENTATION_FAILED = "INSTRUMENTATION_FAILED"
    #: No sandbox was available. The dynamic axis does not exist for this case.
    SKIPPED = "SKIPPED"
    #: The 30-minute wall clock arrived. Whether that run is usable depends on
    #: what it had collected by then, which is why this is a separate status
    #: and not an alias for either PARTIAL or NO_BEHAVIOR_OBSERVED.
    TIME_BUDGET_EXHAUSTED = TIMEOUT_REASON


DYNAMIC_STATUSES = frozenset({
    DynamicCoverageStatus.COMPLETE,
    DynamicCoverageStatus.PARTIAL,
    DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED,
    DynamicCoverageStatus.INSTRUMENTATION_FAILED,
    DynamicCoverageStatus.SKIPPED,
    DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED,
})

#: Statuses under which the dynamic axis carries trustworthy evidence.
_VALID_STATUSES = frozenset({
    DynamicCoverageStatus.COMPLETE,
    DynamicCoverageStatus.PARTIAL,
})


def _int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def build_dynamic_coverage(
    goal_report: Optional[Mapping[str, Any]] = None,
    *,
    sandbox_available: bool = True,
    instrumentation_ok: bool = True,
    evidence_event_count: int = 0,
    meaningful_transition_count: int = 0,
    budget_seconds: float = 0.0,
    elapsed_seconds: float = 0.0,
    timed_out: bool = False,
    extra_limitations: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    The §P12 dynamic result contract, derived from goal states and evidence.

    Parameters
    ----------
    goal_report
        ``GoalTracker.coverage_report()``. Absent or empty means the goal graph
        never ran, which is not the same as every goal failing - a run with no
        goal graph but with Frida evidence is still a valid partial run.
    sandbox_available
        Whether a sandbox existed at all. False is CASE F.
    instrumentation_ok
        Whether Frida attached and the hooks installed. False is CASE E.
    evidence_event_count
        Observed, SAMPLE-attributable events. The caller filters harness
        bookkeeping out before it gets here; this function does not know which
        events describe the harness and must not guess.
    meaningful_transition_count
        Verified UI state transitions - PRE/POST proven, not ADB exit codes.
    timed_out
        Whether the global wall-clock deadline ended the run.

    Returns a dict that is merged into the dynamic result verbatim.

    Status resolution, in the order the cases were specified:

      CASE F  no sandbox                      -> SKIPPED
      CASE E  no instrumentation, no evidence -> INSTRUMENTATION_FAILED
      CASE D  instrumented, nothing observed  -> NO_BEHAVIOR_OBSERVED
      timeout with evidence                   -> TIME_BUDGET_EXHAUSTED (valid)
      timeout with nothing                    -> NO_BEHAVIOR_OBSERVED
      CASE A  every goal confirmed            -> COMPLETE
      CASE B/C anything in between            -> PARTIAL
    """
    report: Mapping[str, Any] = goal_report or {}

    total = _int(report.get("goals_total", report.get("total_goals", 0)))
    successful = _int(report.get("goals_successful", report.get("satisfied_goals", 0)))
    partial = _int(report.get("goals_partial"))
    failed = _int(report.get("goals_failed"))
    skipped = _int(report.get("goals_skipped"))
    not_reached = _int(report.get("goals_not_reached"))
    goals_timed_out = _int(report.get("goals_timed_out"))
    unsupported = _int(report.get("goals_unsupported"))

    effective = _float(
        report.get("effective_goal_count"), successful + partial * 0.5
    )
    coverage_ratio = round(effective / total, 4) if total else 0.0

    events = _int(evidence_event_count)
    transitions = _int(meaningful_transition_count)

    # "Meaningful evidence" is the validity predicate, and it is a disjunction
    # on purpose (§P3): any ONE of these is enough for the run to be worth
    # reporting. A goal-count of zero can still be a valid run - Frida hooks
    # fire from background threads the UI walk never touched.
    has_meaningful_evidence = bool(
        events > 0 or transitions > 0 or successful > 0 or partial > 0
    )

    limitations: List[str] = []
    for note in (extra_limitations or []):
        if note and note not in limitations:
            limitations.append(str(note))

    timeout_reason: Optional[str] = TIMEOUT_REASON if timed_out else None

    # -- Status ladder -------------------------------------------------------
    if not sandbox_available:
        status = DynamicCoverageStatus.SKIPPED
        limitations.insert(
            0,
            "No sandbox device was available; the dynamic axis was not "
            "exercised and is excluded from scoring rather than scored as zero.",
        )
    elif not instrumentation_ok and not has_meaningful_evidence:
        status = DynamicCoverageStatus.INSTRUMENTATION_FAILED
        limitations.insert(
            0,
            "Runtime instrumentation could not be established; dynamic evidence "
            "was unavailable. Absence of findings here is absence of "
            "observation, not evidence that the sample is benign.",
        )
    elif not has_meaningful_evidence:
        # Instrumented, watched, and nothing the SAMPLE did was observed.
        # Deliberately NOT reported as a low-coverage PARTIAL: that would let
        # a silent or evasion-first sample read as "we looked and found
        # little", when the honest statement is "we looked and found nothing".
        # The risk engine's safety floors stay on for this status.
        status = DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED
        limitations.insert(
            0,
            "No substantive runtime behaviour was observed during the bounded "
            "execution window. This is not evidence that the sample is benign.",
        )
    elif timed_out:
        status = DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED
        limitations.insert(
            0,
            f"The {budget_seconds:.0f}-second dynamic analysis budget was "
            f"exhausted before the investigation completed. Everything "
            f"collected up to that point was flushed and scored; the remaining "
            f"goals were not exercised.",
        )
    elif total and successful == total:
        status = DynamicCoverageStatus.COMPLETE
    elif total and (successful + skipped + unsupported) == total and successful:
        # Every applicable goal confirmed; the rest were proven inapplicable or
        # have no instrument. Nothing was left unexercised, so this is COMPLETE
        # rather than a PARTIAL that penalises the run for stages that could
        # never have applied to this sample.
        status = DynamicCoverageStatus.COMPLETE
    else:
        status = DynamicCoverageStatus.PARTIAL

    dynamic_valid = status in _VALID_STATUSES or (
        status == DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED
        and has_meaningful_evidence
    )
    dynamic_complete = status == DynamicCoverageStatus.COMPLETE

    # "Not FULLY exercised" is measured against confirmation, so a
    # PARTIAL_SUCCESS goal counts here as well as in `goals_partial`. The two
    # are not double-counting: this line tells the analyst how much of the plan
    # fell short of confirmation, and `partial_goals` names which of those got
    # part of the way.
    unexercised = total - successful if total else 0
    if unexercised > 0 and status != DynamicCoverageStatus.SKIPPED:
        limitations.append(
            f"{unexercised} of {total} planned investigation goals were not "
            f"fully exercised"
        )
    if not_reached:
        limitations.append(
            f"{not_reached} goal(s) were never reached within the analysis "
            f"budget and say nothing about the sample"
        )
    if unsupported:
        limitations.append(
            f"{unsupported} goal(s) have no confirming instrument in this "
            f"engine and were reported UNSUPPORTED rather than absent"
        )

    coverage = {
        "dynamic_status": status,
        "dynamic_valid": dynamic_valid,
        "dynamic_available": bool(sandbox_available),
        "dynamic_complete": dynamic_complete,
        "dynamic_instrumented": bool(instrumentation_ok),

        "analysis_budget_seconds": round(_float(budget_seconds), 1),
        "analysis_elapsed_seconds": round(_float(elapsed_seconds), 1),

        "goals_total": total,
        "goals_successful": successful,
        "goals_partial": partial,
        "goals_failed": failed,
        "goals_skipped": skipped,
        "goals_not_reached": not_reached,
        "goals_timed_out": goals_timed_out,
        "goals_unsupported": unsupported,

        "effective_goal_count": round(effective, 4),
        "coverage_ratio": coverage_ratio,
        "coverage_percent": round(coverage_ratio * 100.0, 1),

        "evidence_event_count": events,
        "meaningful_transition_count": transitions,

        "successful_goals": list(report.get("successful_goals") or []),
        "partial_goals": list(report.get("partial_goals") or []),
        "failed_goals": list(report.get("failed_goals") or []),
        "goal_states": list(report.get("goal_states") or []),
        "failure_reasons": list(report.get("failure_reasons") or []),

        "timeout_reason": timeout_reason,
        "limitations": limitations,
    }
    coverage["narrative"] = coverage_narrative(coverage)
    return coverage


def coverage_narrative(coverage: Mapping[str, Any]) -> str:
    """
    One analyst-facing sentence about what this run is worth.

    Used verbatim by the HTML/PDF/JSON report so the three cannot drift, and so
    no report can claim "all fraud stages executed" for a run in which they did
    not (§P23).
    """
    status = str(coverage.get("dynamic_status") or "")
    total = _int(coverage.get("goals_total"))
    successful = _int(coverage.get("goals_successful"))
    partial = _int(coverage.get("goals_partial"))
    percent = _float(coverage.get("coverage_percent"))

    if status == DynamicCoverageStatus.SKIPPED:
        return (
            "Dynamic analysis was not performed: no sandbox device was "
            "available. The dynamic axis is excluded from scoring."
        )
    if status == DynamicCoverageStatus.INSTRUMENTATION_FAILED:
        return (
            "Runtime instrumentation could not be established; dynamic "
            "evidence was unavailable for this sample."
        )
    if status == DynamicCoverageStatus.NO_BEHAVIOR_OBSERVED:
        return (
            "No substantive runtime behaviour was observed during the bounded "
            "execution window. Absence of observation is not evidence of "
            "benignity, and the static evidence floors remain in force."
        )
    if status == DynamicCoverageStatus.COMPLETE:
        return "Dynamic analysis completed all planned investigation goals."

    partial_clause = (
        f" A further {partial} produced partial evidence." if partial else ""
    )
    if status == DynamicCoverageStatus.TIME_BUDGET_EXHAUSTED:
        return (
            f"Dynamic analysis reached its wall-clock budget with partial goal "
            f"coverage. {successful} of {total} investigation goals produced "
            f"successful observations ({percent:.1f}% effective coverage)."
            f"{partial_clause} Risk scoring uses only observed runtime evidence."
        )
    return (
        f"Dynamic analysis completed with partial goal coverage. {successful} "
        f"of {total} investigation goals produced successful observations "
        f"({percent:.1f}% effective coverage).{partial_clause} Risk scoring "
        f"uses only observed runtime evidence."
    )
