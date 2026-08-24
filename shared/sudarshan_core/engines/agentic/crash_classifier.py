"""
When the sample dies, say what kind of death it was.

The explorer already detects a crash screen and relaunches, bounded by
MAX_CONSECUTIVE_CRASHES. What it never did was characterise the crash, so every
death read the same in the report - and the distinctions matter a great deal to
an analyst:

* a sample that dies the instant Frida attaches is telling you something about
  itself, and it is the single most common way a dynamic run produces nothing;
* a sample that dies right after an accessibility grant is telling you something
  different again;
* a sample that just crashes is often only a buggy app.

None of these is a malware verdict, and this module does not issue one. §15 is
explicit: "Do NOT automatically classify a crash as malware." The strongest
thing here is a SUSPECTED label, which exists to route the run into the
anti-analysis evidence path where the deterministic engine already weighs it.

The classifier is a pure function of (what we just did, what logcat said, how
many times this has happened). No device access, so every rule is testable.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


class CrashType(str, Enum):
    """The §15 taxonomy."""

    CRASH_ON_LAUNCH = "CRASH_ON_LAUNCH"
    CRASH_AFTER_PERMISSION = "CRASH_AFTER_PERMISSION"
    CRASH_AFTER_ACCESSIBILITY = "CRASH_AFTER_ACCESSIBILITY"
    CRASH_AFTER_ACTION = "CRASH_AFTER_ACTION"
    INSTRUMENTATION_SENSITIVE_CRASH = "INSTRUMENTATION_SENSITIVE_CRASH"
    ANTI_ANALYSIS_SUSPECTED = "ANTI_ANALYSIS_SUSPECTED"
    UNKNOWN_CRASH = "UNKNOWN_CRASH"


#: Logcat fragments that place the fault inside our own instrumentation rather
#: than in the app. Frida injects a memfd-backed agent, so its frames are
#: recognisable even in a stripped native trace.
_INSTRUMENTATION_MARKERS = (
    "frida-agent",
    "frida_agent",
    "gum-js-loop",
    "gmain",
    "re.frida.server",
)

#: Fragments suggesting the app looked for an analysis environment and then
#: quit. Deliberately narrow: a root check alone is ordinary in banking apps.
_EVASION_MARKERS = (
    "ro.kernel.qemu",
    "goldfish",
    "ranchu",
    "emulator detected",
    "debugger detected",
    "root detected",
    "integrity check failed",
    "safetynet",
)

#: A JNI abort raised by CheckJNI while an instrumentation frame is on the
#: stack is our fault, not the sample's - this is exactly the ClassLoader hook
#: crash that killed every run earlier in this project's history.
_JNI_ABORT = re.compile(r"JNI DETECTED ERROR IN APPLICATION", re.IGNORECASE)

#: Stages where a crash really is permission-related, lowercased. Listed
#: explicitly because substring matching sweeps in POST_PERMISSION_EXPLORATION.
_PERMISSION_STAGES = frozenset({
    "permission_analysis",
    "permission_handling",
    "special_permission_analysis",
})


@dataclass
class CrashContext:
    """What was happening when the process died."""

    #: Tool name of the last executed action, "" if none had run yet.
    last_action: str = ""
    #: Investigation stage at the moment of the crash.
    stage: str = ""
    #: Actions executed before the crash, across the whole run.
    actions_before_crash: int = 0
    #: How many times this sample has now died.
    crash_index: int = 1
    #: Whether Frida had attached and its hooks were live.
    instrumented: bool = True
    #: Whether an uninstrumented baseline launch of this sample survived.
    baseline_survived: Optional[bool] = None
    logcat: str = ""
    activity: str = ""


@dataclass
class CrashFinding:
    """The classification, with the evidence that produced it."""

    crash_type: str
    confidence: str = "MEDIUM"     # HIGH | MEDIUM | LOW
    severity: str = "INFO"
    summary: str = ""
    signals: List[str] = field(default_factory=list)
    screenshot_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)

    @property
    def is_suspected_evasion(self) -> bool:
        return self.crash_type in (
            CrashType.ANTI_ANALYSIS_SUSPECTED.value,
            CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary,
            "signals": list(self.signals),
            "screenshot_id": self.screenshot_id,
            "evidence_ids": list(self.evidence_ids),
        }


def _found(haystack: str, needles: Sequence[str]) -> List[str]:
    low = (haystack or "").lower()
    return [n for n in needles if n in low]


def classify_crash(context: CrashContext) -> CrashFinding:
    """
    Name the crash from what surrounded it.

    Order matters, and runs most-specific first. A crash that is BOTH
    instrumentation-shaped and right after an accessibility grant is reported as
    instrumentation-sensitive, because that is the one an analyst can act on:
    it means the run's own tooling is implicated and the result cannot be read
    as sample behaviour.
    """
    signals: List[str] = []

    instrumentation_hits = _found(context.logcat, _INSTRUMENTATION_MARKERS)
    evasion_hits = _found(context.logcat, _EVASION_MARKERS)
    jni_abort = bool(_JNI_ABORT.search(context.logcat or ""))

    # ── Our own instrumentation is on the stack ──────────────────────────────
    if instrumentation_hits or (jni_abort and context.instrumented):
        if instrumentation_hits:
            signals.append(f"instrumentation frames in logcat: {', '.join(instrumentation_hits)}")
        if jni_abort:
            signals.append("CheckJNI abort while instrumented")
        return CrashFinding(
            crash_type=CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value,
            confidence="HIGH" if instrumentation_hits else "MEDIUM",
            severity="MEDIUM",
            summary=(
                "The process died with our own instrumentation on the stack. "
                "This describes the harness, not the sample - the run cannot be "
                "read as evidence about the app's behaviour."
            ),
            signals=signals,
        )

    # ── Survived without Frida, died with it ─────────────────────────────────
    if context.baseline_survived is True and context.instrumented:
        signals.append("uninstrumented baseline launch survived; instrumented run crashed")
        return CrashFinding(
            crash_type=CrashType.INSTRUMENTATION_SENSITIVE_CRASH.value,
            confidence="HIGH",
            severity="MEDIUM",
            summary=(
                "The sample runs uninstrumented and dies under instrumentation. "
                "That may be deliberate anti-analysis or an incompatibility; "
                "either way the dynamic axis is not measuring normal behaviour."
            ),
            signals=signals,
        )

    # ── The app looked for an analysis environment, then quit ────────────────
    if evasion_hits:
        signals.append(f"environment probes in logcat: {', '.join(evasion_hits)}")
        return CrashFinding(
            crash_type=CrashType.ANTI_ANALYSIS_SUSPECTED.value,
            confidence="MEDIUM",
            severity="MEDIUM",
            summary=(
                "The sample probed for an analysis environment and then exited. "
                "SUSPECTED, not concluded: the probe and the exit are correlated "
                "in time, which is not the same as caused."
            ),
            signals=signals,
        )

    # ── Positional classifications ───────────────────────────────────────────
    if context.actions_before_crash == 0 and not context.last_action:
        signals.append("died before any action was executed")
        return CrashFinding(
            crash_type=CrashType.CRASH_ON_LAUNCH.value,
            confidence="HIGH",
            severity="LOW",
            summary=(
                "The sample died on launch, before the explorer acted. No "
                "behaviour could be observed, so the dynamic axis is "
                "inconclusive rather than clean."
            ),
            signals=signals,
        )

    last = (context.last_action or "").lower()
    # Lowercased, like `last`. It was uppercased here while the tests below
    # searched for lowercase substrings, so no stage ever matched.
    stage = (context.stage or "").lower()

    if "accessibility" in stage or "accessibility" in last:
        signals.append(f"crash followed accessibility handling (stage={context.stage})")
        return CrashFinding(
            crash_type=CrashType.CRASH_AFTER_ACCESSIBILITY.value,
            confidence="MEDIUM",
            severity="MEDIUM",
            summary=(
                "The sample died immediately after accessibility was granted or "
                "requested. Worth re-running: a payload gated on accessibility "
                "may have started and failed rather than not existing."
            ),
            signals=signals,
        )

    # Matched against the exact permission-handling stages rather than by
    # substring: POST_PERMISSION_EXPLORATION contains "permission" but is
    # ordinary exploration that happens to come after it, and reporting those
    # crashes as permission-related would misattribute them.
    if "permission" in last or stage in _PERMISSION_STAGES:
        signals.append(f"crash followed permission handling (last_action={context.last_action})")
        return CrashFinding(
            crash_type=CrashType.CRASH_AFTER_PERMISSION.value,
            confidence="MEDIUM",
            severity="LOW",
            summary=(
                "The sample died just after a permission was granted or denied."
            ),
            signals=signals,
        )

    if context.last_action:
        signals.append(f"crash followed action '{context.last_action}'")
        return CrashFinding(
            crash_type=CrashType.CRASH_AFTER_ACTION.value,
            confidence="MEDIUM",
            severity="LOW",
            summary=f"The sample died after the explorer performed '{context.last_action}'.",
            signals=signals,
        )

    return CrashFinding(
        crash_type=CrashType.UNKNOWN_CRASH.value,
        confidence="LOW",
        severity="LOW",
        summary=(
            "The sample died and nothing in the surrounding context explains "
            "why. Recorded so the run is not read as a clean one."
        ),
        signals=["no distinguishing signal in logcat or action history"],
    )


def crash_event(finding: CrashFinding, package_name: str = "") -> Dict[str, Any]:
    """
    The RuntimeEventBus payload for a classified crash.

    Uses the existing event schema (§23) rather than introducing a new one, so
    EvidenceStore and every other subscriber keep working unchanged. The
    category is `anti_analysis` only when the classification actually suspects
    evasion; an ordinary crash is `app_telemetry` and must not be routed into
    the evasion evidence path.
    """
    return {
        "type": "event",
        "category": "anti_analysis" if finding.is_suspected_evasion else "app_telemetry",
        "severity": finding.severity,
        "data": {
            "hook": "process_crash",
            "crash_type": finding.crash_type,
            "confidence": finding.confidence,
            "description": finding.summary,
            "signals": finding.signals,
            "package": package_name,
        },
    }
