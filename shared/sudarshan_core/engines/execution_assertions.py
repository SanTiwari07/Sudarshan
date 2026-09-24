"""Execution Assertion Matrix - did the sandbox actually exercise the sample?

Governing principle: **absence of evidence is not evidence of absence.**

Evasion-first banking trojans (Anatsa, Xenomorph, SOVA, PixStealer, CraxsRAT)
are built to do nothing under observation. They stall behind WorkManager and
AlarmManager timers, wait for a victim to open a targeted banking app, wait for
an OTP SMS to arrive, or require an accessibility grant they never receive in a
sterile sandbox. A run that captured zero threat events is therefore ambiguous
between two very different claims:

  * the sample is benign, or
  * the sample's preconditions were never met and we watched an idle process.

This module makes that distinction explicit rather than leaving it to be
inferred from a score. It records, per run, which *trigger conditions* were
actually reached. When none of them were and nothing was observed, the run is
declared ``INCOMPLETE_EXERCISE`` - the analysis did not fail, but it did not
happen either, and a "benign" verdict cannot be drawn from it.

Assertions are derived from observed telemetry only. Nothing here is a bank
list or a package allowlist: the packages a sample targets come from that
sample's own manifest and DEX references, resolved during static intake.

Relationship to goal coverage
-----------------------------
This module and :mod:`~sudarshan_core.engines.dynamic_coverage` answer two
different questions and must not be merged.

Here: *did the run reach any of the sample's own fraud TRIGGER conditions?*
Six conditions, and ``incomplete_exercise`` requires that NONE of them fired
AND that zero threat events were observed. It is the safety floor against a
completely silent run, and it is deliberately conservative - an unexercised run
must never be readable as a clean bill of health.

There: *how much of the fifteen-goal INVESTIGATION PLAN was exercised, and did
the run produce trustworthy evidence?* That is coverage and validity, and a run
can legitimately have 60% coverage, be valid, and still be an incomplete
exercise - if the nine goals it confirmed happened not to include any trigger
condition.

An unreached individual GOAL therefore has no effect here whatsoever, and never
did: ``incomplete_exercise`` reads trigger conditions and threat events, not the
goal graph. What changed alongside this note is only that such a goal is now
recorded as NOT_REACHED instead of being left PENDING, and that the run around
it reports PARTIAL instead of having no vocabulary for itself. The safety floor
is untouched, and deliberately so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

#: Verdict applied when the sandbox observed nothing and triggered nothing.
VERDICT_INCOMPLETE_EXERCISE = "INCOMPLETE_EXERCISE"

#: Multiplier applied to reported confidence for an unexercised run.
#: The run produced no information about the sample, so the confidence attached
#: to any verdict drawn from it must be halved.
INCOMPLETE_EXERCISE_CONFIDENCE_PENALTY = 0.50


# ── Signal vocabulary ──────────────────────────────────────────────────────
#
# Matched against hook names, evidence categories and API strings. These are
# Android framework identifiers, not sample-specific strings - the framework
# API surface is what it is regardless of which trojan is calling it.

_ACCESSIBILITY_SIGNALS = re.compile(
    r"AccessibilityService|AccessibilityNodeInfo|AccessibilityEvent|"
    r"onServiceConnected|performGlobalAction|BIND_ACCESSIBILITY",
    re.IGNORECASE,
)
_OVERLAY_SIGNALS = re.compile(
    r"WindowManager\.addView|TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT|"
    r"SYSTEM_ALERT_WINDOW|\baddView\b|\bOverlay\b|canDrawOverlays|ACTION_MANAGE_OVERLAY_PERMISSION",
    re.IGNORECASE,
)
_SMS_RECEIVE_SIGNALS = re.compile(
    r"SMS_RECEIVED|SmsMessage|createFromPdu|getMessagesFromIntent|"
    r"SmsRetriever|content://sms|Telephony\.Sms",
    re.IGNORECASE,
)
_OTP_TEXT_SIGNALS = re.compile(
    r"\botp\b|one[\s-]?time[\s-]?(?:password|code|pin)|verification code|"
    r"\b\d{4,8}\b\s*is your",
    re.IGNORECASE,
)
_CONTACTS_SIGNALS = re.compile(
    r"ContactsContract|content://com\.android\.contacts|READ_CONTACTS|"
    r"Contacts\.CONTENT_URI|Phone\.CONTENT_URI",
    re.IGNORECASE,
)
_CALL_LOG_SIGNALS = re.compile(
    r"CallLog|content://call_log|READ_CALL_LOG|Calls\.CONTENT_URI",
    re.IGNORECASE,
)

# Evidence categories the harness writes about itself - these describe the
# sandbox, not the sample, and can never satisfy an assertion.
_HARNESS_CATEGORIES = frozenset({"SCREENSHOT", "HARNESS", "DIAGNOSTIC"})


@dataclass
class Assertion:
    """One trigger condition and whether the run reached it."""

    key: str
    label: str
    fired: bool = False
    evidence: str = ""
    #: What an analyst should do to reach this trigger on a re-run.
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "fired": self.fired,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ExecutionAssertionMatrix:
    """
    Which fraud preconditions a dynamic run actually reached.

    ``incomplete_exercise`` is the load-bearing property: True means the run
    neither observed threat behaviour nor reached a single trigger, so it
    carries no information about whether the sample is malicious.
    """

    banking_app_launched: Assertion = field(
        default_factory=lambda: Assertion(
            "banking_app_launched",
            "Targeted banking app opened",
            remediation=(
                "Launch a banking app the sample references, then re-run. "
                "Overlay and accessibility payloads only arm once their target "
                "is in the foreground."
            ),
        )
    )
    otp_sms_received: Assertion = field(
        default_factory=lambda: Assertion(
            "otp_sms_received",
            "OTP / bank SMS delivered",
            remediation=(
                "Inject a test OTP SMS into the device inbox and re-run. SMS "
                "interception hooks cannot fire on a device that never "
                "receives a message."
            ),
        )
    )
    accessibility_granted: Assertion = field(
        default_factory=lambda: Assertion(
            "accessibility_granted",
            "Accessibility service granted",
            remediation=(
                "Grant the sample's accessibility service and re-run. Most "
                "modern Android banking trojans do nothing at all without it."
            ),
        )
    )
    overlay_triggered: Assertion = field(
        default_factory=lambda: Assertion(
            "overlay_triggered",
            "Overlay window drawn",
            remediation=(
                "Grant SYSTEM_ALERT_WINDOW and open a targeted app so the "
                "overlay has something to draw over."
            ),
        )
    )
    contacts_accessed: Assertion = field(
        default_factory=lambda: Assertion(
            "contacts_accessed",
            "Contacts provider read",
            remediation=(
                "Seed a persona with a populated address book - several "
                "families stay dormant when the contacts provider returns no "
                "rows."
            ),
        )
    )
    call_log_accessed: Assertion = field(
        default_factory=lambda: Assertion(
            "call_log_accessed",
            "Call log read",
            remediation=(
                "Seed a persona with call history so an emptiness check does "
                "not abort the payload."
            ),
        )
    )

    #: Behavioural events observed during the run, harness records excluded.
    threat_events_observed: int = 0
    #: True when the sandbox never ran at all - distinct from running and
    #: seeing nothing, and reported separately so the two are not conflated.
    dynamic_ran: bool = False

    # ── Access ─────────────────────────────────────────────────────────────

    def all_assertions(self) -> List[Assertion]:
        return [
            self.banking_app_launched,
            self.otp_sms_received,
            self.accessibility_granted,
            self.overlay_triggered,
            self.contacts_accessed,
            self.call_log_accessed,
        ]

    @property
    def fired(self) -> List[Assertion]:
        return [a for a in self.all_assertions() if a.fired]

    @property
    def unfired(self) -> List[Assertion]:
        return [a for a in self.all_assertions() if not a.fired]

    @property
    def any_fired(self) -> bool:
        return any(a.fired for a in self.all_assertions())

    @property
    def incomplete_exercise(self) -> bool:
        """
        True when the run reached no trigger and observed no threat behaviour.

        Requires ``dynamic_ran``: a case with no sandbox run at all is already
        reported as "dynamic analysis unavailable", and labelling it an
        incomplete *exercise* would claim we tried and the sample stayed quiet.
        """
        return self.dynamic_ran and self.threat_events_observed == 0 and not self.any_fired

    def coverage_ratio(self) -> float:
        total = len(self.all_assertions())
        return len(self.fired) / total if total else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": VERDICT_INCOMPLETE_EXERCISE if self.incomplete_exercise else "",
            "incomplete_exercise": self.incomplete_exercise,
            "dynamic_ran": self.dynamic_ran,
            "threat_events_observed": self.threat_events_observed,
            "coverage_ratio": round(self.coverage_ratio(), 4),
            "fired_count": len(self.fired),
            "total_count": len(self.all_assertions()),
            "assertions": [a.to_dict() for a in self.all_assertions()],
            "unfired_keys": [a.key for a in self.unfired],
        }

    def evidence_lines(self) -> List[str]:
        """Analyst-facing lines for the risk explanation."""
        lines: List[str] = []
        if not self.dynamic_ran:
            return lines
        for assertion in self.all_assertions():
            mark = "REACHED" if assertion.fired else "NOT REACHED"
            detail = f" - {assertion.evidence}" if assertion.evidence else ""
            lines.append(f"Execution assertion [{mark}] {assertion.label}{detail}")
        if self.incomplete_exercise:
            lines.append(
                "INCOMPLETE EXERCISE: the sandbox reached none of the fraud "
                "trigger conditions and observed no threat behaviour. This run "
                "is not evidence that the sample is benign - it is evidence "
                "that the sample was never exercised."
            )
        return lines


# ── Derivation ─────────────────────────────────────────────────────────────


def _as_text(value: Any) -> str:
    """Flatten an arbitrary telemetry value to searchable text."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_as_text(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_as_text(v) for v in value)
    return str(value)


def _iter_behaviour_blobs(dynamic: Dict[str, Any]) -> Iterable[str]:
    """
    Yield one searchable text blob per observed sample behaviour.

    Harness self-reporting is skipped: a screenshot record proves the sandbox
    took a screenshot, which is not a fact about the sample.
    """
    for field_name in ("api_calls", "network_logs", "activities_triggered", "files_accessed"):
        for item in dynamic.get(field_name) or []:
            yield _as_text(item)

    buckets = dynamic.get("frida_events")
    if isinstance(buckets, dict):
        for events in buckets.values():
            for event in events or []:
                yield _as_text(event)

    for record in dynamic.get("evidence") or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("category") or "").upper() in _HARNESS_CATEGORIES:
            continue
        yield _as_text(record)


def _normalise_packages(packages: Optional[Sequence[Any]]) -> Set[str]:
    out: Set[str] = set()
    for entry in packages or []:
        if isinstance(entry, str):
            name = entry.strip().lower()
        elif isinstance(entry, dict):
            name = str(
                entry.get("package") or entry.get("package_name") or entry.get("name") or ""
            ).strip().lower()
        else:
            name = ""
        # A package name has at least one dot; bare bank labels ("SBI") would
        # match far too much of a telemetry blob.
        if name and "." in name:
            out.add(name)
    return out


def _first_match(blobs: Sequence[str], pattern: re.Pattern[str]) -> str:
    for blob in blobs:
        match = pattern.search(blob)
        if match:
            snippet = blob.strip().replace("\n", " ")
            return snippet[:180]
    return ""


def build_execution_assertions(
    dynamic_result: Optional[Dict[str, Any]],
    *,
    target_bank_packages: Optional[Sequence[Any]] = None,
    threat_events_observed: Optional[int] = None,
) -> ExecutionAssertionMatrix:
    """
    Derive the assertion matrix from one dynamic run.

    ``target_bank_packages`` is the set of banking packages *this sample*
    references, resolved from its own manifest and DEX constants during static
    intake. Passing a curated bank list here would be a hardcoded assumption
    about which institutions matter; passing the sample's own references keeps
    the assertion specific to what this sample is actually hunting.
    """
    matrix = ExecutionAssertionMatrix()
    dynamic = dynamic_result if isinstance(dynamic_result, dict) else {}
    matrix.dynamic_ran = bool(dynamic.get("available"))
    if not matrix.dynamic_ran:
        return matrix

    blobs = [b for b in _iter_behaviour_blobs(dynamic) if b]

    if threat_events_observed is not None:
        matrix.threat_events_observed = max(0, int(threat_events_observed))
    else:
        matrix.threat_events_observed = len(blobs)

    # ── banking app launched ───────────────────────────────────────────────
    # Foreground/activity telemetry naming one of the sample's own targets.
    targets = _normalise_packages(target_bank_packages)
    if targets:
        foreground_blobs = [
            _as_text(dynamic.get("activities_triggered")),
            _as_text(dynamic.get("foreground_packages")),
            _as_text(dynamic.get("launch_timeline")),
            *blobs,
        ]
        haystack = " ".join(b for b in foreground_blobs if b).lower()
        hit = next((pkg for pkg in sorted(targets) if pkg in haystack), "")
        if hit:
            matrix.banking_app_launched.fired = True
            matrix.banking_app_launched.evidence = f"Targeted package observed in foreground: {hit}"
    if not matrix.banking_app_launched.fired and not targets:
        matrix.banking_app_launched.evidence = (
            "Sample references no known banking package, so this trigger is "
            "not applicable to it"
        )

    # ── OTP / bank SMS ─────────────────────────────────────────────────────
    sms_hit = _first_match(blobs, _SMS_RECEIVE_SIGNALS) or _first_match(blobs, _OTP_TEXT_SIGNALS)
    if sms_hit:
        matrix.otp_sms_received.fired = True
        matrix.otp_sms_received.evidence = sms_hit

    # ── accessibility ──────────────────────────────────────────────────────
    # A granted-services list is stronger evidence than a hook name, so it is
    # checked first.
    granted = _as_text(dynamic.get("accessibility_services_enabled"))
    if granted.strip():
        matrix.accessibility_granted.fired = True
        matrix.accessibility_granted.evidence = f"Accessibility services enabled: {granted[:160]}"
    else:
        acc_hit = _first_match(blobs, _ACCESSIBILITY_SIGNALS)
        if acc_hit:
            matrix.accessibility_granted.fired = True
            matrix.accessibility_granted.evidence = acc_hit

    # ── overlay ────────────────────────────────────────────────────────────
    overlay_hit = _first_match(blobs, _OVERLAY_SIGNALS)
    if overlay_hit:
        matrix.overlay_triggered.fired = True
        matrix.overlay_triggered.evidence = overlay_hit
    elif dynamic.get("vide_webview_html"):
        matrix.overlay_triggered.fired = True
        matrix.overlay_triggered.evidence = "WebView overlay HTML captured at runtime"

    # ── contacts / call log ────────────────────────────────────────────────
    contacts_hit = _first_match(blobs, _CONTACTS_SIGNALS)
    if contacts_hit:
        matrix.contacts_accessed.fired = True
        matrix.contacts_accessed.evidence = contacts_hit

    call_hit = _first_match(blobs, _CALL_LOG_SIGNALS)
    if call_hit:
        matrix.call_log_accessed.fired = True
        matrix.call_log_accessed.evidence = call_hit

    return matrix
