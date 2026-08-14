"""Turn an unexercised run into a concrete list of things to do next.

When the Execution Assertion Matrix reports that nothing was triggered, the
analyst's question is immediately "so what do I do about it?". Answering that
with prose is not useful under time pressure; answering it with a ranked list of
one-click actions is.

Every suggestion produced here carries a machine-executable ``action`` that maps
onto a real capability the platform already has - persona seeding, time warp,
launching a target activity, injecting a test SMS - so the UI can offer a button
rather than an instruction.

Generation is **deterministic**. A forensic report has to be reproducible: the
same run must yield the same recommendations on re-render, and the suggestions
have to be available on an air-gapped deployment with no model access. An LLM
may enrich the wording (see :func:`enrich_with_llm`), but it never decides what
is suggested or in what order.

Nothing here hardcodes a bank or a package. Target packages arrive from the
sample's own manifest and DEX references, resolved during static intake.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

# Action types the backend and UI know how to execute. Kept as constants so a
# typo in a suggestion cannot silently produce a dead button.
ACTION_SEED_PERSONA = "seed_persona"
ACTION_TIME_WARP = "time_warp"
ACTION_FORCE_JOBS = "force_jobs"
ACTION_LAUNCH_TARGET_APP = "launch_target_app"
ACTION_INJECT_TEST_SMS = "inject_test_sms"
ACTION_GRANT_ACCESSIBILITY = "grant_accessibility"
ACTION_GRANT_OVERLAY = "grant_overlay"
ACTION_EXTEND_RUN = "extend_run"
ACTION_NONE = "none"

EXECUTABLE_ACTIONS = frozenset(
    {
        ACTION_SEED_PERSONA,
        ACTION_TIME_WARP,
        ACTION_FORCE_JOBS,
        ACTION_LAUNCH_TARGET_APP,
        ACTION_INJECT_TEST_SMS,
        ACTION_GRANT_ACCESSIBILITY,
        ACTION_GRANT_OVERLAY,
        ACTION_EXTEND_RUN,
    }
)

PRIORITY_CRITICAL = "CRITICAL"
PRIORITY_HIGH = "HIGH"
PRIORITY_MEDIUM = "MEDIUM"

_PRIORITY_RANK = {PRIORITY_CRITICAL: 0, PRIORITY_HIGH: 1, PRIORITY_MEDIUM: 2}


@dataclass
class RemedialSuggestion:
    """One actionable step toward closing an evidence gap."""

    suggestion_id: str
    title: str
    rationale: str
    priority: str = PRIORITY_MEDIUM
    #: Which assertion or goal this closes.
    addresses: str = ""
    #: ``{"type": ..., **params}`` - executable by the resilience API.
    action: Dict[str, Any] = field(default_factory=lambda: {"type": ACTION_NONE})
    #: Threat-intel grounding for why this trigger matters.
    threat_context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "title": self.title,
            "rationale": self.rationale,
            "priority": self.priority,
            "addresses": self.addresses,
            "action": dict(self.action),
            "actionable": self.action.get("type") in EXECUTABLE_ACTIONS,
            "threat_context": self.threat_context,
        }


def _normalise_packages(packages: Optional[Sequence[Any]]) -> List[str]:
    out: List[str] = []
    for entry in packages or []:
        if isinstance(entry, str):
            name = entry.strip()
        elif isinstance(entry, dict):
            name = str(
                entry.get("package") or entry.get("package_name") or entry.get("name") or ""
            ).strip()
        else:
            name = ""
        if name and "." in name and name not in out:
            out.append(name)
    return out


# ── Assertion-driven suggestions ───────────────────────────────────────────
#
# Keyed by assertion. Each entry states what to do, why the trigger matters to
# real families, and the executable action that reaches it.

def _suggestion_for_assertion(
    key: str,
    *,
    target_packages: Sequence[str],
    persona_id: str,
) -> Optional[RemedialSuggestion]:
    if key == "accessibility_granted":
        return RemedialSuggestion(
            suggestion_id="remedy_accessibility",
            title="Grant the sample's accessibility service",
            rationale=(
                "The run never granted accessibility, so any payload gated on "
                "it stayed dormant. This is the single highest-yield trigger."
            ),
            priority=PRIORITY_CRITICAL,
            addresses=key,
            action={"type": ACTION_GRANT_ACCESSIBILITY},
            threat_context=(
                "Anatsa, Xenomorph and SOVA all drive their ATS and overlay "
                "logic through AccessibilityService and perform no fraud "
                "actions until the service is bound."
            ),
        )

    if key == "banking_app_launched":
        if not target_packages:
            return None
        return RemedialSuggestion(
            suggestion_id="remedy_launch_target",
            title=f"Open a targeted banking app ({target_packages[0]})",
            rationale=(
                "The sample references "
                f"{len(target_packages)} banking package(s) but none came to "
                "the foreground during the run, so an overlay keyed to them "
                "had nothing to trigger on."
            ),
            priority=PRIORITY_CRITICAL,
            addresses=key,
            action={
                "type": ACTION_LAUNCH_TARGET_APP,
                "packages": list(target_packages[:8]),
            },
            threat_context=(
                "Overlay families poll the foreground activity and inject only "
                "when a package on their target list is on screen."
            ),
        )

    if key == "otp_sms_received":
        return RemedialSuggestion(
            suggestion_id="remedy_inject_sms",
            title="Inject a test OTP SMS",
            rationale=(
                "No SMS reached the device, so SMS interception and forwarding "
                "hooks had nothing to observe."
            ),
            priority=PRIORITY_HIGH,
            addresses=key,
            action={
                "type": ACTION_INJECT_TEST_SMS,
                "sender": "AD-BANKSM",
                "body": "OTP 481902 is valid for 10 minutes. Do not share it.",
            },
            threat_context=(
                "SMS-stealer stages register a BroadcastReceiver for "
                "SMS_RECEIVED and exfiltrate on delivery; with no message, the "
                "receiver never fires."
            ),
        )

    if key == "overlay_triggered":
        return RemedialSuggestion(
            suggestion_id="remedy_overlay",
            title="Grant overlay permission and re-run",
            rationale=(
                "No overlay window was drawn. Without SYSTEM_ALERT_WINDOW the "
                "phishing surface cannot be presented at all."
            ),
            priority=PRIORITY_HIGH,
            addresses=key,
            action={"type": ACTION_GRANT_OVERLAY},
            threat_context=(
                "Credential-harvesting overlays are the primary monetisation "
                "path for this malware class."
            ),
        )

    if key in ("contacts_accessed", "call_log_accessed"):
        which = "contacts" if key == "contacts_accessed" else "call log"
        return RemedialSuggestion(
            suggestion_id=f"remedy_persona_{key}",
            title=f"Seed a device persona ({which} populated)",
            rationale=(
                f"The {which} provider was never read. On a sterile device "
                "these return zero rows, which several families treat as a "
                "sandbox tell and abort on."
            ),
            priority=PRIORITY_HIGH,
            addresses=key,
            action={"type": ACTION_SEED_PERSONA, "persona_id": persona_id},
            threat_context=(
                "Environment fingerprinting: an empty address book is cheaper "
                "to check than emulator properties and just as reliable."
            ),
        )

    return None


def generate_remedial_suggestions(
    unfulfilled_goals: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    execution_assertions: Optional[Dict[str, Any]] = None,
    target_bank_packages: Optional[Sequence[Any]] = None,
    default_persona_id: str = "default_retail_user",
    limit: int = 8,
) -> List[RemedialSuggestion]:
    """
    Rank the actions most likely to convert an empty run into evidence.

    Assertion gaps drive the list, because an unreached trigger is a concrete,
    fixable precondition. Unfulfilled goals refine it: a goal the agent
    *attempted* and failed is a different problem from one it never reached,
    and only the latter is solved by giving the run more time.
    """
    suggestions: List[RemedialSuggestion] = []
    seen_ids: set = set()

    def _add(suggestion: Optional[RemedialSuggestion]) -> None:
        if suggestion and suggestion.suggestion_id not in seen_ids:
            seen_ids.add(suggestion.suggestion_id)
            suggestions.append(suggestion)

    packages = _normalise_packages(target_bank_packages)
    assertions = execution_assertions or {}
    unfired: List[str] = list(assertions.get("unfired_keys") or [])

    for key in unfired:
        _add(
            _suggestion_for_assertion(
                key, target_packages=packages, persona_id=default_persona_id
            )
        )

    # ── Time warp ──────────────────────────────────────────────────────────
    # Offered whenever the run was unexercised: a stalled dropper produces
    # exactly the same telemetry as a benign app, and no assertion can
    # distinguish them - only advancing the clock can.
    if assertions.get("incomplete_exercise"):
        _add(
            RemedialSuggestion(
                suggestion_id="remedy_time_warp",
                title="Fast-forward the device clock (+24h) and force pending jobs",
                rationale=(
                    "The sandbox observed nothing at all. A dropper stalling on "
                    "a WorkManager or AlarmManager delay is indistinguishable "
                    "from a benign app inside a short run window - advancing "
                    "the clock is the only way to separate them."
                ),
                priority=PRIORITY_CRITICAL,
                addresses="dormancy",
                action={"type": ACTION_TIME_WARP, "hours": 24, "force_jobs": True},
                threat_context=(
                    "Anatsa droppers commonly delay their second-stage fetch by "
                    "hours to days specifically to outlast automated analysis."
                ),
            )
        )

    # ── Goal-derived suggestions ───────────────────────────────────────────
    goals = list(unfulfilled_goals or [])
    never_attempted = [g for g in goals if g.get("reason") == "never_attempted"]
    attempted = [g for g in goals if g.get("reason") == "attempted"]
    blocked = [g for g in goals if g.get("reason") == "blocked"]

    if never_attempted:
        names = ", ".join(str(g.get("goal_name")) for g in never_attempted[:4])
        _add(
            RemedialSuggestion(
                suggestion_id="remedy_extend_run",
                title=f"Extend the run - {len(never_attempted)} goal(s) never reached",
                rationale=(
                    f"The run ended before the agent attempted: {names}. These "
                    "carry no information about the sample either way."
                ),
                priority=PRIORITY_HIGH,
                addresses="coverage",
                action={"type": ACTION_EXTEND_RUN, "additional_seconds": 180},
                threat_context="",
            )
        )

    if attempted:
        names = ", ".join(str(g.get("goal_name")) for g in attempted[:4])
        _add(
            RemedialSuggestion(
                suggestion_id="remedy_attempted_goals",
                title=f"Investigate {len(attempted)} goal(s) the agent could not trigger",
                rationale=(
                    f"The agent actively attempted {names} and produced no "
                    "evidence. Unlike an unreached goal, this may be the sample "
                    "resisting - review the anti-analysis timeline alongside it."
                ),
                priority=PRIORITY_MEDIUM,
                addresses="evasion",
                action={"type": ACTION_NONE},
                threat_context="",
            )
        )

    if blocked:
        first = blocked[0]
        blockers = ", ".join(str(n) for n in (first.get("blocked_by_goals") or [])) or "an earlier stage"
        _add(
            RemedialSuggestion(
                suggestion_id="remedy_unblock_goals",
                title=f"Unblock {len(blocked)} dependent goal(s)",
                rationale=(
                    f"'{first.get('goal_name')}' could not be attempted because "
                    f"{blockers} never completed. Satisfying that dependency "
                    "unblocks the rest of the chain."
                ),
                priority=PRIORITY_MEDIUM,
                addresses="dependency",
                action={"type": ACTION_NONE},
                threat_context="",
            )
        )

    suggestions.sort(key=lambda s: (_PRIORITY_RANK.get(s.priority, 9), s.suggestion_id))
    return suggestions[:limit]


def suggestions_to_dicts(
    suggestions: Sequence[RemedialSuggestion],
) -> List[Dict[str, Any]]:
    return [s.to_dict() for s in suggestions]
