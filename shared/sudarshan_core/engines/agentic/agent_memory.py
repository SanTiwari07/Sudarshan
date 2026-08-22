"""
SUDARSHAN - Agentic Memory
===========================
Maintains persistent, cross-iteration exploration state for the agent loop.

What is remembered:
  - Visited screen hashes (to detect loops and measure coverage).
  - Action history per screen (prevents redundant actions on the same screen).
  - Frida evidence mapped per goal (fed back into prompts as context).
  - Network events observed (C2 detection context).
  - Permissions granted / denied (avoids re-requesting).
  - Failed actions with reasons (planner avoids repeating failures).
  - Previous LLM reasoning (last N iterations for context efficiency).
  - Current working activity name.
  - Safe test credentials used (key names only - values NEVER stored).

Security / compliance rules:
  - Credential VALUES are NEVER stored - only the dictionary key name is stored.
    e.g. memory stores "password_key_used: password" not "Password@123".
  - All memory data is treated as analysis metadata, not PII.
  - Memory is ephemeral - it lives only for the duration of one analysis session.

Usage::

    memory = AgentMemory()
    memory.record_action(screen_hash, action_json, result)
    memory.record_frida_events(events, goal_name="Accessibility Abuse")
    context_str = memory.build_prompt_context(max_actions=5)
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict, defaultdict, deque
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from sudarshan_core.engines.agentic.sanitizer import sanitize, sanitize_all

logger = logging.getLogger(__name__)

# ─── Configuration constants (all thresholds named, never magic-numbered) ────

# How many recent reasoning strings to keep (token efficiency).
MAX_REASONING_HISTORY: int = 5

# How many recent actions per screen before we declare a loop.
MAX_ACTIONS_PER_SCREEN: int = 3

# Maximum total action history items kept in memory.
MAX_TOTAL_HISTORY: int = 100

# Maximum Frida events kept per goal (older ones dropped, counts kept).
MAX_FRIDA_EVENTS_PER_GOAL: int = 20

# ── Hard capacity limits ──────────────────────────────────────────────────────
# The analysed application controls how many distinct screens, URLs and failures
# it can generate, so every one of these collections is attacker-influenced and
# MUST be bounded. Oldest entries are evicted first; counters are preserved so
# metrics stay accurate even after eviction.

# Distinct screens retained. Beyond this the least-recently-seen is evicted.
MAX_VISITED_SCREENS: int = 500

# Per-screen action tuples retained (only the most recent matter for loop
# detection, which compares the last MAX_ACTIONS_PER_SCREEN entries).
MAX_ACTIONS_TRACKED_PER_SCREEN: int = 20

# Screens for which per-screen action counts are retained.
MAX_SCREENS_WITH_ACTION_COUNTS: int = 500

# Distinct network indicators retained.
MAX_NETWORK_EVENTS: int = 1000

# Failed action records retained.
MAX_FAILED_ACTIONS: int = 200


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class ActionRecord:
    """
    A single action taken by the agent on a specific screen.

    credential_key is the DICTIONARY KEY used (e.g. "password"), never the value.
    """
    iteration:       int
    screen_hash:     str
    tool:            str
    target:          str          # element id, text, or coordinate string
    goal_name:       str
    reasoning:       str
    success:         bool
    error:           Optional[str]
    timestamp:       str
    credential_key:  Optional[str] = None   # key name only - never the actual value


@dataclass
class ScreenRecord:
    """Metadata about a visited UI screen."""
    screen_hash:    str
    activity_name:  str
    first_seen:     str
    action_count:   int = 0
    frida_triggered: bool = False


#: Trailing actions kept in a snapshot. Enough for the resumed run to detect an
#: action loop it was already in; the complete history lives in the audit log.
MAX_SNAPSHOT_ACTIONS = 40


@dataclass
class CheckpointSnapshot:
    """
    A resumable point in an exploration run.

    Serialised as UTF-8 JSON with no OS-specific line endings, so a checkpoint
    written on one platform restores on another - the analysis engine and the
    backend do not necessarily run on the same host.
    """

    snapshot_id: str
    timestamp: str
    iteration: int = 0
    current_activity: str = "unknown"
    current_screen_hash: str = ""
    satisfied_goals: List[str] = field(default_factory=list)
    frida_events_captured: int = 0
    screenshot_index: int = 0
    visited_screens: List[Dict[str, Any]] = field(default_factory=list)
    total_screens_seen: int = 0
    permissions_granted: List[str] = field(default_factory=list)
    permissions_denied: List[str] = field(default_factory=list)
    frida_event_counts: Dict[str, int] = field(default_factory=dict)
    network_events: List[str] = field(default_factory=list)
    action_history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckpointSnapshot":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})


# ─── Agent Memory ─────────────────────────────────────────────────────────────

class AgentMemory:
    """
    Ephemeral, session-scoped memory for the Agentic Explorer.

    All data lives only for the duration of one analysis run.
    """

    def __init__(self) -> None:
        # ── Screen tracking ────────────────────────────────────────────────────
        # OrderedDict so the least-recently-seen screen can be evicted once
        # MAX_VISITED_SCREENS is reached.
        self.visited_screens: "OrderedDict[str, ScreenRecord]" = OrderedDict()
        self.current_activity: str = "unknown"
        self.current_screen_hash: str = ""

        # Distinct screens ever seen, including those evicted above. Kept so
        # coverage metrics remain truthful after eviction.
        self._total_screens_seen: int = 0

        # ── Action history ─────────────────────────────────────────────────────
        # Per-screen: screen_hash → bounded deque of (tool, target) tuples
        self._screen_action_counts: "OrderedDict[str, Deque[Tuple[str, str]]]" = OrderedDict()
        # Full chronological history (bounded)
        self._action_history: Deque[ActionRecord] = deque(maxlen=MAX_TOTAL_HISTORY)

        # ── Permission tracking ────────────────────────────────────────────────
        self.permissions_granted: Set[str] = set()
        self.permissions_denied: Set[str] = set()

        # ── Frida evidence per goal ────────────────────────────────────────────
        # goal_name → list of events (bounded to MAX_FRIDA_EVENTS_PER_GOAL)
        self._frida_evidence: Dict[str, List[Dict]] = defaultdict(list)
        self._frida_event_counts: Dict[str, int] = defaultdict(int)

        # ── Network events ─────────────────────────────────────────────────────
        # List preserves order for reporting; the parallel set makes the
        # duplicate check O(1) instead of an O(n) scan per event.
        self.network_events: List[str] = []   # URLs/domains seen
        self._network_seen: Set[str] = set()

        # ── Reasoning history ─────────────────────────────────────────────────
        self._reasoning_history: Deque[str] = deque(maxlen=MAX_REASONING_HISTORY)

        # ── Failed actions ────────────────────────────────────────────────────
        self.failed_actions: List[Dict] = []   # {tool, target, error, iteration}

        # (screen_hash, tool, target) triples that handed the foreground to
        # another app. Unbounded on purpose: it is one small tuple per distinct
        # escaping control, and the action budget caps how many can accumulate.
        self._escaping_actions: Set[Tuple[str, str, str]] = set()

        # ── Iteration counter ─────────────────────────────────────────────────
        self.iteration: int = 0

    # ── Screen registration ────────────────────────────────────────────────────

    def register_screen(self, screen_hash: str, activity_name: str) -> bool:
        """
        Register a newly observed screen.
        Returns True if this is a new (unvisited) screen.
        """
        self.current_screen_hash = screen_hash
        self.current_activity = activity_name

        if screen_hash not in self.visited_screens:
            self.visited_screens[screen_hash] = ScreenRecord(
                screen_hash=screen_hash,
                activity_name=activity_name,
                first_seen=_utcnow(),
            )
            self._total_screens_seen += 1
            self._evict_oldest(self.visited_screens, MAX_VISITED_SCREENS, "visited_screens")
            logger.debug(f"[Memory] New screen: {screen_hash[:8]} ({activity_name})")
            return True

        # Re-visiting refreshes recency so an actively-used screen is not evicted.
        self.visited_screens.move_to_end(screen_hash)
        return False

    @staticmethod
    def _trim_list(store: List[Any], limit: int) -> None:
        """Drop oldest entries so `store` stays strictly under `limit`."""
        overflow = len(store) - limit + 1
        if overflow > 0:
            del store[:overflow]

    @staticmethod
    def _evict_oldest(store: "OrderedDict", limit: int, label: str) -> None:
        """
        Trim an OrderedDict to `limit`, dropping least-recently-inserted first.

        The analysed app decides how many unique screens exist, so these stores
        are attacker-influenced and must never grow without bound.
        """
        evicted = 0
        while len(store) > limit:
            store.popitem(last=False)
            evicted += 1
        if evicted:
            logger.debug(f"[Memory] Evicted {evicted} oldest entries from {label}")

    def is_visited(self, screen_hash: str) -> bool:
        return screen_hash in self.visited_screens

    # ── Action recording ───────────────────────────────────────────────────────

    def record_action(
        self,
        tool: str,
        target: str,
        goal_name: str,
        reasoning: str,
        success: bool,
        error: Optional[str] = None,
        credential_key: Optional[str] = None,
    ) -> None:
        """
        Record an action taken this iteration.

        credential_key: the DICTIONARY KEY (e.g. "password") NOT the value.
                        The actual credential value is NEVER stored in memory.
        """
        screen_hash = self.current_screen_hash
        record = ActionRecord(
            iteration=self.iteration,
            screen_hash=screen_hash,
            tool=tool,
            target=target,
            goal_name=goal_name,
            reasoning=reasoning,
            success=success,
            error=error,
            timestamp=_utcnow(),
            credential_key=credential_key,  # key name only, never the value
        )
        self._action_history.append(record)

        if screen_hash not in self._screen_action_counts:
            self._screen_action_counts[screen_hash] = deque(
                maxlen=MAX_ACTIONS_TRACKED_PER_SCREEN
            )
            self._evict_oldest(
                self._screen_action_counts,
                MAX_SCREENS_WITH_ACTION_COUNTS,
                "_screen_action_counts",
            )
        self._screen_action_counts[screen_hash].append((tool, target))

        if screen_hash in self.visited_screens:
            self.visited_screens[screen_hash].action_count += 1

        if not success and error:
            self._trim_list(self.failed_actions, MAX_FAILED_ACTIONS)
            self.failed_actions.append({
                "iteration": self.iteration,
                "tool": tool,
                "target": target,
                "error": error,
            })
            logger.debug(f"[Memory] Failed action recorded: {tool}({target}) - {error}")

    def record_escaping_action(self, tool: str, target: str) -> None:
        """
        Remember that this action handed the foreground to a different app.

        Keyed by the screen the action was taken *from*, which is still
        ``current_screen_hash`` at the moment the explorer notices: out-of-scope
        screens are deliberately never registered, so the blame lands on the
        in-app screen that owns the offending control rather than on the
        Contacts screen the tap led to.

        Without this the scope guard only treats the symptom. It pulls the agent
        back, the planner re-scores the same screen, picks the same "Phone"
        button because nothing recorded that it leads out of the app, and the
        run ping-pongs until the action budget is gone.
        """
        if not tool:
            return
        self._escaping_actions.add((self.current_screen_hash, tool, target or ""))
        logger.debug(
            "[Memory] Escaping action recorded: %s(%s) on screen %s",
            tool, target, self.current_screen_hash,
        )

    def is_escaping_action(self, tool: str, target: str) -> bool:
        """Whether this action already took the agent out of the app from here."""
        return (self.current_screen_hash, tool, target or "") in self._escaping_actions

    def is_action_loop(self, tool: str, target: str) -> bool:
        """
        Return True if the same (tool, target) has been attempted
        MAX_ACTIONS_PER_SCREEN or more times on the current screen.
        """
        history = self._screen_action_counts.get(self.current_screen_hash, [])
        count = sum(1 for t, tgt in history if t == tool and tgt == target)
        return count >= MAX_ACTIONS_PER_SCREEN

    # ── Reasoning history ──────────────────────────────────────────────────────

    def record_reasoning(self, reasoning: str) -> None:
        """Store the last N LLM reasoning strings for context injection."""
        self._reasoning_history.append(f"[Iter {self.iteration}] {reasoning}")

    def get_recent_reasoning(self) -> List[str]:
        return list(self._reasoning_history)

    # ── Frida evidence ─────────────────────────────────────────────────────────

    def record_frida_events(self, events: List[Dict], goal_name: str = "general") -> None:
        """Record Frida events associated with a goal context."""
        for event in events:
            self._frida_event_counts[goal_name] += 1
            if len(self._frida_evidence[goal_name]) < MAX_FRIDA_EVENTS_PER_GOAL:
                self._frida_evidence[goal_name].append(event)

            # Extract network URLs for the C2 goal
            category = event.get("category", "")
            url = event.get("data", {}).get("url", "")
            if category == "network" and url and url not in self._network_seen:
                self._network_seen.add(url)
                self.network_events.append(url)
                if len(self.network_events) > MAX_NETWORK_EVENTS:
                    # Drop the oldest indicator and forget it, so the set and
                    # the list can never disagree about what is retained.
                    self._network_seen.discard(self.network_events.pop(0))

    def get_frida_summary(self) -> Dict[str, int]:
        """Return {goal_name: total_event_count} for prompt injection."""
        return dict(self._frida_event_counts)

    # ── Permission tracking ────────────────────────────────────────────────────

    def record_permission_granted(self, permission: str) -> None:
        self.permissions_granted.add(permission)
        logger.debug(f"[Memory] Permission granted: {permission}")

    def record_permission_denied(self, permission: str) -> None:
        self.permissions_denied.add(permission)

    # ── Prompt context builder ─────────────────────────────────────────────────

    def build_prompt_context(self, max_actions: int = 5) -> str:
        """
        Build a compact, token-efficient context block for the agent prompt.

        This is injected as the MEMORY section of the planner prompt.
        Credential values are NEVER included - only key names.

        NOTE: This entire block will be enclosed in <UNTRUSTED_MEMORY> tags
        by the planner - it is treated as data context, not instructions.
        """
        lines = [
            "=== AGENT MEMORY ===",
            f"Current iteration: {self.iteration}",
            f"Current activity: {sanitize(self.current_activity)}",
            f"Unique screens visited: {len(self.visited_screens)}",
            "",
            "--- Permissions ---",
            f"  Granted: {', '.join(sanitize_all(sorted(self.permissions_granted))) or 'none'}",
            f"  Denied:  {', '.join(sanitize_all(sorted(self.permissions_denied))) or 'none'}",
            "",
            "--- Frida Evidence Summary (by goal) ---",
        ]
        for goal_name, count in self._frida_event_counts.items():
            lines.append(f"  {sanitize(goal_name, max_length=80)}: {count} event(s)")
        if not self._frida_event_counts:
            lines.append("  (none yet)")

        lines.append("")
        lines.append("--- Recent Actions (last actions on current screen) ---")
        recent = [
            r for r in list(self._action_history)[-max_actions:]
            if r.screen_hash == self.current_screen_hash
        ]
        for r in recent:
            status = "✓" if r.success else "✗"
            cred_note = f" [cred_key={sanitize(r.credential_key, max_length=40)}]" if r.credential_key else ""
            # r.target is a UI label from the app; r.reasoning is model output.
            # Both re-enter the next prompt, so both are sanitized.
            lines.append(
                f"  [{status}] {sanitize(r.tool, max_length=32)}"
                f"({sanitize(r.target, max_length=80)}){cred_note} - "
                f"{sanitize(r.reasoning, max_length=60)}"
            )
        if not recent:
            lines.append("  (none on this screen)")

        lines.append("")
        lines.append("--- Failed Actions (all screens) ---")
        for fa in self.failed_actions[-5:]:
            lines.append(
                f"  iter={fa['iteration']}: {sanitize(fa['tool'], max_length=32)}"
                f"({sanitize(fa['target'], max_length=80)}) → "
                f"{sanitize(fa['error'], max_length=60)}"
            )
        if not self.failed_actions:
            lines.append("  (none)")

        lines.append("")
        lines.append("--- Previous Reasoning ---")
        for r in self.get_recent_reasoning():
            lines.append(f"  {sanitize(r, max_length=100)}")

        return "\n".join(lines)

    # ── Iteration management ───────────────────────────────────────────────────

    def advance_iteration(self) -> None:
        """Call at the start of each agent loop cycle."""
        self.iteration += 1

    # ── Checkpoint snapshot / restore ──────────────────────────────────────────

    def create_snapshot(
        self,
        *,
        satisfied_goals: Optional[List[str]] = None,
        frida_events_captured: int = -1,
        screenshot_index: int = 0,
        snapshot_id: str = "",
    ) -> "CheckpointSnapshot":
        """
        Capture enough state to resume this run without repeating it.

        A dynamic analysis session dies for mundane reasons - the sample kills
        the Frida agent, the emulator ANRs, the host drops the ADB transport -
        and restarting from zero re-drives every screen the agent already
        explored. Worse, re-executing a completed goal can double-count its
        evidence, so a crash mid-run could inflate the very numbers the verdict
        rests on.

        What is captured is what makes resumption *safe*: which goals are
        already satisfied, which screens have been visited, and how much
        evidence was already counted. The Frida event payloads themselves are
        not - they are flushed to the evidence store, which is the durable
        record, and duplicating them here would make snapshots unbounded.
        """
        return CheckpointSnapshot(
            snapshot_id=snapshot_id or f"snap-{self.iteration:04d}-{uuid4().hex[:8]}",
            timestamp=_utcnow(),
            iteration=self.iteration,
            current_activity=self.current_activity,
            current_screen_hash=self.current_screen_hash,
            satisfied_goals=list(satisfied_goals or []),
            frida_events_captured=(
                frida_events_captured
                if frida_events_captured >= 0
                else sum(self._frida_event_counts.values())
            ),
            screenshot_index=int(screenshot_index),
            visited_screens=[
                {
                    "screen_hash": record.screen_hash,
                    "activity_name": record.activity_name,
                    "first_seen": record.first_seen,
                    "action_count": record.action_count,
                    "frida_triggered": record.frida_triggered,
                }
                for record in self.visited_screens.values()
            ],
            total_screens_seen=self._total_screens_seen,
            permissions_granted=sorted(self.permissions_granted),
            permissions_denied=sorted(self.permissions_denied),
            frida_event_counts=dict(self._frida_event_counts),
            network_events=list(self.network_events),
            # Bounded: the tail is what a resumed run needs for loop detection;
            # the full history lives in the audit log.
            action_history=[
                {
                    "iteration": record.iteration,
                    "screen_hash": record.screen_hash,
                    "tool": record.tool,
                    "target": record.target,
                    "goal_name": record.goal_name,
                    "success": record.success,
                    "timestamp": record.timestamp,
                }
                for record in list(self._action_history)[-MAX_SNAPSHOT_ACTIONS:]
            ],
        )

    def restore_snapshot(self, snapshot: Any) -> bool:
        """
        Re-hydrate this memory from a snapshot dict or CheckpointSnapshot.

        Returns True when state was applied. Restoring is additive on screen
        history and authoritative on counters, so a resumed run treats
        already-visited screens as visited and does not re-explore them.
        """
        data = (
            snapshot.to_dict()
            if isinstance(snapshot, CheckpointSnapshot)
            else dict(snapshot or {})
        )
        if not data:
            return False

        try:
            self.iteration = int(data.get("iteration") or 0)
        except (TypeError, ValueError):
            self.iteration = 0
        self.current_activity = str(data.get("current_activity") or "unknown")
        self.current_screen_hash = str(data.get("current_screen_hash") or "")

        for entry in data.get("visited_screens") or []:
            if not isinstance(entry, dict):
                continue
            screen_hash = str(entry.get("screen_hash") or "")
            if not screen_hash or screen_hash in self.visited_screens:
                continue
            self.visited_screens[screen_hash] = ScreenRecord(
                screen_hash=screen_hash,
                activity_name=str(entry.get("activity_name") or "unknown"),
                first_seen=str(entry.get("first_seen") or _utcnow()),
                action_count=int(entry.get("action_count") or 0),
                frida_triggered=bool(entry.get("frida_triggered")),
            )
        # Restoring must respect the same bound as live registration, or a
        # long run's snapshot would grow memory past its cap on every resume.
        self._evict_oldest(self.visited_screens, MAX_VISITED_SCREENS, "screen")

        try:
            self._total_screens_seen = max(
                int(data.get("total_screens_seen") or 0), len(self.visited_screens)
            )
        except (TypeError, ValueError):
            self._total_screens_seen = len(self.visited_screens)

        self.permissions_granted |= {str(p) for p in data.get("permissions_granted") or []}
        self.permissions_denied |= {str(p) for p in data.get("permissions_denied") or []}

        for goal, count in (data.get("frida_event_counts") or {}).items():
            try:
                self._frida_event_counts[str(goal)] = int(count)
            except (TypeError, ValueError):
                continue

        for url in data.get("network_events") or []:
            text = str(url)
            if text not in self._network_seen:
                self._network_seen.add(text)
                self.network_events.append(text)

        for entry in data.get("action_history") or []:
            if not isinstance(entry, dict):
                continue
            self._action_history.append(
                ActionRecord(
                    iteration=int(entry.get("iteration") or 0),
                    screen_hash=str(entry.get("screen_hash") or ""),
                    tool=str(entry.get("tool") or ""),
                    target=str(entry.get("target") or ""),
                    goal_name=str(entry.get("goal_name") or ""),
                    reasoning="",
                    success=bool(entry.get("success")),
                    error=None,
                    timestamp=str(entry.get("timestamp") or _utcnow()),
                )
            )

        logger.info(
            "[AgentMemory] Restored snapshot %s: iteration %s, %s screen(s), "
            "%s goal(s) already satisfied",
            data.get("snapshot_id", "?"),
            self.iteration,
            len(self.visited_screens),
            len(data.get("satisfied_goals") or []),
        )
        return True

    # ── Summary for reports ────────────────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return a JSON-serializable summary for the exploration report."""
        return {
            "total_iterations": self.iteration,
            "unique_screens_visited": len(self.visited_screens),
            "total_actions": len(self._action_history),
            "permissions_granted": sorted(self.permissions_granted),
            "permissions_denied": sorted(self.permissions_denied),
            "frida_evidence_counts": dict(self._frida_event_counts),
            "network_events_seen": len(self.network_events),
            "failed_actions_total": len(self.failed_actions),
            "visited_activities": list({
                r.activity_name for r in self.visited_screens.values()
            }),
        }


# ─── Utility ──────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
