"""
SUDARSHAN — Agentic Memory
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
  - Safe test credentials used (key names only — values NEVER stored).

Security / compliance rules:
  - Credential VALUES are NEVER stored — only the dictionary key name is stored.
    e.g. memory stores "password_key_used: password" not "Password@123".
  - All memory data is treated as analysis metadata, not PII.
  - Memory is ephemeral — it lives only for the duration of one analysis session.

Usage::

    memory = AgentMemory()
    memory.record_action(screen_hash, action_json, result)
    memory.record_frida_events(events, goal_name="Accessibility Abuse")
    context_str = memory.build_prompt_context(max_actions=5)
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

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
    credential_key:  Optional[str] = None   # key name only — never the actual value


@dataclass
class ScreenRecord:
    """Metadata about a visited UI screen."""
    screen_hash:    str
    activity_name:  str
    first_seen:     str
    action_count:   int = 0
    frida_triggered: bool = False


# ─── Agent Memory ─────────────────────────────────────────────────────────────

class AgentMemory:
    """
    Ephemeral, session-scoped memory for the Agentic Explorer.

    All data lives only for the duration of one analysis run.
    """

    def __init__(self) -> None:
        # ── Screen tracking ────────────────────────────────────────────────────
        self.visited_screens: Dict[str, ScreenRecord] = {}
        self.current_activity: str = "unknown"
        self.current_screen_hash: str = ""

        # ── Action history ─────────────────────────────────────────────────────
        # Per-screen: screen_hash → list of (tool, target) tuples
        self._screen_action_counts: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
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
        self.network_events: List[str] = []   # URLs/domains seen

        # ── Reasoning history ─────────────────────────────────────────────────
        self._reasoning_history: Deque[str] = deque(maxlen=MAX_REASONING_HISTORY)

        # ── Failed actions ────────────────────────────────────────────────────
        self.failed_actions: List[Dict] = []   # {tool, target, error, iteration}

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
            logger.debug(f"[Memory] New screen: {screen_hash[:8]} ({activity_name})")
            return True
        return False

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
        self._screen_action_counts[screen_hash].append((tool, target))

        if screen_hash in self.visited_screens:
            self.visited_screens[screen_hash].action_count += 1

        if not success and error:
            self.failed_actions.append({
                "iteration": self.iteration,
                "tool": tool,
                "target": target,
                "error": error,
            })
            logger.debug(f"[Memory] Failed action recorded: {tool}({target}) — {error}")

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
            if category == "network" and url and url not in self.network_events:
                self.network_events.append(url)

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
        Credential values are NEVER included — only key names.

        NOTE: This entire block will be enclosed in <UNTRUSTED_MEMORY> tags
        by the planner — it is treated as data context, not instructions.
        """
        lines = [
            "=== AGENT MEMORY ===",
            f"Current iteration: {self.iteration}",
            f"Current activity: {self.current_activity}",
            f"Unique screens visited: {len(self.visited_screens)}",
            "",
            "--- Permissions ---",
            f"  Granted: {', '.join(sorted(self.permissions_granted)) or 'none'}",
            f"  Denied:  {', '.join(sorted(self.permissions_denied)) or 'none'}",
            "",
            "--- Frida Evidence Summary (by goal) ---",
        ]
        for goal_name, count in self._frida_event_counts.items():
            lines.append(f"  {goal_name}: {count} event(s)")
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
            cred_note = f" [cred_key={r.credential_key}]" if r.credential_key else ""
            lines.append(
                f"  [{status}] {r.tool}({r.target}){cred_note} — {r.reasoning[:60]}"
            )
        if not recent:
            lines.append("  (none on this screen)")

        lines.append("")
        lines.append("--- Failed Actions (all screens) ---")
        for fa in self.failed_actions[-5:]:
            lines.append(f"  iter={fa['iteration']}: {fa['tool']}({fa['target']}) → {fa['error'][:60]}")
        if not self.failed_actions:
            lines.append("  (none)")

        lines.append("")
        lines.append("--- Previous Reasoning ---")
        for r in self.get_recent_reasoning():
            lines.append(f"  {r[:100]}")

        return "\n".join(lines)

    # ── Iteration management ───────────────────────────────────────────────────

    def advance_iteration(self) -> None:
        """Call at the start of each agent loop cycle."""
        self.iteration += 1

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
