"""
SUDARSHAN - Explainable Exploration Audit Log
===============================================
Records every agent iteration as a structured, queryable log entry.

Design rules:
  - One entry per agent iteration - no partial writes.
  - Credential VALUES are NEVER written to the log.
    Only field_hint keys (e.g. "password") appear in tool params.
  - All app-controlled strings (UI text, activity names, Frida hook names)
    are recorded verbatim as DATA fields, never as instructions.
  - flush() is idempotent: calling it multiple times produces the same output.
  - The log is intended for SOC analyst review and compliance audit.

Entry schema::

    {
      "iteration": 3,
      "timestamp": "2026-07-24T13:00:00.000Z",
      "observation": {
          "activity": "com.example.MainActivity",
          "screen_hash": "a1b2c3d4e5f6a7b8",
          "ui_node_count": 5,
          "frida_events_count": 2,
          "screenshot_taken": false,
          "vision_reason": ""
      },
      "goal": {
          "current": "Login Flow",
          "stage": 5,
          "status": "IN_PROGRESS"
      },
      "reasoning": "Saw a Login button. Tapping to enter authentication flow.",
      "action": {
          "tool": "click_text",
          "text": "Login",
          "confidence": 0.95
      },
      "execution_result": {
          "success": true,
          "duration": 1.2,
          "retries": 0
      },
      "frida_events": [...],   // raw events from this iteration
      "network_events": [...],
      "goal_status_snapshot": {
          "Launch Application": "COMPLETED",
          "Grant Runtime Permissions": "COMPLETED",
          "Accessibility Abuse": "IN_PROGRESS",
          ...
      },
      "stopping_conditions": {
          "action_budget_used": 3,
          "action_budget_max": 25,
          "empty_action_streak": 0,
          "time_elapsed_s": 15.3
      }
    }

Usage::

    log = AuditLog()
    log.record(iteration=1, observation=obs, goal=goal, reasoning="...",
               action=action_dict, result=tool_result,
               frida_events=[...], goal_status={...})
    log.flush(Path("audit_log.json"))
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Maximum Frida events stored per iteration in the log (prevents log bloat)
MAX_FRIDA_EVENTS_PER_ENTRY: int = 10


class AuditLog:
    """
    Append-only, thread-safe audit log for the Agentic Explorer.

    Every public method is safe to call from multiple threads.
    flush() is idempotent.
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(
        self,
        iteration:        int,
        activity:         str,
        screen_hash:      str,
        ui_node_count:    int,
        screenshot_taken: bool,
        vision_reason:    str,
        goal_name:        str,
        goal_stage:       int,
        goal_status:      str,
        reasoning:        str,
        action:           Dict[str, Any],
        result_success:   bool,
        result_duration:  float,
        result_retries:   int,
        result_error:     Optional[str],
        frida_events:     List[Dict],
        network_events:   List[str],
        goal_status_snapshot: Dict[str, str],
        action_budget_used: int,
        action_budget_max:  int,
        empty_action_streak: int,
        time_elapsed_s:   float,
        source:           str = "AI",   # "AI" | "Fallback" | "Deterministic"
    ) -> None:
        """
        Record a single complete agent iteration.

        SECURITY NOTE:
          - `action` dict is copied and sanitized before storage.
            If action contains a 'text' key whose value is an actual credential
            (not a field_hint), it is replaced with the field_hint placeholder.
          - Frida event data is stored verbatim - it contains only hook names
            and API call data, never user credentials.
        """
        safe_action = self._sanitize_action(action)

        # Truncate Frida events to prevent log bloat
        safe_frida = frida_events[:MAX_FRIDA_EVENTS_PER_ENTRY]

        entry = {
            "iteration":  iteration,
            "timestamp":  _utcnow(),
            "source":     source,
            "observation": {
                "activity":         activity,
                "screen_hash":      screen_hash,
                "ui_node_count":    ui_node_count,
                "frida_events_count": len(frida_events),
                "screenshot_taken": screenshot_taken,
                "vision_reason":    vision_reason,
            },
            "goal": {
                "current": goal_name,
                "stage":   goal_stage,
                "status":  goal_status,
            },
            "reasoning": reasoning,
            "action":    safe_action,
            "execution_result": {
                "success":  result_success,
                "duration": round(result_duration, 3),
                "retries":  result_retries,
                "error":    result_error,
            },
            "frida_events":   safe_frida,
            "network_events": network_events[:10],
            "goal_status_snapshot":  goal_status_snapshot,
            "stopping_conditions": {
                "action_budget_used": action_budget_used,
                "action_budget_max":  action_budget_max,
                "empty_action_streak": empty_action_streak,
                "time_elapsed_s":     round(time_elapsed_s, 1),
            },
        }

        with self._lock:
            self._entries.append(entry)

    def record_system_event(self, event_type: str, detail: str) -> None:
        """Record a system-level event (start, stop, fallback activation, etc.)."""
        entry = {
            "type":      "system_event",
            "timestamp": _utcnow(),
            "event":     event_type,
            "detail":    detail,
        }
        with self._lock:
            self._entries.append(entry)

    def flush(self, output_path: Path) -> int:
        """
        Write the complete audit log to a JSON file.
        Returns the number of entries written.
        Idempotent - can be called multiple times.
        """
        with self._lock:
            snapshot = list(self._entries)

        payload = {
            "log_version": "1.0",
            "generated_at": _utcnow(),
            "total_entries": len(snapshot),
            "entries": snapshot,
        }

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, default=str)
            logger.info(f"[AuditLog] Flushed {len(snapshot)} entries → {output_path}")
        except Exception as e:
            logger.error(f"[AuditLog] Failed to write audit log: {e}")

        return len(snapshot)

    def get_entries(self) -> List[Dict[str, Any]]:
        """Return a snapshot of all recorded entries (thread-safe)."""
        with self._lock:
            return list(self._entries)

    # ── Sanitization ───────────────────────────────────────────────────────────

    @staticmethod
    def _sanitize_action(action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return a copy of the action dict with any raw credential values redacted.

        The planner always uses field_hint (e.g. "password"), not the value.
        But as a belt-and-suspenders defence, any 'text' field whose value
        matches a known credential value is replaced with '[REDACTED]'.

        This prevents accidental credential leakage if the planner or fallback
        ever embeds an actual form value directly.
        """
        from sudarshan_core.engines.agentic.tool_executor import FORM_VALUES
        from sudarshan_core.engines.agentic.credentials import all_secret_values

        safe = dict(action)
        if "text" in safe:
            # Both sources, because the static table is no longer the only one:
            # values are now generated per run and regenerated on each login
            # attempt, so redacting FORM_VALUES alone would leave every actually
            # used credential in the audit log. all_secret_values() is a
            # superset over the process, so a password issued before a
            # regeneration is still redacted afterwards.
            credential_values = set(FORM_VALUES.values()) | all_secret_values()
            if safe["text"] in credential_values:
                safe["text"] = "[REDACTED_CREDENTIAL_VALUE]"
        return safe


# ─── Utility ──────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
