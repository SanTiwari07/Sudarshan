"""
SUDARSHAN - Replay Engine
==========================
Records UI actions taken by the AI Explorer or manually by an analyst,
and allows them to be replayed deterministically via ADB.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from sudarshan_core.engines.event_bus import RuntimeEventBus
from sudarshan_core.sandbox import get_sandbox_provider

logger = logging.getLogger(__name__)

class ReplayEngine:
    def __init__(self, event_bus: Optional[RuntimeEventBus] = None):
        self.actions: List[Dict[str, Any]] = []
        
        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[ReplayEngine] Subscribed to RuntimeEventBus")

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Listen for UI actions and record them."""
        category = event.get("category", "")
        
        if category == "ui_action":
            # Assume UIExplorer publishes its actions to the event bus with category 'ui_action'
            action_data = event.get("data", {})
            
            # Record relative timestamp
            if not self.actions:
                self.start_time = event.get("timestamp", int(time.time() * 1000))
            
            ts = event.get("timestamp", int(time.time() * 1000))
            delay_ms = ts - self.start_time if self.actions else 0
            
            record = {
                "type": action_data.get("type", "tap"), # tap, swipe, text
                "x": action_data.get("x", 0),
                "y": action_data.get("y", 0),
                "text": action_data.get("text", ""),
                "delay_ms": delay_ms,
                "timestamp": ts,
                "screen_hash": action_data.get("screen_hash", "")
            }
            self.actions.append(record)

    def replay(self, device_serial: str, replay_json_path: Path, adb_path: str = "adb") -> bool:
        """Replay a recorded JSON sequence."""
        provider = get_sandbox_provider()
        try:
            with open(replay_json_path, "r", encoding="utf-8") as f:
                sequence = json.load(f)
        except Exception as e:
            logger.error(f"[ReplayEngine] Failed to load replay JSON: {e}")
            return False

        logger.info(f"[ReplayEngine] Replaying {len(sequence)} actions...")
        
        for action in sequence:
            delay_sec = action.get("delay_ms", 0) / 1000.0
            time.sleep(min(delay_sec, 2.0))  # cap wait between actions

            atype = action.get("type")
            shell_args: List[str] = []
            if atype == "tap":
                shell_args = ["tap", str(action.get("x")), str(action.get("y"))]
            elif atype == "text":
                shell_args = ["text", action.get("text", "")]
            elif atype == "swipe":
                continue

            if shell_args:
                try:
                    provider.adb(
                        "-s",
                        device_serial,
                        "shell",
                        "input",
                        *shell_args,
                        timeout=5,
                    )
                except Exception as e:
                    logger.warning(f"[ReplayEngine] Replay command failed: {e}")

        return True

    def flush(self, output_path: Path) -> int:
        """Write recorded actions to JSON."""
        if not self.actions:
            return 0
            
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.actions, f, indent=4)
            logger.info(f"[ReplayEngine] Flushed {len(self.actions)} actions → {output_path}")
        except Exception as e:
            logger.error(f"[ReplayEngine] Failed to write replay.json: {e}")
            
        return len(self.actions)
