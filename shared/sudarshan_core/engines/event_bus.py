"""
SUDARSHAN — Runtime Event Bus
==============================
Lightweight asynchronous Pub/Sub event bus for decoupling dynamic analysis subsystems.

Supported Event Types:
  - SESSION_STARTED
  - SESSION_FINISHED
  - SCREEN_CHANGED
  - SCREENSHOT_CAPTURED
  - FRIDA_EVENT
  - NETWORK_EVENT
  - UI_ACTION
  - THREAT_DETECTED
  - EVIDENCE_CREATED
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


# ─── Telemetry sinks ──────────────────────────────────────────────────────────
#
# Process-wide callbacks invoked for every event, regardless of which bus
# instance published it. This exists so an outer layer (the API gateway) can
# observe runtime telemetry WITHOUT sudarshan_core importing that layer — the
# dependency runs downward only, which is what lets the same package run in a
# service that has no such layer at all.
_TELEMETRY_SINKS: List[Callable[[Dict[str, Any]], None]] = []


def register_telemetry_sink(sink: Callable[[Dict[str, Any]], None]) -> None:
    """Register a callback invoked for every event published on any bus."""
    if sink not in _TELEMETRY_SINKS:
        _TELEMETRY_SINKS.append(sink)
        logger.info("[EventBus] Telemetry sink registered (%d active)", len(_TELEMETRY_SINKS))


def clear_telemetry_sinks() -> None:
    """Remove all sinks. Used by tests."""
    _TELEMETRY_SINKS.clear()


class EventType:
    SESSION_STARTED     = "SESSION_STARTED"
    SESSION_FINISHED    = "SESSION_FINISHED"
    SCREEN_CHANGED      = "SCREEN_CHANGED"
    SCREENSHOT_CAPTURED = "SCREENSHOT_CAPTURED"
    FRIDA_EVENT         = "FRIDA_EVENT"
    NETWORK_EVENT       = "NETWORK_EVENT"
    UI_ACTION           = "UI_ACTION"
    THREAT_DETECTED     = "THREAT_DETECTED"
    EVIDENCE_CREATED    = "EVIDENCE_CREATED"


@dataclass
class RuntimeEvent:
    """
    Standardized payload for events passing through the RuntimeEventBus.
    """
    event_type: str
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"
    severity: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        """Convert RuntimeEvent to dict representation."""
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "payload": self.payload,
            "category": self.category,
            "severity": self.severity,
            # Legacy compatibility fields
            "data": self.payload,
            "type": self.event_type,
        }


class RuntimeEventBus:
    """
    Thread-safe asynchronous event bus.
    Uses an internal queue and background worker to decouple publishers from subscribers.
    """

    def __init__(self) -> None:
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._typed_subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._process_events, daemon=True)
        self._worker.start()

    def subscribe(
        self,
        callback: Callable[[Dict[str, Any]], None],
        event_type: Optional[str] = None
    ) -> None:
        """Register a subscriber callback, optionally filtered by event_type."""
        with self._lock:
            if event_type:
                if event_type not in self._typed_subscribers:
                    self._typed_subscribers[event_type] = []
                if callback not in self._typed_subscribers[event_type]:
                    self._typed_subscribers[event_type].append(callback)
            else:
                if callback not in self._subscribers:
                    self._subscribers.append(callback)

    def unsubscribe(
        self,
        callback: Callable[[Dict[str, Any]], None],
        event_type: Optional[str] = None
    ) -> None:
        """Remove a subscriber callback."""
        with self._lock:
            if event_type and event_type in self._typed_subscribers:
                if callback in self._typed_subscribers[event_type]:
                    self._typed_subscribers[event_type].remove(callback)
            elif callback in self._subscribers:
                self._subscribers.remove(callback)

    def publish(self, event: Union[RuntimeEvent, Dict[str, Any]]) -> None:
        """
        Publish an event to all subscribers.
        Accepts either a RuntimeEvent instance or a raw Dict.
        """
        if isinstance(event, RuntimeEvent):
            event_dict = event.to_dict()
        elif isinstance(event, dict):
            event_dict = event.copy()
            if "event_type" not in event_dict:
                event_dict["event_type"] = event_dict.get("type", EventType.FRIDA_EVENT)
        else:
            logger.warning("[EventBus] Unsupported event object type: %s", type(event))
            return

        self._queue.put(event_dict)

    def _process_events(self) -> None:
        """Background thread pulling events from queue and notifying subscribers."""
        while True:
            try:
                event = self._queue.get()
                etype = event.get("event_type", "")

                with self._lock:
                    all_subs = list(self._subscribers)
                    typed_subs = list(self._typed_subscribers.get(etype, []))

                # Auto-forward to any registered telemetry sink.
                #
                # This used to import the gateway's runtime-telemetry module
                # directly — an import from sudarshan_core UP into the
                # backend, inside a bare `except: pass`. The analysis engine has
                # no `app.routes` package, so in the process that actually runs
                # the instrumentation the import raised ModuleNotFoundError on
                # EVERY event and was silently swallowed. Since delegation is
                # the primary path, that meant all hook and event telemetry from
                # real analyses was discarded, and the dashboard read counters
                # from a process that never saw them.
                #
                # The bus already had the right mechanism — subscribers. The
                # gateway registers itself; the engine simply has no sink.
                for sink in list(_TELEMETRY_SINKS):
                    try:
                        sink(event)
                    except Exception as e:
                        logger.error("[EventBus] Telemetry sink error: %s", e)

                # Notify general subscribers
                for cb in all_subs:
                    try:
                        cb(event)
                    except Exception as e:
                        logger.error("[EventBus] General subscriber error: %s", e)

                # Notify typed subscribers
                for cb in typed_subs:
                    try:
                        cb(event)
                    except Exception as e:
                        logger.error("[EventBus] Typed subscriber (%s) error: %s", etype, e)

                self._queue.task_done()
            except Exception as e:
                logger.error("[EventBus] Worker loop error: %s", e)

    def pending_count(self) -> int:
        """Approximate number of events not yet delivered to subscribers."""
        return self._queue.qsize()

    def drain(self, timeout_seconds: float = 5.0) -> bool:
        """
        Block until the event queue is empty and all subscribers have run.

        Returns True if drained within *timeout_seconds*, False on timeout.
        Screenshot threads and other async work may still be in flight — use
        ScreenshotManager.wait_pending() after this when flushing artifacts.
        """
        deadline = time.time() + max(0.1, timeout_seconds)
        while time.time() < deadline:
            if self._queue.unfinished_tasks == 0 and self._queue.empty():
                return True
            time.sleep(0.05)
        logger.warning(
            "[EventBus] drain() timed out after %.1fs (%d unfinished)",
            timeout_seconds,
            self._queue.unfinished_tasks,
        )
        return False
