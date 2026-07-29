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

                # Auto-forward to in-process telemetry ring buffer
                try:
                    from app.routes.runtime_api import record_event
                    record_event(event)
                except Exception:
                    pass

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
