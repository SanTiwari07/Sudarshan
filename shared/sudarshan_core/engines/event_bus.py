"""
SUDARSHAN - Runtime Event Bus
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
import os
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
# observe runtime telemetry WITHOUT sudarshan_core importing that layer - the
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


#: Upper bound on undelivered events. A hostile sample can call a hooked API
#: in a tight loop; an unbounded queue turned that into unbounded host memory.
DEFAULT_MAX_QUEUE = int(os.getenv("SUDARSHAN_EVENT_BUS_MAX_QUEUE", "20000") or 20000)
#: How long a publisher waits for room before the event is dropped (and
#: counted). Blocking the publisher is the backpressure: it slows Frida's
#: message delivery instead of growing the queue.
DEFAULT_PUBLISH_TIMEOUT_S = float(os.getenv("SUDARSHAN_EVENT_BUS_PUBLISH_TIMEOUT", "2.0") or 2.0)

_STOP = object()


class RuntimeEventBus:
    """
    Thread-safe asynchronous event bus.
    Uses an internal queue and background worker to decouple publishers from subscribers.

    Delivery guarantees, all observable through :meth:`metrics`:
      * a subscriber that raises never affects other subscribers or later events;
      * the queue is bounded - a publisher blocks up to ``publish_timeout`` for
        room, then the event is dropped and counted in ``dropped`` rather than
        lost silently;
      * :meth:`close` stops the worker thread. Each bus used to own a daemon
        thread for the life of the process, one per analysed sample.
    """

    def __init__(
        self,
        max_queue: Optional[int] = None,
        publish_timeout: Optional[float] = None,
    ) -> None:
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._typed_subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        size = DEFAULT_MAX_QUEUE if max_queue is None else max(1, int(max_queue))
        self._queue: queue.Queue = queue.Queue(maxsize=size)
        self._publish_timeout = (
            DEFAULT_PUBLISH_TIMEOUT_S if publish_timeout is None else max(0.0, float(publish_timeout))
        )
        self._lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._metrics: Dict[str, int] = {
            "published": 0,
            "delivered": 0,
            "dropped": 0,
            "rejected_after_close": 0,
            "subscriber_errors": 0,
            "sink_errors": 0,
            "max_depth": 0,
        }
        self._closed = False
        self._worker = threading.Thread(
            target=self._process_events, name="runtime-event-bus", daemon=True
        )
        self._worker.start()

    def _bump(self, key: str, n: int = 1) -> None:
        with self._metrics_lock:
            self._metrics[key] = self._metrics.get(key, 0) + n

    def metrics(self) -> Dict[str, int]:
        """Snapshot of delivery counters, plus the current queue depth."""
        with self._metrics_lock:
            out = dict(self._metrics)
        out["pending"] = self._queue.qsize()
        out["capacity"] = self._queue.maxsize
        return out

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

    def publish(self, event: Union[RuntimeEvent, Dict[str, Any]]) -> bool:
        """
        Publish an event to all subscribers.
        Accepts either a RuntimeEvent instance or a raw Dict.

        Returns True when the event was queued, False when it was rejected
        (bus closed, unsupported type, or the queue stayed full).
        """
        if isinstance(event, RuntimeEvent):
            event_dict = event.to_dict()
        elif isinstance(event, dict):
            event_dict = event.copy()
            if "event_type" not in event_dict:
                event_dict["event_type"] = event_dict.get("type", EventType.FRIDA_EVENT)
        else:
            logger.warning("[EventBus] Unsupported event object type: %s", type(event))
            return False

        if self._closed:
            self._bump("rejected_after_close")
            return False

        try:
            if threading.current_thread() is self._worker:
                # A subscriber publishing a follow-up event (EvidenceStore's
                # EVIDENCE_CREATED). Blocking here would wait on the very
                # thread that drains the queue, so never block.
                self._queue.put_nowait(event_dict)
            else:
                self._queue.put(event_dict, timeout=self._publish_timeout)
        except queue.Full:
            self._bump("dropped")
            logger.error(
                "[EventBus] Queue full (%d) - dropped %s event. Runtime telemetry "
                "is being lost; see event_bus metrics in the result.",
                self._queue.maxsize, event_dict.get("event_type"),
            )
            return False

        self._bump("published")
        depth = self._queue.qsize()
        with self._metrics_lock:
            if depth > self._metrics["max_depth"]:
                self._metrics["max_depth"] = depth
        return True

    def _process_events(self) -> None:
        """Background thread pulling events from queue and notifying subscribers."""
        while True:
            event = self._queue.get()
            try:
                if event is _STOP:
                    return
                etype = event.get("event_type", "")

                with self._lock:
                    all_subs = list(self._subscribers)
                    typed_subs = list(self._typed_subscribers.get(etype, []))

                # Auto-forward to any registered telemetry sink.
                #
                # This used to import the gateway's runtime-telemetry module
                # directly - an import from sudarshan_core UP into the
                # backend, inside a bare `except: pass`. The analysis engine has
                # no `app.routes` package, so in the process that actually runs
                # the instrumentation the import raised ModuleNotFoundError on
                # EVERY event and was silently swallowed. Since delegation is
                # the primary path, that meant all hook and event telemetry from
                # real analyses was discarded, and the dashboard read counters
                # from a process that never saw them.
                #
                # The bus already had the right mechanism - subscribers. The
                # gateway registers itself; the engine simply has no sink.
                for sink in list(_TELEMETRY_SINKS):
                    try:
                        sink(event)
                    except Exception as e:
                        self._bump("sink_errors")
                        logger.error("[EventBus] Telemetry sink error: %s", e)

                # Notify general subscribers
                for cb in all_subs:
                    try:
                        cb(event)
                    except Exception as e:
                        self._bump("subscriber_errors")
                        logger.error("[EventBus] General subscriber error: %s", e)

                # Notify typed subscribers
                for cb in typed_subs:
                    try:
                        cb(event)
                    except Exception as e:
                        self._bump("subscriber_errors")
                        logger.error("[EventBus] Typed subscriber (%s) error: %s", etype, e)

                self._bump("delivered")
            except Exception as e:
                logger.error("[EventBus] Worker loop error: %s", e)
            finally:
                # Always. A task_done() skipped on the error path left
                # unfinished_tasks permanently above zero, so every later
                # drain() waited out its full timeout and reported failure.
                self._queue.task_done()

    def close(self, timeout_seconds: float = 5.0) -> bool:
        """
        Deliver what is queued, then stop the worker thread.

        Idempotent. Returns True when the worker exited within the timeout.
        """
        if self._closed:
            return not self._worker.is_alive()
        self._closed = True
        try:
            self._queue.put(_STOP, timeout=max(0.1, timeout_seconds))
        except queue.Full:
            logger.warning("[EventBus] close(): queue still full, worker not signalled")
            return False
        self._worker.join(timeout=max(0.1, timeout_seconds))
        return not self._worker.is_alive()

    @property
    def closed(self) -> bool:
        return self._closed

    def pending_count(self) -> int:
        """Approximate number of events not yet delivered to subscribers."""
        return self._queue.qsize()

    def drain(self, timeout_seconds: float = 5.0) -> bool:
        """
        Block until the event queue is empty and all subscribers have run.

        Returns True if drained within *timeout_seconds*, False on timeout.
        Screenshot threads and other async work may still be in flight - use
        ScreenshotManager.wait_pending() after this when flushing artifacts.
        """
        deadline = time.time() + max(0.1, timeout_seconds)
        while time.time() < deadline:
            if self._queue.unfinished_tasks == 0 and self._queue.empty():
                time.sleep(0.15)  # Allow subscriber callbacks and background handlers to settle
                return True
            time.sleep(0.05)
        logger.warning(
            "[EventBus] drain() timed out after %.1fs (%d unfinished)",
            timeout_seconds,
            self._queue.unfinished_tasks,
        )
        return False
