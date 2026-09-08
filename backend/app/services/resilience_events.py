"""In-process pub/sub hub for investigation-resilience events.

The resilience controls are things an analyst does *to a run that is already
happening* - restore a checkpoint, warp the clock, seed a persona. Polling for
their effect defeats the point: the value is seeing the sandbox react.

This is a deliberately small hub rather than a message broker. Sudarshan's
backend is a single process fronting one analysis engine, so the fan-out is one
publisher to a handful of analyst browsers. A broker would add an operational
dependency to deliver five event types.

Delivery is best-effort and bounded. A browser tab that stops reading must not
be able to grow the backend's memory or block the analysis thread, so each
subscriber has a fixed-size queue and slow subscribers lose their oldest events
rather than applying backpressure to the sandbox.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Event names, matching the resilience specification. Constants rather than
# literals so a typo in a publisher is a NameError, not a silently undelivered
# event.
EVT_CHECKPOINT_SAVED = "CHECKPOINT_SAVED"
EVT_SESSION_RECOVERED = "SESSION_RECOVERED"
EVT_TIME_WARP_APPLIED = "TIME_WARP_APPLIED"
EVT_PERSONA_SEEDED = "PERSONA_SEEDED"
EVT_EXECUTION_ASSERTION_UPDATED = "EXECUTION_ASSERTION_UPDATED"
EVT_ANTI_EVASION_STEP = "ANTI_EVASION_STEP"
EVT_ANTI_EVASION_COMPLETE = "ANTI_EVASION_COMPLETE"

KNOWN_EVENTS = frozenset(
    {
        EVT_CHECKPOINT_SAVED,
        EVT_SESSION_RECOVERED,
        EVT_TIME_WARP_APPLIED,
        EVT_PERSONA_SEEDED,
        EVT_EXECUTION_ASSERTION_UPDATED,
        EVT_ANTI_EVASION_STEP,
        EVT_ANTI_EVASION_COMPLETE,
    }
)

#: Per-subscriber buffer. Ten events is several seconds of the busiest
#: realistic stream; beyond that the client is not really connected.
_QUEUE_SIZE = 32

#: Replay buffer so a browser that connects mid-run, or reconnects after a
#: network blip, still sees what it missed instead of an empty panel.
_HISTORY_SIZE = 50


class ResilienceEventHub:
    """Fan-out of resilience events to connected WebSocket clients."""

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._history: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    def history(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if session_id is None:
            return list(self._history)
        return [e for e in self._history if e.get("session_id") == session_id]

    async def publish(
        self,
        event_type: str,
        session_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Broadcast one event. Never raises, never blocks on a slow client."""
        event = {
            "event": event_type,
            "session_id": session_id,
            "timestamp": time.time(),
            "payload": payload or {},
        }
        if event_type not in KNOWN_EVENTS:
            logger.warning("[Resilience] publishing unknown event type %r", event_type)

        self._history.append(event)
        if len(self._history) > _HISTORY_SIZE:
            del self._history[: len(self._history) - _HISTORY_SIZE]

        async with self._lock:
            targets = list(self._subscribers)

        for queue in targets:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop this subscriber's oldest event and retry once. A client
                # that cannot keep up gets a gap in its stream, which is the
                # correct trade against stalling the publisher.
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    logger.debug("[Resilience] dropping event for a stalled subscriber")
        return event

    def publish_threadsafe(
        self,
        loop: Optional[asyncio.AbstractEventLoop],
        event_type: str,
        session_id: str = "",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Publish from a non-async context (the Frida callback thread).

        The analysis engine runs hooks on its own threads; calling the async
        publish directly from one would either raise or silently do nothing.
        """
        if loop is None or loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(
            self.publish(event_type, session_id, payload), loop
        )

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


#: Process-wide hub. One backend process fronts one analysis engine.
hub = ResilienceEventHub()
