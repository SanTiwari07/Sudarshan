import asyncio
import logging
from typing import Callable, Any, Dict, List

logger = logging.getLogger(__name__)

import queue
import threading

class RuntimeEventBus:
    """
    Lightweight Event Bus for the Sudarshan Sandbox.
    Allows decoupling of components (e.g., Frida monitoring and UI Explorer).
    Now uses a thread-safe Queue to isolate publishers from subscribers.
    """
    def __init__(self):
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._queue = queue.Queue()
        self._worker = threading.Thread(target=self._process_events, daemon=True)
        self._worker.start()

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback to receive events."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]):
        """Remove a callback from receiving events."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def publish(self, event: Dict[str, Any]):
        """
        Publish an event to all subscribers.
        Places the event in an unbounded queue to prevent blocking the caller.
        """
        self._queue.put(event)

    def _process_events(self):
        """Background worker that pulls events and notifies subscribers."""
        while True:
            event = self._queue.get()
            for callback in self._subscribers:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(f"[EventBus] Error notifying subscriber: {e}")
            self._queue.task_done()
