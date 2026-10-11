"""RuntimeEventBus delivery guarantees. Pure in-process, no mocks needed."""

from __future__ import annotations

import threading
import time

from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus


def test_failing_subscriber_does_not_affect_others():
    bus = RuntimeEventBus()
    got = []

    def bad(_e):
        raise RuntimeError("boom")

    bus.subscribe(bad)
    bus.subscribe(got.append)
    for i in range(5):
        bus.publish({"event_type": EventType.FRIDA_EVENT, "n": i})
    assert bus.drain(5.0)
    assert [e["n"] for e in got] == list(range(5))
    m = bus.metrics()
    assert m["subscriber_errors"] == 5 and m["delivered"] == 5 and m["published"] == 5
    assert bus.close()


def test_worker_error_does_not_wedge_drain():
    """Regression: task_done() was skipped on the worker's error path."""
    bus = RuntimeEventBus()
    bus._queue.put(object())          # not a dict: worker raises on .get()
    assert bus.drain(3.0) is True
    bus.publish({"event_type": "X"})
    assert bus.drain(3.0) is True
    bus.close()


def test_full_queue_drops_and_counts_instead_of_growing():
    release = threading.Event()
    bus = RuntimeEventBus(max_queue=2, publish_timeout=0.05)
    bus.subscribe(lambda _e: release.wait(5))
    results = [bus.publish({"event_type": "X", "i": i}) for i in range(6)]
    assert results.count(False) >= 3
    assert bus.metrics()["dropped"] == results.count(False)
    release.set()
    assert bus.drain(5.0)
    bus.close()


def test_subscriber_publishing_on_full_queue_does_not_deadlock():
    """EvidenceStore publishes EVIDENCE_CREATED from the worker thread."""
    bus = RuntimeEventBus(max_queue=1, publish_timeout=5.0)

    def echo(e):
        if e.get("event_type") != "ECHO":
            bus.publish({"event_type": "ECHO"})
            bus.publish({"event_type": "ECHO"})  # queue full: must not block

    bus.subscribe(echo)
    t0 = time.time()
    bus.publish({"event_type": "X"})
    assert bus.drain(5.0)
    assert time.time() - t0 < 3.0
    bus.close()


def test_close_stops_worker_and_rejects_later_events():
    bus = RuntimeEventBus()
    got = []
    bus.subscribe(got.append)
    bus.publish(RuntimeEvent(event_type="A"))
    assert bus.close(2.0) is True
    assert not bus._worker.is_alive()
    assert got and got[0]["event_type"] == "A"   # queued work delivered first
    assert bus.publish({"event_type": "B"}) is False
    assert bus.metrics()["rejected_after_close"] == 1
    assert bus.close() is True                   # idempotent


def test_typed_subscription_filters():
    bus = RuntimeEventBus()
    net = []
    bus.subscribe(net.append, EventType.NETWORK_EVENT)
    bus.publish({"event_type": EventType.FRIDA_EVENT})
    bus.publish({"event_type": EventType.NETWORK_EVENT})
    assert bus.drain(3.0)
    assert len(net) == 1
    bus.close()
