"""
SUDARSHAN - stage-level diagnostics for Frida runtime telemetry.

Why this exists
---------------
A dynamic run that ends with zero runtime events can mean any of seven
different things, and they are not interchangeable:

    FRIDA_ATTACH_FAILED             no session was ever established
    AGENT_INIT_FAILED               a session existed, but the agent did not
                                    load, or loaded without a working Java
                                    bridge
    HOOK_INSTALL_FAILED             the agent loaded and installed no hooks
    HOOKS_INSTALLED_NOT_EXERCISED   hooks were installed and the session stayed
                                    attached for the whole window, but nothing
                                    called them
    NO_TELEMETRY_OBSERVED           hooks were installed but the instrumentation
                                    was lost before the window ended (session
                                    detached, process died), so silence proves
                                    nothing
    EVENT_PROCESSING_FAILED         events arrived but some were lost on the
                                    host - a handler raised, the bus dropped
                                    them, or persistence failed
    RUNTIME_EVENTS_RECEIVED         events arrived and every one was processed

Before this module the controller tracked a handful of these facts as loose
attributes and had no record at all of two of them: whether the Frida session
detached during the run (there was no `detached` handler), and whether the
host-side message handler raised (frida-python prints the traceback to stderr
and the event is gone). Both failure modes produce a run that looks exactly
like a quiet sample.

Nothing here classifies the SAMPLE. The classification is about the
instrumentation pipeline, and it is never used as risk evidence - the risk
engine reads `dynamic_status`, which is unchanged by this module.

Thread-safety: every mutator takes the lock, because Frida delivers messages on
its own thread while the controller runs on another.
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

__all__ = [
    "TelemetryClassification",
    "TelemetryDiagnostics",
]

#: Error strings kept per kind. Bounded so a hook that throws on every call
#: cannot grow the result without limit.
_MAX_ERRORS_KEPT = 20


class TelemetryClassification(str, Enum):
    FRIDA_ATTACH_FAILED = "FRIDA_ATTACH_FAILED"
    AGENT_INIT_FAILED = "AGENT_INIT_FAILED"
    HOOK_INSTALL_FAILED = "HOOK_INSTALL_FAILED"
    HOOKS_INSTALLED_NOT_EXERCISED = "HOOKS_INSTALLED_NOT_EXERCISED"
    NO_TELEMETRY_OBSERVED = "NO_TELEMETRY_OBSERVED"
    EVENT_PROCESSING_FAILED = "EVENT_PROCESSING_FAILED"
    RUNTIME_EVENTS_RECEIVED = "RUNTIME_EVENTS_RECEIVED"


_EXPLANATIONS: Dict[TelemetryClassification, str] = {
    TelemetryClassification.FRIDA_ATTACH_FAILED:
        "No Frida session was established with the target process.",
    TelemetryClassification.AGENT_INIT_FAILED:
        "A Frida session existed but the instrumentation agent did not "
        "initialise (script load failed, no load canary, or no Java bridge).",
    TelemetryClassification.HOOK_INSTALL_FAILED:
        "The agent loaded but reported zero installed hooks.",
    TelemetryClassification.HOOKS_INSTALLED_NOT_EXERCISED:
        "Hooks were installed and the session stayed attached for the whole "
        "analysis window, but no hooked API was called.",
    TelemetryClassification.NO_TELEMETRY_OBSERVED:
        "Hooks were installed but instrumentation was lost before the window "
        "ended, and no runtime event was received. The silence is not "
        "evidence of benign behaviour.",
    TelemetryClassification.EVENT_PROCESSING_FAILED:
        "Runtime events were received but some were lost on the host "
        "(handler exception, event-bus drop, or persistence failure).",
    TelemetryClassification.RUNTIME_EVENTS_RECEIVED:
        "Runtime events were received and processed.",
}


def _now() -> float:
    return time.time()


class TelemetryDiagnostics:
    """Thread-safe recorder for one dynamic-analysis session's telemetry."""

    def __init__(self, analysis_id: str = "", package_name: str = "") -> None:
        self.analysis_id = analysis_id
        self.package_name = package_name
        self._lock = threading.Lock()

        self.attach_attempted = False
        self.attached = False
        self.attach_error: str = ""
        self.attached_pid: Optional[int] = None
        self.attached_at: Optional[float] = None

        self.agent_load_attempted = False
        self.agent_loaded = False          # script.load() returned
        self.agent_load_error: str = ""
        self.canary_received = False
        self.java_bridge_failed = False
        self.agent_errors: List[str] = []
        #: Distinct `diag` milestones the agent reported, in arrival order
        #: (java_bridge_ready, deoptimizeEverything_skipped_api34_plus, ...).
        #: Reports state these instead of assuming them.
        self.agent_diagnostics: List[str] = []

        self.hooks_installed = 0
        self.hook_errors = 0
        self.hook_error_samples: List[str] = []

        self.messages_by_type: Counter = Counter()
        self.malformed_messages = 0
        self.script_errors: List[str] = []
        self.handler_exceptions = 0
        self.handler_errors: List[str] = []

        self.events_received = 0
        self.events_accepted = 0
        self.events_published = 0
        self.events_filtered = 0
        self.first_event_at: Optional[float] = None
        self.last_event_at: Optional[float] = None
        self.hook_fires: Counter = Counter()

        self.detached = False
        self.detach_reason: str = ""
        self.detach_crash: Optional[Dict[str, Any]] = None
        self.detached_at: Optional[float] = None
        self.window_ended_at: Optional[float] = None
        self.attached_at_window_end: Optional[bool] = None

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _keep(bucket: List[str], text: str) -> None:
        if len(bucket) < _MAX_ERRORS_KEPT:
            bucket.append(str(text)[:300])

    # ── attach / agent lifecycle ─────────────────────────────────────────────

    def record_attach_attempt(self) -> None:
        with self._lock:
            self.attach_attempted = True

    def record_attach(self, pid: Optional[int] = None) -> None:
        with self._lock:
            self.attach_attempted = True
            self.attached = True
            self.attached_pid = pid
            self.attached_at = self.attached_at or _now()
            # A re-attach after a detach is a fresh session.
            self.detached = False
            self.detach_reason = ""
            self.detach_crash = None
            self.detached_at = None

    def record_attach_failed(self, error: str) -> None:
        with self._lock:
            self.attach_attempted = True
            self.attach_error = str(error)[:300]

    def record_agent_load_attempt(self) -> None:
        with self._lock:
            self.agent_load_attempted = True

    def record_agent_loaded(self) -> None:
        with self._lock:
            self.agent_load_attempted = True
            self.agent_loaded = True
            self.agent_load_error = ""

    def record_agent_load_failed(self, error: str) -> None:
        with self._lock:
            self.agent_load_attempted = True
            self.agent_load_error = str(error)[:300]

    def record_canary(self) -> None:
        with self._lock:
            self.canary_received = True

    def record_agent_error(self, description: str, *, java_bridge_failed: bool = False) -> None:
        with self._lock:
            if java_bridge_failed:
                self.java_bridge_failed = True
            self._keep(self.agent_errors, description)

    def record_diag(self, name: str) -> None:
        with self._lock:
            name = str(name or "")[:80]
            if name and name not in self.agent_diagnostics and len(self.agent_diagnostics) < 40:
                self.agent_diagnostics.append(name)

    def record_hook_installed(self, total: Optional[int] = None) -> None:
        with self._lock:
            if isinstance(total, int) and total >= 0:
                self.hooks_installed = max(self.hooks_installed, total)
            else:
                self.hooks_installed += 1

    def record_hook_error(self, hook: str, error: str) -> None:
        with self._lock:
            self.hook_errors += 1
            self._keep(self.hook_error_samples, f"{hook}: {error}")

    def record_detached(self, reason: Any, crash: Any = None) -> None:
        with self._lock:
            self.detached = True
            self.detach_reason = str(reason or "unknown")
            self.detached_at = _now()
            if crash is not None:
                summary = getattr(crash, "summary", None)
                self.detach_crash = {
                    "summary": str(summary or crash)[:300],
                    "process_name": str(getattr(crash, "process_name", "") or ""),
                    "pid": getattr(crash, "pid", None),
                }

    def mark_window_end(self) -> None:
        """Call when the observation window closes, BEFORE our own teardown."""
        with self._lock:
            if self.window_ended_at is None:
                self.window_ended_at = _now()
                self.attached_at_window_end = bool(self.attached and not self.detached)

    # ── messages ─────────────────────────────────────────────────────────────

    def record_message(self, message: Any) -> Optional[str]:
        """
        Count a raw Frida message. Returns the payload type for `send`
        messages, None for anything else. Never raises.
        """
        with self._lock:
            if not isinstance(message, Mapping):
                self.malformed_messages += 1
                return None
            mtype = message.get("type")
            if mtype == "error":
                self.messages_by_type["frida_error"] += 1
                self._keep(self.script_errors, message.get("description") or "script error")
                return None
            if mtype != "send":
                self.messages_by_type[f"other:{mtype}"] += 1
                return None
            payload = message.get("payload")
            if not isinstance(payload, Mapping):
                self.malformed_messages += 1
                return None
            ptype = str(payload.get("type") or "untyped")
            self.messages_by_type[ptype] += 1
            if ptype == "event":
                self.events_received += 1
                now = _now()
                self.first_event_at = self.first_event_at or now
                self.last_event_at = now
            return ptype

    def record_event_accepted(self, hook: str = "") -> None:
        with self._lock:
            self.events_accepted += 1
            if hook:
                self.hook_fires[hook] += 1

    def record_event_filtered(self) -> None:
        with self._lock:
            self.events_filtered += 1

    def record_event_published(self) -> None:
        with self._lock:
            self.events_published += 1

    def record_handler_exception(self, exc: BaseException) -> None:
        with self._lock:
            self.handler_exceptions += 1
            self._keep(self.handler_errors, f"{type(exc).__name__}: {exc}")

    # ── classification ───────────────────────────────────────────────────────

    def _processing_losses(
        self,
        bus_metrics: Optional[Mapping[str, Any]],
        store_metrics: Optional[Mapping[str, Any]],
    ) -> Dict[str, int]:
        losses = {
            "handler_exceptions": self.handler_exceptions,
            # Received, not deliberately filtered, and never reached the bus.
            "unpublished_events": max(
                0, self.events_received - self.events_filtered - self.events_published
            ),
        }
        if bus_metrics:
            losses["bus_dropped"] = int(bus_metrics.get("dropped", 0) or 0)
            losses["bus_subscriber_errors"] = int(bus_metrics.get("subscriber_errors", 0) or 0)
        if store_metrics:
            losses["evidence_build_failures"] = int(store_metrics.get("failed", 0) or 0)
            losses["evidence_persist_failures"] = int(store_metrics.get("persist_failures", 0) or 0)
        return losses

    def classify(
        self,
        bus_metrics: Optional[Mapping[str, Any]] = None,
        store_metrics: Optional[Mapping[str, Any]] = None,
    ) -> TelemetryClassification:
        with self._lock:
            return self._classify_locked(bus_metrics, store_metrics)

    def _classify_locked(self, bus_metrics, store_metrics) -> TelemetryClassification:
        C = TelemetryClassification
        if self.events_received > 0:
            # Events are the strongest fact: they prove attach, load and hooks.
            losses = self._processing_losses(bus_metrics, store_metrics)
            if any(v > 0 for v in losses.values()):
                return C.EVENT_PROCESSING_FAILED
            return C.RUNTIME_EVENTS_RECEIVED
        if not self.attached:
            return C.FRIDA_ATTACH_FAILED
        if self.agent_load_error or not self.canary_received or self.java_bridge_failed:
            return C.AGENT_INIT_FAILED
        if self.hooks_installed <= 0:
            return C.HOOK_INSTALL_FAILED
        if self.handler_exceptions > 0:
            # Something arrived and the handler threw before it could be
            # counted as an event; we cannot say nothing was observed.
            return C.EVENT_PROCESSING_FAILED
        if self.attached_at_window_end is False or (
            self.attached_at_window_end is None and self.detached
        ):
            return C.NO_TELEMETRY_OBSERVED
        if self.attached_at_window_end is None:
            # The window never closed normally (the run aborted), so we cannot
            # claim the hooks were live for it.
            return C.NO_TELEMETRY_OBSERVED
        return C.HOOKS_INSTALLED_NOT_EXERCISED

    def to_dict(
        self,
        bus_metrics: Optional[Mapping[str, Any]] = None,
        store_metrics: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            cls = self._classify_locked(bus_metrics, store_metrics)
            return {
                "schema_version": 1,
                "analysis_id": self.analysis_id,
                "package_name": self.package_name,
                "classification": cls.value,
                "explanation": _EXPLANATIONS[cls],
                "attach": {
                    "attempted": self.attach_attempted,
                    "attached": self.attached,
                    "pid": self.attached_pid,
                    "error": self.attach_error,
                    "attached_at": self.attached_at,
                },
                "agent": {
                    "load_attempted": self.agent_load_attempted,
                    "loaded": self.agent_loaded,
                    "load_error": self.agent_load_error,
                    "canary_received": self.canary_received,
                    "java_bridge_failed": self.java_bridge_failed,
                    "errors": list(self.agent_errors),
                    "script_errors": list(self.script_errors),
                    "diagnostics": list(self.agent_diagnostics),
                },
                "hooks": {
                    "installed": self.hooks_installed,
                    "errors": self.hook_errors,
                    "error_samples": list(self.hook_error_samples),
                    "exercised": len(self.hook_fires),
                    "fire_counts": dict(self.hook_fires),
                },
                "messages": {
                    "by_type": dict(self.messages_by_type),
                    "malformed": self.malformed_messages,
                    "handler_exceptions": self.handler_exceptions,
                    "handler_errors": list(self.handler_errors),
                },
                "events": {
                    "received": self.events_received,
                    "accepted": self.events_accepted,
                    "filtered": self.events_filtered,
                    "published": self.events_published,
                    "first_at": self.first_event_at,
                    "last_at": self.last_event_at,
                },
                "session": {
                    "detached": self.detached,
                    "detach_reason": self.detach_reason,
                    "detach_crash": self.detach_crash,
                    "detached_at": self.detached_at,
                    "window_ended_at": self.window_ended_at,
                    "attached_at_window_end": self.attached_at_window_end,
                },
                "processing_losses": self._processing_losses(bus_metrics, store_metrics),
                "event_bus": dict(bus_metrics or {}),
                "evidence_store": dict(store_metrics or {}),
            }
