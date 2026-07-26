"""
SUDARSHAN — Structured Evidence Store
======================================
Subscribes to the RuntimeEventBus and builds rich, structured
EvidenceRecord objects from every Frida hook event.

Each record captures:
  - timestamp, API, class, method, args, return value
  - thread_id, stack_trace (up to 6 frames)
  - severity (LOW / MED / HIGH / CRITICAL)
  - screenshot_ref (linked by ScreenshotManager after capture)
  - runtime_context (package, pid, analysis stage)

Design rules:
  - Pure subscriber — no side effects outside this module
  - BFCI scoring logic is never touched
  - flush() is idempotent and thread-safe
  - Every public method is unit-testable with mock events

Usage::

    bus = RuntimeEventBus()
    store = EvidenceStore(event_bus=bus, package_name="com.example")
    ...  # analysis runs
    store.flush(Path("output/evidence.json"))
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.engines.event_bus import RuntimeEventBus

import logging
logger = logging.getLogger(__name__)

# ─── Severity ordering for sorting / filtering ─────────────────────────────────

SEVERITY_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2, "CRITICAL": 3}

# ─── Data model ───────────────────────────────────────────────────────────────


@dataclass
class EvidenceRecord:
    """
    A single structured evidence record produced from one Frida hook event.

    All fields map directly to the enriched payload emitted by banking_trojan.js v2.
    Fields that are unavailable in older hook payloads default gracefully.
    """

    id:              str           # UUID4 — unique per record
    timestamp:       str           # ISO-8601 UTC
    timestamp_ms:    int           # Unix milliseconds (from Frida)
    category:        str           # accessibility / sms / overlay / ...
    severity:        str           # LOW / MED / HIGH / CRITICAL
    api:             str           # e.g. "AccessibilityService.onAccessibilityEvent"
    class_name:      str           # Derived from hook name (e.g. "AccessibilityService")
    method:          str           # Derived from hook name (e.g. "onAccessibilityEvent")
    args:            List[str]     # Sanitized argument list from hook
    return_value:    str           # Return value (if captured by hook)
    thread_id:       int           # OS thread ID from Frida
    stack_trace:     List[str]     # Up to 6 Java stack frames
    description:     str           # Human-readable hook description
    screenshot_ref:  str           # Populated by ScreenshotManager.attach()
    runtime_context: Dict[str, Any]  # package, analysis_stage, pid, etc.

    # Extra fields present on some hooks
    extra:           Dict[str, Any] = field(default_factory=dict)


def _parse_hook_name(hook: str) -> tuple[str, str]:
    """Split 'ClassName.methodName' into (class_name, method)."""
    if "." in hook:
        parts = hook.rsplit(".", 1)
        return parts[0], parts[1]
    return hook, ""


def _build_record(event: Dict[str, Any], runtime_context: Dict[str, Any]) -> EvidenceRecord:
    """Construct an EvidenceRecord from a raw Frida event dict."""
    data       = event.get("data", {})
    hook       = data.get("hook", "unknown")
    class_name, method = _parse_hook_name(hook)

    # Timestamp: prefer Frida's ms timestamp, fall back to now
    ts_ms = event.get("timestamp", 0) or 0
    if ts_ms:
        dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
        ts_ms = int(dt.timestamp() * 1000)
    iso_ts = dt.isoformat()

    # Reserved keys that have their own top-level fields
    _reserved = {"hook", "severity", "args", "return_value", "description"}

    return EvidenceRecord(
        id              = str(uuid.uuid4()),
        timestamp       = iso_ts,
        timestamp_ms    = ts_ms,
        category        = event.get("category", "unknown"),
        severity        = data.get("severity", event.get("severity", "MED")).upper(),
        api             = hook,
        class_name      = class_name,
        method          = method,
        args            = data.get("args", []),
        return_value    = str(data.get("return_value", "")),
        thread_id       = event.get("thread_id", 0),
        stack_trace     = event.get("stack_trace", []),
        description     = data.get("description", ""),
        screenshot_ref  = "",   # filled in later by ScreenshotManager
        runtime_context = runtime_context.copy(),
        extra           = {k: v for k, v in data.items() if k not in _reserved},
    )


# ─── Evidence Store ────────────────────────────────────────────────────────────


class EvidenceStore:
    """
    Collects structured EvidenceRecords from the RuntimeEventBus.

    Thread-safe: can be called from Frida's background thread and the
    UIExplorer's asyncio thread simultaneously.

    Example::

        store = EvidenceStore(event_bus=bus, package_name="com.example")
        # ... analysis runs ...
        store.flush(Path("output/evidence.json"))
        critical = store.get_by_severity("CRITICAL")
    """

    def __init__(
        self,
        event_bus: Optional[RuntimeEventBus] = None,
        package_name: str = "",
        analysis_stage: str = "single",
    ):
        self._records: List[EvidenceRecord] = []
        self._lock    = threading.Lock()
        self._runtime_context = {
            "package_name":   package_name,
            "analysis_stage": analysis_stage,
            "pid":            0,   # updated externally if needed
        }

        if event_bus is not None:
            event_bus.subscribe(self._on_event)
            logger.debug("[EvidenceStore] Subscribed to RuntimeEventBus")

    # ── EventBus callback ──────────────────────────────────────────────────────

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Called by RuntimeEventBus for every published Frida event."""
        try:
            record = _build_record(event, self._runtime_context)
            with self._lock:
                self._records.append(record)

            if record.severity in ("HIGH", "CRITICAL"):
                logger.info(
                    f"[EvidenceStore] [{record.severity}] {record.api} "
                    f"— {record.description[:80]}"
                )
        except Exception as exc:
            logger.error(f"[EvidenceStore] Failed to build record: {exc}")

    # ── ScreenshotManager integration ──────────────────────────────────────────

    def attach_screenshot(self, record_id: str, screenshot_ref: str) -> bool:
        """
        Link a screenshot path to an existing evidence record by ID.
        Called by ScreenshotManager after capturing a screenshot triggered
        by a CRITICAL event.

        Returns True if the record was found and updated.
        """
        with self._lock:
            for rec in self._records:
                if rec.id == record_id:
                    rec.screenshot_ref = screenshot_ref
                    return True
        return False

    def attach_screenshot_to_latest(self, screenshot_ref: str) -> Optional[str]:
        """
        Attach a screenshot to the most recently received evidence record.
        Returns the record ID that was updated, or None.
        """
        with self._lock:
            if self._records:
                self._records[-1].screenshot_ref = screenshot_ref
                return self._records[-1].id
        return None

    # ── Context updates ────────────────────────────────────────────────────────

    def set_stage(self, stage: str) -> None:
        """Update the analysis stage label applied to future records."""
        self._runtime_context["analysis_stage"] = stage

    def set_pid(self, pid: int) -> None:
        """Store the target process PID in the runtime context."""
        self._runtime_context["pid"] = pid

    # ── Querying ───────────────────────────────────────────────────────────────

    def get_all(self) -> List[EvidenceRecord]:
        """Return a snapshot of all collected records (thread-safe copy)."""
        with self._lock:
            return list(self._records)

    def get_by_severity(self, severity: str) -> List[EvidenceRecord]:
        """Return all records at or above the given severity level."""
        threshold = SEVERITY_ORDER.get(severity.upper(), 0)
        with self._lock:
            return [
                r for r in self._records
                if SEVERITY_ORDER.get(r.severity, 0) >= threshold
            ]

    def get_by_category(self, category: str) -> List[EvidenceRecord]:
        """Return all records for a specific Frida event category."""
        with self._lock:
            return [r for r in self._records if r.category == category]

    def count(self) -> int:
        with self._lock:
            return len(self._records)

    def summary(self) -> Dict[str, Any]:
        """Return a quick summary suitable for logging or the final report."""
        with self._lock:
            records = list(self._records)

        by_severity: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        for r in records:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
            by_category[r.category] = by_category.get(r.category, 0) + 1

        return {
            "total":       len(records),
            "by_severity": by_severity,
            "by_category": by_category,
            "critical":    by_severity.get("CRITICAL", 0),
            "high":        by_severity.get("HIGH", 0),
        }

    # ── Persistence ────────────────────────────────────────────────────────────

    def flush(self, output_path: Path) -> int:
        """
        Write all collected evidence records to a JSON file.

        The output file contains:
        - ``summary``: aggregated counts by severity and category
        - ``records``: full list of EvidenceRecord objects

        Returns the number of records written.
        Thread-safe and idempotent (can be called multiple times).
        """
        with self._lock:
            records_snapshot = list(self._records)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "package_name": self._runtime_context.get("package_name", ""),
            "summary":      self.summary(),
            "records":      [asdict(r) for r in records_snapshot],
        }

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(
                f"[EvidenceStore] Flushed {len(records_snapshot)} records → {output_path}"
            )
        except Exception as exc:
            logger.error(f"[EvidenceStore] Failed to write {output_path}: {exc}")

        return len(records_snapshot)
