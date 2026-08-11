"""
SUDARSHAN - Structured Evidence Store
======================================
Subscribes to the RuntimeEventBus and builds rich, structured
EvidenceRecord objects from every Frida hook event.

Each record captures:
  - finding_id   : sequential EVID-NNN identifier for report cross-referencing
  - timestamp_ms : Unix milliseconds (from Frida) - used by the report renderer
  - api, class_name, method, args, return_value
  - severity (LOW / MED / HIGH / CRITICAL)
  - mitre_technique_id / mitre_technique_name / mitre_tactic
    resolved at record-build time from the HOOK_TO_MITRE lookup table
  - screenshot_ref (linked by ScreenshotManager after capture)
  - runtime_context (package, pid, analysis stage)
  - human_description : plain-English event summary for the report timeline

Design rules:
  - Pure subscriber - no side effects outside this module
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
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.event_bus import RuntimeEventBus

import logging
logger = logging.getLogger(__name__)

# ─── MITRE lookup (mirrors mitre_mapper.py - duplicated here so evidence_store
# ─── has zero runtime dependency on mitre_mapper and is fully self-contained) ──

HOOK_TO_MITRE: dict = {
    "AccessibilityService.onAccessibilityEvent": ("T1417.001", "Input Capture: GUI"),
    "AccessibilityNodeInfo.performAction":        ("T1417.002", "Input Injection"),
    "SmsManager.sendTextMessage":                 ("T1582",     "SMS Control"),
    "ContentResolver.query":                      ("T1636.004", "Protected Data: SMS"),
    "WindowManager.addView":                      ("T1416",     "Overlay Attack"),
    "DexClassLoader.<init>":                      ("T1407",     "Download New Code at Runtime"),
    "DevicePolicyManager.isAdminActive":          ("T1626.001", "Device Admin Abuse"),
    "DevicePolicyManager.lockNow":                ("T1626.001", "Device Admin Abuse"),
    "URL.openConnection":                         ("T1437.001", "Web Protocols C2"),
    "OkHttp.RealCall.execute":                    ("T1437.001", "Web Protocols C2"),
    "KeyStore.getInstance":                       ("T1634",     "Credentials from Password Store"),
    "SystemProperties.get":                       ("T1497.001", "Virtualization/Sandbox Evasion"),
    "Debug.isDebuggerConnected":                  ("T1497.001", "Virtualization/Sandbox Evasion"),
    "Build.getSerial":                            ("T1497.001", "Virtualization/Sandbox Evasion"),
    "SharedPreferences.getString":                ("T1409",     "Stored Application Data"),
    "SharedPreferences.Editor.putString":         ("T1409",     "Stored Application Data"),
    "ClipboardManager.getText":                   ("T1414",     "Clipboard Data"),
    "AudioRecord.startRecording":                 ("T1429",     "Microphone/Camera Abuse"),
    "Camera.open":                                ("T1429",     "Microphone/Camera Abuse"),
    "TelephonyManager.getDeviceId":               ("T1420",     "File and Directory Discovery"),
    "TelephonyManager.getSubscriberId":           ("T1422",     "System Network Configuration Discovery"),
    "ContactsContract.Contacts":                  ("T1636.003", "Protected Data: Contacts"),
}

# ─── Severity ordering for sorting / filtering ──────────────────────────────────

SEVERITY_ORDER = {"LOW": 0, "MED": 1, "HIGH": 2, "CRITICAL": 3}

# ─── Data model ───────────────────────────────────────────────────────────────


@dataclass
class EvidenceRecord:
    """
    A single structured evidence record produced from one Frida hook event.

    All fields map directly to the enriched payload emitted by banking_trojan.js v2.
    Fields that are unavailable in older hook payloads default gracefully.

    Report-renderer contract
    ------------------------
    The following fields are consumed by report_generator.py's dynamic timeline:

      finding_id - EVID-NNN cross-reference label
      timestamp_ms - Unix ms integer (used for display timestamp)
      api - Hook name shown in timeline header
      description - Human-readable event description
      human_description - Alias for description (renderer checks both)
      severity - LOW / MED / HIGH / CRITICAL
      mitre_technique_id - e.g. "T1417.001" (used for MITRE column)
      screenshot_ref - relative path to linked screenshot PNG
    """

    id:                   str           # UUID4 - unique per record
    finding_id:           str           # EVID-NNN sequential cross-reference
    timestamp:            str           # ISO-8601 UTC
    timestamp_ms:         int           # Unix milliseconds (from Frida) - used by renderer
    category:             str           # accessibility / sms / overlay / ...
    severity:             str           # LOW / MED / HIGH / CRITICAL
    api:                  str           # e.g. "AccessibilityService.onAccessibilityEvent"
    class_name:           str           # Derived from hook name
    method:               str           # Derived from hook name
    args:                 list          # Sanitized argument list from hook
    return_value:         str           # Return value (if captured by hook)
    thread_id:            int           # OS thread ID from Frida
    stack_trace:          list          # Up to 6 Java stack frames
    description:          str           # Human-readable hook description
    human_description:    str           # Alias for description - explicit for renderer
    mitre_technique_id:   str           # e.g. "T1417.001" (empty string if unmapped)
    mitre_technique_name: str           # e.g. "Input Capture: GUI"
    screenshot_ref:       str           # Populated by ScreenshotManager.attach()
    screenshot_id:        str           # SCR-NNN cross-reference (set by ScreenshotManager)
    runtime_context:      dict          # package, analysis_stage, pid, etc.

    # Extra fields present on some hooks
    extra:                dict = field(default_factory=dict)


def _parse_hook_name(hook: str) -> tuple:
    """Split 'ClassName.methodName' into (class_name, method)."""
    if "." in hook:
        parts = hook.rsplit(".", 1)
        return parts[0], parts[1]
    return hook, ""


def _resolve_mitre(api: str) -> tuple:
    """
    Resolve a hook API name to a (technique_id, technique_name) pair.
    Returns empty strings if the hook is not in the lookup table.
    Falls back to partial matching on class name prefix.
    """
    # Exact match
    if api in HOOK_TO_MITRE:
        return HOOK_TO_MITRE[api]
    # Prefix match on class name (e.g. 'AccessibilityService.someOtherMethod')
    for key, val in HOOK_TO_MITRE.items():
        klass = key.split(".")[0] if "." in key else key
        if api.startswith(klass + "."):
            return val
    return ("", "")


def _build_record(
    event: Dict[str, Any],
    runtime_context: Dict[str, Any],
    finding_id: str,
) -> "EvidenceRecord":
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

    # MITRE resolution
    mitre_id, mitre_name = _resolve_mitre(hook)

    # Human description: prefer hook-provided, else synthesize from API name
    raw_desc = data.get("description", "")
    human_desc = raw_desc or f"{hook} called (category: {event.get('category', 'unknown')})"

    # Reserved keys that have their own top-level fields
    _reserved = {"hook", "severity", "args", "return_value", "description"}

    return EvidenceRecord(
        id                   = str(uuid.uuid4()),
        finding_id           = finding_id,
        timestamp            = iso_ts,
        timestamp_ms         = ts_ms,
        category             = event.get("category", "unknown"),
        severity             = data.get("severity", event.get("severity", "MED")).upper(),
        api                  = hook,
        class_name           = class_name,
        method               = method,
        args                 = data.get("args", []),
        return_value         = str(data.get("return_value", "")),
        thread_id            = event.get("thread_id", 0),
        stack_trace          = event.get("stack_trace", []),
        description          = raw_desc,
        human_description    = human_desc,
        mitre_technique_id   = mitre_id,
        mitre_technique_name = mitre_name,
        screenshot_ref       = "",   # filled in later by ScreenshotManager
        screenshot_id        = "",   # filled in later by ScreenshotManager
        runtime_context      = runtime_context.copy(),
        extra                = {k: v for k, v in data.items() if k not in _reserved},
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
        case_id: str = "",
    ):
        self._records: List[EvidenceRecord] = []
        self._lock    = threading.Lock()
        self._evid_counter = 0          # drives EVID-NNN sequence
        self._runtime_context = {
            "package_name":   package_name,
            "case_id":        case_id,
            "sha256":         case_id,
            "analysis_stage": analysis_stage,
            "pid":            0,   # updated externally if needed
        }

        self.event_bus = event_bus
        if event_bus is not None:
            event_bus.subscribe(self._on_event)
            logger.debug("[EvidenceStore] Subscribed to RuntimeEventBus")

    def _next_evid(self) -> str:
        """Return the next sequential finding ID, e.g. EVID-001."""
        self._evid_counter += 1
        return f"EVID-{self._evid_counter:03d}"

    # ── EventBus callback ──────────────────────────────────────────────────────

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Called by RuntimeEventBus for published events."""
        etype = event.get("event_type", event.get("type", ""))
        if etype == "EVIDENCE_CREATED":
            return  # Prevent recursive loop

        try:
            with self._lock:
                finding_id = self._next_evid()

            payload = event.get("payload", event.get("data", {}))
            if etype == "SCREENSHOT_CAPTURED":
                ts_ms = int(event.get("timestamp", time.time()) * 1000)
                record = EvidenceRecord(
                    id=str(uuid.uuid4()),
                    finding_id=finding_id,
                    timestamp=datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat(),
                    timestamp_ms=ts_ms,
                    category="SCREENSHOT",
                    severity="INFO",
                    api="ScreenshotManager.capture",
                    class_name="ScreenshotManager",
                    method="capture",
                    args=[],
                    return_value=str(payload.get("filename", "")),
                    thread_id=0,
                    stack_trace=[],
                    description=f"Screenshot captured ({payload.get('label', 'ui')})",
                    human_description=f"Screenshot captured: {payload.get('filename', '')}",
                    mitre_technique_id="",
                    mitre_technique_name="",
                    screenshot_ref=str(payload.get("filename", "")),
                    screenshot_id=str(payload.get("screenshot_id", "")),
                    runtime_context=self._runtime_context.copy(),
                    extra=payload if isinstance(payload, dict) else {},
                )
            elif etype == "NETWORK_EVENT":
                ts_ms = int(event.get("timestamp", time.time()) * 1000)
                url = payload.get("url", "network_traffic")
                record = EvidenceRecord(
                    id=str(uuid.uuid4()),
                    finding_id=finding_id,
                    timestamp=datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat(),
                    timestamp_ms=ts_ms,
                    category="NETWORK",
                    severity=event.get("severity", "MED"),
                    api="NetworkCapture",
                    class_name="NetworkCapture",
                    method="request",
                    args=[url],
                    return_value=str(payload.get("status", "")),
                    thread_id=0,
                    stack_trace=[],
                    description=f"Network request to {url}",
                    human_description=f"Network request: {url}",
                    mitre_technique_id="T1437.001",
                    mitre_technique_name="Web Protocols C2",
                    screenshot_ref="",
                    screenshot_id="",
                    runtime_context=self._runtime_context.copy(),
                    extra=payload if isinstance(payload, dict) else {},
                )
            elif etype == "THREAT_DETECTED":
                ts_ms = int(event.get("timestamp", time.time()) * 1000)
                indicator = payload.get("indicator", "IOC")
                record = EvidenceRecord(
                    id=str(uuid.uuid4()),
                    finding_id=finding_id,
                    timestamp=datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc).isoformat(),
                    timestamp_ms=ts_ms,
                    category="THREAT_INTEL",
                    severity=payload.get("severity", "HIGH"),
                    api="ThreatCorrelator",
                    class_name="ThreatCorrelator",
                    method="correlate",
                    args=[indicator],
                    return_value=str(payload.get("reputation", "")),
                    thread_id=0,
                    stack_trace=[],
                    description=f"Threat detected for {indicator}",
                    human_description=f"Threat correlate match: {indicator} ({payload.get('source', '')})",
                    mitre_technique_id="",
                    mitre_technique_name="",
                    screenshot_ref="",
                    screenshot_id="",
                    runtime_context=self._runtime_context.copy(),
                    extra=payload if isinstance(payload, dict) else {},
                )
            else:
                record = _build_record(event, self._runtime_context, finding_id)

            with self._lock:
                self._records.append(record)

            # Same-bus subscribers (e.g. ScreenshotManager) can read causal targets.
            if etype not in ("SCREENSHOT_CAPTURED", "EVIDENCE_CREATED"):
                event["evidence_record_id"] = record.id
                event["evidence_finding_id"] = record.finding_id

            if self.event_bus:
                from sudarshan_core.engines.event_bus import EventType, RuntimeEvent
                self.event_bus.publish(RuntimeEvent(
                    event_type=EventType.EVIDENCE_CREATED,
                    timestamp=record.timestamp_ms / 1000.0,
                    payload={"evidence_id": record.finding_id, "id": record.id, "category": record.category, "severity": record.severity}
                ))

            if record.severity in ("HIGH", "CRITICAL"):
                logger.info(
                    f"[EvidenceStore] [{record.severity}] [{record.finding_id}] {record.api} "
                    f" - {record.description[:80]}"
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

    def set_screenshot_id(self, record_id: str, screenshot_id: str) -> bool:
        """
        Set the SCR-NNN screenshot_id on an existing evidence record by ID.
        """
        with self._lock:
            for rec in self._records:
                if rec.id == record_id:
                    rec.screenshot_id = screenshot_id
                    return True
        return False

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
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            logger.info(
                f"[EvidenceStore] Flushed {len(records_snapshot)} records → {output_path}"
            )
        except Exception as exc:
            logger.error(f"[EvidenceStore] Failed to write {output_path}: {exc}")

        return len(records_snapshot)
