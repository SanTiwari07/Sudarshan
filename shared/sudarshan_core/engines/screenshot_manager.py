"""
SUDARSHAN -- Screenshot Manager
================================
Captures and indexes screenshots at key moments during dynamic analysis.
Triggered either automatically by CRITICAL Frida events from the EventBus,
or manually by the UIExplorer/PermissionOrchestrator.

SCR-NNN Scheme
--------------
Every captured screenshot is assigned a sequential SCR-NNN identifier.
This ID is:
  - Embedded in the filename: 001_<ts>_<label>.png
  - Written to screenshots/manifest.json alongside the linked EVID-NNN
  - Set on the EvidenceRecord via evidence_store.set_screenshot_id()

Gating Rule
-----------
Automatic event-driven screenshots ONLY capture when at least one
EvidenceRecord already exists in the store. This prevents generating
empty SCR entries when no dynamic telemetry was observed (no fabrication).
Manual captures (UIExplorer, PermissionOrchestrator) are always permitted.

NOTE: The screenshot path is exercised only when Frida hooks actually fire.
      The gating logic will remain untested against real data until substrate
      Defect #1 (hardcoded accessibility class name) is resolved.
"""

import json
import logging
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Screenshot manifest record
# ---------------------------------------------------------------------------

@dataclass
class ScreenshotRecord:
    """One entry in the screenshot manifest."""
    screenshot_id:  str         # SCR-NNN
    filename:       str         # relative path within output_dir
    label:          str         # trigger label (e.g. 'critical_overlay')
    trigger_event:  str         # EVID-NNN of triggering evidence record, or ""
    timestamp_ms:   int         # capture time Unix ms
    category:       str         # event category that triggered capture
    source:         str         # "auto" | "manual"
    gated:          bool        # True if captured subject to has_evidence gate
    extra:          dict = field(default_factory=dict)


class ScreenshotManager:
    def __init__(
        self,
        device_serial: str,
        output_dir: Path,
        event_bus: Optional[RuntimeEventBus] = None,
        evidence_store: Optional[Any] = None,
        adb_path: str = "adb"
    ):
        self.device_serial = device_serial
        self.output_dir = Path(output_dir) / "screenshots"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path
        self.evidence_store = evidence_store

        self._lock = Lock()
        self._counter = 0
        self._manifest: List[ScreenshotRecord] = []

        self.event_bus = event_bus
        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[ScreenshotManager] Subscribed to RuntimeEventBus")

    # -- ID management --------------------------------------------------------

    def _next_scr_id(self) -> str:
        """Return the next sequential screenshot ID, e.g. SCR-001.
        Caller must hold self._lock."""
        self._counter += 1
        return f"SCR-{self._counter:03d}"

    # -- Core capture ---------------------------------------------------------

    def capture(
        self,
        label: str,
        trigger_evid: str = "",
        category: str = "",
        source: str = "manual",
        gated: bool = False,
    ) -> Optional[str]:
        """
        Take a screenshot on the device, pull it locally, and record it in
        the manifest. Returns the relative path (e.g. 'screenshots/001_...png')
        or None if the capture fails.

        Parameters
        ----------
        label : str
            Short slug for the filename and manifest.
        trigger_evid : str
            The EVID-NNN of the evidence record that triggered this capture.
        category : str
            Frida event category (for manifest context).
        source : str
            'auto' (event-driven) or 'manual' (UIExplorer / orchestrator).
        gated : bool
            True if this capture was subject to the has_evidence gate.
        """
        with self._lock:
            scr_id = self._next_scr_id()
            idx_str = f"{self._counter:03d}"

        timestamp_ms = int(time.time() * 1000)
        safe_label = label.replace("/", "_").replace(" ", "_")[:40]
        filename = f"{idx_str}_{timestamp_ms}_{safe_label}.png"
        remote_path = f"/sdcard/sudarshan_screen_{timestamp_ms}.png"
        local_path = self.output_dir / filename
        rel_path = f"screenshots/{filename}"

        try:
            subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell",
                 "screencap", "-p", remote_path],
                capture_output=True, timeout=5
            )
            res = subprocess.run(
                [self.adb_path, "-s", self.device_serial, "pull",
                 remote_path, str(local_path)],
                capture_output=True, timeout=5
            )
            subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell", "rm", remote_path],
                capture_output=True, timeout=2
            )

            if local_path.exists():
                record = ScreenshotRecord(
                    screenshot_id=scr_id,
                    filename=rel_path,
                    label=label,
                    trigger_event=trigger_evid,
                    timestamp_ms=timestamp_ms,
                    category=category,
                    source=source,
                    gated=gated,
                )
                with self._lock:
                    self._manifest.append(record)
                logger.debug(
                    "[ScreenshotManager] [%s] Captured %s (EVID: %s)",
                    scr_id, filename, trigger_evid or "none"
                )
                if self.event_bus:
                    from sudarshan_core.engines.event_bus import EventType, RuntimeEvent
                    self.event_bus.publish(RuntimeEvent(
                        event_type=EventType.SCREENSHOT_CAPTURED,
                        timestamp=timestamp_ms / 1000.0,
                        payload={
                            "screenshot_id": scr_id,
                            "filename": rel_path,
                            "label": label,
                            "category": category,
                            "source": source,
                            "trigger_event": trigger_evid,
                        }
                    ))
                return rel_path
            else:
                logger.warning(
                    "[ScreenshotManager] Failed to pull screenshot: %s",
                    res.stderr.decode(errors="replace")
                )
                return None

        except Exception as e:
            logger.error("[ScreenshotManager] Screencap failed: %s", e)
            return None

    # -- Event-driven capture -------------------------------------------------

    def _on_event(self, event: Dict[str, Any]) -> None:
        """
        Listens for CRITICAL events or specific overlay/anti-analysis
        detections and triggers a screenshot.

        Gating rule: only fires if the evidence_store already contains at
        least one record (i.e., at least one hook event has been processed).
        This prevents generating screenshot entries when there is no runtime
        evidence to link them to (no fabrication guarantee).
        """
        data = event.get("data", {})
        severity = data.get("severity", event.get("severity", ""))
        category = event.get("category", "")

        trigger = False
        label = "auto"
        if severity == "CRITICAL":
            trigger = True
            label = f"critical_{category}" if category else "critical"
        elif category == "overlay":
            trigger = True
            label = "overlay_detected"
        elif category == "anti_analysis":
            trigger = True
            label = "anti_analysis_detected"

        if not trigger:
            return

        # Gating: only capture if evidence_store has records
        if self.evidence_store is not None and self.evidence_store.count() == 0:
            logger.debug(
                "[ScreenshotManager] Gate: skipping capture -- no evidence records yet"
            )
            return

        def _bg_capture():
            ref = self.capture(
                label=label,
                category=category,
                source="auto",
                gated=True,
            )
            if ref and self.evidence_store:
                updated_id = self.evidence_store.attach_screenshot_to_latest(ref)
                if updated_id and self._manifest:
                    scr_id = self._manifest[-1].screenshot_id
                    self.evidence_store.set_screenshot_id(updated_id, scr_id)
                    self._manifest[-1].trigger_event = updated_id

        threading.Thread(target=_bg_capture, daemon=True).start()

    # -- Manifest persistence -------------------------------------------------

    def flush_manifest(self, output_path: Optional[Path] = None) -> int:
        """
        Write the screenshot manifest to JSON.

        If output_path is None, writes to <output_dir>/manifest.json.
        Returns the number of screenshots recorded.
        """
        with self._lock:
            snapshot = list(self._manifest)

        if output_path is None:
            output_path = self.output_dir / "manifest.json"

        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_screenshots": len(snapshot),
            "screenshots": [asdict(r) for r in snapshot],
        }
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(
                "[ScreenshotManager] Manifest flushed: %d screenshots -> %s",
                len(snapshot), output_path
            )
        except Exception as e:
            logger.error("[ScreenshotManager] Failed to write manifest: %s", e)
        return len(snapshot)

    def get_manifest(self) -> List[ScreenshotRecord]:
        """Return a thread-safe snapshot of the screenshot manifest."""
        with self._lock:
            return list(self._manifest)

    def get_manifest_with_base64(self) -> List[Dict[str, Any]]:
        """
        Return the screenshot manifest with base64 data URIs embedded
        for single-file HTML report rendering.
        """
        import base64
        with self._lock:
            snapshot = list(self._manifest)

        records = []
        for r in snapshot:
            d = asdict(r)
            local_file = self.output_dir / Path(r.filename).name
            d["base64_data_uri"] = ""
            if local_file.exists():
                try:
                    data = local_file.read_bytes()
                    b64 = base64.b64encode(data).decode("utf-8")
                    d["base64_data_uri"] = f"data:image/png;base64,{b64}"
                except Exception as e:
                    logger.warning("[ScreenshotManager] Failed to encode %s: %s", local_file, e)
            records.append(d)
        return records

