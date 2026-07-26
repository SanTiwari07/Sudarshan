"""
SUDARSHAN — Screenshot Manager
===============================
Captures and indexes screenshots at key moments during dynamic analysis.
Triggered either automatically by CRITICAL Frida events from the EventBus,
or manually by the UIExplorer/PermissionOrchestrator.
"""

import os
import subprocess
import time
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from threading import Lock

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)


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

        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[ScreenshotManager] Subscribed to RuntimeEventBus")

    def capture(self, label: str) -> Optional[str]:
        """
        Takes a screenshot on the device, pulls it to the output directory,
        and returns the relative path (or None if failed).
        """
        with self._lock:
            self._counter += 1
            idx = f"{self._counter:03d}"
            
        timestamp = int(time.time() * 1000)
        filename = f"{idx}_{timestamp}_{label}.png"
        remote_path = f"/sdcard/screen_{timestamp}.png"
        local_path = self.output_dir / filename

        try:
            # Take screenshot
            subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell", "screencap", "-p", remote_path],
                capture_output=True, timeout=5
            )
            # Pull to local
            res = subprocess.run(
                [self.adb_path, "-s", self.device_serial, "pull", remote_path, str(local_path)],
                capture_output=True, timeout=5
            )
            # Cleanup remote
            subprocess.run(
                [self.adb_path, "-s", self.device_serial, "shell", "rm", remote_path],
                capture_output=True, timeout=2
            )

            if local_path.exists():
                logger.debug(f"[ScreenshotManager] Captured: {filename}")
                return f"screenshots/{filename}"
            else:
                logger.warning(f"[ScreenshotManager] Failed to pull screenshot: {res.stderr.decode()}")
                return None
        except Exception as e:
            logger.error(f"[ScreenshotManager] Screencap failed: {e}")
            return None

    def _on_event(self, event: Dict[str, Any]) -> None:
        """
        Listens for CRITICAL events or specific overlay detections and triggers
        a screenshot. Links it back to the EvidenceStore if available.
        """
        data = event.get("data", {})
        severity = data.get("severity", event.get("severity", ""))
        category = event.get("category", "")

        # Trigger conditions
        trigger = False
        label = "auto"
        
        if severity == "CRITICAL":
            trigger = True
            label = f"critical_{category}"
        elif category == "overlay":
            trigger = True
            label = "overlay_detected"
        elif category == "anti_analysis":
            trigger = True
            label = "anti_analysis_detected"

        if trigger:
            import threading
            def _bg_capture():
                ref = self.capture(label)
                if ref and self.evidence_store:
                    # The event just fired, so the most recent evidence record is likely the match
                    self.evidence_store.attach_screenshot_to_latest(ref)
            
            threading.Thread(target=_bg_capture, daemon=True).start()
