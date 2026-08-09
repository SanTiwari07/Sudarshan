"""
SUDARSHAN -- Screenshot Manager
================================
Unified screenshot pipeline for dynamic analysis.

All explorer, lifecycle, and hook-driven captures flow through this manager so
evidence paths, manifests, and report embedding stay consistent.

SCR-NNN Scheme
--------------
Every captured screenshot is assigned a sequential SCR-NNN identifier plus a
UUID for cross-system correlation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from sudarshan_core.sandbox import get_sandbox_provider
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Set

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

# Primary external storage is empty on some Genymotion/AVD images; /data/local/tmp
# is always writable and is the reliable screencap target.
REMOTE_CAPTURE_DIR = "/data/local/tmp"

# Visual similarity: skip capture when perceptual hash Hamming distance ≤ this.
_PHASH_DUPLICATE_THRESHOLD = 2


class ScreenshotReason(str, Enum):
    APP_LAUNCH = "APP_LAUNCH"
    PERMISSION_DIALOG = "PERMISSION_DIALOG"
    ACCESSIBILITY = "ACCESSIBILITY"
    OVERLAY = "OVERLAY"
    LOGIN = "LOGIN"
    OTP = "OTP"
    BANK_SELECTION = "BANK_SELECTION"
    NETWORK_ALERT = "NETWORK_ALERT"
    SUSPICIOUS_UI = "SUSPICIOUS_UI"
    ROOT_DETECTION = "ROOT_DETECTION"
    APP_CRASH = "APP_CRASH"
    FINAL_STATE = "FINAL_STATE"
    EXPLORER_ACTION = "EXPLORER_ACTION"
    HOOK_TRIGGER = "HOOK_TRIGGER"
    LIFECYCLE = "LIFECYCLE"
    AUTO_CRITICAL = "AUTO_CRITICAL"
    OTHER = "OTHER"


@dataclass
class ScreenshotRecord:
    """One entry in the screenshot manifest."""
    screenshot_id: str
    filename: str
    label: str
    trigger_event: str
    timestamp_ms: int
    category: str
    source: str
    gated: bool
    uuid: str = ""
    package: str = ""
    activity: str = ""
    fragment: str = ""
    window: str = ""
    screen_hash: str = ""
    layout_hash: str = ""
    stage: str = ""
    reason: str = ""
    explorer_action: str = ""
    risk_category: str = ""
    confidence: float = 0.0
    thumbnail_path: str = ""
    report_path: str = ""
    storage_status: str = "stored"
    embedding_status: str = "pending"
    extra: dict = field(default_factory=dict)


class ScreenshotManager:
    def __init__(
        self,
        device_serial: str,
        output_dir: Path,
        event_bus: Optional[RuntimeEventBus] = None,
        evidence_store: Optional[Any] = None,
        adb_path: str = "adb",
        package_name: str = "",
    ):
        self.device_serial = device_serial
        self.package_name = package_name
        self.output_dir = Path(output_dir) / "screenshots"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.adb_path = adb_path
        self.evidence_store = evidence_store

        self._lock = Lock()
        self._counter = 0
        self._manifest: List[ScreenshotRecord] = []
        self._pending_threads: Set[threading.Thread] = set()
        self._last_phashes: List[str] = []
        self._last_layout_hashes: Set[str] = set()
        self.skipped_duplicates: int = 0

        self.event_bus = event_bus
        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[ScreenshotManager] Subscribed to RuntimeEventBus")

    # -- ID management --------------------------------------------------------

    def _next_scr_id(self) -> str:
        """Return the next sequential screenshot ID, e.g. SCR-001."""
        self._counter += 1
        return f"SCR-{self._counter:03d}"

    # -- Dedup ----------------------------------------------------------------

    @staticmethod
    def _perceptual_hash(image_path: Path) -> str:
        try:
            from PIL import Image

            img = Image.open(image_path).convert("L").resize(
                (8, 8), Image.Resampling.LANCZOS
            )
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels)
            bits = "".join("1" if p > avg else "0" for p in pixels)
            return hashlib.sha256(bits.encode()).hexdigest()[:16]
        except Exception as exc:
            logger.debug("[ScreenshotManager] phash failed: %s", exc)
            return hashlib.sha256(image_path.read_bytes()[:4096]).hexdigest()[:16]

    @staticmethod
    def _hamming(a: str, b: str) -> int:
        if len(a) != len(b):
            return 99
        return sum(ch1 != ch2 for ch1, ch2 in zip(a, b))

    def _is_duplicate(self, phash: str, layout_hash: str) -> bool:
        if layout_hash and layout_hash in self._last_layout_hashes:
            return True
        for prev in self._last_phashes[-12:]:
            if self._hamming(prev, phash) <= _PHASH_DUPLICATE_THRESHOLD:
                return True
        return False

    def wait_pending(self, timeout_seconds: float = 30.0) -> bool:
        """Wait for in-flight background capture threads."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            with self._lock:
                alive = [t for t in self._pending_threads if t.is_alive()]
                self._pending_threads = set(alive)
                if not alive:
                    return True
            time.sleep(0.1)
        logger.warning(
            "[ScreenshotManager] wait_pending timed out after %.1fs",
            timeout_seconds,
        )
        return False

    # -- Core capture ---------------------------------------------------------

    def capture(
        self,
        label: str,
        trigger_evid: str = "",
        category: str = "",
        source: str = "manual",
        gated: bool = False,
        *,
        reason: str = "",
        stage: str = "",
        explorer_action: str = "",
        activity: str = "",
        fragment: str = "",
        layout_hash: str = "",
        force: bool = False,
        risk_category: str = "",
        confidence: float = 0.0,
    ) -> Optional[str]:
        """
        Take a screenshot on the device, pull it locally, and record it in
        the manifest.         Returns the relative path or None on failure.
        """
        if os.getenv("SUDARSHAN_DISABLE_SCREENSHOTS", "").lower() in ("1", "true", "yes"):
            logger.debug("[ScreenshotManager] Capture disabled via SUDARSHAN_DISABLE_SCREENSHOTS")
            return None

        with self._lock:
            scr_id = self._next_scr_id()
            idx_str = f"{self._counter:03d}"
            scr_uuid = str(uuid.uuid4())

        timestamp_ms = int(time.time() * 1000)
        safe_label = label.replace("/", "_").replace(" ", "_")[:40]
        filename = f"{idx_str}_{timestamp_ms}_{safe_label}.png"
        remote_path = f"{REMOTE_CAPTURE_DIR}/sudarshan_screen_{timestamp_ms}.png"
        local_path = self.output_dir / filename
        rel_path = f"screenshots/{filename}"

        try:
            provider = get_sandbox_provider()
            provider.adb(
                "-s",
                self.device_serial,
                "shell",
                "screencap",
                "-p",
                remote_path,
                timeout=8,
            )
            res_ok, res_out = provider.adb(
                "-s",
                self.device_serial,
                "pull",
                remote_path,
                str(local_path),
                timeout=10,
            )
            provider.adb(
                "-s",
                self.device_serial,
                "shell",
                "rm",
                remote_path,
                timeout=3,
            )

            if not local_path.exists():
                logger.warning(
                    "[ScreenshotManager] Failed to pull screenshot: %s",
                    res_out,
                )
                return None

            phash = self._perceptual_hash(local_path)
            if not force and self._is_duplicate(phash, layout_hash):
                try:
                    local_path.unlink(missing_ok=True)
                except OSError:
                    pass
                with self._lock:
                    self.skipped_duplicates += 1
                    self._counter -= 1
                logger.debug(
                    "[ScreenshotManager] Skipped duplicate screen (%s)", label
                )
                return None

            with self._lock:
                self._last_phashes.append(phash)
                if layout_hash:
                    self._last_layout_hashes.add(layout_hash)

            record = ScreenshotRecord(
                screenshot_id=scr_id,
                filename=rel_path,
                label=label,
                trigger_event=trigger_evid,
                timestamp_ms=timestamp_ms,
                category=category,
                source=source,
                gated=gated,
                uuid=scr_uuid,
                package=self.package_name,
                activity=activity,
                fragment=fragment,
                screen_hash=phash,
                layout_hash=layout_hash,
                stage=stage,
                reason=reason or ScreenshotReason.OTHER.value,
                explorer_action=explorer_action,
                risk_category=risk_category,
                confidence=confidence,
                report_path=rel_path,
                storage_status="stored",
                embedding_status="embedded_in_manifest",
            )
            with self._lock:
                self._manifest.append(record)
            logger.debug(
                "[ScreenshotManager] [%s] Captured %s (EVID: %s)",
                scr_id, filename, trigger_evid or "none",
            )
            if self.event_bus:
                from sudarshan_core.engines.event_bus import EventType, RuntimeEvent
                self.event_bus.publish(RuntimeEvent(
                    event_type=EventType.SCREENSHOT_CAPTURED,
                    timestamp=timestamp_ms / 1000.0,
                    payload={
                        "screenshot_id": scr_id,
                        "screenshot_uuid": scr_uuid,
                        "filename": rel_path,
                        "label": label,
                        "category": category,
                        "source": source,
                        "trigger_event": trigger_evid,
                        "reason": record.reason,
                        "screen_hash": phash,
                    },
                ))
            return rel_path

        except Exception as e:
            logger.error("[ScreenshotManager] Screencap failed: %s", e)
            return None

    def capture_for_explorer(
        self,
        label: str,
        *,
        reason: ScreenshotReason = ScreenshotReason.EXPLORER_ACTION,
        explorer_action: str = "",
        activity: str = "",
        layout_hash: str = "",
        before_action: bool = False,
    ) -> Optional[str]:
        """Explorer-facing capture with standard metadata."""
        suffix = "before" if before_action else "after"
        full_label = f"{label}_{suffix}"[:40]
        return self.capture(
            full_label,
            category="ui",
            source="explorer",
            reason=reason.value,
            explorer_action=explorer_action,
            activity=activity,
            layout_hash=layout_hash,
        )

    # -- Event-driven capture -------------------------------------------------

    def _on_event(self, event: Dict[str, Any]) -> None:
        data = event.get("data", {})
        severity = data.get("severity", event.get("severity", ""))
        category = event.get("category", "")

        trigger = False
        label = "auto"
        reason = ScreenshotReason.HOOK_TRIGGER
        if severity == "CRITICAL":
            trigger = True
            label = f"critical_{category}" if category else "critical"
            reason = ScreenshotReason.AUTO_CRITICAL
        elif category == "overlay":
            trigger = True
            label = "overlay_detected"
            reason = ScreenshotReason.OVERLAY
        elif category == "anti_analysis":
            trigger = True
            label = "anti_analysis_detected"
            reason = ScreenshotReason.ROOT_DETECTION

        if not trigger:
            return

        if self.evidence_store is not None and self.evidence_store.count() == 0:
            logger.debug(
                "[ScreenshotManager] Gate: skipping capture -- no evidence records yet"
            )
            return

        trigger_uuid = str(event.get("evidence_record_id") or "")

        def _bg_capture():
            self.capture(
                label=label,
                category=category,
                source="auto",
                gated=True,
                reason=reason.value,
                trigger_evid=trigger_uuid,
            )

        t = threading.Thread(target=_bg_capture, daemon=True)
        with self._lock:
            self._pending_threads.add(t)
        t.start()

    # -- Manifest persistence -------------------------------------------------

    def flush_manifest(self, output_path: Optional[Path] = None) -> int:
        """
        Write the screenshot manifest to JSON.

        Default path: <artifact_dir>/screenshots/manifest.json (canonical).
        """
        self.wait_pending()

        with self._lock:
            snapshot = list(self._manifest)

        if output_path is None:
            output_path = self.output_dir / "manifest.json"

        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_screenshots": len(snapshot),
            "skipped_duplicates": self.skipped_duplicates,
            "screenshots": [asdict(r) for r in snapshot],
        }
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(
                "[ScreenshotManager] Manifest flushed: %d screenshots -> %s",
                len(snapshot), output_path,
            )
        except Exception as e:
            logger.error("[ScreenshotManager] Failed to write manifest: %s", e)
        return len(snapshot)

    def get_manifest(self) -> List[ScreenshotRecord]:
        with self._lock:
            return list(self._manifest)

    def get_telemetry(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "screenshots_captured": len(self._manifest),
                "skipped_duplicates": self.skipped_duplicates,
                "pending_threads": sum(1 for t in self._pending_threads if t.is_alive()),
            }

    def get_manifest_with_base64(self) -> List[Dict[str, Any]]:
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
                    logger.warning(
                        "[ScreenshotManager] Failed to encode %s: %s", local_file, e
                    )
            records.append(d)
        return records
