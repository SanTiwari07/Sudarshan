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
    UPDATE_PROMPT = "UPDATE_PROMPT"
    DOWNLOAD_PROMPT = "DOWNLOAD_PROMPT"
    EXTERNAL_APK = "EXTERNAL_APK"
    VPN_REQUEST = "VPN_REQUEST"
    PACKAGE_INSTALLER = "PACKAGE_INSTALLER"
    EVIDENCE_MOMENT = "EVIDENCE_MOMENT"
    OTHER = "OTHER"


# Deterministic caption templates, one per ScreenshotReason. Placeholders are
# filled from the capture call; a template whose placeholder is empty falls back
# to UNCLEAR_CAPTION rather than emitting a half-formed sentence.
REASON_TO_CAPTION: Dict[str, str] = {
    ScreenshotReason.APP_LAUNCH.value:        "Application launched - initial screen state",
    ScreenshotReason.PERMISSION_DIALOG.value: "Runtime permission dialog presented",
    ScreenshotReason.ACCESSIBILITY.value:     "App requesting Accessibility Service permission",
    ScreenshotReason.OVERLAY.value:           "Overlay window displayed over target app",
    ScreenshotReason.LOGIN.value:             "App presenting login or credential entry screen",
    ScreenshotReason.OTP.value:               "App displaying OTP input field",
    ScreenshotReason.BANK_SELECTION.value:    "Bank or payment provider selection screen",
    ScreenshotReason.NETWORK_ALERT.value:     "Network communication event detected",
    ScreenshotReason.SUSPICIOUS_UI.value:     "Suspicious or unreadable UI state captured for vision analysis",
    ScreenshotReason.ROOT_DETECTION.value:    "Anti-analysis or root detection behavior observed",
    ScreenshotReason.APP_CRASH.value:         "Application crash or ANR detected",
    ScreenshotReason.FINAL_STATE.value:       "Final application state at end of analysis",
    ScreenshotReason.EXPLORER_ACTION.value:   "Screen state after explorer action - {explorer_action}",
    ScreenshotReason.HOOK_TRIGGER.value:      "Hook-triggered capture - {category} event",
    ScreenshotReason.LIFECYCLE.value:         "Lifecycle capture - {label}",
    ScreenshotReason.AUTO_CRITICAL.value:     "Critical behavioral event detected - {category}",
    ScreenshotReason.UPDATE_PROMPT.value:     "Application update prompt displayed",
    ScreenshotReason.DOWNLOAD_PROMPT.value:   "Download prompt displayed",
    ScreenshotReason.EXTERNAL_APK.value:      "External APK install request observed",
    ScreenshotReason.VPN_REQUEST.value:       "VPN enable/install request observed",
    ScreenshotReason.PACKAGE_INSTALLER.value: "Package installer screen displayed",
    ScreenshotReason.EVIDENCE_MOMENT.value:   "Security-relevant evidence moment - {label}",
    ScreenshotReason.OTHER.value:             "",
}

# Honest fallback when no template matches or a template placeholder is empty.
UNCLEAR_CAPTION: str = "Screen state unclear - no matching trigger"


def build_caption(
    reason: str,
    category: str = "",
    label: str = "",
    explorer_action: str = "",
) -> str:
    """
    Render the deterministic caption for a screenshot.

    Never raises and never invents detail: an unknown reason, an empty
    template, or a template whose placeholder has no value all yield
    UNCLEAR_CAPTION.
    """
    template = REASON_TO_CAPTION.get(reason or "", "")
    if not template:
        return UNCLEAR_CAPTION
    values = {
        "category": category,
        "label": label,
        "explorer_action": explorer_action,
    }
    try:
        needed = [
            f for f in values
            if "{" + f + "}" in template
        ]
        if any(not values[f] for f in needed):
            return UNCLEAR_CAPTION
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return UNCLEAR_CAPTION


def resolve_screen_observation(
    *,
    screen_observation: Any = None,
    ui_xml: str = "",
    activity: str = "",
    semantic_type: str = "",
    reason: str = "",
    label: str = "",
    explorer_action: str = "",
    package_name: str = "",
) -> Dict[str, str]:
    """
    Best available perceptual reading of a frame, from whatever the caller has.

    Three sources, in descending order of how much they know:
      1. a ScreenObservation the caller already built from parsed UI nodes,
      2. a raw uiautomator dump taken alongside the frame,
      3. the frame's own metadata - Activity and screen classification.

    Never raises and never returns empty strings: a description is presentation
    metadata, and the failure mode it replaces (every screenshot captioned with
    the reason it was taken) is worse than a short sentence.
    """
    try:
        from sudarshan_core.engines.agentic.ui_observation import (
            describe_from_metadata,
            describe_screen,
        )
    except Exception as exc:  # pragma: no cover - description must never block
        logger.debug("[ScreenshotManager] ui_observation unavailable: %s", exc)
        return {
            "visual_observation": "",
            "screen_summary": "",
            "observation_source": "",
            "screen_type": semantic_type,
        }

    try:
        if screen_observation is not None:
            text = str(getattr(screen_observation, "visual_observation", "") or "")
            if text:
                return {
                    "visual_observation": text,
                    "screen_summary": str(
                        getattr(screen_observation, "screen_summary", "") or ""
                    ),
                    "observation_source": str(
                        getattr(screen_observation, "source", "") or "ui_tree"
                    ),
                    "screen_type": str(
                        getattr(screen_observation, "screen_type", "") or semantic_type
                    ),
                }

        if ui_xml:
            obs = describe_screen(
                activity=activity, ui_xml=ui_xml, screen_type=semantic_type,
            )
            return {
                "visual_observation": obs.visual_observation,
                "screen_summary": obs.screen_summary,
                "observation_source": obs.source,
                "screen_type": obs.screen_type,
            }

        obs = describe_screen(activity=activity, screen_type=semantic_type)
        return {
            "visual_observation": describe_from_metadata(
                activity=activity,
                screen_type=semantic_type,
                label=label,
                reason=reason,
                explorer_action=explorer_action,
            ),
            "screen_summary": obs.screen_summary,
            "observation_source": "metadata",
            "screen_type": obs.screen_type,
        }
    except Exception as exc:  # pragma: no cover
        logger.debug("[ScreenshotManager] Could not describe screen: %s", exc)
        return {
            "visual_observation": "",
            "screen_summary": "",
            "observation_source": "",
            "screen_type": semantic_type,
        }


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
    # PDF-facing presentation fields (read by pdf_generator Appendix A).
    description: str = ""
    capture_trigger: str = ""
    title: str = ""
    quality: str = "A"
    # ── What the frame SHOWS ─────────────────────────────────────────────────
    # `description` answers "why was this captured" and is looked up from the
    # capture reason, which is why the appendix used to repeat five sentences
    # down the page. These two answer "what is on it", read from the UI
    # hierarchy dumped alongside the frame (see agentic.ui_observation) or, when
    # vision captioning is enabled, from the pixels.
    #
    # Kept as separate fields rather than overwriting `description`: the reason
    # is still worth recording, and the report shows them in different columns.
    visual_observation: str = ""
    screen_summary: str = ""
    observation_source: str = ""
    # The screen classification at capture time. Already resolved by every
    # caller and previously used only to pick a policy branch, so it never
    # reached the manifest - which left downstream consumers (the linker, the
    # appendix) unable to say what KIND of screen a frame shows.
    semantic_type: str = ""
    # Causal linking to exploration graph / evidence
    state_id: str = ""
    action_id: str = ""
    evidence_id: str = ""
    evidence_moment_id: str = ""
    deduplication_status: str = ""
    trigger_reason: str = ""
    foreground_package: str = ""
    target_package: str = ""
    ownership: str = ""
    reused_screenshot_id: str = ""
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
        self.suppressed_count: int = 0
        self.reused_count: int = 0

        # Central screenshot policy (state/event-aware deduplication)
        from sudarshan_core.engines.agentic.screenshot_policy import ScreenshotPolicy
        self._policy = ScreenshotPolicy(target_package=package_name)

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
        state_id: str = "",
        action_id: str = "",
        evidence_id: str = "",
        evidence_moment_id: str = "",
        foreground_package: str = "",
        transition_event: str = "",
        semantic_type: str = "",
        screen_observation: Optional[Any] = None,
        ui_xml: str = "",
    ) -> Optional[str]:
        """
        Take a screenshot on the device, pull it locally, and record it in
        the manifest. Returns the relative path or None on failure/suppression.

        All capture requests pass through the central ScreenshotPolicy before
        adb screencap runs.  Suppressed captures return None but are audited.

        `screen_observation` is a ui_observation.ScreenObservation (or anything
        with the same attributes) describing what is on the screen, supplied by
        a caller that already holds the UI hierarchy. `ui_xml` is the raw dump
        for a caller that holds only that. Supplying neither still yields a
        description - built from the Activity and the screen classification -
        rather than falling back to restating the capture reason.
        """
        if os.getenv("SUDARSHAN_DISABLE_SCREENSHOTS", "").lower() in ("1", "true", "yes"):
            logger.debug("[ScreenshotManager] Capture disabled via SUDARSHAN_DISABLE_SCREENSHOTS")
            return None

        from sudarshan_core.engines.agentic.screenshot_policy import (
            ScreenshotRequest,
            ScreenshotDecision,
            resolve_screen_ownership,
        )

        fg_pkg = foreground_package or self.package_name
        ownership = resolve_screen_ownership(
            fg_pkg, self.package_name, activity, semantic_type,
        )

        policy_req = ScreenshotRequest(
            trigger_type=reason or category,
            reason=reason or category,
            foreground_package=fg_pkg,
            target_package=self.package_name,
            activity=activity,
            state_id=state_id,
            action_id=action_id,
            evidence_moment_id=evidence_moment_id,
            screen_hash=layout_hash or "",
            layout_hash=layout_hash,
            semantic_type=semantic_type,
            ownership=ownership,
            force=force,
            label=label,
            transition_event=transition_event,
        )

        decision, decision_reason, reuse_id = self._policy.should_capture(policy_req)

        if decision in (ScreenshotDecision.SUPPRESSED, ScreenshotDecision.BLOCKED):
            self.suppressed_count += 1
            logger.debug(
                "[ScreenshotManager] Screenshot %s: %s (%s)",
                decision.value, label, decision_reason,
            )
            return None

        if decision == ScreenshotDecision.REUSE and reuse_id:
            self.reused_count += 1
            logger.debug(
                "[ScreenshotManager] Screenshot REUSE %s -> %s (%s)",
                label, reuse_id, decision_reason,
            )
            return reuse_id

        if decision == ScreenshotDecision.DEDUPLICATED:
            self.skipped_duplicates += 1
            logger.debug(
                "[ScreenshotManager] Screenshot DEDUPLICATED: %s (%s)",
                label, decision_reason,
            )
            return None

        with self._lock:
            scr_id = self._next_scr_id()
            idx_str = f"{self._counter:03d}"
            scr_uuid = str(uuid.uuid4())

        timestamp_ms = int(time.time() * 1000)

        # Semantic filename via policy
        semantic_stem = self._policy.build_semantic_filename(
            self._counter,
            reason or category,
            ownership,
            label,
        )
        safe_label = semantic_stem.replace("/", "_").replace(" ", "_")[:60]
        filename = f"{safe_label}.png"
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

            resolved_reason = reason or ScreenshotReason.OTHER.value
            observation = resolve_screen_observation(
                screen_observation=screen_observation,
                ui_xml=ui_xml,
                activity=activity,
                semantic_type=semantic_type,
                reason=resolved_reason,
                label=label,
                explorer_action=explorer_action,
                package_name=self.package_name,
            )
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
                package=fg_pkg,
                activity=activity,
                fragment=fragment,
                screen_hash=phash,
                layout_hash=layout_hash,
                stage=stage,
                reason=resolved_reason,
                explorer_action=explorer_action,
                risk_category=risk_category,
                confidence=confidence,
                report_path=rel_path,
                storage_status="stored",
                embedding_status="embedded_in_manifest",
                description=build_caption(
                    resolved_reason,
                    category=category,
                    label=label,
                    explorer_action=explorer_action,
                ),
                capture_trigger=resolved_reason,
                title=f"{scr_id} - {label}" if label else scr_id,
                visual_observation=observation["visual_observation"],
                screen_summary=observation["screen_summary"],
                observation_source=observation["observation_source"],
                semantic_type=semantic_type or observation["screen_type"],
                state_id=state_id,
                action_id=action_id,
                evidence_id=evidence_id,
                evidence_moment_id=evidence_moment_id,
                deduplication_status=decision.value,
                trigger_reason=decision_reason,
                foreground_package=fg_pkg,
                target_package=self.package_name,
                ownership=ownership.value,
                reused_screenshot_id=reuse_id or "",
            )
            with self._lock:
                self._manifest.append(record)

            if trigger_evid and self.evidence_store is not None:
                try:
                    self.evidence_store.attach_screenshot(trigger_evid, rel_path)
                except Exception as exc:
                    logger.debug(
                        "[ScreenshotManager] attach_screenshot failed: %s", exc
                    )

            # Register with policy for future dedup/reuse
            self._policy.register_capture(
                scr_id, ownership, layout_hash or phash, layout_hash,
            )
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

    def capture_async(self, **kwargs: Any) -> None:
        """
        Capture on a background thread.

        capture() shells out to adb three times (screencap, pull, rm) and blocks
        for seconds. Callers on an event loop - the agentic explorer's action
        loop in particular - must not stall there while a Frida session is live.
        The thread is registered with the same bookkeeping _on_event uses, so
        flush_manifest() still waits for it.
        """
        def _bg_capture() -> None:
            try:
                self.capture(**kwargs)
            except Exception as exc:
                logger.debug("[ScreenshotManager] async capture failed: %s", exc)

        thread = threading.Thread(target=_bg_capture, daemon=True)
        with self._lock:
            self._pending_threads.add(thread)
        thread.start()

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
            reason = ScreenshotReason.HOOK_TRIGGER

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

    def enrich_captions_with_vision(self) -> int:
        """
        Refine screen descriptions with Gemini Vision.

        No-op unless SUDARSHAN_VISION_CAPTIONS=1. Runs after exploration ends,
        so vision latency cannot eat the runtime action budget. Returns the
        number of frames the model described.

        What it writes has changed: the model's sentence now lands on
        `visual_observation` - the field that answers "what is on screen" -
        rather than overwriting `description`, which records why the shutter
        fired. Both are kept, because they are different questions and the
        report shows them in different places. `description` is still replaced
        when the deterministic table gave up on it, since UNCLEAR_CAPTION is
        not worth preserving.

        The UI-tree reading already on the record is passed to the model as
        grounding, so an ambiguous frame is corrected by the image rather than
        described from nothing.
        """
        try:
            from sudarshan_core.engines.agentic.caption_generator import (
                caption_budget,
                caption_priority,
                generate_caption,
                should_caption,
                vision_captions_enabled,
            )
        except Exception as e:
            logger.debug("[ScreenshotManager] Caption generator unavailable: %s", e)
            return 0

        if not vision_captions_enabled():
            return 0

        budget = caption_budget()
        if budget <= 0:
            return 0

        with self._lock:
            snapshot = list(self._manifest)

        eligible = [
            rec for rec in snapshot
            if should_caption(rec.reason, rec.description)
        ]
        # Ordered so a run that cannot afford every frame spends what it has on
        # the frames whose deterministic description says the least.
        eligible.sort(key=lambda r: (
            caption_priority(r.reason, r.description), r.timestamp_ms,
        ))

        replaced = 0
        for rec in eligible[:budget]:
            local = self.output_dir / Path(rec.filename).name
            hint = rec.visual_observation or (
                f"reason={rec.reason} category={rec.category} label={rec.label}"
            )
            caption = generate_caption(local, hint_context=hint)
            if not caption:
                continue
            rec.visual_observation = caption
            rec.observation_source = "gemini_vision"
            rec.extra["caption_source"] = "gemini_vision"
            if rec.description in ("", UNCLEAR_CAPTION):
                rec.description = caption
            replaced += 1

        if replaced:
            logger.info(
                "[ScreenshotManager] Vision descriptions applied to %d of %d "
                "eligible screenshot(s) (budget=%d)",
                replaced, len(eligible), budget,
            )
        return replaced

    def flush_manifest(self, output_path: Optional[Path] = None) -> int:
        """
        Write the screenshot manifest to JSON.

        Default path: <artifact_dir>/screenshots/manifest.json (canonical).
        """
        self.wait_pending()
        self.enrich_captions_with_vision()

        with self._lock:
            snapshot = list(self._manifest)

        if output_path is None:
            output_path = self.output_dir / "manifest.json"

        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_screenshots": len(snapshot),
            "skipped_duplicates": self.skipped_duplicates,
            "suppressed_count": self.suppressed_count,
            "reused_count": self.reused_count,
            "policy_statistics": self._policy.get_statistics(),
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
                "suppressed_count": self.suppressed_count,
                "reused_count": self.reused_count,
                "pending_threads": sum(1 for t in self._pending_threads if t.is_alive()),
                "policy_statistics": self._policy.get_statistics(),
            }

    def get_policy_statistics(self) -> Dict[str, Any]:
        return self._policy.get_statistics()

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
