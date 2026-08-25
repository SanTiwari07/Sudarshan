"""
Secondary payloads: the second APK a dropper fetches.

The exploration graph already had `record_secondary_apk()`, but nothing in the
production path ever called it - only tests did. So a dropper could download a
payload, write it to storage and ask Android to install it, and the run would
report nothing: the API existed, the producer did not.

This module is that producer. It consumes runtime events the Frida agent
already emits and turns them into a tracked artifact.

The distinction this file exists to protect is §20's status ladder:

    DETECTED  -> we saw a reference to an APK
    DOWNLOADED-> the file exists on the device and we know its size
    HASHED    -> we preserved it and computed SHA-256
    INSTALL_REQUESTED -> the app asked Android to install it
    INSTALLED -> Android confirmed the package is present
    ANALYZED  -> the child APK was actually run through analysis

Each rung is a different claim. "Installation was requested" and "malware was
installed" are not the same sentence, and only one of them is usually true.
Nothing here promotes a payload to a rung it has not reached, and nothing here
ever installs anything - the victim may tap Install inside the sandbox, but the
investigator only ever observes.
"""

from __future__ import annotations

import hashlib
import logging
import posixpath
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Refuse to preserve anything larger than this. A malicious sample can point
#: at an arbitrarily large file, and pulling it would be the DoS.
MAX_PAYLOAD_BYTES = 200 * 1024 * 1024

#: Hooks whose events describe a secondary payload. Keep in step with
#: banking_trojan.js; tests assert every name here is actually emitted.
HOOK_APK_WRITE = "FileOutputStream.apkWrite"
HOOK_DOWNLOAD_ENQUEUE = "DownloadManager.enqueue"
HOOK_INSTALL_REQUEST = "Intent.installPackageRequest"

_APK_PATH_RE = re.compile(r"(/[\w./@\-+ ]*?\.apk)", re.IGNORECASE)


class PayloadStatus(str, Enum):
    """How far along the chain a payload actually got. Ordered."""

    DETECTED = "DETECTED"
    DOWNLOADED = "DOWNLOADED"
    HASHED = "HASHED"
    INSTALL_REQUESTED = "INSTALL_REQUESTED"
    INSTALLED = "INSTALLED"
    ANALYZED = "ANALYZED"
    BLOCKED = "BLOCKED"


#: Rank for monotonic promotion. BLOCKED is terminal and outside the ladder:
#: a payload policy refused to preserve must not later read as ANALYZED.
_RANK: Dict[str, int] = {
    PayloadStatus.DETECTED.value: 0,
    PayloadStatus.DOWNLOADED.value: 1,
    PayloadStatus.HASHED.value: 2,
    PayloadStatus.INSTALL_REQUESTED.value: 3,
    PayloadStatus.INSTALLED.value: 4,
    PayloadStatus.ANALYZED.value: 5,
}


@dataclass
class SecondaryPayload:
    """One secondary APK, and the strongest claim we can make about it."""

    device_path: str
    filename: str = ""
    parent_package: str = ""
    source_hook: str = ""
    status: str = PayloadStatus.DETECTED.value
    sha256: str = ""
    size_bytes: int = 0
    package_name: str = ""
    version_name: str = ""
    local_path: str = ""
    url: str = ""
    first_seen_ms: int = 0
    install_requested: bool = False
    install_confirmed: bool = False
    blocked_by_policy: bool = False
    notes: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.filename and self.device_path:
            self.filename = posixpath.basename(self.device_path)

    def promote(self, status: str, note: str = "") -> None:
        """Move up the ladder only. Never sideways, never down."""
        if self.blocked_by_policy and status != PayloadStatus.BLOCKED.value:
            return
        current = _RANK.get(self.status, -1)
        target = _RANK.get(status, -1)
        if target > current:
            self.status = status
        if note and note not in self.notes:
            self.notes.append(note)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_path": self.device_path,
            "filename": self.filename,
            "parent_package": self.parent_package,
            "source_hook": self.source_hook,
            "status": self.status,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "local_path": self.local_path,
            "url": self.url,
            "first_seen_ms": self.first_seen_ms,
            # Kept as separate booleans rather than folded into `status`,
            # because a report must be able to say "requested but not
            # confirmed" without the reader inferring it from an enum.
            "install_requested": self.install_requested,
            "install_confirmed": self.install_confirmed,
            "blocked_by_policy": self.blocked_by_policy,
            "notes": list(self.notes),
        }


def extract_apk_path(event: Dict[str, Any]) -> str:
    """Recover an APK path from an event, or "" when it names none."""
    for key in ("path", "file_path", "url", "description"):
        value = event.get(key) or (event.get("data") or {}).get(key)
        if not isinstance(value, str):
            continue
        match = _APK_PATH_RE.search(value)
        if match:
            return match.group(1)
    return ""


class SecondaryPayloadTracker:
    """
    Turns runtime events into tracked secondary payloads.

    Deliberately passive: it observes events and, when asked, preserves and
    hashes an artifact. It never installs, never launches, and never removes
    anything from the device.
    """

    def __init__(self, parent_package: str = "", max_payloads: int = 8) -> None:
        self.parent_package = parent_package
        self.max_payloads = max_payloads
        self._by_path: Dict[str, SecondaryPayload] = {}
        self.dropped_over_budget = 0

    # ── observation ──────────────────────────────────────────────────────────

    def observe_event(self, event: Dict[str, Any]) -> Optional[SecondaryPayload]:
        """
        Consume one runtime event. Returns the payload it touched, if any.

        Events that do not describe a secondary payload return None, so this is
        safe to call over the whole event stream.
        """
        if not isinstance(event, dict):
            return None
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        hook = event.get("hook") or data.get("hook") or ""
        if hook not in (
            HOOK_APK_WRITE, HOOK_DOWNLOAD_ENQUEUE, HOOK_INSTALL_REQUEST,
        ):
            return None

        merged = {**data, **{k: v for k, v in event.items() if k != "data"}}
        path = extract_apk_path(merged)

        if hook == HOOK_DOWNLOAD_ENQUEUE and not path:
            # A queued download we cannot attribute to a file yet. Recording it
            # as a payload would invent an artifact, so it stays an event.
            return None
        if not path:
            return None

        payload = self._get_or_create(path, hook, event)
        if payload is None:
            return None

        if hook == HOOK_APK_WRITE:
            payload.promote(
                PayloadStatus.DETECTED.value,
                "APK written to device storage by the application",
            )
        elif hook == HOOK_INSTALL_REQUEST:
            payload.install_requested = True
            payload.promote(
                PayloadStatus.INSTALL_REQUESTED.value,
                "Application asked Android to install this package; "
                "completion not confirmed by this event",
            )
        return payload

    def observe_events(self, events: List[Dict[str, Any]]) -> List[SecondaryPayload]:
        touched: List[SecondaryPayload] = []
        for event in events or []:
            payload = self.observe_event(event)
            if payload is not None and payload not in touched:
                touched.append(payload)
        return touched

    def _get_or_create(
        self, path: str, hook: str, event: Dict[str, Any],
    ) -> Optional[SecondaryPayload]:
        existing = self._by_path.get(path)
        if existing is not None:
            return existing
        if len(self._by_path) >= self.max_payloads:
            # Bounded so a sample writing APKs in a loop cannot exhaust us.
            self.dropped_over_budget += 1
            logger.warning(
                "[SecondaryPayload] budget %d reached; not tracking %s "
                "(%d dropped so far)",
                self.max_payloads, path, self.dropped_over_budget,
            )
            return None
        payload = SecondaryPayload(
            device_path=path,
            parent_package=self.parent_package,
            source_hook=hook,
            first_seen_ms=int(event.get("timestamp_ms") or 0),
        )
        self._by_path[path] = payload
        logger.info(
            "[SecondaryPayload] DETECTED path=%s hook=%s parent=%s",
            path, hook, self.parent_package,
        )
        return payload

    # ── preservation ─────────────────────────────────────────────────────────

    def preserve(
        self,
        payload: SecondaryPayload,
        output_dir: Path,
        adb: Callable[..., Any],
        device_serial: str = "",
        max_bytes: int = MAX_PAYLOAD_BYTES,
    ) -> SecondaryPayload:
        """
        Pull the artifact off the device and hash it.

        `adb` is the sandbox provider's adb callable - injected rather than
        imported so this never opens its own path to the device, and so tests
        do not need an emulator. A failure to preserve leaves the payload at
        the rung it had reached; it never fabricates a hash.
        """
        size = self._device_file_size(payload.device_path, adb, device_serial)
        if size > 0:
            payload.size_bytes = size
            payload.promote(
                PayloadStatus.DOWNLOADED.value,
                f"Artifact present on device ({size} bytes)",
            )
        if size > max_bytes:
            payload.blocked_by_policy = True
            payload.status = PayloadStatus.BLOCKED.value
            payload.notes.append(
                f"Not preserved: {size} bytes exceeds the {max_bytes}-byte limit"
            )
            logger.warning(
                "[SecondaryPayload] BLOCKED %s (%d > %d bytes)",
                payload.device_path, size, max_bytes,
            )
            return payload

        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            payload.notes.append(f"Could not create output directory: {exc}")
            return payload

        local = output_dir / (payload.filename or "secondary.apk")
        args = ["-s", device_serial] if device_serial else []
        try:
            adb(*args, "pull", payload.device_path, str(local), timeout=60)
        except Exception as exc:  # noqa: BLE001 - adb failure must not abort a run
            payload.notes.append(f"Pull failed: {exc}")
            logger.warning(
                "[SecondaryPayload] pull failed for %s: %s",
                payload.device_path, exc,
            )
            return payload

        if not local.exists():
            payload.notes.append("Pull reported success but no local file appeared")
            return payload

        payload.local_path = str(local)
        payload.sha256 = sha256_file(local)
        if not payload.size_bytes:
            payload.size_bytes = local.stat().st_size
            payload.promote(PayloadStatus.DOWNLOADED.value)
        payload.promote(PayloadStatus.HASHED.value, "Preserved and hashed")
        logger.info(
            "[SecondaryPayload] HASHED %s sha256=%s size=%d",
            payload.filename, payload.sha256, payload.size_bytes,
        )
        self.identify(payload)
        return payload

    def _device_file_size(
        self, path: str, adb: Callable[..., Any], device_serial: str,
    ) -> int:
        args = ["-s", device_serial] if device_serial else []
        try:
            result = adb(*args, "shell", "stat", "-c", "%s", path, timeout=10)
        except Exception:  # noqa: BLE001
            return 0
        text = result[1] if isinstance(result, tuple) and len(result) > 1 else result
        if not isinstance(text, str):
            return 0
        match = re.search(r"\d+", text)
        return int(match.group(0)) if match else 0

    def identify(self, payload: SecondaryPayload) -> SecondaryPayload:
        """
        Read the child's package name from the preserved file.

        Best effort: if androguard is unavailable or the file is not a valid
        APK, the payload keeps its hash and simply has no package name. An
        unreadable child is still a real finding.
        """
        if not payload.local_path:
            return payload
        try:
            from androguard.core.apk import APK  # type: ignore

            apk = APK(payload.local_path)
            payload.package_name = apk.get_package() or ""
            payload.version_name = apk.get_androidversion_name() or ""
        except Exception as exc:  # noqa: BLE001
            payload.notes.append(f"Could not parse child APK metadata: {exc}")
        return payload

    def confirm_installed(self, package_name: str) -> Optional[SecondaryPayload]:
        """Promote to INSTALLED only on evidence the package is really present."""
        for payload in self._by_path.values():
            if payload.package_name and payload.package_name == package_name:
                payload.install_confirmed = True
                payload.promote(
                    PayloadStatus.INSTALLED.value,
                    f"Package {package_name} confirmed present on the device",
                )
                return payload
        return None

    # ── output ───────────────────────────────────────────────────────────────

    @property
    def payloads(self) -> List[SecondaryPayload]:
        return list(self._by_path.values())

    def to_records(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._by_path.values()]

    def summary(self) -> Dict[str, Any]:
        payloads = self.payloads
        return {
            "count": len(payloads),
            "hashed": sum(1 for p in payloads if p.sha256),
            "install_requested": sum(1 for p in payloads if p.install_requested),
            "install_confirmed": sum(1 for p in payloads if p.install_confirmed),
            "blocked": sum(1 for p in payloads if p.blocked_by_policy),
            "dropped_over_budget": self.dropped_over_budget,
        }


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of a file, read in chunks so a large APK cannot exhaust memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
