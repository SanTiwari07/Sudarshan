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
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

#: Refuse to preserve anything larger than this. A malicious sample can point
#: at an arbitrarily large file, and pulling it would be the DoS.
MAX_PAYLOAD_BYTES = 200 * 1024 * 1024

#: Hooks whose events describe a secondary payload. Keep in step with
#: banking_trojan.js; tests assert every name here is actually emitted.
HOOK_APK_WRITE = "FileOutputStream.apkWrite"
HOOK_DOWNLOAD_ENQUEUE = "DownloadManager.enqueue"
HOOK_INSTALL_REQUEST = "Intent.installPackageRequest"

#: Executable payload extensions. A dropper that ships its second stage as a
#: ZIP of DEX and SO files is not doing anything exotic - it is the ordinary
#: way to avoid an install prompt - and matching only ".apk" meant those runs
#: reported no secondary payload at all while the archive sat on disk.
PAYLOAD_EXTENSIONS: frozenset[str] = frozenset({
    ".apk", ".zip", ".dex", ".jar", ".so",
})

_PAYLOAD_PATH_RE = re.compile(
    r"(/[\w./@\-+ ]*?\.(?:apk|zip|dex|jar|so))", re.IGNORECASE
)

#: Retained under its old name: it is imported by name elsewhere, and a rename
#: is not what this change is about.
_APK_PATH_RE = _PAYLOAD_PATH_RE


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
    #: Executable members recovered from this artifact when it is an archive.
    #: Kept on the parent rather than promoted to payloads of their own: a DEX
    #: inside a ZIP was never written to the device as a file, and inventing a
    #: device_path for it would claim an artifact that does not exist there.
    child_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    #: What the parent did that produced this payload ("download", "install
    #: intent", the hook name). Distinct from `source_hook`, which names the
    #: instrumentation that saw it, where this names the app behaviour.
    trigger: str = ""
    #: Exploration state of the installed child, as a surface in its own right.
    #: "" until the child is actually installed and launchable.
    exploration_state: str = ""
    #: Screens attributed to the child, so its coverage can be reported without
    #: being confused with the parent's.
    child_states_explored: int = 0
    child_actions_taken: int = 0
    launched_at_ms: int = 0

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
            "child_artifacts": [dict(c) for c in self.child_artifacts],
            "notes": list(self.notes),
            "trigger": self.trigger,
            "exploration_state": self.exploration_state,
            "child_states_explored": self.child_states_explored,
            "child_actions_taken": self.child_actions_taken,
            "launched_at_ms": self.launched_at_ms,
        }


def extract_apk_path(event: Dict[str, Any]) -> str:
    """
    Recover a payload path from an event, or "" when it names none.

    Matches every extension in :data:`PAYLOAD_EXTENSIONS`, not only ``.apk``.
    The name is unchanged because callers import it by name; what it finds is
    wider than it once was.
    """
    for key in ("path", "file_path", "url", "description"):
        value = event.get(key) or (event.get("data") or {}).get(key)
        if not isinstance(value, str):
            continue
        match = _PAYLOAD_PATH_RE.search(value)
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
        #: Packages the sample LAUNCHED rather than installed, keyed by package.
        #:
        #: A loader whose own UI is empty and whose entire journey lives in a
        #: second, already-installed package is not covered by the payload
        #: machinery above: nothing was downloaded, so no install hook fires and
        #: `child_packages()` stays empty. Without this the payload's screens are
        #: EXTERNAL_APP, get no action inventory, and the run reports that the
        #: app never rendered a screen while a form sits on the emulator.
        self._launched: Dict[str, Dict[str, Any]] = {}

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

        local = output_dir / (payload.filename or "secondary_payload.bin")
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
        self.unpack(payload, output_dir)
        self.identify(payload)
        return payload

    def unpack(self, payload: SecondaryPayload, output_dir: Path) -> SecondaryPayload:
        """
        Catalogue the executable code inside a preserved archive.

        Reads only. The child artifacts are recorded against the parent's hash
        so the chain "app wrote un2vis.zip, which contained classes.dex" can be
        stated as one fact rather than two unconnected ones. A non-archive is
        left alone, and a failure to unpack leaves the payload exactly where it
        was on the ladder - nothing here promotes anything.
        """
        if not payload.local_path:
            return payload
        local = Path(payload.local_path)
        # An APK is a ZIP too, and unpacking every preserved APK would copy its
        # whole classes*.dex and lib/ tree onto disk for no new claim - APKs go
        # through identify() instead. Archives are the case where the executable
        # code is otherwise invisible.
        if local.suffix.lower() == ".apk":
            return payload
        if not zipfile.is_zipfile(local):
            return payload

        children = extract_and_catalog_archive(
            local,
            output_dir / f"{local.stem}_unpacked",
            parent_sha256=payload.sha256,
        )
        if not children:
            return payload
        payload.child_artifacts = children
        payload.notes.append(
            f"Archive contained {len(children)} executable artifact(s): "
            + ", ".join(sorted({c["type"] for c in children}))
        )
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

    # ── child applications as exploration surfaces ───────────────────────────
    #
    # An installed child APK is not just an artifact to hash. It is a second
    # application the sample chose to put on the device, and the interesting
    # behaviour - the overlay, the accessibility abuse, the SMS interception -
    # usually lives there rather than in the dropper. The walk therefore has to
    # be able to treat it as somewhere to go.
    #
    # Two rules make that safe, and both exist because the explorer's scope
    # guard would otherwise fight it:
    #
    #   · the parent investigation OWNS the child. Evidence collected inside
    #     the child stays attached to the parent's investigation, and the
    #     original APK context is never replaced.
    #   · a foreground package that is a KNOWN CHILD is in scope. Without this
    #     the scope guard sees a foreign package, calls it a departure, and
    #     navigates back - which is exactly the wrong response to the sample
    #     having just installed its own payload.

    def register_launch_handoff(
        self,
        package_name: str,
        *,
        activity: str = "",
        detected_at_ms: int = 0,
        evidence: str = "",
    ) -> Dict[str, Any]:
        """
        Record that the sample put ANOTHER package's UI in front of the victim.

        This is a hand-off, not a departure: the sample chose the destination,
        the sample is still running behind it, and the journey the analysis
        exists to observe is happening there. Registering it makes the package
        a first-class surface of THIS investigation - in scope for the walk,
        TARGET_APP for ownership, and counted in target-app depth - while the
        parent package remains the subject of the report.

        Idempotent: re-registering the same package refreshes nothing and
        returns the existing record, so a package that keeps returning to the
        foreground does not accumulate duplicates.
        """
        if not package_name or package_name == self.parent_package:
            return {}
        existing = self._launched.get(package_name)
        if existing is not None:
            return existing
        record = {
            "parent_package": self.parent_package,
            "child_package": package_name,
            "trigger": "launched_by_sample",
            "activity": activity,
            "detected_at_ms": detected_at_ms,
            "evidence": evidence,
            "relationship": "launched_by",
            "child_state": "not_explored",
        }
        self._launched[package_name] = record
        logger.info(
            "[SecondaryPayload] LAUNCH_HANDOFF parent=%s child=%s activity=%s "
            "- adopting as a surface of this investigation (%s)",
            self.parent_package, package_name, activity,
            evidence or "no further evidence",
        )
        return record

    def launched_packages(self) -> Set[str]:
        """Packages the sample launched but did not install."""
        return set(self._launched)

    def child_packages(self) -> Set[str]:
        """Packages the sample installed or launched - either way, its own."""
        return {
            p.package_name for p in self._by_path.values()
            if p.package_name and p.install_confirmed
        } | set(self._launched)

    def is_child_package(self, package_name: str) -> bool:
        """Whether this foreground package is a child of the investigation."""
        if not package_name:
            return False
        return package_name in self.child_packages()

    def relationship_for(self, package_name: str) -> Optional[Dict[str, Any]]:
        """
        The parent→child relationship record for an installed child.

        Returned rather than logged so the caller can attach it to the
        investigation's evidence with the parent context intact.
        """
        launched = self._launched.get(package_name)
        if launched is not None:
            return launched
        for payload in self._by_path.values():
            if payload.package_name and payload.package_name == package_name:
                return {
                    "parent_package": payload.parent_package or self.parent_package,
                    "child_package": payload.package_name,
                    "trigger": payload.trigger or payload.source_hook,
                    "installation_event": {
                        "install_requested": payload.install_requested,
                        "install_confirmed": payload.install_confirmed,
                        "status": payload.status,
                        "device_path": payload.device_path,
                        "url": payload.url,
                    },
                    "child_state": payload.exploration_state or "not_explored",
                    "sha256": payload.sha256,
                    "relationship": "installed_by",
                }
        return None

    def exploration_candidates(self) -> List[SecondaryPayload]:
        """
        Installed children that are worth exploring and have not been yet.

        A payload policy refused to preserve is excluded: the run declined to
        handle that artifact, and launching it anyway would contradict the
        containment decision already taken.
        """
        return [
            p for p in self._by_path.values()
            if p.package_name
            and p.install_confirmed
            and not p.blocked_by_policy
            and p.exploration_state in ("", "pending")
        ]

    def mark_child_exploration(
        self,
        package_name: str,
        *,
        state: str,
        states_explored: int = 0,
        actions_taken: int = 0,
        launched_at_ms: int = 0,
    ) -> Optional[SecondaryPayload]:
        """Record how far exploration of a child application got."""
        launched = self._launched.get(package_name)
        if launched is not None:
            launched["child_state"] = state
            if states_explored:
                launched["child_states_explored"] = states_explored
            if actions_taken:
                launched["child_actions_taken"] = actions_taken
            if launched_at_ms:
                launched["launched_at_ms"] = launched_at_ms
            return None
        for payload in self._by_path.values():
            if payload.package_name and payload.package_name == package_name:
                payload.exploration_state = state
                if states_explored:
                    payload.child_states_explored = states_explored
                if actions_taken:
                    payload.child_actions_taken = actions_taken
                if launched_at_ms:
                    payload.launched_at_ms = launched_at_ms
                if state == "explored":
                    payload.promote(
                        PayloadStatus.ANALYZED.value,
                        f"Child application {package_name} explored as a "
                        f"first-class surface of this investigation",
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
            "archives_unpacked": sum(1 for p in payloads if p.child_artifacts),
            "child_artifacts": sum(len(p.child_artifacts) for p in payloads),
            "dropped_over_budget": self.dropped_over_budget,
        }


def extract_and_catalog_archive(
    archive_path: Path,
    output_dir: Path,
    parent_sha256: str = "",
    max_members: int = 64,
    max_total_bytes: int = MAX_PAYLOAD_BYTES,
) -> List[Dict[str, Any]]:
    """
    Unpack a downloaded archive and catalogue the executable code inside it.

    Extracts only members with an executable extension - a ZIP of a thousand
    PNGs is not the finding - and records SHA-256 and declared size for each,
    linked to `parent_sha256` so the report can show provenance rather than a
    flat list of hashes.

    Three things the sample controls are bounded here, because it authored the
    archive and every one of them is a way to attack the analyst:

      * member paths, which may contain ``../`` or an absolute root and would
        otherwise write outside `output_dir` (Zip Slip);
      * member count, capped at `max_members`;
      * uncompressed size, capped in aggregate at `max_total_bytes`, which is
        what stops a zip bomb.

    Never raises on a malformed archive: an unreadable archive is a finding,
    not a crash. Returns the catalogue, which is empty when nothing executable
    was recovered.
    """
    discovered: List[Dict[str, Any]] = []
    if not archive_path.is_file() or not zipfile.is_zipfile(archive_path):
        return discovered

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning(
            "[SecondaryPayload] could not create %s for archive %s: %s",
            output_dir, archive_path.name, exc,
        )
        return discovered

    resolved_out = output_dir.resolve()
    extracted_bytes = 0

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for member in zf.infolist():
                if len(discovered) >= max_members:
                    logger.warning(
                        "[SecondaryPayload] archive %s: member cap %d reached",
                        archive_path.name, max_members,
                    )
                    break
                if member.is_dir():
                    continue

                ext = Path(member.filename).suffix.lower()
                if ext not in PAYLOAD_EXTENSIONS:
                    continue

                # Zip Slip: resolve the destination and require it to stay
                # inside output_dir. Checked BEFORE extraction, because
                # ZipFile.extract writes the file and then there is nothing
                # left to prevent.
                try:
                    target_file = (output_dir / member.filename).resolve()
                except (OSError, ValueError):
                    logger.warning(
                        "[Security] Unusable member path in archive %s: %s",
                        archive_path.name, member.filename,
                    )
                    continue
                if resolved_out not in target_file.parents and target_file != resolved_out:
                    logger.warning(
                        "[Security] Path traversal attempt in archive: %s",
                        member.filename,
                    )
                    continue

                if extracted_bytes + member.file_size > max_total_bytes:
                    logger.warning(
                        "[SecondaryPayload] archive %s: %s would exceed the "
                        "%d-byte extraction budget; not extracted",
                        archive_path.name, member.filename, max_total_bytes,
                    )
                    continue

                try:
                    extracted = zf.extract(member, path=output_dir)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "[SecondaryPayload] could not extract %s from %s: %s",
                        member.filename, archive_path.name, exc,
                    )
                    continue

                extracted_path = Path(extracted)
                extracted_bytes += extracted_path.stat().st_size
                discovered.append({
                    "filename": member.filename,
                    "local_path": str(extracted_path),
                    "sha256": sha256_file(extracted_path),
                    "size_bytes": member.file_size,
                    "type": ext.lstrip(".").upper(),
                    "parent_sha256": parent_sha256,
                    "parent_archive": archive_path.name,
                })
    except (zipfile.BadZipFile, OSError) as exc:
        logger.warning(
            "[SecondaryPayload] archive %s could not be read: %s",
            archive_path.name, exc,
        )
        return discovered

    if discovered:
        logger.info(
            "[SecondaryPayload] ARCHIVE_UNPACKED %s -> %d executable child "
            "artifact(s): %s",
            archive_path.name, len(discovered),
            ", ".join(c["filename"] for c in discovered[:6]),
        )
    return discovered


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """SHA-256 of a file, read in chunks so a large APK cannot exhaust memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
