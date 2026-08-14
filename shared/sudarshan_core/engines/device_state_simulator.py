"""
SUDARSHAN - Device State Simulator
===================================
Two jobs, both about making the sandbox look like a phone somebody uses:

1. **Runtime conditions** - WiFi, battery, location - applied through the active
   SandboxProvider so multi-stage profiles work on Genymotion and Android
   Studio without hardcoding ``adb emu``.

2. **Device history** - contacts, SMS, call log and camera roll, seeded from a
   JSON persona (see :mod:`sudarshan_core.engines.persona`).

The second exists because an empty device is the cheapest sandbox tell there
is. Checking whether the contacts provider returns zero rows costs one query,
survives every emulator-property patch, and is used by evasion-first banking
trojans to decide whether to unpack. A sample that aborts on it yields a clean
run that proves nothing.

Every device write goes through ``SandboxProvider.adb_shell``, so the ADB
binary is discovered dynamically, the containment policy is enforced, and the
subprocess is invoked with an argument list rather than a shell string.
"""

from __future__ import annotations

import logging
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sudarshan_core.engines.persona import (
    CallEntry,
    Contact,
    Persona,
    Photo,
    SmsMessage,
    list_personas,
    load_persona,
)

logger = logging.getLogger(__name__)

# Content provider URIs. Android framework constants - not sample-specific.
_URI_RAW_CONTACTS = "content://com.android.contacts/raw_contacts"
_URI_CONTACT_DATA = "content://com.android.contacts/data"
_URI_SMS_INBOX = "content://sms/inbox"
_URI_CALL_LOG = "content://call_log/calls"

_MIME_NAME = "vnd.android.cursor.item/name"
_MIME_PHONE = "vnd.android.cursor.item/phone_v2"

# Where the camera roll lives on every Android release this project supports.
_DCIM_DIR = "/sdcard/DCIM/Camera"

# `content insert` is one process spawn per row. Batching the shell round-trips
# keeps a 120-contact seed to a few seconds instead of a few minutes.
_BATCH_SIZE = 12


def sh_quote(value: str) -> str:
    """
    Quote a value for the *device's* shell.

    ``adb shell <cmd>`` hands ``cmd`` to the guest's ``sh`` as a single string,
    which then word-splits it. SMS bodies contain spaces, commas and
    apostrophes, so without quoting here a message body silently becomes a
    dozen mis-parsed arguments and the insert fails or - worse - inserts a
    truncated row. Host-side quoting cannot help: the host never sees a shell.
    """
    text = "" if value is None else str(value)
    return "'" + text.replace("'", "'\\''") + "'"


@dataclass
class SeedResult:
    """Outcome of one persona seeding pass."""

    persona_id: str = ""
    display_name: str = ""
    ok: bool = False
    rooted: bool = False
    api_level: int = 0
    contacts_inserted: int = 0
    messages_inserted: int = 0
    calls_inserted: int = 0
    photos_pushed: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persona_id": self.persona_id,
            "display_name": self.display_name,
            "ok": self.ok,
            "rooted": self.rooted,
            "api_level": self.api_level,
            "seeded": {
                "contacts": self.contacts_inserted,
                "messages": self.messages_inserted,
                "calls": self.calls_inserted,
                "photos": self.photos_pushed,
            },
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def _solid_png(width: int, height: int, rgb: Tuple[int, int, int]) -> bytes:
    """
    Encode a single-colour PNG.

    Written by hand rather than with Pillow: this runs inside the analysis
    engine, and adding a hard image-library dependency to seed a placeholder
    photo is not a trade worth making. The output is a spec-valid PNG that the
    Android media scanner indexes normally.
    """
    width = max(1, min(int(width), 4096))
    height = max(1, min(int(height), 4096))

    # Each scanline is prefixed with filter type 0 (None).
    row = bytes([0]) + bytes(rgb) * width
    raw = row * height

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(raw, 6))
        + _chunk(b"IEND", b"")
    )


class DeviceStateSimulator:
    def __init__(
        self,
        device_serial: str,
        adb_path: str = "adb",
        provider=None,
    ):
        self.device_serial = device_serial
        self.adb_path = adb_path
        self._provider = provider

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        from sudarshan_core.sandbox import get_sandbox_provider
        return get_sandbox_provider()

    def apply_profile(self, profile: str) -> bool:
        """Applies a predefined state profile via the sandbox provider."""
        logger.info(f"[DeviceState] Applying profile: {profile}")
        try:
            return self._get_provider().apply_state_profile(self.device_serial, profile)
        except Exception as e:
            logger.error(f"[DeviceState] Profile {profile!r} failed: {e}")
            return False

    def reset(self) -> bool:
        """Restores the device to a clean, default state."""
        try:
            return self._get_provider().reset_state(self.device_serial)
        except Exception as e:
            logger.error(f"[DeviceState] Reset failed: {e}")
            return False

    # ── Device probes ──────────────────────────────────────────────────────

    def _shell(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        try:
            return self._get_provider().adb_shell(
                self.device_serial, command, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[DeviceState] shell failed: %s", exc)
            return False, str(exc)

    def _shell_batch(self, commands: Sequence[str], timeout: int = 90) -> int:
        """
        Run several device commands per ADB round-trip.

        Returns the number that reported success. Commands are joined with
        ``;`` rather than ``&&`` so one rejected insert does not abandon the
        rest of the batch - partial seeding is far better than none.
        """
        if not commands:
            return 0
        succeeded = 0
        for start in range(0, len(commands), _BATCH_SIZE):
            chunk = commands[start : start + _BATCH_SIZE]
            # Each command echoes a marker on success so the count reflects
            # what the device actually did, not what we asked for.
            joined = " ; ".join(f"{c} && echo __OK__" for c in chunk)
            ok, out = self._shell(joined, timeout=timeout)
            succeeded += (out or "").count("__OK__")
            if not ok and "__OK__" not in (out or ""):
                logger.debug("[DeviceState] batch produced no successes: %s", (out or "")[:200])
        return succeeded

    def api_level(self) -> int:
        ok, out = self._shell("getprop ro.build.version.sdk", timeout=15)
        if not ok:
            return 0
        try:
            return int((out or "").strip().splitlines()[-1].strip())
        except (ValueError, IndexError):
            return 0

    def is_rooted(self) -> bool:
        try:
            return bool(self._get_provider().check_root(self.device_serial))
        except Exception:  # noqa: BLE001
            return False

    # ── Persona seeding ────────────────────────────────────────────────────

    @staticmethod
    def available_personas() -> List[Dict[str, Any]]:
        """Catalogue for the UI persona selector."""
        return list_personas()

    def seed_persona(
        self,
        persona_id: str = "default_retail_user",
        *,
        persona: Optional[Persona] = None,
        include: Optional[Sequence[str]] = None,
    ) -> SeedResult:
        """
        Write a persona's device history to the connected sandbox.

        ``include`` restricts which providers are touched (``contacts``,
        ``messages``, ``calls``, ``photos``); the default is all of them.

        Partial success is a normal outcome, not a failure. Writing to the SMS
        provider from the shell is refused on many stock images from API 29
        onward, while contacts and the call log usually still accept it. The
        result reports exactly what landed so the analyst knows which
        emptiness checks are actually cleared, rather than assuming a green
        tick means a fully furnished device.
        """
        loaded = persona or load_persona(persona_id)
        result = SeedResult(persona_id=persona_id)
        if loaded is None:
            result.errors.append(f"No persona template matching {persona_id!r}")
            return result

        result.persona_id = loaded.persona_id
        result.display_name = loaded.display_name
        result.api_level = self.api_level()
        result.rooted = self.is_rooted()

        wanted = set(include or ("contacts", "messages", "calls", "photos"))

        if not result.rooted:
            result.warnings.append(
                "Device shell is not root. Content-provider writes are "
                "attempted anyway - stock images often still permit contacts "
                "and call log, but the SMS provider usually refuses."
            )

        if "contacts" in wanted:
            result.contacts_inserted = self._seed_contacts(loaded.contacts, result)
        if "messages" in wanted:
            result.messages_inserted = self._seed_messages(loaded.messages, result)
        if "calls" in wanted:
            result.calls_inserted = self._seed_calls(loaded.calls, result)
        if "photos" in wanted:
            result.photos_pushed = self._seed_photos(loaded.photos, result)

        result.ok = any(
            (
                result.contacts_inserted,
                result.messages_inserted,
                result.calls_inserted,
                result.photos_pushed,
            )
        )
        if not result.ok:
            result.errors.append(
                "No provider accepted a write. The device may be non-root with "
                "a hardened provider policy; seed the emulator image manually "
                "or use a userdebug build."
            )
        logger.info(
            "[DeviceState] Persona %s seeded: %s contacts, %s SMS, %s calls, %s photos",
            result.persona_id,
            result.contacts_inserted,
            result.messages_inserted,
            result.calls_inserted,
            result.photos_pushed,
        )
        return result

    # ── Providers ──────────────────────────────────────────────────────────

    def _seed_contacts(self, contacts: Sequence[Contact], result: SeedResult) -> int:
        """
        Insert contacts as raw_contact + name row + phone row.

        A raw contact carries no name of its own - the display name and the
        number are separate ``data`` rows joined by ``raw_contact_id``. Since
        ``content insert`` does not return the new id, the id is read back from
        the provider after each batch of raw contacts.
        """
        if not contacts:
            return 0

        inserted = 0
        for start in range(0, len(contacts), _BATCH_SIZE):
            chunk = contacts[start : start + _BATCH_SIZE]

            raw_cmds = [
                f"content insert --uri {_URI_RAW_CONTACTS} "
                f"--bind account_name:s:{sh_quote('Sudarshan')} "
                f"--bind account_type:s:{sh_quote('com.sudarshan.persona')}"
                for _ in chunk
            ]
            created = self._shell_batch(raw_cmds)
            if not created:
                if start == 0:
                    result.warnings.append(
                        "Contacts provider rejected raw_contacts inserts."
                    )
                break

            ids = self._recent_raw_contact_ids(created)
            if not ids:
                result.warnings.append(
                    "Inserted raw contacts but could not read their ids back; "
                    "names and numbers were not attached."
                )
                break

            data_cmds: List[str] = []
            for contact, raw_id in zip(chunk, ids):
                data_cmds.append(
                    f"content insert --uri {_URI_CONTACT_DATA} "
                    f"--bind raw_contact_id:i:{raw_id} "
                    f"--bind mimetype:s:{sh_quote(_MIME_NAME)} "
                    f"--bind data1:s:{sh_quote(contact.display_name)} "
                    f"--bind data2:s:{sh_quote(contact.given_name)} "
                    f"--bind data3:s:{sh_quote(contact.family_name)}"
                )
                data_cmds.append(
                    f"content insert --uri {_URI_CONTACT_DATA} "
                    f"--bind raw_contact_id:i:{raw_id} "
                    f"--bind mimetype:s:{sh_quote(_MIME_PHONE)} "
                    f"--bind data1:s:{sh_quote(contact.phone)} "
                    f"--bind data2:i:2"
                )
            self._shell_batch(data_cmds, timeout=120)
            inserted += len(ids)

        return inserted

    def _recent_raw_contact_ids(self, count: int) -> List[int]:
        """Read back the ids of the raw contacts just inserted."""
        # Built outside the f-string: a backslash escape is not permitted
        # inside an f-string expression before Python 3.12.
        where_clause = sh_quote("account_type='com.sudarshan.persona'")
        ok, out = self._shell(
            f"content query --uri {_URI_RAW_CONTACTS} --projection _id "
            f"--where {where_clause}",
            timeout=45,
        )
        if not ok:
            return []
        ids: List[int] = []
        for line in (out or "").splitlines():
            # Rows look like: `Row: 0 _id=42`
            marker = "_id="
            if marker not in line:
                continue
            value = line.split(marker, 1)[1].split(",")[0].strip()
            if value.isdigit():
                ids.append(int(value))
        # Newest last; take the tail matching this batch.
        return ids[-count:] if count and len(ids) >= count else ids

    def _seed_messages(self, messages: Sequence[SmsMessage], result: SeedResult) -> int:
        if not messages:
            return 0
        commands = [
            f"content insert --uri {_URI_SMS_INBOX} "
            f"--bind address:s:{sh_quote(m.address)} "
            f"--bind body:s:{sh_quote(m.body)} "
            f"--bind date:l:{m.timestamp_ms} "
            f"--bind date_sent:l:{m.timestamp_ms} "
            f"--bind read:i:{m.read} "
            f"--bind type:i:{m.msg_type}"
            for m in messages
        ]
        inserted = self._shell_batch(commands, timeout=120)
        if not inserted:
            result.warnings.append(
                "SMS provider refused inserts. Android restricts writes to the "
                "default SMS app from API 29; bank-alert history was not seeded."
            )
        return inserted

    def _seed_calls(self, calls: Sequence[CallEntry], result: SeedResult) -> int:
        if not calls:
            return 0
        commands = [
            f"content insert --uri {_URI_CALL_LOG} "
            f"--bind number:s:{sh_quote(c.number)} "
            f"--bind date:l:{c.timestamp_ms} "
            f"--bind duration:l:{c.duration_s} "
            f"--bind type:i:{c.call_type} "
            f"--bind new:i:0"
            for c in calls
        ]
        inserted = self._shell_batch(commands, timeout=120)
        if not inserted:
            result.warnings.append("Call log provider refused inserts.")
        return inserted

    def _seed_photos(self, photos: Sequence[Photo], result: SeedResult) -> int:
        """
        Write placeholder photos into the camera roll and index them.

        The bytes are generated on the fly and streamed through
        ``base64 -d`` on the device: pushing files would need a host-side temp
        directory, and the images are a few hundred bytes each.
        """
        if not photos:
            return 0

        import base64

        self._shell(f"mkdir -p {_DCIM_DIR}", timeout=20)
        written = 0
        # A handful of muted tones - a camera roll of identical images is its
        # own implausibility.
        palette = [(52, 73, 94), (127, 140, 141), (44, 62, 80), (149, 165, 166)]

        for index, photo in enumerate(photos):
            png = _solid_png(photo.width, photo.height, palette[index % len(palette)])
            encoded = base64.b64encode(png).decode("ascii")
            remote = f"{_DCIM_DIR}/{photo.filename}"
            # `echo | base64 -d` avoids a host temp file and works on toybox
            # (Android 6+) as well as busybox images.
            ok, _ = self._shell(
                f"echo {sh_quote(encoded)} | base64 -d > {sh_quote(remote)}",
                timeout=45,
            )
            if ok:
                written += 1

        if written:
            # Ask the media scanner to index the directory so the images appear
            # in MediaStore, which is what an app actually queries.
            self._shell(
                "am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE "
                f"-d file://{_DCIM_DIR}",
                timeout=30,
            )
        else:
            result.warnings.append("Could not write placeholder photos to the camera roll.")
        return written
