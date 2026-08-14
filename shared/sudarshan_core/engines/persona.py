"""Persona templates - the device history a sandbox is missing.

An out-of-the-box emulator has no contacts, no messages, no call history and no
photos. That is a stronger sandbox tell than any emulator property: checking
whether ``ContactsContract`` returns zero rows costs one query and cannot be
patched away by renaming a build fingerprint. Evasive banking trojans use it,
and a sample that aborts on it produces a perfectly clean - and perfectly
worthless - analysis run.

This module turns a JSON template into concrete rows to insert. It performs no
I/O against a device: expansion is deterministic and pure so it can be unit
tested without an emulator, and so the same persona produces the same device
state on every run, which a reproducible forensic process requires.

Templates live in ``sudarshan_core/config/personas/*.json`` and are
operator-editable - see :func:`sudarshan_core.runtime_paths.persona_dir`.
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from sudarshan_core import runtime_paths

logger = logging.getLogger(__name__)

#: Expansion is seeded from the persona id, not from the clock, so a given
#: persona always yields the same names and numbers. A run that is re-executed
#: for verification must land on the same device state.
_SEED_SALT = "sudarshan-persona-v1"

# Bounds. A template is operator-editable, so a typo must not turn into a
# 100k-row insert loop that hangs the run.
_MAX_CONTACTS = 500
_MAX_SMS = 200
_MAX_CALLS = 300
_MAX_PHOTOS = 100


@dataclass
class Contact:
    display_name: str
    given_name: str
    family_name: str
    phone: str
    label: str = "Mobile"


@dataclass
class SmsMessage:
    address: str
    body: str
    timestamp_ms: int
    read: int = 1
    #: 1 = inbox, 2 = sent (Telephony.Sms.MESSAGE_TYPE_*)
    msg_type: int = 1


@dataclass
class CallEntry:
    number: str
    timestamp_ms: int
    duration_s: int
    #: 1 = incoming, 2 = outgoing, 3 = missed (CallLog.Calls.*_TYPE)
    call_type: int = 1


@dataclass
class Photo:
    filename: str
    width: int
    height: int
    album: str = "Camera"


@dataclass
class Persona:
    """A fully expanded device history, ready to be written to a device."""

    persona_id: str
    display_name: str
    description: str = ""
    rationale: List[str] = field(default_factory=list)
    contacts: List[Contact] = field(default_factory=list)
    messages: List[SmsMessage] = field(default_factory=list)
    calls: List[CallEntry] = field(default_factory=list)
    photos: List[Photo] = field(default_factory=list)
    source_path: Optional[Path] = None

    def summary(self) -> Dict[str, Any]:
        return {
            "persona_id": self.persona_id,
            "display_name": self.display_name,
            "description": self.description,
            "contacts": len(self.contacts),
            "messages": len(self.messages),
            "calls": len(self.calls),
            "photos": len(self.photos),
            "source": str(self.source_path) if self.source_path else "",
        }


# ── Template discovery ─────────────────────────────────────────────────────


def list_persona_files(directory: Optional[Path] = None) -> List[Path]:
    base = Path(directory) if directory else runtime_paths.persona_dir()
    if not base.is_dir():
        logger.warning("[Persona] template directory missing: %s", base)
        return []
    return sorted(p for p in base.glob("*.json") if p.is_file())


def list_personas(directory: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Lightweight catalogue for the persona selector, without expanding rows."""
    out: List[Dict[str, Any]] = []
    for path in list_persona_files(directory):
        try:
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[Persona] unreadable template %s: %s", path.name, exc)
            continue
        if not isinstance(raw, dict):
            continue
        out.append(
            {
                "persona_id": str(raw.get("persona_id") or path.stem),
                "display_name": str(raw.get("display_name") or path.stem),
                "description": str(raw.get("description") or ""),
                "contacts": int((raw.get("contacts") or {}).get("count") or 0),
                "messages": len(raw.get("sms") or []),
                "calls": int((raw.get("call_log") or {}).get("count") or 0),
                "photos": int((raw.get("gallery") or {}).get("count") or 0),
                "source": path.name,
            }
        )
    return out


def _resolve_template(persona_id: str, directory: Optional[Path]) -> Optional[Path]:
    wanted = runtime_paths.safe_component(persona_id)
    for path in list_persona_files(directory):
        if path.stem == wanted:
            return path
        try:
            raw = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(raw, dict) and str(raw.get("persona_id") or "") == persona_id:
            return path
    return None


# ── Expansion ──────────────────────────────────────────────────────────────


def _clamp(value: Any, default: int, maximum: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(n, maximum))


def _expand_contacts(spec: Dict[str, Any], rng: random.Random) -> List[Contact]:
    count = _clamp(spec.get("count"), 0, _MAX_CONTACTS)
    given = [str(n) for n in (spec.get("given_names") or []) if str(n).strip()]
    family = [str(n) for n in (spec.get("family_names") or []) if str(n).strip()]
    labels = [str(l) for l in (spec.get("labels") or ["Mobile"]) if str(l).strip()]
    prefixes = [str(p) for p in (spec.get("phone_prefixes") or ["+9198"]) if str(p).strip()]
    if not (count and given and family):
        return []

    contacts: List[Contact] = []
    seen_numbers: set = set()
    for index in range(count):
        # Deterministic walk rather than random choice, so a 120-contact
        # persona covers the name pool evenly instead of clustering.
        first = given[index % len(given)]
        last = family[(index // len(given)) % len(family)]
        prefix = prefixes[index % len(prefixes)]
        # Uniqueness matters: a contacts provider will happily store duplicate
        # numbers, but a sample profiling the device would see an implausible
        # address book.
        while True:
            number = f"{prefix}{rng.randint(1000000, 9999999)}"
            if number not in seen_numbers:
                seen_numbers.add(number)
                break
        contacts.append(
            Contact(
                display_name=f"{first} {last}",
                given_name=first,
                family_name=last,
                phone=number,
                label=labels[index % len(labels)],
            )
        )
    return contacts


def _expand_sms(entries: Sequence[Any], now_ms: int) -> List[SmsMessage]:
    messages: List[SmsMessage] = []
    for entry in list(entries or [])[:_MAX_SMS]:
        if not isinstance(entry, dict):
            continue
        address = str(entry.get("address") or "").strip()
        body = str(entry.get("body") or "").strip()
        if not address or not body:
            continue
        days_ago = _clamp(entry.get("days_ago"), 1, 3650)
        messages.append(
            SmsMessage(
                address=address,
                body=body,
                timestamp_ms=now_ms - days_ago * 86_400_000,
                read=1 if entry.get("read", 1) else 0,
                msg_type=_clamp(entry.get("type"), 1, 6) or 1,
            )
        )
    # Oldest first, so the inbox reads chronologically after insertion.
    messages.sort(key=lambda m: m.timestamp_ms)
    return messages


def _expand_calls(
    spec: Dict[str, Any],
    contacts: Sequence[Contact],
    now_ms: int,
    rng: random.Random,
) -> List[CallEntry]:
    count = _clamp(spec.get("count"), 0, _MAX_CALLS)
    if not count:
        return []
    max_days = _clamp(spec.get("max_days_ago"), 30, 3650) or 30
    try:
        incoming_ratio = float(spec.get("incoming_ratio", 0.5))
        missed_ratio = float(spec.get("missed_ratio", 0.1))
    except (TypeError, ValueError):
        incoming_ratio, missed_ratio = 0.5, 0.1

    calls: List[CallEntry] = []
    for index in range(count):
        # Calls to people in the address book, not to random numbers - a call
        # log full of unknown numbers is its own kind of implausible.
        if contacts:
            number = contacts[index % len(contacts)].phone
        else:
            number = f"+9198{rng.randint(1000000, 9999999)}"
        roll = rng.random()
        if roll < missed_ratio:
            call_type, duration = 3, 0
        elif roll < missed_ratio + incoming_ratio:
            call_type, duration = 1, rng.randint(15, 900)
        else:
            call_type, duration = 2, rng.randint(15, 900)
        offset_ms = rng.randint(0, max_days * 86_400_000)
        calls.append(
            CallEntry(
                number=number,
                timestamp_ms=now_ms - offset_ms,
                duration_s=duration,
                call_type=call_type,
            )
        )
    calls.sort(key=lambda c: c.timestamp_ms)
    return calls


def _expand_photos(spec: Dict[str, Any]) -> List[Photo]:
    count = _clamp(spec.get("count"), 0, _MAX_PHOTOS)
    if not count:
        return []
    width = _clamp(spec.get("width"), 1080, 8192) or 1080
    height = _clamp(spec.get("height"), 1920, 8192) or 1920
    album = str(spec.get("album") or "Camera").strip() or "Camera"
    return [
        Photo(
            filename=f"IMG_{20260101 + index:08d}_{100000 + index}.png",
            width=width,
            height=height,
            album=album,
        )
        for index in range(count)
    ]


def load_persona(
    persona_id: str = "default_retail_user",
    *,
    directory: Optional[Path] = None,
    now_ms: Optional[int] = None,
) -> Optional[Persona]:
    """
    Load and expand a persona template into concrete device rows.

    Returns ``None`` when the template is missing or unparseable, so a seeding
    request for an unknown persona fails visibly rather than silently seeding
    an empty device.
    """
    path = _resolve_template(persona_id, directory)
    if path is None:
        logger.warning("[Persona] no template matching %r", persona_id)
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[Persona] template %s unreadable: %s", path.name, exc)
        return None
    if not isinstance(raw, dict):
        return None

    resolved_id = str(raw.get("persona_id") or path.stem)
    rng = random.Random(f"{_SEED_SALT}:{resolved_id}")
    stamp = int(now_ms if now_ms is not None else time.time() * 1000)

    contacts = _expand_contacts(raw.get("contacts") or {}, rng)
    return Persona(
        persona_id=resolved_id,
        display_name=str(raw.get("display_name") or resolved_id),
        description=str(raw.get("description") or ""),
        rationale=[str(r) for r in (raw.get("rationale") or [])],
        contacts=contacts,
        messages=_expand_sms(raw.get("sms") or [], stamp),
        calls=_expand_calls(raw.get("call_log") or {}, contacts, stamp, rng),
        photos=_expand_photos(raw.get("gallery") or {}),
        source_path=path,
    )
