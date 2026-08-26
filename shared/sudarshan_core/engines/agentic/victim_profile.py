"""
SUDARSHAN - The Dumb Victim's identity.

A coherent synthetic citizen for the run to present to the application under
analysis: a name that reads like a name, an email whose local part matches it,
a phone in the Indian ten-digit shape, and a real city/state/PIN-code triple.

Why this exists
---------------
:func:`~sudarshan_core.engines.agentic.field_constraints.generate_value` used
to build every value from a per-run random token - ``user4f2kqz``,
``Analysis Kqmz``, ``user4f2kqz@sudarshan-analysis.test``, ``Testville`` /
``Testland``. Three separate costs:

1. Apps reject it. A city picker validating against a gazetteer has no
   ``Testville``, and a "name must be alphabetic, two words" check has no
   opinion in favour of ``Analysis Kqmz``. The form shows a validation error,
   the walk reads the app as refusing its data, and a journey that was never
   actually attempted is recorded as blocked.
2. It is incoherent. ``Analysis Kqmz`` with ``user4f2kqz@...`` and an unrelated
   address is not one person, so an app that cross-checks two fields cannot be
   satisfied.
3. It is unreadable as evidence. A screenshot of a form containing
   ``Analysis Kqmz`` tells an analyst nothing about what the app asked for.

What is deliberately NOT fixed
------------------------------
The identity varies between runs, and that is a security property, not an
oversight. A sample that sees ``sanskar_test`` typed into its login box on
every analysis can fingerprint the sandbox on one string compare and go
dormant - which would cost far more than incoherent form data ever did. So the
*template* is deterministic and meaningful while the *instance* is drawn per
run from :data:`_ROSTER` with a per-run numeric salt. Every roster entry is a
plausible person; none of them is always the same person.

Set ``SUDARSHAN_VICTIM_DETERMINISTIC=1`` to pin the identity for a reproducible
forensic run, accepting the fingerprinting trade-off in exchange for a run that
replays byte-for-byte.

Email addresses stay on the RFC 2606 reserved ``.test`` TLD, which cannot
resolve and cannot be delivered to. A real provider's domain would mean that a
sample exfiltrating its form contents, or triggering a "forgot password" flow,
reached real infrastructure belonging to someone else. ``.test`` is four
letters and passes Android's own ``Patterns.EMAIL_ADDRESS``, so nothing is
given up on the validation side.

Configuration
-------------
Every field is overridable by environment variable
(``SUDARSHAN_VICTIM_EMAIL``, ``SUDARSHAN_VICTIM_CITY``, ...), and a whole
profile can be supplied as JSON via ``SUDARSHAN_VICTIM_PROFILE_FILE``. An
operator who wants a specific identity - including a real-provider address, on
their own authority - sets it there.

Nothing here is a real credential. Like every other issued value these are
enrolled in the redaction set, so they do not reach a persistent report in
plaintext (§P28).
"""

from __future__ import annotations

import json
import logging
import os
import random
import string
from dataclasses import asdict, dataclass, fields as dataclass_fields
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

__all__ = [
    "SyntheticVictimProfile",
    "build_victim_profile",
    "get_victim_profile",
    "reset_profile_cache",
]


#: Prefix for the per-field environment overrides, e.g.
#: ``SUDARSHAN_VICTIM_EMAIL=alice@example.test``.
_ENV_PREFIX = "SUDARSHAN_VICTIM_"

#: (first, last, city, state, pincode, street). Each row is internally
#: consistent - the PIN code really does belong to that city - because an app
#: that validates a PIN against a city is exactly the kind of form the old
#: random values could never get past.
_ROSTER: Tuple[Tuple[str, str, str, str, str, str], ...] = (
    ("Sanskar", "Deshmukh", "Pune",      "Maharashtra",   "411001", "MG Road"),
    ("Aarav",   "Sharma",   "Jaipur",    "Rajasthan",     "302001", "Station Road"),
    ("Priya",   "Menon",    "Kochi",     "Kerala",        "682001", "Marine Drive"),
    ("Rohan",   "Iyer",     "Bengaluru", "Karnataka",     "560001", "Church Street"),
    ("Ananya",  "Bose",     "Kolkata",   "West Bengal",   "700001", "Park Street"),
    ("Vikram",  "Nair",     "Chennai",   "Tamil Nadu",    "600001", "Anna Salai"),
    ("Neha",    "Kulkarni", "Nagpur",    "Maharashtra",   "440001", "Civil Lines"),
    ("Arjun",   "Reddy",    "Hyderabad", "Telangana",     "500001", "Tank Bund Road"),
)

#: Reserved by RFC 2606. Cannot resolve, cannot receive mail.
_EMAIL_DOMAIN = "sudarshan-analysis.test"


@dataclass(frozen=True)
class SyntheticVictimProfile:
    """
    The synthetic citizen a run presents to the application under analysis.

    Frozen: a form filled across several actions must not be able to observe
    the identity changing underneath it.
    """

    # ── Person ──────────────────────────────────────────────────────────────
    first_name: str = "Sanskar"
    last_name: str = "Deshmukh"
    full_name: str = "Sanskar Deshmukh"

    # ── Identity ────────────────────────────────────────────────────────────
    user_id: str = "sanskar_deshmukh_001"
    username: str = "sanskar.deshmukh01"
    email: str = f"sanskar.deshmukh01@{_EMAIL_DOMAIN}"

    # ── Contact ─────────────────────────────────────────────────────────────
    #: Ten digits, leading 9, so an Indian-format validator accepts the shape.
    phone: str = "9812345670"

    # ── Secrets (sandbox values - authenticate against nothing) ─────────────
    #: Mixed character classes so a password policy cannot reject it out of
    #: hand, which would look like a credential failure and stop the walk for
    #: the wrong reason.
    password: str = "Sudarshan@2401"
    pin: str = "2401"
    mpin: str = "2401"
    #: Only useful where the sandbox can actually supply an OTP. An app that
    #: sends a real SMS will not accept this, and the walk must not read the
    #: resulting error as the app refusing the whole journey.
    otp: str = "240193"

    # ── Address ─────────────────────────────────────────────────────────────
    address: str = "12 MG Road, Pune"
    city: str = "Pune"
    state: str = "Maharashtra"
    pincode: str = "411001"

    # ── Demographics ────────────────────────────────────────────────────────
    date_of_birth: str = "01/01/1990"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def redactable_values(self) -> set:
        """
        Every value this profile can put on screen, for log redaction.

        Returned wholesale rather than only the obvious secrets: §P28 asks that
        the forensic record carry the field TYPE and the value SOURCE rather
        than the value, and an address and a phone number are personal-shaped
        data even when they are invented.
        """
        return {str(v) for v in asdict(self).values() if v}


def _env_overrides() -> Dict[str, str]:
    """Per-field overrides from the environment and the optional JSON file."""
    known = {f.name for f in dataclass_fields(SyntheticVictimProfile)}
    values: Dict[str, str] = {}

    path = os.getenv("SUDARSHAN_VICTIM_PROFILE_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if not isinstance(raw, dict):
                raise ValueError("profile file must contain a JSON object")
            for key, val in raw.items():
                name = str(key).strip().lower()
                if name in known and val:
                    values[name] = str(val)
                elif name not in known:
                    logger.warning(
                        "[VictimProfile] Ignoring unknown key '%s' in %s",
                        key, path,
                    )
        except Exception as exc:
            # An operator's typo degrades to the built-in identity. It must
            # never be able to abort a run.
            logger.warning(
                "[VictimProfile] Could not read %s (%s) - using built-in profile",
                path, exc,
            )

    for name in known:
        override = os.getenv(f"{_ENV_PREFIX}{name.upper()}", "").strip()
        if override:
            values[name] = override
    return values


def _deterministic() -> bool:
    return os.getenv("SUDARSHAN_VICTIM_DETERMINISTIC", "0").strip().lower() in (
        "1", "true", "yes", "on",
    )


def build_victim_profile(
    rng: Optional[random.Random] = None,
) -> SyntheticVictimProfile:
    """
    One synthetic citizen, drawn for this run.

    A roster entry supplies the person - name, city, state, PIN code - and a
    four-digit salt makes the identifiers unique to the run, so two analyses of
    the same sample never present the same login. Under
    ``SUDARSHAN_VICTIM_DETERMINISTIC`` the first roster entry and a fixed salt
    are used instead, which is what makes a forensic re-run reproducible.

    Environment overrides are applied last and win over everything.
    """
    overrides = _env_overrides()

    if _deterministic():
        first, last, city, state, pincode, street = _ROSTER[0]
        salt = "2401"
        house = "12"
    else:
        r = rng or random
        first, last, city, state, pincode, street = r.choice(_ROSTER)
        salt = "".join(r.choice(string.digits) for _ in range(4))
        house = str(r.randint(1, 99))

    handle = f"{first.lower()}.{last.lower()}{salt[:2]}"
    built = SyntheticVictimProfile(
        first_name=first,
        last_name=last,
        full_name=f"{first} {last}",
        user_id=f"{first.lower()}_{last.lower()}_{salt}",
        username=handle,
        email=f"{handle}@{_EMAIL_DOMAIN}",
        phone="9" + salt + salt[::-1] + salt[0],
        password=f"Sudarshan@{salt}",
        pin=salt,
        mpin=salt,
        otp=salt + salt[:2],
        address=f"{house} {street}, {city}",
        city=city,
        state=state,
        pincode=pincode,
        date_of_birth="01/01/1990",
    )
    if not overrides:
        return built

    merged = built.to_dict()
    merged.update(overrides)
    logger.info(
        "[VictimProfile] %d override(s) applied: %s",
        len(overrides), sorted(overrides),
    )
    return SyntheticVictimProfile(**merged)


_CACHED: Optional[SyntheticVictimProfile] = None


def get_victim_profile() -> SyntheticVictimProfile:
    """
    A process-level profile, for callers that hold no vault of their own.

    The vault builds and owns its own instance - that is what keeps two vaults
    in one process from presenting the same identity. This is the fallback for
    the few call sites that need *an* identity without a run behind them.
    """
    global _CACHED
    if _CACHED is None:
        _CACHED = build_victim_profile()
    return _CACHED


def reset_profile_cache() -> None:
    """Drop the cached profile so the next read re-consults the environment."""
    global _CACHED
    _CACHED = None
