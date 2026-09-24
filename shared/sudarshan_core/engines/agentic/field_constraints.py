"""
SUDARSHAN - Constraint-aware synthetic value generation.

The vault used to issue one value per kind: a six-digit number for anything
OTP-shaped. Typed into a four-digit MPIN box the IME accepts the first four
digits and drops the rest, or the field rejects the entry outright - either way
the app answers with a validation error, the walk reads that as "credentials
refused", and a login that was never actually attempted is recorded as failed.
The value has to fit the field.

What we can actually observe
----------------------------
Standard ``uiautomator dump`` XML carries no ``maxlength``, no ``inputType``
and no ``pattern``. The attributes that exist are ``class``, ``password``,
``text``, ``content-desc`` and ``resource-id``. Some vendor builds and newer
API levels additionally emit ``hint`` and ``max-length``; those are read when
present and simply absent otherwise.

So length is established in falling order of authority:

1. an explicit ``max-length`` attribute, when the dump provides one;
2. a number stated in the label, hint or resource-id ("Enter 4-digit MPIN",
   "otp_6_digit") - which is how these apps actually tell the user;
3. the per-FieldType default below.

(2) is inference, not a declared constraint. It is right far more often than
the fixed six-digit default it replaces, and when it is wrong the cost is one
mistyped field rather than a misread login outcome.
"""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from sudarshan_core.engines.agentic.field_taxonomy import (
    NUMERIC_FIELD_TYPES,
    FieldType,
)

__all__ = [
    "FieldConstraints",
    "extract_constraints",
    "generate_value",
]


#: Default (min, max) length per field type. `None` means "no opinion" - the
#: generator produces its natural form and does not pad or truncate.
_DEFAULT_LENGTHS: Dict[FieldType, Tuple[Optional[int], Optional[int]]] = {
    FieldType.PIN:               (4, 4),
    FieldType.MPIN:              (4, 4),
    FieldType.PASSCODE:          (6, 6),
    FieldType.OTP:               (6, 6),
    FieldType.EMAIL_OTP:         (6, 6),
    FieldType.VERIFICATION_CODE: (6, 6),
    FieldType.RECOVERY_CODE:     (8, 8),
    FieldType.CARD_CVV:          (3, 3),
    FieldType.CARD_NUMBER:       (16, 16),
    FieldType.PHONE:             (10, 10),
    FieldType.MOBILE:            (10, 10),
    FieldType.POSTAL_CODE:       (6, 6),
    FieldType.ACCOUNT_NUMBER:    (12, 12),
    FieldType.BENEFICIARY_ACCOUNT: (12, 12),
    FieldType.CUSTOMER_NUMBER:   (10, 10),
    FieldType.IFSC:              (11, 11),
    FieldType.PASSWORD:          (8, 16),
}

#: "4-digit", "6 digit", "enter 4 digits". The digit count an app states in
#: prose is the most reliable length signal available on a WebView login form.
_DIGIT_COUNT_RE = re.compile(
    r"(\d{1,2})\s*[\-\s]?\s*(?:digit|digits|character|characters|char)\b",
    re.IGNORECASE,
)

#: "otp_6", "mpin4", "pin_4_box" - the same number hiding in a resource-id.
_ID_DIGIT_RE = re.compile(r"(?:^|[_\-])(\d{1,2})(?:$|[_\-])")

#: Values that are plausible but deliberately non-functional. These are typed
#: into a sandboxed sample under analysis; none of them is, or resembles, a
#: real financial credential. Card numbers use the 4111... test-BIN family that
#: every payment processor treats as non-transactable.
_SYNTHETIC_CARD_PREFIX = "4111"


@dataclass
class FieldConstraints:
    """
    What a value typed into this field has to look like.

    Carries `evidence` for the same reason the classifier does: when a field is
    filled with something odd, the run has to be able to say which observation
    produced that shape.
    """

    field_type: FieldType = FieldType.UNKNOWN
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    numeric_only: bool = False
    is_password: bool = False
    pattern: Optional[str] = None
    evidence: list = field(default_factory=list)

    @property
    def exact_length(self) -> Optional[int]:
        """The single length this field demands, when min and max agree."""
        if self.min_length is not None and self.min_length == self.max_length:
            return self.min_length
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_type": self.field_type.value,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "numeric_only": self.numeric_only,
            "is_password": self.is_password,
            "pattern": self.pattern,
            "evidence": list(self.evidence),
        }


def _stated_length(*sources: str) -> Tuple[Optional[int], str]:
    """A digit count stated in prose, with the text that stated it."""
    for src in sources:
        if not src:
            continue
        m = _DIGIT_COUNT_RE.search(src)
        if m:
            n = int(m.group(1))
            if 1 <= n <= 32:
                return n, f"stated_length={n} in {src.strip()[:48]!r}"
    return None, ""


def extract_constraints(
    *,
    field_type: "FieldType | str" = FieldType.UNKNOWN,
    field_label: str = "",
    hint: str = "",
    resource_id: str = "",
    content_desc: str = "",
    class_name: str = "",
    text: str = "",
    is_password: bool = False,
    max_length: Optional[int] = None,
    input_type: str = "",
) -> FieldConstraints:
    """
    Work out the shape of value this field will accept.

    `max_length` and `input_type` are threaded through for the dumps that
    provide them; both are optional and the function is complete without them.
    """
    from sudarshan_core.engines.agentic.field_taxonomy import coerce_field_type

    ft = coerce_field_type(field_type)
    evidence: list = []

    numeric = ft in NUMERIC_FIELD_TYPES
    if numeric:
        evidence.append(f"field_type={ft.value} is numeric")

    lo, hi = _DEFAULT_LENGTHS.get(ft, (None, None))
    if lo is not None or hi is not None:
        evidence.append(f"default_length[{ft.value}]=({lo},{hi})")

    # An input type, when the platform gave us one, is authoritative about
    # numeric-ness in a way that a caption never is.
    it_lower = (input_type or "").lower()
    if it_lower:
        if "number" in it_lower or "phone" in it_lower or "numeric" in it_lower:
            numeric = True
            evidence.append(f"inputType={input_type}")
        elif "email" in it_lower:
            numeric = False
            evidence.append(f"inputType={input_type}")

    # A stated digit count overrides the per-type default. "Enter your 4-digit
    # MPIN" beats our belief that an MPIN is 4 long, and beats it correctly on
    # the banks that use 6.
    stated, why = _stated_length(field_label, hint, content_desc, text)
    if stated is None:
        m = _ID_DIGIT_RE.search(resource_id or "")
        if m:
            n = int(m.group(1))
            # Guard against `otp_1` meaning "the first OTP box" rather than a
            # length. A single-digit length is a per-character keypad cell,
            # which the tap_sequence path handles, not the type path.
            if 3 <= n <= 32:
                stated, why = n, f"resource_id length hint={n}"

    if stated is not None:
        lo = hi = stated
        evidence.append(why)

    if max_length is not None and max_length > 0:
        # An explicit platform constraint outranks everything inferred.
        hi = max_length
        if lo is not None and lo > hi:
            lo = hi
        evidence.append(f"max-length={max_length}")

    return FieldConstraints(
        field_type=ft,
        min_length=lo,
        max_length=hi,
        numeric_only=numeric,
        is_password=bool(is_password) or ft in {
            FieldType.PASSWORD, FieldType.PIN, FieldType.MPIN, FieldType.PASSCODE,
        },
        evidence=evidence,
    )


# ─── Value generation ────────────────────────────────────────────────────────

def _digits(n: int, rng: random.Random) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def _fit(value: str, c: FieldConstraints, rng: random.Random) -> str:
    """
    Force a generated value inside the length window.

    Truncation is safe for the digit-shaped fields; for anything else growing
    is done with the value's own alphabet so a padded password still satisfies
    the character-class rules it was built to satisfy.
    """
    if c.max_length is not None and len(value) > c.max_length:
        value = value[: c.max_length]
    if c.min_length is not None and len(value) < c.min_length:
        pad_alphabet = string.digits if c.numeric_only else string.ascii_lowercase
        value += "".join(
            rng.choice(pad_alphabet) for _ in range(c.min_length - len(value))
        )
    return value


def _profile_value(
    constraints: FieldConstraints, profile: Any
) -> Optional[str]:
    """
    The Dumb Victim's own value for this field, or None if it has no opinion.

    Only the person-shaped types are answered here - a name, an email, an
    address, a login secret. Instrument numbers (card, IFSC, account) and
    one-shot codes stay randomised below: they are not part of an identity, a
    fixed card number across every run would be a fingerprint of the analyser,
    and the profile deliberately does not claim to own them.

    A profile value that cannot satisfy the field's measured constraints is
    REFUSED rather than mangled. Padding "Pune" out to a declared 8-character
    minimum produces "Punexqvz", which is neither the profile's city nor a
    plausible one; falling through to the generator gives a value built for
    that shape in the first place.
    """
    p = profile
    ft = constraints.field_type

    candidate: Optional[str] = {
        FieldType.FULL_NAME:     p.full_name,
        FieldType.FIRST_NAME:    p.first_name,
        FieldType.LAST_NAME:     p.last_name,
        FieldType.MOTHER_NAME:   p.mother_name,
        FieldType.FATHER_NAME:   p.father_name,
        FieldType.EMAIL:         p.email,
        FieldType.PHONE:         p.phone,
        FieldType.MOBILE:        p.phone,
        FieldType.USERNAME:      p.username,
        FieldType.USER_ID:       p.user_id,
        FieldType.LOGIN_ID:      p.user_id,
        FieldType.PASSWORD:      p.password,
        FieldType.PIN:           p.pin,
        FieldType.MPIN:          p.mpin,
        FieldType.OTP:           p.otp,
        FieldType.EMAIL_OTP:     p.otp,
        FieldType.ADDRESS:       p.address,
        FieldType.CITY:          p.city,
        FieldType.STATE:         p.state,
        FieldType.POSTAL_CODE:   p.pincode,
        FieldType.DATE_OF_BIRTH: p.date_of_birth,
    }.get(ft)

    if not candidate:
        return None

    # A numeric-only box cannot take "Sanskar Test User", and an identifier the
    # app renders on a digit keypad would silently drop every letter.
    if constraints.numeric_only and not candidate.isdigit():
        return None
    if constraints.exact_length is not None and len(candidate) != constraints.exact_length:
        return None
    if constraints.max_length is not None and len(candidate) > constraints.max_length:
        return None
    if constraints.min_length is not None and len(candidate) < constraints.min_length:
        return None
    return candidate



def generate_value(
    constraints: FieldConstraints,
    profile: Optional[Any] = None,
    rng: Optional[random.Random] = None,
    seed_token: str = "",
) -> str:
    """
    Generate a deterministic synthetic value satisfying the constraints.
    """
    r = rng or random

    if profile is not None:
        chosen = _profile_value(constraints, profile)
        if chosen is not None:
            return chosen

    from sudarshan_core.engines.agentic.synthetic_persona import generate_synthetic_value
    
    val = generate_synthetic_value(constraints.field_type)
    if val and not (constraints.numeric_only and not val.isdigit()):
        return _fit(val, constraints, r)

    # Fallback if somehow not mapped
    exact = constraints.exact_length
    if constraints.numeric_only:
        return _digits(exact or constraints.max_length or 6, r)
    return _fit("Test", constraints, r)
