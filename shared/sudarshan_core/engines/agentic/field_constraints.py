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


def generate_value(
    constraints: FieldConstraints,
    *,
    seed_token: str = "",
    rng: Optional[random.Random] = None,
) -> str:
    """
    A synthetic value that fits `constraints`.

    `seed_token` is the vault's per-run token, threaded in so the identity a
    form presents stays internally consistent across the several actions it
    takes to fill that form - a username and the email built from it have to
    agree, and a retry has to be able to re-enter what it entered before.

    Nothing here produces a value that could authenticate against a real
    service: identifiers are namespaced to the analysis domain, card numbers
    use a non-transactable test BIN, and every digit run is random.
    """
    r = rng or random
    ft = constraints.field_type
    token = seed_token or "".join(r.choice(string.ascii_lowercase) for _ in range(6))

    exact = constraints.exact_length

    # ── Codes and secrets ───────────────────────────────────────────────────
    if ft in {
        FieldType.OTP, FieldType.EMAIL_OTP, FieldType.VERIFICATION_CODE,
        FieldType.PIN, FieldType.MPIN, FieldType.PASSCODE, FieldType.CARD_CVV,
    }:
        n = exact or constraints.max_length or constraints.min_length or 6
        return _digits(n, r)

    if ft is FieldType.RECOVERY_CODE:
        n = exact or 8
        return _fit(
            "".join(r.choice(string.ascii_uppercase + string.digits) for _ in range(n)),
            constraints, r,
        )

    if ft is FieldType.PASSWORD:
        # Mixed classes so a password policy cannot reject it out of hand,
        # which would look like a credential failure and stop the walk for the
        # wrong reason.
        lo = constraints.min_length or 12
        hi = constraints.max_length or max(lo, 16)
        target = max(8, min(lo if lo > 8 else 12, hi))
        body = "".join(
            r.choice(string.ascii_letters) for _ in range(max(1, target - 5))
        )
        value = f"Pw{body}{_digits(2, r)}!"
        if constraints.numeric_only:
            value = _digits(target, r)
        return _fit(value, constraints, r)

    if ft is FieldType.SECURITY_ANSWER:
        return _fit(f"answer{token[:4]}", constraints, r)

    # ── Identity ────────────────────────────────────────────────────────────
    if ft in {
        FieldType.USERNAME, FieldType.USER_ID, FieldType.LOGIN_ID,
        FieldType.CUSTOMER_ID, FieldType.CIF,
    }:
        # Some banks make the login id numeric-only; honour that rather than
        # typing letters the keypad will drop.
        if constraints.numeric_only:
            return _digits(exact or constraints.max_length or 10, r)
        return _fit(f"user{token}", constraints, r)

    if ft is FieldType.CUSTOMER_NUMBER:
        return _digits(exact or 10, r)

    if ft is FieldType.EMAIL:
        return f"user{token}@sudarshan-analysis.test"

    if ft is FieldType.UPI_ID:
        return f"user{token}@analysis"

    # ── Contact ─────────────────────────────────────────────────────────────
    if ft in {FieldType.PHONE, FieldType.MOBILE}:
        n = exact or constraints.max_length or 10
        # Leading 9 so Indian-format validators accept the shape.
        return ("9" + _digits(max(0, n - 1), r))[:n]

    # ── Person ──────────────────────────────────────────────────────────────
    if ft is FieldType.FULL_NAME:
        return _fit(f"Analysis {token[:4].title()}", constraints, r)
    if ft is FieldType.FIRST_NAME:
        return _fit("Analysis", constraints, r)
    if ft is FieldType.LAST_NAME:
        return _fit(token[:5].title() or "Tester", constraints, r)
    if ft is FieldType.BENEFICIARY_NAME:
        return _fit(f"Beneficiary {token[:3].title()}", constraints, r)

    # ── Demographics ────────────────────────────────────────────────────────
    if ft is FieldType.DATE_OF_BIRTH:
        return "01/01/1990"
    if ft is FieldType.ADDRESS:
        return _fit("1 Security Lab, Cyber District", constraints, r)
    if ft is FieldType.CITY:
        return _fit("Testville", constraints, r)
    if ft is FieldType.STATE:
        return _fit("Testland", constraints, r)
    if ft is FieldType.POSTAL_CODE:
        return _digits(exact or 6, r)

    # ── Instruments ─────────────────────────────────────────────────────────
    if ft in {FieldType.ACCOUNT_NUMBER, FieldType.BENEFICIARY_ACCOUNT}:
        return _digits(exact or constraints.max_length or 12, r)
    if ft is FieldType.CARD_NUMBER:
        n = exact or 16
        return (_SYNTHETIC_CARD_PREFIX + _digits(max(0, n - 4), r))[:n]
    if ft is FieldType.CARD_EXPIRY:
        return "12/30"
    if ft is FieldType.IFSC:
        # 4 letters + '0' + 6 alphanumerics is the published IFSC shape.
        return "TEST0" + _digits(6, r)

    # ── Reference numbers ───────────────────────────────────────────────────
    if ft in {
        FieldType.EMPLOYEE_ID, FieldType.APPLICATION_ID,
        FieldType.POLICY_NUMBER, FieldType.REFERENCE_NUMBER,
    }:
        return _fit(f"REF{_digits(8, r)}", constraints, r)
    if ft is FieldType.REFERRAL_CODE:
        return _fit(f"REFER{token[:4].upper()}", constraints, r)

    # ── Non-credential ──────────────────────────────────────────────────────
    if ft is FieldType.AMOUNT:
        return "100"
    if ft is FieldType.SEARCH:
        return "search_query"
    if ft is FieldType.HOST:
        # Loopback on purpose: exercise the field without repointing the sample
        # at something it was not already talking to.
        return "127.0.0.1"
    if ft is FieldType.PORT:
        return "8080"

    if constraints.numeric_only:
        return _digits(exact or constraints.max_length or 6, r)
    return _fit(f"t{token}", constraints, r)
