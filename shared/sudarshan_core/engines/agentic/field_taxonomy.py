"""
SUDARSHAN - Semantic field taxonomy for synthetic-victim form filling.

The agent used to know thirteen kinds of field. That was enough to tell a
password box from a search box, and not enough for anything a banking app
actually asks for: "CIF Number", "MPIN", "IFSC", "Beneficiary Account" and
"Card CVV" all collapsed into `account` or fell through to `username`, and the
value typed was wrong in a way the app answered with a validation error rather
than a login. This module names the fields properly.

Two vocabularies exist, deliberately:

:class:`FieldType`
    The semantic vocabulary. What the field IS. New code classifies into this.

**legacy kinds**
    The thirteen strings that already travel on the wire as ``field_hint``
    (``username``, ``password``, ``otp``, ...). ``ToolExecutor``, the planner
    prompt, the audit log and several tests all speak this. Every FieldType
    maps onto one via :func:`legacy_kind_for`, so a screen classified as
    ``CARD_CVV`` still reaches an executor that has only ever heard of
    ``account`` - the wire format does not change and nothing downstream has to
    be taught the new names at the same time as the new names appear.

The mapping is many-to-one and lossy on purpose. It exists to keep the old
contract working, not to round-trip: `legacy_kind_for(CIF) == "username"` is
correct, because a CIF number is the thing you log in with, and an executor
that only knows legacy kinds should treat it as an identifier.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Optional, Set

__all__ = [
    "FieldType",
    "LEGACY_FIELD_KINDS",
    "NUMERIC_FIELD_TYPES",
    "SECRET_FIELD_TYPES",
    "coerce_field_type",
    "is_secret_field",
    "legacy_kind_for",
]


class FieldType(str, Enum):
    """
    What a form field is asking for.

    ``str`` mixin so a FieldType serialises as its own name in JSON, evidence
    payloads and log lines without a caller having to remember ``.value``.
    """

    UNKNOWN = "UNKNOWN"

    # ── Identity ────────────────────────────────────────────────────────────
    USERNAME = "USERNAME"
    USER_ID = "USER_ID"
    LOGIN_ID = "LOGIN_ID"

    # ── Banking customer identifiers ────────────────────────────────────────
    CUSTOMER_ID = "CUSTOMER_ID"
    CUSTOMER_NUMBER = "CUSTOMER_NUMBER"
    CIF = "CIF"

    # ── Secrets ─────────────────────────────────────────────────────────────
    EMAIL = "EMAIL"
    PASSWORD = "PASSWORD"
    PIN = "PIN"
    MPIN = "MPIN"
    PASSCODE = "PASSCODE"

    # ── One-time / recovery codes ───────────────────────────────────────────
    OTP = "OTP"
    EMAIL_OTP = "EMAIL_OTP"
    VERIFICATION_CODE = "VERIFICATION_CODE"
    RECOVERY_CODE = "RECOVERY_CODE"

    # ── Contact ─────────────────────────────────────────────────────────────
    PHONE = "PHONE"
    MOBILE = "MOBILE"

    # ── Person ──────────────────────────────────────────────────────────────
    FULL_NAME = "FULL_NAME"
    FIRST_NAME = "FIRST_NAME"
    LAST_NAME = "LAST_NAME"

    # ── Relatives ───────────────────────────────────────────────────────────
    # Indian KYC and challan/RTO forms ask for a parent's name alongside the
    # applicant's. Without their own types both collapsed into FULL_NAME, and
    # because the vault caches a value per (type, length) the parent box then
    # received the IDENTICAL string as the applicant box - a form that names
    # the same person as themselves and their own mother, which is exactly the
    # cross-field check a validator catches.
    MOTHER_NAME = "MOTHER_NAME"
    FATHER_NAME = "FATHER_NAME"

    # ── Demographics ────────────────────────────────────────────────────────
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    ADDRESS = "ADDRESS"
    CITY = "CITY"
    STATE = "STATE"
    POSTAL_CODE = "POSTAL_CODE"

    # ── Instruments ─────────────────────────────────────────────────────────
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    CARD_NUMBER = "CARD_NUMBER"
    CARD_EXPIRY = "CARD_EXPIRY"
    CARD_CVV = "CARD_CVV"

    # ── Payment rails ───────────────────────────────────────────────────────
    IFSC = "IFSC"
    UPI_ID = "UPI_ID"

    # ── Transfer counterparty ───────────────────────────────────────────────
    BENEFICIARY_NAME = "BENEFICIARY_NAME"
    BENEFICIARY_ACCOUNT = "BENEFICIARY_ACCOUNT"

    # ── Reference numbers ───────────────────────────────────────────────────
    EMPLOYEE_ID = "EMPLOYEE_ID"
    APPLICATION_ID = "APPLICATION_ID"
    REFERRAL_CODE = "REFERRAL_CODE"
    POLICY_NUMBER = "POLICY_NUMBER"
    REFERENCE_NUMBER = "REFERENCE_NUMBER"

    # ── Knowledge-based auth ────────────────────────────────────────────────
    SECURITY_ANSWER = "SECURITY_ANSWER"

    # ── Non-credential fields the walk still has to fill ────────────────────
    # Not in the requested list, but they already exist as legacy kinds and the
    # explorer relies on them: dropping them would regress config-screen and
    # transfer-amount handling that works today.
    AMOUNT = "AMOUNT"
    SEARCH = "SEARCH"
    HOST = "HOST"
    PORT = "PORT"
    TEXT = "TEXT"


#: The pre-existing wire vocabulary. Unchanged - this is the compatibility
#: surface, and adding to it would defeat the point.
LEGACY_FIELD_KINDS: FrozenSet[str] = frozenset({
    "username", "password", "email", "phone", "amount", "account",
    "name", "address", "search", "port", "host", "otp", "text",
})


#: FieldType → legacy ``field_hint``. Many-to-one and lossy by design; see the
#: module docstring. Every FieldType MUST appear here, which
#: ``test_field_taxonomy`` enforces so a new member cannot be added without
#: deciding how it degrades for old consumers.
_LEGACY_KIND: Dict[FieldType, str] = {
    FieldType.UNKNOWN: "text",

    # Everything you log in WITH is an identifier. A legacy executor asked for
    # "username" types the vault's identifier, which is the right value.
    FieldType.USERNAME: "username",
    FieldType.USER_ID: "username",
    FieldType.LOGIN_ID: "username",
    FieldType.CUSTOMER_ID: "username",
    FieldType.CUSTOMER_NUMBER: "username",
    FieldType.CIF: "username",

    FieldType.EMAIL: "email",

    # PIN/MPIN/PASSCODE degrade to "password" rather than "otp": they are
    # standing secrets re-entered every session, not one-shot codes, and the
    # legacy vault's password value is the closest honest match.
    FieldType.PASSWORD: "password",
    FieldType.PIN: "password",
    FieldType.MPIN: "password",
    FieldType.PASSCODE: "password",

    FieldType.OTP: "otp",
    FieldType.EMAIL_OTP: "otp",
    FieldType.VERIFICATION_CODE: "otp",
    FieldType.RECOVERY_CODE: "otp",

    FieldType.PHONE: "phone",
    FieldType.MOBILE: "phone",

    FieldType.FULL_NAME: "name",
    FieldType.FIRST_NAME: "name",
    FieldType.LAST_NAME: "name",
    FieldType.BENEFICIARY_NAME: "name",
    FieldType.MOTHER_NAME: "name",
    FieldType.FATHER_NAME: "name",

    FieldType.DATE_OF_BIRTH: "text",
    FieldType.ADDRESS: "address",
    FieldType.CITY: "address",
    FieldType.STATE: "address",
    FieldType.POSTAL_CODE: "address",

    FieldType.ACCOUNT_NUMBER: "account",
    FieldType.CARD_NUMBER: "account",
    FieldType.CARD_EXPIRY: "account",
    FieldType.CARD_CVV: "account",
    FieldType.IFSC: "account",
    FieldType.BENEFICIARY_ACCOUNT: "account",

    FieldType.UPI_ID: "email",   # user@handle - an email-shaped identifier

    FieldType.EMPLOYEE_ID: "text",
    FieldType.APPLICATION_ID: "text",
    FieldType.REFERRAL_CODE: "text",
    FieldType.POLICY_NUMBER: "text",
    FieldType.REFERENCE_NUMBER: "text",
    FieldType.SECURITY_ANSWER: "text",

    FieldType.AMOUNT: "amount",
    FieldType.SEARCH: "search",
    FieldType.HOST: "host",
    FieldType.PORT: "port",
    FieldType.TEXT: "text",
}


#: Fields whose VALUE must never appear in a log, a prompt, a ToolResult or an
#: evidence payload. Drives redaction and the G9 password-safe verification
#: path, so membership is a security decision rather than a formatting one.
SECRET_FIELD_TYPES: FrozenSet[FieldType] = frozenset({
    FieldType.PASSWORD,
    FieldType.PIN,
    FieldType.MPIN,
    FieldType.PASSCODE,
    FieldType.OTP,
    FieldType.EMAIL_OTP,
    FieldType.VERIFICATION_CODE,
    FieldType.RECOVERY_CODE,
    FieldType.CARD_CVV,
    FieldType.CARD_NUMBER,
    FieldType.SECURITY_ANSWER,
})


#: Fields that must be filled with digits only. A letter typed into a numeric
#: keypad field is silently dropped by the IME, which the walk then reads as a
#: field that would not accept input.
NUMERIC_FIELD_TYPES: FrozenSet[FieldType] = frozenset({
    FieldType.PIN,
    FieldType.MPIN,
    FieldType.PASSCODE,
    FieldType.OTP,
    FieldType.EMAIL_OTP,
    FieldType.VERIFICATION_CODE,
    FieldType.PHONE,
    FieldType.MOBILE,
    FieldType.ACCOUNT_NUMBER,
    FieldType.BENEFICIARY_ACCOUNT,
    FieldType.CARD_NUMBER,
    FieldType.CARD_CVV,
    FieldType.POSTAL_CODE,
    FieldType.CUSTOMER_NUMBER,
    FieldType.AMOUNT,
    FieldType.PORT,
})


def legacy_kind_for(field_type: "FieldType | str") -> str:
    """
    The legacy ``field_hint`` string for a semantic field type.

    Total over FieldType. Unrecognised input degrades to ``"text"`` rather than
    raising: a classification failure must cost one mistyped field, never the
    run.
    """
    ft = coerce_field_type(field_type)
    return _LEGACY_KIND.get(ft, "text")


def coerce_field_type(value: "FieldType | str | None") -> FieldType:
    """
    Best-effort FieldType from whatever a caller has.

    Accepts a FieldType, a semantic name (``"MPIN"``), or a legacy kind
    (``"password"``). The legacy direction is needed because actions replayed
    from a checkpoint, or produced by the LLM planner's prompt vocabulary,
    carry only the old string.
    """
    if isinstance(value, FieldType):
        return value
    if not value:
        return FieldType.UNKNOWN

    token = str(value).strip()
    try:
        return FieldType(token.upper())
    except ValueError:
        pass

    return _LEGACY_TO_TYPE.get(token.lower(), FieldType.UNKNOWN)


#: Legacy kind → the FieldType it most likely meant. Used only when upgrading
#: an old string; the reverse map is the authoritative one.
_LEGACY_TO_TYPE: Dict[str, FieldType] = {
    "username": FieldType.USERNAME,
    "password": FieldType.PASSWORD,
    "email":    FieldType.EMAIL,
    "phone":    FieldType.PHONE,
    "otp":      FieldType.OTP,
    "amount":   FieldType.AMOUNT,
    "account":  FieldType.ACCOUNT_NUMBER,
    "name":     FieldType.FULL_NAME,
    "address":  FieldType.ADDRESS,
    "search":   FieldType.SEARCH,
    "host":     FieldType.HOST,
    "port":     FieldType.PORT,
    "text":     FieldType.TEXT,
}


def is_secret_field(field_type: "FieldType | str") -> bool:
    """Whether this field's value must be redacted everywhere it could surface."""
    return coerce_field_type(field_type) in SECRET_FIELD_TYPES
