"""
SUDARSHAN - Synthetic credential handling for dynamic analysis.

Two jobs, both of which the run used to do badly:

1. Work out WHAT a form field wants. The banking corpus renders its login
   screens in a WebView, so the EditText nodes carry no resource-id, no text
   and no content-desc - the only distinguishing signals are uiautomator's
   `password` attribute and the caption node rendered above the field. Without
   using them, every field resolved to the same fallback string and no login
   could ever succeed.

2. Supply a VALUE that is disposable and different every run. These are
   synthetic credentials for an app under analysis in a sandbox; they are never
   real user data, and they are never logged (see AuditLog's redaction, which
   reads :func:`all_secret_values`).

The agent keeps offering credentials until the app SAYS they are wrong.
:func:`login_rejected` is the stopping condition: an app that shows
"Invalid credentials" has answered the question, and retrying is pointless. An
app that shows nothing has not, and the walk should try again rather than
conclude the login screen is a dead end.
"""

from __future__ import annotations

import os
import random
import re
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sudarshan_core.engines.agentic.field_classifier import FieldClassification
    from sudarshan_core.engines.agentic.field_constraints import FieldConstraints

__all__ = [
    "FIELD_KINDS",
    "CredentialVault",
    "all_secret_values",
    "get_vault",
    "login_rejected",
    "login_succeeded_hint",
    "register_static_values",
    "resolve_field_kind",
    "resolve_field_classification",
]


#: The legacy kind vocabulary, retained because :data:`FIELD_KINDS` is part of
#: the public surface and ``field_hint`` still travels as one of these strings.
#: The MATCHING itself moved to
#: :mod:`~sudarshan_core.engines.agentic.field_classifier`, which resolves the
#: full semantic taxonomy; this table is no longer consulted at run time and is
#: kept only so the set of legal legacy kinds has one definition.
_KIND_PATTERNS: List[tuple] = [
    ("otp",      r"\b(otp|one[\s\-_]?time|verification\s*code|auth\s*code|mpin|passcode)\b"),
    ("password", r"(password|passwd|\bpwd\b|pin\b|secret)"),
    ("email",    r"(e[\s\-_]?mail|email)"),
    ("phone",    r"(mobile|phone|msisdn|contact\s*(no|number))"),
    ("amount",   r"(amount|amt|balance|value)"),
    ("account",  r"(account\s*(no|number)|\bacct\b|ifsc|card\s*(no|number))"),
    ("name",     r"(full\s*name|first\s*name|last\s*name|\bname\b)"),
    ("address",  r"(address|street|city|pincode|zip)"),
    ("search",   r"(search|query|find)"),
    # Config fields on debug/preferences screens. Given loopback values rather
    # than a username: the point is to exercise the field, not to repoint the
    # sample at something it was not already talking to.
    ("port",     r"\bport\b"),
    ("host",     r"(server\s*ip|\bip\b|hostname|\bhost\b|\burl\b|endpoint|domain)"),
    # Deliberately last: "Customer ID", "CRN", "User ID" and friends all mean
    # "the identifier you log in with", and they must not be swallowed by the
    # broader `name` or `account` patterns above.
    ("username", r"(user\s*name|username|user\s*id|userid|\buid\b|login\s*id|"
                 r"customer\s*id|\bcrn\b|client\s*id|\blogin\b|\bid\b)"),
]

FIELD_KINDS: Set[str] = {kind for kind, _ in _KIND_PATTERNS}


def resolve_field_classification(
    *,
    field_label: str = "",
    resource_id: str = "",
    content_desc: str = "",
    class_name: str = "",
    text: str = "",
    hint: str = "",
    input_type: str = "",
    is_password: bool = False,
    index: int = 0,
    screen_type: str = "",
) -> "FieldClassification":
    """
    The full classification of an input: type, confidence, evidence, source.

    This is the richer answer. :func:`resolve_field_kind` is the same
    computation collapsed to the legacy string, so the two can never disagree
    about what a field is.
    """
    from sudarshan_core.engines.agentic.field_classifier import classify_field

    return classify_field(
        field_label=field_label,
        resource_id=resource_id,
        content_desc=content_desc,
        class_name=class_name,
        text=text,
        hint=hint,
        input_type=input_type,
        is_password=is_password,
        index=index,
        screen_type=screen_type,
    )


def resolve_field_kind(
    *,
    field_label: str = "",
    resource_id: str = "",
    content_desc: str = "",
    class_name: str = "",
    text: str = "",
    hint: str = "",
    input_type: str = "",
    is_password: bool = False,
    index: int = 0,
) -> str:
    """
    The kind of value this input wants, as a legacy ``field_hint`` string.

    Unchanged contract: the return value is one of the thirteen strings in
    :data:`FIELD_KINDS` plus ``"text"``, which is what ``ToolExecutor``, the
    planner prompt and the audit log have always consumed.

    The computation now lives in
    :mod:`~sudarshan_core.engines.agentic.field_classifier`, which resolves the
    full semantic type (``MPIN``, ``CIF``, ``CARD_CVV``, ...) and then degrades
    it to the legacy vocabulary. Callers that want the specific type - to size
    a value correctly, or to decide whether it is a secret - should use
    :func:`resolve_field_classification` instead of re-deriving it from this
    string, which cannot distinguish an MPIN from a login password.
    """
    return resolve_field_classification(
        field_label=field_label,
        resource_id=resource_id,
        content_desc=content_desc,
        class_name=class_name,
        text=text,
        hint=hint,
        input_type=input_type,
        is_password=is_password,
        index=index,
    ).legacy_kind


# ─── Per-run synthetic values ────────────────────────────────────────────────

def _rand(n: int, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


@dataclass
class CredentialVault:
    """
    Disposable credentials for one analysis run.

    Regenerated per run so two runs of the same sample never present the same
    identity, and stable WITHIN a run so a form filled across several actions
    stays internally consistent - a password box and its confirm box have to
    agree, and a retry has to re-enter what it entered before.
    """

    values: Dict[str, str] = field(default_factory=dict)
    attempt: int = 0
    #: The per-run token every generated value is derived from, so an identity
    #: stays internally consistent across the several actions it takes to fill
    #: one form. Rotated by :meth:`regenerate`.
    seed_token: str = ""
    #: Values issued for the expanded taxonomy, keyed by FieldType name and by
    #: the constraint shape they were built for. Separate from `values` so the
    #: legacy dict keeps exactly its old thirteen keys and old readers of it
    #: are unaffected.
    typed_values: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.values:
            self.regenerate()

    def regenerate(self) -> None:
        """New identity. Called on each fresh login attempt."""
        self.attempt += 1
        suffix = _rand(6)
        digits = "".join(random.choice(string.digits) for _ in range(6))
        self.seed_token = suffix
        # Values for the expanded taxonomy are issued lazily by
        # :meth:`value_for_field`, because their shape depends on the field
        # they are going into and that is not known until one is seen.
        self.typed_values = {}
        self.values = {
            "username": f"user{suffix}",
            # Mixed classes so a password policy cannot reject it out of hand,
            # which would look like a credential failure and stop the walk for
            # the wrong reason.
            "password": f"Pw{_rand(6, string.ascii_letters)}{digits[:3]}!",
            "email":    f"user{suffix}@sudarshan-analysis.test",
            "phone":    f"9{digits[:3]}{digits[:6]}"[:10],
            "otp":      digits,
            "amount":   "100",
            "account":  digits + digits[:6],
            "name":     f"Analysis {suffix[:4].title()}",
            "address":  "1 Security Lab, Cyber District",
            "search":   "search_query",
            "host":     "127.0.0.1",
            "port":     "8080",
            "text":     f"t{suffix}",
        }

    def value_for(self, kind: str) -> str:
        return self.values.get(kind, self.values.get("text", "test"))

    def value_for_field(self, constraints: "FieldConstraints") -> str:
        """
        The value for a specific field, shaped to fit it.

        The legacy :meth:`value_for` issues one value per kind, which is why a
        four-digit MPIN box used to receive six digits: `otp` and `mpin` both
        degrade to the same legacy kind and the same stored string. Here the
        constraints are part of the identity of the value, so two numeric
        secrets of different lengths on the same screen each get one that fits,
        and a retry of the SAME field gets the SAME value back.

        Cached per (type, length) so a form re-entered after a failed submit is
        re-entered identically - a password box and its confirm box have to
        agree.
        """
        from sudarshan_core.engines.agentic.field_constraints import generate_value

        key = (
            f"{constraints.field_type.value}"
            f":{constraints.min_length}:{constraints.max_length}"
            f":{int(constraints.numeric_only)}"
        )
        cached = self.typed_values.get(key)
        if cached is not None:
            return cached

        value = generate_value(constraints, seed_token=self.seed_token)
        self.typed_values[key] = value
        _ISSUED.add(value)
        return value

    def secrets(self) -> Set[str]:
        """Every value this vault has ever issued, for log redaction."""
        return set(self.values.values()) | set(self.typed_values.values())


_VAULTS: Dict[str, CredentialVault] = {}
_ISSUED: Set[str] = set()


def get_vault(package_name: str = "") -> CredentialVault:
    """The vault for a package, created on first use."""
    key = package_name or "_default"
    vault = _VAULTS.get(key)
    if vault is None:
        vault = CredentialVault()
        _VAULTS[key] = vault
    _ISSUED.update(vault.secrets())
    return vault


def register_static_values(values: "Set[str] | Dict[str, str] | List[str]") -> None:
    """
    Enrol values from a static table into the redaction set.

    The agentic executor and the legacy UIExplorer each ship a fixed
    ``FORM_VALUES`` fallback for callers that pass a legacy hint before a vault
    exists. Those strings can reach ``adb shell input text``, so they are
    credentials in every sense that matters for logging - and a value that can
    be typed has to be a value that can be redacted. Registering them here puts
    them behind the same :func:`all_secret_values` choke point the audit log
    already uses, instead of requiring every log site to know about a second
    table.
    """
    if isinstance(values, dict):
        _ISSUED.update(str(v) for v in values.values() if v)
    else:
        _ISSUED.update(str(v) for v in values if v)


def all_secret_values() -> Set[str]:
    """
    Every synthetic value issued this process, for redaction.

    Superset of any single vault: a regenerated vault must not leave its old
    password un-redacted in a log line written before the regeneration. Also
    covers the static fallback tables enrolled via :func:`register_static_values`.
    """
    for vault in _VAULTS.values():
        _ISSUED.update(vault.secrets())
    return set(_ISSUED)


# ─── Outcome detection ───────────────────────────────────────────────────────

#: The app telling us the credentials are wrong. This is the ONLY thing that
#: settles the question, and it is the agent's stopping condition for retrying
#: a login form.
_REJECTION_PATTERNS = (
    r"invalid\s+(credential|login|user|username|password|pin|otp|mpin|crn|customer)",
    r"incorrect\s+(credential|login|user|username|password|pin|otp|mpin)",
    r"(username|user\s*id|password|pin|otp|mpin|crn)\s+(is\s+)?(invalid|incorrect|wrong)",
    r"\bwrong\s+(password|username|pin|credential|otp)",
    r"authentication\s+(failed|error|unsuccessful)",
    r"login\s+(failed|unsuccessful|error|denied)",
    r"(bad|unrecognis\w+|unrecogniz\w+)\s+credential",
    r"(user|account)\s+not\s+found",
    r"no\s+such\s+user",
    r"credentials?\s+(do\s+not|don'?t)\s+match",
    r"please\s+(check|enter)\s+(your\s+)?(valid\s+)?(credential|password|username)",
)

#: Landmarks that only exist once a session is open. Used as a positive signal
#: for reporting, never as a reason to stop exploring.
_SUCCESS_HINTS = (
    r"\b(log\s*out|logout|sign\s*out)\b",
    r"\b(dashboard|my\s+account|account\s+summary|available\s+balance)\b",
    r"\b(fund\s+transfer|transfer\s+funds|beneficiary|statement|passbook)\b",
    r"\bwelcome\s+back\b.*\b(user|customer)\b",
)


def login_rejected(screen_text: str) -> bool:
    """Whether the screen says the credentials were refused."""
    if not screen_text:
        return False
    blob = re.sub(r"\s+", " ", screen_text).lower()
    return any(re.search(p, blob) for p in _REJECTION_PATTERNS)


def login_succeeded_hint(screen_text: str) -> bool:
    """Whether the screen shows something only a signed-in session has."""
    if not screen_text:
        return False
    blob = re.sub(r"\s+", " ", screen_text).lower()
    return any(re.search(p, blob) for p in _SUCCESS_HINTS)
