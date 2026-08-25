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
from typing import Dict, List, Optional, Set

__all__ = [
    "FIELD_KINDS",
    "CredentialVault",
    "all_secret_values",
    "get_vault",
    "login_rejected",
    "login_succeeded_hint",
    "resolve_field_kind",
]


#: Ordered kind matchers. First hit wins, so the more specific patterns lead.
#: Matched against the field caption, resource-id, content-desc and class name
#: joined together and lower-cased.
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


def resolve_field_kind(
    *,
    field_label: str = "",
    resource_id: str = "",
    content_desc: str = "",
    class_name: str = "",
    text: str = "",
    is_password: bool = False,
    index: int = 0,
) -> str:
    """
    The kind of value this input wants.

    `is_password` is authoritative: uiautomator sets it from the field's own
    input type, which is a stronger statement than any caption. Everything else
    is inferred from the words around the field.

    When nothing matches, `index` decides: the first unlabelled field on a
    screen is treated as the identifier and the rest as free text. That is the
    right guess for a login form, which is the case that matters, and a wrong
    guess costs one action rather than the run.
    """
    if is_password:
        return "password"

    haystack = " ".join(
        p for p in (field_label, resource_id, content_desc, text, class_name) if p
    ).lower()
    haystack = re.sub(r"[_\-./]+", " ", haystack)

    for kind, pattern in _KIND_PATTERNS:
        if re.search(pattern, haystack):
            return kind

    return "username" if index == 0 else "text"


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

    def __post_init__(self) -> None:
        if not self.values:
            self.regenerate()

    def regenerate(self) -> None:
        """New identity. Called on each fresh login attempt."""
        self.attempt += 1
        suffix = _rand(6)
        digits = "".join(random.choice(string.digits) for _ in range(6))
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

    def secrets(self) -> Set[str]:
        """Every value this vault has ever issued, for log redaction."""
        return set(self.values.values())


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


def all_secret_values() -> Set[str]:
    """
    Every synthetic value issued this process, for redaction.

    Superset of any single vault: a regenerated vault must not leave its old
    password un-redacted in a log line written before the regeneration.
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
