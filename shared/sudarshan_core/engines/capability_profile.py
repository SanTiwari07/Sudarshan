"""
What capabilities should this application plausibly need?

The dynamic engine can already say "the APK requests CAMERA". It cannot say
whether that is *surprising*, and surprise is what an analyst actually reasons
about: a camera app asking for CAMERA is a non-event, a calculator asking for it
is the whole finding.

This module is the deterministic half of that judgement. It infers an
application category from static signals and answers, per permission, whether
that category plausibly needs it.

Three rules govern everything here:

* **This module never says "malicious".** Its vocabulary is EXPECTED /
  PLAUSIBLE / UNEXPECTED, and the strongest thing it emits is
  REQUIRES_REVIEW. An unexpected permission is a question, not a verdict. The
  malware verdict stays in risk_engine, which is the only component allowed to
  reach one.

* **Inference is deterministic and explainable.** Every category decision
  carries the signals that produced it, so a report can say *why* an app was
  treated as a calculator rather than asserting it.

* **Unknown is a real answer.** An app that matches no category returns
  ``UNKNOWN``, and every permission against ``UNKNOWN`` is ``PLAUSIBLE`` - not
  ``UNEXPECTED``. Guessing a category and then flagging permissions against
  the guess would manufacture findings out of our own uncertainty, which is
  worse than staying silent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

# ─── Permission vocabulary ────────────────────────────────────────────────────

P = "android.permission."

#: Permission groups, so a category profile does not have to enumerate every
#: constant. Grouping also keeps the expectation tables readable: a messaging
#: app needs "SMS", not seven individual strings.
PERMISSION_GROUPS: Dict[str, FrozenSet[str]] = {
    "SMS": frozenset({
        P + "READ_SMS", P + "RECEIVE_SMS", P + "SEND_SMS", P + "WRITE_SMS",
        P + "RECEIVE_MMS", P + "RECEIVE_WAP_PUSH", P + "BROADCAST_SMS",
    }),
    "CALL": frozenset({
        P + "CALL_PHONE", P + "READ_CALL_LOG", P + "WRITE_CALL_LOG",
        P + "ANSWER_PHONE_CALLS", P + "PROCESS_OUTGOING_CALLS",
        P + "READ_PHONE_STATE", P + "READ_PHONE_NUMBERS",
    }),
    "CONTACTS": frozenset({
        P + "READ_CONTACTS", P + "WRITE_CONTACTS", P + "GET_ACCOUNTS",
    }),
    "CAMERA": frozenset({P + "CAMERA"}),
    "MICROPHONE": frozenset({P + "RECORD_AUDIO", P + "CAPTURE_AUDIO_OUTPUT"}),
    "LOCATION": frozenset({
        P + "ACCESS_FINE_LOCATION", P + "ACCESS_COARSE_LOCATION",
        P + "ACCESS_BACKGROUND_LOCATION",
    }),
    "STORAGE": frozenset({
        P + "READ_EXTERNAL_STORAGE", P + "WRITE_EXTERNAL_STORAGE",
        P + "MANAGE_EXTERNAL_STORAGE", P + "READ_MEDIA_IMAGES",
        P + "READ_MEDIA_VIDEO", P + "READ_MEDIA_AUDIO",
    }),
    "NETWORK": frozenset({
        P + "INTERNET", P + "ACCESS_NETWORK_STATE", P + "ACCESS_WIFI_STATE",
        P + "CHANGE_WIFI_STATE",
    }),
    "CALENDAR": frozenset({P + "READ_CALENDAR", P + "WRITE_CALENDAR"}),
    "BIOMETRIC": frozenset({P + "USE_BIOMETRIC", P + "USE_FINGERPRINT"}),
    "NOTIFICATIONS": frozenset({P + "POST_NOTIFICATIONS"}),
    "BACKGROUND": frozenset({
        P + "FOREGROUND_SERVICE", P + "RECEIVE_BOOT_COMPLETED",
        P + "WAKE_LOCK", P + "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    }),
    "PACKAGE_CONTROL": frozenset({
        P + "REQUEST_INSTALL_PACKAGES", P + "REQUEST_DELETE_PACKAGES",
        P + "QUERY_ALL_PACKAGES",
    }),
    "OVERLAY": frozenset({P + "SYSTEM_ALERT_WINDOW"}),
    "ACCESSIBILITY": frozenset({P + "BIND_ACCESSIBILITY_SERVICE"}),
    "DEVICE_ADMIN": frozenset({P + "BIND_DEVICE_ADMIN"}),
    "NOTIFICATION_ACCESS": frozenset({P + "BIND_NOTIFICATION_LISTENER_SERVICE"}),
    "VPN": frozenset({P + "BIND_VPN_SERVICE"}),
}

#: Permissions Android does not grant through a runtime dialog - they are
#: toggled in a Settings screen the user has to be walked to. They matter
#: disproportionately to fraud, and they need their own investigation flow
#: (see permission_investigator.SPECIAL_PERMISSION_FLOWS).
SPECIAL_PERMISSION_GROUPS: FrozenSet[str] = frozenset({
    "ACCESSIBILITY", "OVERLAY", "DEVICE_ADMIN",
    "NOTIFICATION_ACCESS", "VPN", "PACKAGE_CONTROL",
})

_PERMISSION_TO_GROUP: Dict[str, str] = {
    perm: group for group, perms in PERMISSION_GROUPS.items() for perm in perms
}


def group_of(permission: str) -> str:
    """
    The group a permission belongs to, or "" when it is not one we model.

    Bare names ("CAMERA") are accepted alongside fully-qualified ones: MobSF and
    androguard disagree on which they emit, and a caller should not have to
    normalise before asking.
    """
    if not permission:
        return ""
    name = permission.strip()
    if name in _PERMISSION_TO_GROUP:
        return _PERMISSION_TO_GROUP[name]
    if "." not in name:
        return _PERMISSION_TO_GROUP.get(P + name.upper(), "")
    return ""


def is_special(permission: str) -> bool:
    """Whether this permission needs a Settings workflow rather than a dialog."""
    return group_of(permission) in SPECIAL_PERMISSION_GROUPS


# ─── Expectation vocabulary ───────────────────────────────────────────────────

class Expectation(str, Enum):
    """
    How surprising a permission is for a category.

    Deliberately three values, none of which is a verdict. PLAUSIBLE is the one
    that earns its place: most permissions for most apps are neither clearly
    needed nor clearly wrong, and collapsing that middle into UNEXPECTED would
    flood an analyst with findings about storage access.
    """

    EXPECTED = "EXPECTED"
    PLAUSIBLE = "PLAUSIBLE"
    UNEXPECTED = "UNEXPECTED"


class AppCategory(str, Enum):
    """Apparent purpose of the application, inferred from static signals."""

    CALCULATOR = "CALCULATOR"
    CAMERA = "CAMERA"
    MESSAGING = "MESSAGING"
    DIALER = "DIALER"
    BANKING = "BANKING"
    MEDIA_PLAYER = "MEDIA_PLAYER"
    FILE_MANAGER = "FILE_MANAGER"
    BROWSER = "BROWSER"
    PASSWORD_MANAGER = "PASSWORD_MANAGER"
    NAVIGATION = "NAVIGATION"
    UTILITY = "UTILITY"
    UNKNOWN = "UNKNOWN"


#: Groups each category is expected to need. Anything not listed here and not in
#: PLAUSIBLE_GROUPS is UNEXPECTED for that category.
EXPECTED_GROUPS: Dict[AppCategory, FrozenSet[str]] = {
    AppCategory.CALCULATOR: frozenset(),
    AppCategory.CAMERA: frozenset({"CAMERA", "STORAGE", "MICROPHONE"}),
    AppCategory.MESSAGING: frozenset({"SMS", "CONTACTS", "NOTIFICATIONS"}),
    AppCategory.DIALER: frozenset({"CALL", "CONTACTS"}),
    AppCategory.BANKING: frozenset({"NETWORK", "BIOMETRIC", "NOTIFICATIONS"}),
    AppCategory.MEDIA_PLAYER: frozenset({"STORAGE", "NETWORK", "NOTIFICATIONS"}),
    AppCategory.FILE_MANAGER: frozenset({"STORAGE"}),
    AppCategory.BROWSER: frozenset({"NETWORK", "STORAGE"}),
    AppCategory.PASSWORD_MANAGER: frozenset({"BIOMETRIC", "STORAGE"}),
    AppCategory.NAVIGATION: frozenset({"LOCATION", "NETWORK"}),
    AppCategory.UTILITY: frozenset(),
    AppCategory.UNKNOWN: frozenset(),
}

#: Groups that are unremarkable for a category without being required. NETWORK
#: and BACKGROUND are here for nearly everything on purpose - almost every
#: modern app has them, so flagging them produces noise rather than findings.
_UNIVERSALLY_PLAUSIBLE: FrozenSet[str] = frozenset({
    "NETWORK", "BACKGROUND", "NOTIFICATIONS", "STORAGE",
})

PLAUSIBLE_GROUPS: Dict[AppCategory, FrozenSet[str]] = {
    AppCategory.CALCULATOR: frozenset({"NETWORK", "BACKGROUND", "NOTIFICATIONS"}),
    AppCategory.CAMERA: _UNIVERSALLY_PLAUSIBLE | {"LOCATION"},
    AppCategory.MESSAGING: _UNIVERSALLY_PLAUSIBLE | {"CALL", "CAMERA", "MICROPHONE"},
    AppCategory.DIALER: _UNIVERSALLY_PLAUSIBLE | {"SMS", "MICROPHONE"},
    # SMS, CONTACTS and CALL are plausible for a real banking app: SMS-based
    # registration and OTP autofill, payee lists, and in-app customer service
    # are all ordinary features. Measured as false positives on InsecureBankv2.
    #
    # This does narrow what the module can say about a trojan that impersonates
    # a bank - and that is the right trade. ACCESSIBILITY, OVERLAY and
    # DEVICE_ADMIN stay UNEXPECTED for every category including this one, and
    # those are the actual fraud mechanisms; SMS access on something calling
    # itself a bank is too close to legitimate to carry a finding on its own.
    # The verdict comes from the risk engine, which sees the runtime evidence.
    AppCategory.BANKING: _UNIVERSALLY_PLAUSIBLE | {
        "CAMERA", "LOCATION", "CALL", "SMS", "CONTACTS",
    },
    # MICROPHONE: media apps capture and stream audio.
    # OVERLAY: picture-in-picture and floating players draw over other apps.
    # Both were measured as false positives on VLC.
    AppCategory.MEDIA_PLAYER: _UNIVERSALLY_PLAUSIBLE | {"MICROPHONE", "OVERLAY"},
    # PACKAGE_CONTROL: installing, deleting and listing APKs is what a file
    # manager is for. BIOMETRIC: app-lock. Both measured on Amaze File Manager.
    AppCategory.FILE_MANAGER: _UNIVERSALLY_PLAUSIBLE | {"PACKAGE_CONTROL", "BIOMETRIC"},
    AppCategory.BROWSER: _UNIVERSALLY_PLAUSIBLE | {
        "LOCATION", "CAMERA", "MICROPHONE", "PACKAGE_CONTROL",
    },
    # PACKAGE_CONTROL: autofill has to match a stored credential to the app
    # asking for it, which means enumerating packages. Measured on KeePassDX.
    AppCategory.PASSWORD_MANAGER: _UNIVERSALLY_PLAUSIBLE | {"CAMERA", "PACKAGE_CONTROL"},
    AppCategory.NAVIGATION: _UNIVERSALLY_PLAUSIBLE,
    AppCategory.UTILITY: _UNIVERSALLY_PLAUSIBLE,
    # Everything is plausible for an app we could not categorise - see the
    # module docstring. UNKNOWN is handled explicitly in expectation_for().
    AppCategory.UNKNOWN: frozenset(),
}

#: Package-name and label tokens that identify a category. Matched against the
#: package's own segments and the label's words, never as a substring of the
#: whole string - "com.calculator.evil" and "MyCalculator" should both match
#: CALCULATOR, but "com.example.recalculation" should not.
CATEGORY_TOKENS: Dict[AppCategory, FrozenSet[str]] = {
    AppCategory.CALCULATOR: frozenset({"calculator", "calc", "calculate"}),
    AppCategory.CAMERA: frozenset({"camera", "photo", "selfie", "cam"}),
    AppCategory.MESSAGING: frozenset({"sms", "messaging", "messenger", "message", "chat", "texting"}),
    AppCategory.DIALER: frozenset({"dialer", "phone", "call", "contacts"}),
    AppCategory.BANKING: frozenset({"bank", "banking", "wallet", "pay", "payment", "upi", "finance"}),
    AppCategory.MEDIA_PLAYER: frozenset({"player", "video", "music", "audio", "media", "vlc", "tube"}),
    AppCategory.FILE_MANAGER: frozenset({"file", "files", "explorer", "manager", "storage"}),
    AppCategory.BROWSER: frozenset({"browser", "chrome", "firefox", "webview"}),
    AppCategory.PASSWORD_MANAGER: frozenset({"password", "keepass", "vault", "authenticator"}),
    AppCategory.NAVIGATION: frozenset({"maps", "navigation", "gps", "route"}),
}


@dataclass(frozen=True)
class CategoryInference:
    """A category decision, with the signals that produced it."""

    category: AppCategory
    confidence: str            # HIGH | MEDIUM | LOW
    signals: Tuple[str, ...] = ()

    @property
    def is_known(self) -> bool:
        return self.category is not AppCategory.UNKNOWN


def _tokens(text: str) -> List[str]:
    """
    Split a package name or label into comparable lowercase words.

    Splits on separators AND on camelCase boundaries. Without the latter,
    "InsecureBankv2" is a single token and never matches "bank" - measured on
    the corpus, that is exactly what happened. Digits terminate a word too, so
    "Bankv2" yields "bank".

    Substring matching is still deliberately avoided: "recalculation" must not
    read as a calculator, which is why tokens are compared whole.
    """
    if not text:
        return []
    out: List[str] = []
    word: List[str] = []

    def flush(before_digit: bool = False) -> None:
        if not word:
            return
        token = "".join(word).lower()
        # "InsecureBankv2" tokenises to "bankv" without this, and never matches
        # "bank". A trailing "v" immediately before digits is a version marker,
        # not part of the name - measured on the corpus, where it was the
        # difference between recognising a banking app and giving up on it.
        if before_digit and len(token) > 1 and token.endswith("v"):
            token = token[:-1]
        out.append(token)
        word.clear()

    for index, ch in enumerate(text):
        if not ch.isalnum():
            flush()
            continue
        if ch.isdigit():
            flush(before_digit=True)
            continue
        # A capital after a lowercase letter starts a new word: "FileManager".
        if ch.isupper() and index > 0 and text[index - 1].islower():
            flush()
        word.append(ch)
    flush()
    return out


def infer_category(
    package_name: str = "",
    app_label: str = "",
    permissions: Optional[Sequence[str]] = None,
) -> CategoryInference:
    """
    Infer what kind of application this appears to be.

    The label is weighted above the package name, because the label is what the
    app claims to be to the user - which is exactly the claim an impersonating
    sample makes and the one worth testing against observed behaviour.

    Permissions are used only to break ties, never to establish a category on
    their own: deducing "this is an SMS app" from SMS permissions and then
    reporting SMS permissions as expected would launder every SMS stealer into
    a messaging app.
    """
    label_tokens = set(_tokens(app_label))
    package_tokens = set(_tokens(package_name))

    label_hits = [
        cat for cat, toks in CATEGORY_TOKENS.items() if label_tokens & toks
    ]
    if len(label_hits) == 1:
        matched = sorted(label_tokens & CATEGORY_TOKENS[label_hits[0]])
        return CategoryInference(
            label_hits[0], "HIGH", (f"app label matched {', '.join(matched)}",)
        )

    # An ambiguous label is decisive, and stops here rather than falling through
    # to the package name. "Bank Messenger" installed as com.example.camera
    # would otherwise be resolved to CAMERA - a category the label never
    # suggested - and every permission would then be judged against a guess the
    # stronger signal contradicts.
    if label_hits:
        names = sorted({c.value for c in label_hits})
        return CategoryInference(
            AppCategory.UNKNOWN, "LOW",
            (f"ambiguous app label, matched: {', '.join(names)}",),
        )

    package_hits = [
        cat for cat, toks in CATEGORY_TOKENS.items() if package_tokens & toks
    ]
    if len(package_hits) == 1:
        matched = sorted(package_tokens & CATEGORY_TOKENS[package_hits[0]])
        return CategoryInference(
            package_hits[0], "MEDIUM", (f"package name matched {', '.join(matched)}",)
        )

    # Ambiguous package name: same reasoning, no winner picked.
    if package_hits:
        names = sorted({c.value for c in package_hits})
        return CategoryInference(
            AppCategory.UNKNOWN, "LOW",
            (f"ambiguous package name, matched: {', '.join(names)}",),
        )
    return CategoryInference(
        AppCategory.UNKNOWN, "LOW", ("no category signal in label or package name",)
    )


def expectation_for(category: AppCategory, permission: str) -> Expectation:
    """
    How surprising this permission is for this category.

    An unmodelled permission is PLAUSIBLE, not UNEXPECTED: the group tables
    describe what we understand, and silence about a permission is our gap, not
    the app's fault.
    """
    group = group_of(permission)
    if not group:
        return Expectation.PLAUSIBLE

    # Everything is plausible for an app we could not categorise. Flagging
    # permissions against a category we did not actually establish would
    # manufacture findings out of our own uncertainty.
    if category is AppCategory.UNKNOWN:
        return Expectation.PLAUSIBLE

    if group in EXPECTED_GROUPS.get(category, frozenset()):
        return Expectation.EXPECTED
    if group in PLAUSIBLE_GROUPS.get(category, frozenset()):
        return Expectation.PLAUSIBLE
    return Expectation.UNEXPECTED


@dataclass
class CapabilityProfile:
    """The expected-capability model for one application."""

    package_name: str = ""
    app_label: str = ""
    inference: CategoryInference = field(
        default_factory=lambda: CategoryInference(AppCategory.UNKNOWN, "LOW", ())
    )

    @property
    def category(self) -> AppCategory:
        return self.inference.category

    def expectation(self, permission: str) -> Expectation:
        return expectation_for(self.category, permission)

    def unexpected(self, permissions: Sequence[str]) -> List[str]:
        """Those permissions this category would not be expected to need."""
        return [
            p for p in permissions
            if self.expectation(p) is Expectation.UNEXPECTED
        ]

    def to_dict(self) -> Dict[str, object]:
        return {
            "package_name": self.package_name,
            "app_label": self.app_label,
            "category": self.category.value,
            "confidence": self.inference.confidence,
            "signals": list(self.inference.signals),
        }


def build_profile(
    package_name: str = "",
    app_label: str = "",
    permissions: Optional[Sequence[str]] = None,
) -> CapabilityProfile:
    """Infer the category and return the profile that answers questions about it."""
    return CapabilityProfile(
        package_name=package_name or "",
        app_label=app_label or "",
        inference=infer_category(package_name, app_label, permissions),
    )
