"""
SUDARSHAN - canonical runtime behaviours, and what it takes to claim one.

The problem this solves
-----------------------
Goals matched raw hook NAMES. That coupling is why four
`test_goal_hook_contract` tests have been red at baseline: the goal graph
declared triggers the compiled agent does not emit, so those stages were
unreachable by construction, and no amount of runtime evidence could move them.

It also loses meaning. Measured on Drinik: 50 events under `code_execution`,
BFCI 10.0 scored from them, goal graph reporting zero. The events were
`ProcessBuilder.start` x16 and `libc.execve` x34 - real command execution -
while stage 10 was waiting for `DexClassLoader.<init>`. Both are code
execution; only one had a name the graph recognised.

So goals now declare BEHAVIOURS, and this module owns the single mapping from
observed hooks to behaviours. A hook rename breaks one table entry here instead
of silently disabling a stage.

Every hook name below was extracted from the agent's own source
(`frida_hooks/banking_trojan.js`) and appears in the compiled bundle. None is
invented; `test_behavior_taxonomy_matches_the_agent` fails the build if a name
here stops being emitted.

Observing a behaviour is not completing a goal
----------------------------------------------
A `DexClassLoader` call is not a fraud campaign. An accessibility callback is
not account takeover. An SMS read is not OTP theft. A socket is not a C2
channel. So each behaviour carries a WEIGHT that says how much it proves:

    DECISIVE     on its own, this behaviour is the thing the goal is named for
    STRONG       characteristic, but wants corroboration to be called complete
    SUPPORTING   consistent with the goal; never sufficient alone
    UBIQUITOUS   every app does this; evidence of nothing by itself

Goal completion needs a DECISIVE behaviour, or two independent STRONG ones.
Anything less is PARTIAL, which is a real finding with its own evidence rather
than a consolation prize. The thresholds live in
:func:`evaluate_behaviour_evidence` and are pure, deterministic and testable.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set

from sudarshan_core.engines.runtime_event import NormalizedEvent

logger = logging.getLogger(__name__)

__all__ = [
    "Behavior",
    "BehaviorObservation",
    "BehaviorWeight",
    "BEHAVIOR_RULES",
    "EvidenceStrength",
    "all_declared_hooks",
    "classify_event",
    "classify_events",
    "evaluate_behaviour_evidence",
]


class Behavior(str, Enum):
    """
    What a runtime observation MEANS, independent of which hook reported it.

    Deliberately finer-grained than the agent's event categories: `code_execution`
    covers both dynamic Dex loading and shell exec, and a goal graph that cannot
    tell them apart cannot say which one it saw.
    """

    # -- Accessibility -------------------------------------------------------
    ACCESSIBILITY_SERVICE_ACTIVE = "ACCESSIBILITY_SERVICE_ACTIVE"
    ACCESSIBILITY_NODE_HARVEST = "ACCESSIBILITY_NODE_HARVEST"
    ACCESSIBILITY_GESTURE_INJECTION = "ACCESSIBILITY_GESTURE_INJECTION"

    # -- SMS / OTP -----------------------------------------------------------
    SMS_READ = "SMS_READ"
    SMS_SEND = "SMS_SEND"
    NOTIFICATION_INTERCEPTION = "NOTIFICATION_INTERCEPTION"

    # -- Overlay -------------------------------------------------------------
    OVERLAY_WINDOW_ADDED = "OVERLAY_WINDOW_ADDED"
    OVERLAY_WINDOW_MANIPULATED = "OVERLAY_WINDOW_MANIPULATED"

    # -- Banking -------------------------------------------------------------
    INSTALLED_PACKAGE_ENUMERATION = "INSTALLED_PACKAGE_ENUMERATION"
    CREDENTIAL_STORE_ACCESS = "CREDENTIAL_STORE_ACCESS"
    KEYSTORE_ACCESS = "KEYSTORE_ACCESS"

    # -- Network -------------------------------------------------------------
    HTTP_REQUEST = "HTTP_REQUEST"
    SOCKET_CONNECTION = "SOCKET_CONNECTION"
    TLS_PAYLOAD_CAPTURE = "TLS_PAYLOAD_CAPTURE"

    # -- Code execution ------------------------------------------------------
    DYNAMIC_DEX_LOADING = "DYNAMIC_DEX_LOADING"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    NATIVE_LIBRARY_LOAD = "NATIVE_LIBRARY_LOAD"
    NATIVE_METHOD_REGISTRATION = "NATIVE_METHOD_REGISTRATION"

    # -- Payload deployment --------------------------------------------------
    PAYLOAD_WRITE = "PAYLOAD_WRITE"
    PAYLOAD_DOWNLOAD = "PAYLOAD_DOWNLOAD"
    PACKAGE_INSTALL_REQUEST = "PACKAGE_INSTALL_REQUEST"

    # -- Persistence ---------------------------------------------------------
    SCHEDULED_EXECUTION = "SCHEDULED_EXECUTION"
    DEVICE_ADMIN_QUERY = "DEVICE_ADMIN_QUERY"
    DEVICE_ADMIN_ABUSE = "DEVICE_ADMIN_ABUSE"

    # -- Anti-analysis -------------------------------------------------------
    SELF_TERMINATION = "SELF_TERMINATION"
    DEBUGGER_CHECK = "DEBUGGER_CHECK"
    PTRACE_CHECK = "PTRACE_CHECK"
    SYSTEM_PROPERTY_PROBE = "SYSTEM_PROPERTY_PROBE"

    # -- Reconnaissance ------------------------------------------------------
    DEVICE_IDENTITY_HARVEST = "DEVICE_IDENTITY_HARVEST"
    ACCOUNT_HARVEST = "ACCOUNT_HARVEST"
    FOREGROUND_APP_MONITORING = "FOREGROUND_APP_MONITORING"
    CLIPBOARD_ACCESS = "CLIPBOARD_ACCESS"
    CONTENT_PROVIDER_QUERY = "CONTENT_PROVIDER_QUERY"

    # -- WebView -------------------------------------------------------------
    WEBVIEW_NAVIGATION = "WEBVIEW_NAVIGATION"
    WEBVIEW_SCRIPT_EXECUTION = "WEBVIEW_SCRIPT_EXECUTION"
    WEBVIEW_JS_BRIDGE = "WEBVIEW_JS_BRIDGE"

    # -- Ordinary application activity --------------------------------------
    APP_LIFECYCLE = "APP_LIFECYCLE"
    FILE_ACCESS = "FILE_ACCESS"
    KEYBOARD_ACTIVITY = "KEYBOARD_ACTIVITY"
    CRYPTO_OPERATION = "CRYPTO_OPERATION"


class BehaviorWeight(str, Enum):
    """How much one observation of a behaviour proves."""

    #: On its own, this IS the thing. `SmsMessage.getMessageBody` is OTP
    #: interception; there is no innocent reading of it in a sandbox where no
    #: human sent a message.
    DECISIVE = "DECISIVE"
    #: Characteristic of the goal, but a second independent signal is wanted
    #: before calling the goal complete.
    STRONG = "STRONG"
    #: Consistent with the goal and worth recording. Never sufficient alone.
    SUPPORTING = "SUPPORTING"
    #: Every app does this. Evidence that the process ran, and nothing more.
    UBIQUITOUS = "UBIQUITOUS"


@dataclass(frozen=True)
class BehaviorRule:
    """One behaviour, and the observations that establish it."""

    behavior: Behavior
    weight: BehaviorWeight
    #: Hook names, as the agent emits them. Matched via
    #: NormalizedEvent.matches_hook, so a subclass-qualified emission
    #: (`<pkg>.MyService.onAccessibilityEvent`) still matches the declaration.
    hooks: FrozenSet[str]
    #: Categories under which those hooks count. Empty means any category.
    #:
    #: This gate is load-bearing. The agent routes the same hook name to a
    #: scored or an unscored category depending on what it saw -
    #: `WindowManager.updateViewLayout` goes to `overlay` for a view it watched
    #: being added as an overlay and to `app_telemetry` otherwise - and
    #: ignoring that routing is how "Login Flow" used to complete on an
    #: ordinary preferences read.
    categories: FrozenSet[str] = frozenset()
    description: str = ""

    def matches(self, event: NormalizedEvent) -> bool:
        if self.categories and event.category not in self.categories:
            return False
        return any(event.matches_hook(name) for name in self.hooks)


def _rule(
    behavior: Behavior,
    weight: BehaviorWeight,
    hooks: Sequence[str],
    categories: Sequence[str] = (),
    description: str = "",
) -> BehaviorRule:
    return BehaviorRule(
        behavior=behavior,
        weight=weight,
        hooks=frozenset(hooks),
        categories=frozenset(categories),
        description=description,
    )


#: The single mapping from emitted hooks to canonical behaviours.
#:
#: Ordering is irrelevant - an event may satisfy several rules and produces one
#: observation per rule it matches, because a hook genuinely can be evidence of
#: more than one thing.
BEHAVIOR_RULES: List[BehaviorRule] = [
    # -- Accessibility -------------------------------------------------------
    _rule(
        Behavior.ACCESSIBILITY_SERVICE_ACTIVE, BehaviorWeight.STRONG,
        ["onAccessibilityEvent"], ["accessibility"],
        "An accessibility service belonging to the sample received an event, "
        "so the service is connected and running.",
    ),
    _rule(
        Behavior.ACCESSIBILITY_NODE_HARVEST, BehaviorWeight.DECISIVE,
        ["AccessibilityNodeInfo.getText",
         "AccessibilityNodeInfo.findAccessibilityNodeInfosByText"],
        ["accessibility"],
        "The sample read the text content of another application's UI through "
        "the accessibility tree - the mechanism by which credentials typed "
        "into a banking app are captured.",
    ),
    _rule(
        Behavior.ACCESSIBILITY_GESTURE_INJECTION, BehaviorWeight.DECISIVE,
        ["AccessibilityNodeInfo.performAction", "AccessibilityService.dispatchGesture"],
        ["accessibility"],
        "The sample drove another application's UI by injecting actions or "
        "gestures, acting on the victim's behalf without their input.",
    ),

    # -- SMS / OTP -----------------------------------------------------------
    _rule(
        Behavior.SMS_READ, BehaviorWeight.DECISIVE,
        ["SmsMessage.getMessageBody"], ["sms"],
        "The sample read the body of an SMS message - the OTP interception "
        "primitive.",
    ),
    _rule(
        Behavior.SMS_SEND, BehaviorWeight.STRONG,
        ["SmsManager.sendTextMessage", "SmsManager.sendMultipartTextMessage"], ["sms"],
        "The sample sent an SMS without user interaction.",
    ),
    _rule(
        Behavior.NOTIFICATION_INTERCEPTION, BehaviorWeight.STRONG,
        ["NotificationListenerService.onNotificationPosted"], ["notification"],
        "The sample read notifications posted by other applications, which "
        "carry OTPs on modern Android.",
    ),

    # -- Overlay -------------------------------------------------------------
    _rule(
        Behavior.OVERLAY_WINDOW_ADDED, BehaviorWeight.DECISIVE,
        ["WindowManager.addView"], ["overlay"],
        "The sample drew a window on top of other applications.",
    ),
    _rule(
        Behavior.OVERLAY_WINDOW_MANIPULATED, BehaviorWeight.STRONG,
        ["WindowManager.updateViewLayout", "WindowManager.removeView"], ["overlay"],
        "The sample repositioned or removed a live overlay window.",
    ),

    # -- Banking -------------------------------------------------------------
    _rule(
        Behavior.INSTALLED_PACKAGE_ENUMERATION, BehaviorWeight.SUPPORTING,
        ["PackageManager.getInstalledPackages",
         "PackageManager.getInstalledApplications"],
        ["banking", "device_fingerprint"],
        "The sample enumerated installed applications. Reconnaissance - "
        "characteristic of target selection, but launchers and security apps "
        "do it too.",
    ),
    _rule(
        Behavior.CREDENTIAL_STORE_ACCESS, BehaviorWeight.SUPPORTING,
        ["SharedPreferences.getString"], ["banking"],
        "The sample read a credential-shaped key from SharedPreferences. "
        "Category-gated: the same hook under app_telemetry is an ordinary "
        "session read.",
    ),
    _rule(
        Behavior.KEYSTORE_ACCESS, BehaviorWeight.SUPPORTING,
        ["KeyStore.getInstance"], [],
        "The sample opened a keystore.",
    ),

    # -- Network -------------------------------------------------------------
    _rule(
        Behavior.HTTP_REQUEST, BehaviorWeight.STRONG,
        ["HttpURLConnection.getInputStream", "HttpsURLConnection.connect",
         "OkHttp.RealCall.execute", "OkHttp.RealCall.enqueue",
         "Retrofit.OkHttpCall.execute", "URL.openConnection"],
        ["network"],
        "The sample issued an HTTP(S) request. Category-gated to `network` so "
        "the agent's own start-up liveness probe under `smoke` cannot count.",
    ),
    _rule(
        Behavior.SOCKET_CONNECTION, BehaviorWeight.SUPPORTING,
        ["Socket.connect", "libc.connect"], ["network"],
        "The sample opened a socket.",
    ),
    _rule(
        Behavior.TLS_PAYLOAD_CAPTURE, BehaviorWeight.STRONG,
        ["SSL_read", "SSL_write", "native:SSL_read", "native:SSL_write"], [],
        "Plaintext was captured either side of TLS, so the request contents "
        "are known rather than inferred.",
    ),

    # -- Code execution ------------------------------------------------------
    _rule(
        Behavior.DYNAMIC_DEX_LOADING, BehaviorWeight.DECISIVE,
        ["DexClassLoader.<init>", "InMemoryDexClassLoader.<init>"], ["code_execution"],
        "The sample loaded executable code that was not in the APK the "
        "analysis started from.",
    ),
    _rule(
        # The Drinik case. `Runtime.exec` / `ProcessBuilder.start` / native
        # `execve` are how a dropper roots a device, drops a payload and runs
        # it. They are code execution by the engine's own definition - the
        # agent files them under `code_execution` and BFCI weights that axis -
        # and the goal graph simply had no name for them.
        Behavior.COMMAND_EXECUTION, BehaviorWeight.DECISIVE,
        ["Runtime.exec", "Runtime.exec[]", "ProcessBuilder.start", "libc.execve",
         "execve"],
        ["code_execution"],
        "The sample executed an operating-system command in a child process.",
    ),
    _rule(
        Behavior.NATIVE_LIBRARY_LOAD, BehaviorWeight.UBIQUITOUS,
        ["System.loadLibrary"], [],
        "A native library was loaded. Any application with native code does "
        "this, including the analysis agent's own.",
    ),
    _rule(
        Behavior.NATIVE_METHOD_REGISTRATION, BehaviorWeight.SUPPORTING,
        ["libart.RegisterNatives", "native:RegisterNatives", "RegisterNatives"], [],
        "Native methods were registered at runtime - the packer/unpacker "
        "pattern, where the real implementation is bound after start-up.",
    ),

    # -- Payload deployment --------------------------------------------------
    _rule(
        Behavior.PAYLOAD_WRITE, BehaviorWeight.DECISIVE,
        ["FileOutputStream.apkWrite"], [],
        "The sample wrote an APK to disk.",
    ),
    _rule(
        Behavior.PAYLOAD_DOWNLOAD, BehaviorWeight.STRONG,
        ["DownloadManager.enqueue"], [],
        "The sample queued a download.",
    ),
    _rule(
        Behavior.PACKAGE_INSTALL_REQUEST, BehaviorWeight.DECISIVE,
        ["Intent.installPackageRequest"], [],
        "The sample asked Android to install a package.",
    ),

    # -- Persistence ---------------------------------------------------------
    _rule(
        Behavior.SCHEDULED_EXECUTION, BehaviorWeight.STRONG,
        ["AlarmManager.setExact", "JobScheduler.schedule"], ["persistence"],
        "The sample scheduled work to run later, surviving its own process.",
    ),
    _rule(
        # Deliberately SUPPORTING, not STRONG. Querying whether you are a
        # device admin is a check any app may make; it is not the exercise of
        # device-admin power. Treating it as proof of persistence is exactly
        # the false completion the category gate exists to prevent.
        Behavior.DEVICE_ADMIN_QUERY, BehaviorWeight.SUPPORTING,
        ["DevicePolicyManager.isAdminActive"], ["persistence"],
        "The sample checked whether it holds device-administrator rights. A "
        "query, not an exercise of the power.",
    ),
    _rule(
        Behavior.DEVICE_ADMIN_ABUSE, BehaviorWeight.DECISIVE,
        ["DevicePolicyManager.lockNow"], ["persistence"],
        "The sample exercised device-administrator power to lock the device.",
    ),

    # -- Anti-analysis -------------------------------------------------------
    _rule(
        Behavior.SELF_TERMINATION, BehaviorWeight.DECISIVE,
        ["Process.killProcess", "System.exit", "Runtime.exit"], ["anti_analysis"],
        "The sample ended its own process. In an instrumented environment "
        "this is refusal to be observed, not a crash.",
    ),
    _rule(
        Behavior.DEBUGGER_CHECK, BehaviorWeight.SUPPORTING,
        ["Debug.isDebuggerConnected"], [],
        "The sample checked for an attached debugger.",
    ),
    _rule(
        Behavior.PTRACE_CHECK, BehaviorWeight.STRONG,
        ["libc.ptrace", "ptrace"], [],
        "The sample used ptrace, the native anti-debugging primitive.",
    ),
    _rule(
        Behavior.SYSTEM_PROPERTY_PROBE, BehaviorWeight.SUPPORTING,
        ["SystemProperties.get"], [],
        "The sample read system properties, which is how emulator "
        "fingerprinting is performed.",
    ),

    # -- Reconnaissance ------------------------------------------------------
    _rule(
        Behavior.DEVICE_IDENTITY_HARVEST, BehaviorWeight.STRONG,
        ["TelephonyManager.getDeviceId", "TelephonyManager.getSubscriberId",
         "TelephonyManager.getSimSerialNumber", "TelephonyManager.getLine1Number"],
        [],
        "The sample read hardware or subscriber identifiers.",
    ),
    _rule(
        Behavior.ACCOUNT_HARVEST, BehaviorWeight.STRONG,
        ["AccountManager.getAccountsByType"], [],
        "The sample enumerated accounts registered on the device.",
    ),
    _rule(
        Behavior.FOREGROUND_APP_MONITORING, BehaviorWeight.STRONG,
        ["ActivityManager.getRunningTasks", "UsageStatsManager.queryEvents"], [],
        "The sample watched which application is in the foreground - the "
        "trigger mechanism for a targeted overlay.",
    ),
    _rule(
        Behavior.CLIPBOARD_ACCESS, BehaviorWeight.STRONG,
        ["ClipboardManager.getPrimaryClip"], [],
        "The sample read the clipboard.",
    ),
    _rule(
        Behavior.CONTENT_PROVIDER_QUERY, BehaviorWeight.SUPPORTING,
        ["ContentResolver.query", "ContentResolver.insert", "ContentResolver.delete"],
        [],
        "The sample queried a content provider. The agent scopes this hook to "
        "sms / mms / contacts, but it cannot say which from the name alone.",
    ),

    # -- WebView -------------------------------------------------------------
    _rule(
        Behavior.WEBVIEW_NAVIGATION, BehaviorWeight.SUPPORTING,
        ["WebView.loadUrl", "WebView.postUrl", "WebView.loadData",
         "WebView.loadDataWithBaseURL"],
        [],
        "The sample loaded content into a WebView.",
    ),
    _rule(
        Behavior.WEBVIEW_SCRIPT_EXECUTION, BehaviorWeight.STRONG,
        ["WebView.evaluateJavascript"], [],
        "The sample executed JavaScript inside a WebView.",
    ),
    _rule(
        Behavior.WEBVIEW_JS_BRIDGE, BehaviorWeight.STRONG,
        ["WebView.addJavascriptInterface"], [],
        "The sample exposed native methods to page JavaScript.",
    ),

    # -- Ordinary application activity --------------------------------------
    _rule(
        Behavior.APP_LIFECYCLE, BehaviorWeight.UBIQUITOUS,
        ["Application.onCreate", "Activity.onCreate", "Activity.onResume"], [],
        "The application's own lifecycle callbacks ran, which proves the "
        "process started and executed its code. Every app does this.",
    ),
    _rule(
        Behavior.FILE_ACCESS, BehaviorWeight.UBIQUITOUS,
        ["File.<init>", "FileInputStream.<init>", "libc.open"], [],
        "The sample opened a file.",
    ),
    _rule(
        Behavior.KEYBOARD_ACTIVITY, BehaviorWeight.UBIQUITOUS,
        ["InputMethodManager.showSoftInput"], [],
        "A soft keyboard was raised.",
    ),
    _rule(
        Behavior.CRYPTO_OPERATION, BehaviorWeight.UBIQUITOUS,
        ["Cipher.doFinal"], [],
        "A cryptographic operation ran. Fires for any encryption, including "
        "ordinary TLS and preference encryption.",
    ),
]


@dataclass
class BehaviorObservation:
    """One canonical behaviour, and every event that evidenced it."""

    behavior: Behavior
    weight: BehaviorWeight
    description: str = ""
    events: List[NormalizedEvent] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def first_seen_ms(self) -> Optional[int]:
        stamps = [e.timestamp_ms for e in self.events if e.timestamp_ms is not None]
        return min(stamps) if stamps else None

    @property
    def hooks(self) -> List[str]:
        """Distinct hook names that evidenced this behaviour, for the report."""
        seen: List[str] = []
        for event in self.events:
            name = event.qualified_hook
            if name and name not in seen:
                seen.append(name)
        return seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "behavior": self.behavior.value,
            "weight": self.weight.value,
            "description": self.description,
            "count": self.count,
            "first_seen_ms": self.first_seen_ms,
            "hooks": self.hooks,
            # Bounded: a behaviour with 34 execve calls does not need 34 copies
            # of the same record in a report, but the count above is exact.
            "sample_events": [e.to_dict() for e in self.events[:3]],
        }


def classify_event(event: NormalizedEvent) -> List[BehaviorRule]:
    """Every behaviour rule this single event satisfies. May be more than one."""
    return [rule for rule in BEHAVIOR_RULES if rule.matches(event)]


def classify_events(
    events: Iterable[NormalizedEvent],
) -> Dict[Behavior, BehaviorObservation]:
    """
    Fold a normalized event stream into canonical behaviours.

    Harness-attributed events are skipped: they describe what the sandbox did
    to conceal itself, and attributing our own countermeasure to the sample is
    the misreading that scored five banking trojans Safe.
    """
    observations: Dict[Behavior, BehaviorObservation] = {}
    for event in events or ():
        if event.harness_attributed:
            continue
        for rule in classify_event(event):
            obs = observations.get(rule.behavior)
            if obs is None:
                obs = BehaviorObservation(
                    behavior=rule.behavior,
                    weight=rule.weight,
                    description=rule.description,
                )
                observations[rule.behavior] = obs
            obs.events.append(event)
    return observations


class EvidenceStrength(str, Enum):
    """How strongly a set of observations supports a claim."""

    NONE = "NONE"
    #: Something consistent was seen. Not enough to claim the behaviour.
    WEAK = "WEAK"
    #: Real evidence, short of proof. This is what PARTIAL is made of.
    MODERATE = "MODERATE"
    #: Enough to claim it. This is what SUCCESS is made of.
    CONCLUSIVE = "CONCLUSIVE"


def evaluate_behaviour_evidence(
    observed: Mapping[Behavior, BehaviorObservation],
    required: Sequence[Behavior],
    supporting: Sequence[Behavior] = (),
    weight_overrides: Optional[Mapping[Behavior, BehaviorWeight]] = None,
) -> "EvidenceVerdict":
    """
    Decide how strongly the observed behaviours support one goal.

    Deterministic and pure - no clock, no device, no model. The rule:

      * one DECISIVE required behaviour            -> CONCLUSIVE
      * two or more distinct STRONG behaviours     -> CONCLUSIVE
      * one STRONG behaviour                       -> MODERATE
      * only SUPPORTING behaviours                 -> MODERATE
      * only UBIQUITOUS behaviours                 -> WEAK
      * nothing                                    -> NONE

    Two STRONG behaviours reach CONCLUSIVE because they are independent
    observations of the same claim, which is the standard the whole engine
    applies elsewhere. Volume never promotes: fifty of one UBIQUITOUS behaviour
    is still WEAK, so a chatty app cannot buy its way to a completed goal - the
    rule that generic event volume must not become behavioural confidence.

    `weight_overrides` lets ONE caller restate what a behaviour proves FOR ITS
    OWN question, because weight is a property of the (behaviour, claim) pair
    and not of the behaviour alone. `Activity.onCreate` is UBIQUITOUS evidence
    of dynamic code loading and DECISIVE evidence that the application launched
    and executed its own code - the same observation, two different questions.
    An override may only be declared alongside the goal that needs it, so the
    reasoning sits next to the claim it supports rather than in this table.
    """
    overrides = dict(weight_overrides or {})

    def _weight(obs: BehaviorObservation) -> BehaviorWeight:
        return overrides.get(obs.behavior, obs.weight)

    matched: List[BehaviorObservation] = []
    for behaviour in required:
        obs = observed.get(behaviour)
        if obs is not None:
            matched.append(obs)

    support: List[BehaviorObservation] = []
    for behaviour in supporting:
        obs = observed.get(behaviour)
        if obs is not None and obs not in matched:
            support.append(obs)

    if not matched and not support:
        return EvidenceVerdict(EvidenceStrength.NONE, [], [], "")

    decisive = [o for o in matched if _weight(o) is BehaviorWeight.DECISIVE]
    strong = [o for o in matched if _weight(o) is BehaviorWeight.STRONG]
    supporting_hits = [o for o in matched if _weight(o) is BehaviorWeight.SUPPORTING]
    ubiquitous = [o for o in matched if _weight(o) is BehaviorWeight.UBIQUITOUS]

    if decisive:
        return EvidenceVerdict(
            EvidenceStrength.CONCLUSIVE, matched, support,
            f"{decisive[0].behavior.value} observed "
            f"({decisive[0].count} event(s)): {decisive[0].description}",
        )
    if len(strong) >= 2:
        names = ", ".join(o.behavior.value for o in strong[:3])
        return EvidenceVerdict(
            EvidenceStrength.CONCLUSIVE, matched, support,
            f"two or more independent characteristic behaviours observed: {names}",
        )
    if strong:
        return EvidenceVerdict(
            EvidenceStrength.MODERATE, matched, support,
            f"{strong[0].behavior.value} observed ({strong[0].count} event(s)), "
            f"without a second corroborating behaviour",
        )
    if supporting_hits:
        names = ", ".join(o.behavior.value for o in supporting_hits[:3])
        return EvidenceVerdict(
            EvidenceStrength.MODERATE, matched, support,
            f"supporting behaviour(s) observed: {names}",
        )
    if ubiquitous:
        return EvidenceVerdict(
            EvidenceStrength.WEAK, matched, support,
            f"only behaviour common to every application was observed: "
            f"{', '.join(o.behavior.value for o in ubiquitous[:3])}",
        )
    if support:
        return EvidenceVerdict(
            EvidenceStrength.WEAK, matched, support,
            "only peripherally related behaviour was observed",
        )
    return EvidenceVerdict(EvidenceStrength.NONE, [], [], "")


@dataclass
class EvidenceVerdict:
    """The strength of the case for one goal, and what it rests on."""

    strength: EvidenceStrength
    matched: List[BehaviorObservation] = field(default_factory=list)
    supporting: List[BehaviorObservation] = field(default_factory=list)
    reason: str = ""

    @property
    def conclusive(self) -> bool:
        return self.strength is EvidenceStrength.CONCLUSIVE

    @property
    def partial(self) -> bool:
        return self.strength in (EvidenceStrength.MODERATE, EvidenceStrength.WEAK)

    def evidence_events(self) -> List[NormalizedEvent]:
        out: List[NormalizedEvent] = []
        for obs in list(self.matched) + list(self.supporting):
            out.extend(obs.events)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strength": self.strength.value,
            "reason": self.reason,
            "matched_behaviors": [o.behavior.value for o in self.matched],
            "supporting_behaviors": [o.behavior.value for o in self.supporting],
            "evidence_event_count": len(self.evidence_events()),
        }


def all_declared_hooks() -> Set[str]:
    """
    Every hook name this taxonomy depends on.

    Consumed by the contract test, which reads the agent source and fails the
    build when a name here stops being emitted - the check that stops this
    table drifting into fiction the way the goal graph's did.
    """
    names: Set[str] = set()
    for rule in BEHAVIOR_RULES:
        names.update(rule.hooks)
    return names


def behaviors_by_weight(
    observed: Mapping[Behavior, BehaviorObservation],
) -> Dict[str, List[str]]:
    """Observed behaviours grouped by weight, for the diagnostics panel."""
    grouped: Dict[str, List[str]] = defaultdict(list)
    for obs in observed.values():
        grouped[obs.weight.value].append(obs.behavior.value)
    return {k: sorted(v) for k, v in grouped.items()}
