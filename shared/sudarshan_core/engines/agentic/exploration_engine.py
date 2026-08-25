"""
SUDARSHAN - Deep Exploration Engine
====================================
Deterministic state-graph exploration with AI-assisted prioritization.

Architecture:
    DETERMINISTIC EXPLORATION ENGINE + AI PRIORITIZER + STATE/GRAPH MEMORY

The 15-stage fraud DAG remains as threat-intelligence prioritization only.
Exploration boundary is the reachable application state graph, not goal completion.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


# ─── Configurable exploration budgets ─────────────────────────────────────────

class ExplorationBudget:
    """Configurable limits for deep exploration."""

    MAX_ACTIONS: int = int(os.getenv("SUDARSHAN_AGENT_ACTION_BUDGET", "120"))
    MAX_STATES: int = int(os.getenv("SUDARSHAN_MAX_EXPLORATION_STATES", "200"))
    MAX_DEPTH: int = int(os.getenv("SUDARSHAN_MAX_EXPLORATION_DEPTH", "25"))
    MAX_REPEATED_STATE_VISITS: int = int(
        os.getenv("SUDARSHAN_MAX_REPEATED_STATE_VISITS", "5")
    )
    MAX_SCROLL_DEPTH: int = int(os.getenv("SUDARSHAN_MAX_SCROLL_DEPTH", "8"))
    MAX_SECONDARY_APKS: int = int(os.getenv("SUDARSHAN_MAX_SECONDARY_APKS", "3"))
    MAX_EXTERNAL_INSTALL_ATTEMPTS: int = int(
        os.getenv("SUDARSHAN_MAX_EXTERNAL_INSTALL_ATTEMPTS", "2")
    )
    MAX_CRASH_RECOVERY_ATTEMPTS: int = int(
        os.getenv("SUDARSHAN_MAX_CONSECUTIVE_CRASHES", "3")
    )
    MAX_BACKTRACKS: int = int(os.getenv("SUDARSHAN_MAX_BACKTRACKS", "20"))
    #: Actions the agent may spend inside one system boundary (installer,
    #: permission controller, a consent screen hosted by Settings) before it is
    #: sent back to the sample. Answering a prompt takes 1-2 actions; 6 leaves
    #: room for a scroll and a confirm step without letting a system app absorb
    #: the run, which a measured 300s trace showed it otherwise does entirely.
    MAX_BOUNDARY_ACTIONS: int = int(
        os.getenv("SUDARSHAN_MAX_BOUNDARY_ACTIONS", "6")
    )
    #: Credential sets offered to one login form before the walk moves on.
    #: The run does NOT give up after a single silent attempt - a submit can
    #: race the keyboard, and a form can clear itself - so a fresh identity is
    #: tried up to this many times. An explicit "invalid credentials" from the
    #: app ends it immediately, whatever the count (see note_login_outcome).
    MAX_LOGIN_ATTEMPTS: int = int(
        os.getenv("SUDARSHAN_MAX_LOGIN_ATTEMPTS", "5")
    )
    MAX_RETRIES_PER_ACTION: int = int(
        os.getenv("SUDARSHAN_MAX_ACTION_RETRIES", "3")
    )
    FRIDA_SILENCE_THRESHOLD: int = int(
        os.getenv("SUDARSHAN_AGENT_SILENCE_THRESHOLD", "8")
    )


class StopReason(str, Enum):
    EXPLORATION_COMPLETE = "EXPLORATION_COMPLETE"
    EXPLORATION_BUDGET_EXHAUSTED = "EXPLORATION_BUDGET_EXHAUSTED"
    TIME_BUDGET_EXHAUSTED = "TIME_BUDGET_EXHAUSTED"
    SAFETY_BOUNDARY_REACHED = "SAFETY_BOUNDARY_REACHED"
    SANDBOX_FAILURE = "SANDBOX_FAILURE"
    SANDBOX_BLOCKED = "SANDBOX_BLOCKED"
    APPLICATION_CRASH_LOOP = "APPLICATION_CRASH_LOOP"
    APPLICATION_UNAVAILABLE = "APPLICATION_UNAVAILABLE"
    NO_UNEXPLORED_ACTIONS = "NO_UNEXPLORED_ACTIONS"
    CANCELLED = "CANCELLED"
    FATAL_ERROR = "FATAL_ERROR"


# ─── Application profile (evolving understanding) ───────────────────────────────

@dataclass
class ApplicationProfile:
    """Dynamic model of the unknown application under investigation."""

    apparent_purpose: str = "Unknown application"
    discovered_features: List[str] = field(default_factory=list)
    discovered_workflows: List[str] = field(default_factory=list)
    discovered_permissions: List[str] = field(default_factory=list)
    discovered_external_apps: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    discovered_activities: List[str] = field(default_factory=list)
    discovered_webviews: List[str] = field(default_factory=list)
    discovered_security_capabilities: List[str] = field(default_factory=list)
    discovered_suspicious_behaviors: List[str] = field(default_factory=list)
    discovered_ui_states: List[str] = field(default_factory=list)
    unexplored_capabilities: List[str] = field(default_factory=list)

    def add_feature(self, feature: str) -> None:
        if feature and feature not in self.discovered_features:
            self.discovered_features.append(feature)

    def add_workflow(self, workflow: str) -> None:
        if workflow and workflow not in self.discovered_workflows:
            self.discovered_workflows.append(workflow)

    def add_suspicious(self, behavior: str) -> None:
        if behavior and behavior not in self.discovered_suspicious_behaviors:
            self.discovered_suspicious_behaviors.append(behavior)

    def add_security_capability(self, capability: str) -> None:
        if capability and capability not in self.discovered_security_capabilities:
            self.discovered_security_capabilities.append(capability)

    def revise_purpose(self, new_purpose: str, evidence: str = "") -> None:
        if new_purpose and new_purpose != self.apparent_purpose:
            logger.info(
                "[ApplicationProfile] Purpose revised: '%s' -> '%s' (%s)",
                self.apparent_purpose, new_purpose, evidence,
            )
            self.apparent_purpose = new_purpose

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Evidence moments ───────────────────────────────────────────────────────────

class EvidenceMomentType(str, Enum):
    SUSPICIOUS_PERMISSION = "SUSPICIOUS_PERMISSION"
    EXTERNAL_APK_DOWNLOAD = "EXTERNAL_APK_DOWNLOAD"
    EXTERNAL_APK_INSTALL_REQUEST = "EXTERNAL_APK_INSTALL_REQUEST"
    VPN_REQUEST = "VPN_REQUEST"
    ACCESSIBILITY_REQUEST = "ACCESSIBILITY_REQUEST"
    OVERLAY_REQUEST = "OVERLAY_REQUEST"
    SMS_REQUEST = "SMS_REQUEST"
    UPDATE_REQUEST = "UPDATE_REQUEST"
    SUSPICIOUS_WEBVIEW = "SUSPICIOUS_WEBVIEW"
    DYNAMIC_CODE_LOAD = "DYNAMIC_CODE_LOAD"
    C2_COMMUNICATION = "C2_COMMUNICATION"
    AUTHENTICATION_BOUNDARY = "AUTHENTICATION_BOUNDARY"
    CRASH = "CRASH"
    ANTI_ANALYSIS = "ANTI_ANALYSIS"
    EXTERNAL_NAVIGATION = "EXTERNAL_NAVIGATION"
    DOWNLOAD_PROMPT = "DOWNLOAD_PROMPT"


@dataclass
class EvidenceMoment:
    evidence_moment_id: str
    timestamp: str
    moment_type: str
    title: str
    description: str
    package: str = ""
    activity: str = ""
    state_id: str = ""
    action_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    screenshot_ids: List[str] = field(default_factory=list)
    runtime_event_ids: List[str] = field(default_factory=list)
    network_event_ids: List[str] = field(default_factory=list)
    permission: str = ""
    external_package: str = ""
    external_url: str = ""
    severity: str = "MEDIUM"
    context: str = ""
    analyst_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Action inventory item ────────────────────────────────────────────────────

@dataclass
class ActionItem:
    """One actionable UI element discovered on a screen."""

    action_id: str
    node_id: str
    action_type: str          # click / input / scroll / check / tab / menu
    label: str
    resource_id: str = ""
    class_name: str = ""
    center_x: int = 0
    center_y: int = 0
    is_input: bool = False
    is_scrollable: bool = False
    is_clickable: bool = True
    is_checkable: bool = False
    #: What this input wants ("username", "password", "otp", ...). Resolved once
    #: at discovery from the field's password flag and its caption, and carried
    #: to the executor as `field_hint`, so the value typed matches the field.
    field_kind: str = ""
    priority: int = 50
    explored: bool = False
    failed: bool = False
    blocked: bool = False
    unreachable: bool = False
    scroll_container_id: str = ""
    scroll_direction: str = ""
    scroll_position: int = 0
    semantic_role: str = "UNKNOWN"
    #: Victim-policy score for this control on the screen it was ranked for.
    #: Recomputed by every rank_actions() call, because the same label scores
    #: differently on a permission prompt than in a settings list.
    victim_score: int = 0
    detection_source: str = "uiautomator"
    confidence: float = 0.99
    bounds: str = ""
    selected: bool = False
    dispatched: bool = False
    executed: bool = False
    verified: bool = False
    execution_attempts: int = 0

    def signature(self) -> str:
        """
        Stable identity for de-duplicating an action across observations.

        `node_id` is deliberately absent. Perception numbers nodes positionally
        (`n0`, `n1`, ...), so raising the soft keyboard - which reorders and
        reflows a WebView hierarchy - renumbered every node and made each
        control look new. The merge path in observe() then appended a second
        unexplored copy of the same button on every visit, and the inventory
        grew without bound while the screen stood still.

        What a control IS - its role, its caption, its id, its class and its
        size - does not change when the layout moves.
        """
        return ":".join((
            self.action_type,
            self.label,
            self.resource_id,
            self.class_name,
            _bounds_bucket(self.bounds),
            self.scroll_direction,
        ))

    @property
    def resolved(self) -> bool:
        return self.verified or self.failed or self.blocked or self.unreachable or self.explored


# ─── Exploration state node ───────────────────────────────────────────────────

@dataclass
class ExplorationState:
    state_id: str
    screen_hash: str
    ui_tree_hash: str
    activity_name: str
    package_name: str
    foreground_package: str
    visible_text_summary: str
    semantic_type: str
    ownership: str = "TARGET_APP"
    screenshot_ref: str = ""
    actionable_elements: List[ActionItem] = field(default_factory=list)
    scrollable_regions: List[str] = field(default_factory=list)
    dialogs: List[str] = field(default_factory=list)
    webviews: List[str] = field(default_factory=list)
    timestamp: str = ""
    visit_count: int = 1
    explored: bool = False
    parent_state_id: str = ""
    entry_action: str = ""
    #: The screen is rendered inside a WebView. Recorded because it changes what
    #: the back key means: a WebView app runs its whole journey in one Activity,
    #: so back leaves the app rather than traversing it.
    is_webview: bool = False
    runtime_event_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    scroll_positions_explored: Dict[str, Set[str]] = field(default_factory=dict)

    def unexplored_actions(self) -> List[ActionItem]:
        return [a for a in self.actionable_elements if not a.resolved]

    def unresolved_actions(self) -> List[ActionItem]:
        return [a for a in self.actionable_elements if not a.resolved]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scroll_positions_explored"] = {
            k: list(v) for k, v in self.scroll_positions_explored.items()
        }
        return d


@dataclass
class ExplorationEdge:
    edge_id: str
    source_state_id: str
    target_state_id: str
    action_type: str
    target_description: str
    resource_id: str = ""
    coordinates: str = ""
    result: str = "unknown"
    verified: bool = False
    timestamp: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    screenshot_ids: List[str] = field(default_factory=list)
    runtime_event_ids: List[str] = field(default_factory=list)
    action_id: str = ""
    pre_state_hash: str = ""
    post_state_hash: str = ""
    ui_changed: bool = False
    new_actions_found: int = 0
    runtime_event_count: int = 0
    retry_count: int = 0
    failure_reason: str = ""
    status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── State identity ─────────────────────────────────────────────────────────────

#: Geometry bucket, in pixels, applied to a control's SIZE.
#:
#: Position is deliberately not part of the signature. On the WebView banking
#: apps in the corpus, focusing an input raises the soft keyboard and shifts
#: every control below it - measured at 63px on the SBI baseline, which is
#: enough to change any position bucket fine enough to be worth having. Scroll
#: does the same thing to a whole screen. Both would make one screen read as
#: several, which is exactly the fragmentation this signature exists to stop.
#:
#: Size does not move: a 955x118 text box is that size wherever the keyboard
#: pushes it, and a full-width banner is still distinguishable from a small
#: icon button, which is what geometry is here to contribute.
_BOUNDS_BUCKET_PX: int = 16

_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


def _bounds_bucket(bounds: str) -> str:
    """Fold a control's width and height onto a coarse grid, ignoring position."""
    if not bounds:
        return ""
    m = _BOUNDS_RE.match(bounds.strip())
    if not m:
        return ""
    x1, y1, x2, y2 = (int(v) for v in m.groups())
    b = _BOUNDS_BUCKET_PX
    return f"{max(0, x2 - x1) // b}x{max(0, y2 - y1) // b}"


#: Resource ids that name chrome, not controls. A node carrying one of these is
#: decoration even when an ancestor happens to be clickable.
_DECORATIVE_RESOURCE_IDS = frozenset({
    "action_bar_title",
    "action_bar_subtitle",
    "toolbar_title",
    "alertTitle",
    "title_template",
    "topPanel",
    "contentPanel",
})


def _is_decorative_label(
    label: str, resource_id: str, detection_source: str,
) -> bool:
    """
    Whether a text node is chrome that only *looks* actionable.

    Only nodes admitted by `clickable_parent_recovery` are judged. That recovery
    exists so a label inside a clickable list row is still reachable, and it is
    worth keeping - but it also promotes an ActionBar title, whose ancestor
    toolbar is clickable and does nothing when tapped. A measured run spent 22s
    each on `InsecureBankv2` and `FilePref`, both `action_bar_title`, and on the
    form labels `Server IP:` / `Server Port:`, before the retry ladder gave up.

    Nodes that declare `clickable="true"` in the hierarchy are never judged
    here: an app is entitled to make a TextView a button, and a genuine
    text-labelled control must survive this filter.
    """
    if detection_source != "clickable_parent_recovery":
        return False
    if resource_id in _DECORATIVE_RESOURCE_IDS:
        return True
    # "Server IP:" labels a field; "Preferences" is a menu item. The trailing
    # colon is the convention that separates them.
    return label.strip().endswith(":")


def _is_input_node(node: Any) -> bool:
    """
    Whether a node holds user-entered text.

    Checked structurally as well as by flag: `is_input` is set by the perception
    parser, but a node arriving from visual grounding or a test fixture may only
    carry its class name.
    """
    if bool(getattr(node, "is_input", False)):
        return True
    cls = (getattr(node, "class_name", "") or "").lower()
    return "edittext" in cls or "autocomplete" in cls or "searchview" in cls


def compute_composite_state_signature(
    activity: str,
    package: str,
    ui_nodes: List[Any],
    visible_text: str = "",
    webview_sig: str = "",
    scroll_position: int = 0,
) -> Tuple[str, str]:
    """
    Build composite state identity from multiple evidence sources.

    Returns (screen_hash, ui_tree_hash).

    Identity is STRUCTURAL. What a screen *is* - its activity, its controls,
    their ids, classes, roles, interactivity and geometry - decides the state.
    What a control currently *contains* does not, for input fields.

    This distinction is the difference between exploring a form and looping on
    it. Volatile typed text used to be hashed directly, so `Password=""` and
    `Password="a"` were two different states: filling one field re-forked the
    screen, every action on it reset to unexplored, and the previously explored
    branches were offered again. A live run on InsecureBankv2 turned a single
    LoginActivity into five states and issued 306 action ids for six widgets,
    and the form was never completed because typing field 1 invalidated the plan
    for field 2.

    Input fields therefore contribute a *filled/empty* bucket rather than their
    contents. Non-input text still contributes in full: a label changing from
    "Sign in" to "Welcome back" is a real transition and must remain one.
    """
    tree_parts: List[str] = [activity, package]

    for n in ui_nodes:
        cls = getattr(n, "class_name", "") or ""
        text = getattr(n, "text", "") or ""
        desc = getattr(n, "desc", "") or ""
        res_id = getattr(n, "resource_id", "") or ""
        clickable = bool(getattr(n, "is_clickable", False))
        scrollable = bool(getattr(n, "is_scrollable", False))
        checkable = bool(getattr(n, "is_checkable", False))
        enabled = bool(getattr(n, "enabled", True))
        is_input = _is_input_node(n)
        # A container's size tracks the soft keyboard, not the screen. The
        # WebView hosting a login form measures 1080x2209 with the keyboard down
        # and 1080x2272 with it up, which is enough to fork one screen into
        # three states. Controls keep their size bucket; the page does not.
        geom = (
            ""
            if any(c in cls.lower() for c in _CONTAINER_CLASSES)
            else _bounds_bucket(getattr(n, "bounds", "") or "")
        )

        if is_input:
            # A field's VALUE is not part of what the screen is. Bucketing on
            # "filled vs empty" is not enough either: the first character still
            # forks the state, and a two-field form still splits four ways. The
            # field's identity, role, geometry and enabled-ness all still count
            # below - only what the user typed into it is excluded.
            #
            # Whether the form has been filled is tracked where it belongs, on
            # the input ActionItem's `explored` flag, which now survives because
            # the state no longer forks underneath it.
            content = "<input>"
        else:
            content = text[:30]

        tree_parts.append(
            f"{cls}|{content}|{desc[:30]}|{res_id}|"
            f"c{int(clickable)}e{int(enabled)}s{int(scrollable)}"
            f"k{int(checkable)}i{int(is_input)}|{geom}"
        )

    if webview_sig:
        tree_parts.append(f"webview:{webview_sig}")
    if scroll_position:
        tree_parts.append(f"scroll:{scroll_position}")

    tree_raw = ";".join(tree_parts)
    ui_tree_hash = hashlib.sha256(tree_raw.encode()).hexdigest()[:16]
    screen_hash = hashlib.sha256(
        f"{activity}:{package}:{ui_tree_hash}".encode()
    ).hexdigest()[:16]
    return screen_hash, ui_tree_hash


def _visible_text_summary(ui_nodes: List[Any], max_chars: int = 300) -> str:
    parts: List[str] = []
    for n in ui_nodes:
        t = getattr(n, "text", "") or getattr(n, "desc", "") or ""
        if t.strip():
            parts.append(t.strip()[:60])
    return " | ".join(parts)[:max_chars]


# ─── Keyword detectors (generic, not app-specific) ───────────────────────────

_UPDATE_KEYWORDS = (
    "update available", "new update", "install update", "download update",
    "update now", "new version", "upgrade", "update required",
)
_VPN_KEYWORDS = (
    "enable vpn", "install vpn", "vpn required", "configure vpn",
    "vpn connection", "vpn app", "turn on vpn",
)
_APK_KEYWORDS = (
    "install app", "install application", "install security", "install this",
    "download apk", "unknown sources", "install from", "package installer",
)
_DOWNLOAD_KEYWORDS = (
    "download", "downloading", "fetch", "get update",
)
_MENU_KEYWORDS = (
    "menu", "more options", "overflow", "navigation drawer", "hamburger",
)
_SMS_KEYWORDS = ("sms", "read messages", "send sms", "text message")
_AUTH_KEYWORDS = ("login", "sign in", "password", "otp", "pin", "captcha")

#: Controls that SUBMIT a form. Pressing one before the fields are filled asks
#: the app to validate an empty form: it refuses, the UI does not move, and the
#: action is written off as failed - which is what a measured run did to the
#: only Login button on the screen, three attempts and ~22s before ever typing
#: a character. These are held back until the inputs above them are filled.
#: Matched on WORD boundaries, never as substrings. Plain substring matching
#: made "Forgot MPIN?" a submit control, because "go" is inside "Forgot" - so
#: the agent treated a password-reset link as the login button and spent its
#: credential-retry budget on it.
#:
#: "register" / "sign up" are deliberately absent: they open a different flow
#: rather than submitting the credentials on screen.
_SUBMIT_KEYWORDS = (
    "login", "log in", "signin", "sign in", "submit", "continue", "proceed",
    "next", "confirm", "verify", "done", "go", "ok", "pay", "send",
    "unlock", "authenticate",
)

_SUBMIT_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in _SUBMIT_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def _is_submit_label(label: str) -> bool:
    """Whether this caption reads like a form-submit control."""
    text = (label or "").strip()
    if not text:
        return False
    # A question is a prompt, not a submit: "Forgot Password?",
    # "New user? Register", "Don't have an account?".
    if "?" in text:
        return False
    return bool(_SUBMIT_RE.search(text))


#: Minimum distinct digit keys before a screen counts as a numeric keypad.
#: A 0-9 pad has ten; requiring eight tolerates one hidden or mis-parsed key
#: without matching a screen that merely happens to show a couple of numbers.
_KEYPAD_MIN_DIGITS: int = 8

#: Digits entered when a keypad is detected. Six is the common MPIN length in
#: the corpus; a pad that wants four accepts the first four and ignores the
#: rest, and a pad that wants more simply stays on screen for another pass.
PIN_ENTRY_LENGTH: int = int(os.getenv("SUDARSHAN_PIN_ENTRY_LENGTH", "6"))


def _digit_keys(items: List["ActionItem"]) -> Dict[str, "ActionItem"]:
    """Single-digit keys on this screen, by digit."""
    keys: Dict[str, ActionItem] = {}
    for item in items:
        label = (item.label or "").strip()
        if len(label) == 1 and label.isdigit() and item.action_type in ("click", "check"):
            keys.setdefault(label, item)
    return keys


def _is_keypad_state(state: "ExplorationState") -> bool:
    """
    Whether this screen is a numeric PIN pad.

    The banking corpus gates its dashboard behind an MPIN pad after the password
    login. Explored one key per iteration it is not a screen but a wall: at
    ~11s an action, entering six digits costs a minute and the pad clears itself
    whenever the walk wanders off to try another key.
    """
    return len(_digit_keys(state.actionable_elements)) >= _KEYPAD_MIN_DIGITS


def _is_submit_action(item: "ActionItem") -> bool:
    """Whether this control submits the form it sits on."""
    if item.action_type not in ("click", "check"):
        return False
    return _is_submit_label(item.label)

#: Tie-breaking nudge for the affirmative option in a two-way decision dialog.
#: Deliberately small: score_action() has already ranked on the security
#: signal, and this only settles otherwise-close pairs (Yes/No, OK/Cancel).
_AFFIRMATIVE_BOOST = 15


def _text_matches(text: str, keywords: Tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(k in lower for k in keywords)


def _is_unlabeled_action(action: "ActionItem") -> bool:
    label = (action.label or "").strip()
    if not label:
        return True
    if re.fullmatch(r"n\d+", label, re.I):
        return True
    if label.lower().startswith("scroll:"):
        return False
    return False


def _bounds_area(bounds: str) -> int:
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
    if not m:
        return 0
    x1, y1, x2, y2 = map(int, m.groups())
    return max(0, (x2 - x1) * (y2 - y1))


#: Classes that hold other views rather than being controls themselves. A
#: clickable one is a page background, not a button.
_CONTAINER_CLASSES = (
    "webview", "scrollview", "viewgroup", "framelayout", "linearlayout",
    "relativelayout", "recyclerview", "listview", "gridview", "constraintlayout",
    "coordinatorlayout", "nestedscrollview", "viewpager",
)

#: A control this large is the page, not a control on it.
_FULLSCREEN_AREA_PX = 900_000


def _is_container_action(item: "ActionItem") -> bool:
    """
    Whether this 'control' is really the page background.

    The WebView hosting a banking app's login form is itself clickable and
    carries the document title as its text ("app"), so it entered the inventory
    as a full-screen labelled button. Tapping it does nothing, and it is offered
    on every screen of every WebView app in the corpus.
    """
    cls = (item.class_name or "").lower()
    if not any(c in cls for c in _CONTAINER_CLASSES):
        return False
    return _bounds_area(item.bounds) >= _FULLSCREEN_AREA_PX


def _prune_container_actions(items: List["ActionItem"]) -> List["ActionItem"]:
    """Drop full-screen parents when real CTAs exist."""
    labeled = [
        i for i in items
        if not _is_unlabeled_action(i)
        and not _is_container_action(i)
        and i.action_type != "scroll"
    ]
    if not labeled:
        return items
    kept: List[ActionItem] = []
    for item in items:
        if item.action_type == "scroll":
            kept.append(item)
            continue
        if _is_unlabeled_action(item) and _bounds_area(item.bounds) >= 40_000:
            continue
        if _is_unlabeled_action(item):
            continue
        # A labelled full-screen container is still the page, not a control.
        # Only dropped when genuine CTAs exist, so a screen whose ONLY
        # interactive element really is a full-bleed surface keeps it.
        if _is_container_action(item):
            continue
        kept.append(item)
    return kept or items


#: Screen types that ARE a required boundary action - a prompt the sample put
#: in front of the user, which the run exists to answer. These are admitted to
#: the target graph wherever they appear, including inside Settings, because the
#: accessibility and VPN consent flows are hosted by com.android.settings.
#:
#: "SETTINGS" is deliberately NOT here. A generic Settings screen is not a
#: prompt the sample raised; it is somewhere the agent wandered.
_INTERACTIVE_BOUNDARY_TYPES = frozenset({
    "SYSTEM_PERMISSION",
    "ACCESSIBILITY_DIALOG",
    "VPN_REQUEST",
    "PACKAGE_INSTALLER",
    "EXTERNAL_APK",
    "UPDATE_PROMPT",
    "DOWNLOAD_PROMPT",
})

#: Packages whose ENTIRE purpose is to host boundary dialogs, so ownership alone
#: is sufficient evidence that the screen is a prompt.
#:
#: SYSTEM_SETTINGS was removed. com.android.settings is a full application with
#: effectively unbounded UI; admitting it on ownership turned every Settings
#: screen into first-class target work. A measured 300s run answered 55 of 55
#: observations from com.android.settings, made 0 out-of-scope recoveries and 0
#: observations of the sample. A Settings screen now qualifies only when its
#: semantic_type is one of _INTERACTIVE_BOUNDARY_TYPES above.
_INTERACTIVE_BOUNDARY_OWNERSHIP = frozenset({
    "SYSTEM_INSTALLER",
    "SYSTEM_PERMISSION",
})

#: Visits after which a state's pending scroll actions are promoted ahead of its
#: clicks. Low enough that below-the-fold content is reached early, high enough
#: that a screen is not scrolled before its visible controls are tried.
_SCROLL_FAIRNESS_VISITS: int = int(
    os.getenv("SUDARSHAN_SCROLL_FAIRNESS_VISITS", "2")
)

#: Ownership values that denote a system surface rather than the sample.
_SYSTEM_OWNERSHIP = frozenset({
    "SYSTEM_INSTALLER",
    "SYSTEM_PERMISSION",
    "SYSTEM_SETTINGS",
    "EXTERNAL_APP",
})


# ─── Action prioritizer ─────────────────────────────────────────────────────────

class ActionPrioritizer:
    """Deterministic exploration priority scoring."""

    @staticmethod
    def score_action(
        action: ActionItem,
        profile: ApplicationProfile,
        semantic_type: str = "",
        context_text: str = "",
    ) -> int:
        from sudarshan_core.engines.agentic.semantic_action import (
            SemanticRole,
            acceptance_priority_boost,
            is_acceptance_role,
        )
        from sudarshan_core.engines.agentic.victim_policy import score_ui_node

        score = 50
        label_lower = (action.label or "").lower()

        if not action.resolved:
            score += 30
        if action.failed:
            score -= 40
        if action.blocked:
            score -= 50

        # Semantic acceptance policy — simulated unsuspecting user
        try:
            role = SemanticRole(action.semantic_role)
        except ValueError:
            role = SemanticRole.UNKNOWN
        if is_acceptance_role(role):
            score += acceptance_priority_boost(role)
        score += int((action.confidence or 0.5) * 10)

        # Security-relevant UI patterns (generic keyword detection)
        if _text_matches(label_lower, _APK_KEYWORDS):
            score += 80
        if _text_matches(label_lower, _VPN_KEYWORDS):
            score += 75
        if _text_matches(label_lower, _UPDATE_KEYWORDS):
            score += 70
        if _text_matches(label_lower, _DOWNLOAD_KEYWORDS):
            score += 65
        # Screen-type bonus applies to meaningful CTAs only. Applying it to
        # every node flattened ranking to 100 and made XML order (often a
        # full-screen clickable parent) win over Install/OK/Allow.
        if is_acceptance_role(role):
            if semantic_type in ("SYSTEM_PERMISSION", "ACCESSIBILITY_DIALOG"):
                score += 90
            if semantic_type in (
                "UPDATE_PROMPT", "VPN_REQUEST", "EXTERNAL_APK",
                "PACKAGE_INSTALLER", "DOWNLOAD_PROMPT",
            ):
                score += 85
        if _text_matches(label_lower, _SMS_KEYWORDS):
            score += 80
        if _text_matches(label_lower, ("settings", "configure", "permission")):
            score += 55
        if _text_matches(label_lower, _MENU_KEYWORDS):
            score += 60
        if action.is_scrollable and not action.explored:
            score += 20
        if action.action_type == "scroll":
            score += 15
        if _text_matches(label_lower, ("help", "about", "history", "info")):
            score += 35
        if _text_matches(label_lower, ("continue", "next", "proceed", "get started")):
            score += 50  # Primary flow progression
        if _text_matches(label_lower, ("cancel", "close", "dismiss", "not now")):
            score -= 20  # deprioritize but don't exclude
        if _is_unlabeled_action(action):
            score -= 35

        # ── Victim policy ────────────────────────────────────────────────────
        # The scoring above answers "what is worth exploring". This answers
        # "what would a gullible user tap", which is a different question and
        # the one that decides whether a multi-stage journey continues. Added,
        # not substituted: exploration value still ranks the screens where no
        # control is a consent control.
        action.victim_score = score_ui_node(
            action.label, "", action.resource_id, action.class_name, semantic_type,
        )
        score += action.victim_score

        return max(0, score)

    @staticmethod
    def rank_actions(
        actions: List[ActionItem],
        profile: ApplicationProfile,
        semantic_type: str = "",
        context_text: str = "",
    ) -> List[ActionItem]:
        from sudarshan_core.engines.agentic.semantic_action import infer_affirmative_choice

        for a in actions:
            a.priority = ActionPrioritizer.score_action(
                a, profile, semantic_type, context_text,
            )
        ranked = sorted(actions, key=lambda a: (-a.priority, a.action_id))
        # Boost the inferred affirmative choice for decision dialogs.
        #
        # This must ADD, never clamp. It previously read
        # `min(100, priority + 15)`, which silently DEMOTED any affirmative
        # scoring above 85 - and the clearer the acceptance signal, the higher
        # score_action() puts it, so the clamp hit hardest exactly where the
        # victim most needed to say yes. Measured: "Install update" scored 159
        # against "Help" at 124, then the clamp knocked it to 100 and the
        # explorer clicked Help. That is the shallow-exploration bug: the
        # naive victim never reached INSTALL. Scores are an open-ended ranking
        # signal, not a 0-100 scale, so there is nothing to clamp to.
        if len(ranked) >= 2:
            affirmative = infer_affirmative_choice(ranked, context_text=context_text)
            if affirmative is not None:
                affirmative.priority += _AFFIRMATIVE_BOOST
                ranked = sorted(ranked, key=lambda a: (-a.priority, a.action_id))
        return ranked


# ─── Evidence moment detector ─────────────────────────────────────────────────

class EvidenceMomentDetector:
    """Detect security-relevant evidence moments from observations."""

    def __init__(self, package_name: str = "") -> None:
        self.package_name = package_name
        self._seen_types: Set[str] = set()

    def detect(
        self,
        obs: Any,
        semantic_type: str,
        state_id: str = "",
        elapsed_ts: str = "00:00",
    ) -> List[EvidenceMoment]:
        moments: List[EvidenceMoment] = []
        combined = _visible_text_summary(getattr(obs, "ui_nodes", []))
        activity = getattr(obs, "activity", "")

        checks = [
            (EvidenceMomentType.UPDATE_REQUEST, _UPDATE_KEYWORDS, "Update prompt displayed"),
            (EvidenceMomentType.VPN_REQUEST, _VPN_KEYWORDS, "VPN enable/install requested"),
            (EvidenceMomentType.EXTERNAL_APK_INSTALL_REQUEST, _APK_KEYWORDS, "External application install requested"),
            (EvidenceMomentType.DOWNLOAD_PROMPT, _DOWNLOAD_KEYWORDS, "Download prompt displayed"),
        ]

        for moment_type, keywords, title in checks:
            key = f"{moment_type.value}:{state_id}"
            if key in self._seen_types:
                continue
            if _text_matches(combined, keywords) or _text_matches(activity.lower(), keywords):
                self._seen_types.add(key)
                moments.append(EvidenceMoment(
                    evidence_moment_id=f"EVM-{uuid4().hex[:8]}",
                    timestamp=elapsed_ts,
                    moment_type=moment_type.value,
                    title=title,
                    description=f"Observed on screen: {combined[:200]}",
                    package=self.package_name,
                    activity=activity,
                    state_id=state_id,
                    severity="HIGH" if moment_type in (
                        EvidenceMomentType.VPN_REQUEST,
                        EvidenceMomentType.EXTERNAL_APK_INSTALL_REQUEST,
                    ) else "MEDIUM",
                    context=combined[:300],
                ))

        if semantic_type == "SYSTEM_PERMISSION":
            key = f"perm:{state_id}"
            if key not in self._seen_types:
                self._seen_types.add(key)
                moments.append(EvidenceMoment(
                    evidence_moment_id=f"EVM-{uuid4().hex[:8]}",
                    timestamp=elapsed_ts,
                    moment_type=EvidenceMomentType.SUSPICIOUS_PERMISSION.value,
                    title="Runtime permission dialog",
                    description=combined[:200],
                    package=self.package_name,
                    activity=activity,
                    state_id=state_id,
                    severity="HIGH",
                ))

        if semantic_type == "ACCESSIBILITY_DIALOG":
            key = f"acc:{state_id}"
            if key not in self._seen_types:
                self._seen_types.add(key)
                moments.append(EvidenceMoment(
                    evidence_moment_id=f"EVM-{uuid4().hex[:8]}",
                    timestamp=elapsed_ts,
                    moment_type=EvidenceMomentType.ACCESSIBILITY_REQUEST.value,
                    title="Accessibility service request",
                    description=combined[:200],
                    package=self.package_name,
                    state_id=state_id,
                    severity="CRITICAL",
                ))

        if getattr(obs, "is_webview", False):
            key = f"wv:{state_id}"
            if key not in self._seen_types:
                self._seen_types.add(key)
                moments.append(EvidenceMoment(
                    evidence_moment_id=f"EVM-{uuid4().hex[:8]}",
                    timestamp=elapsed_ts,
                    moment_type=EvidenceMomentType.SUSPICIOUS_WEBVIEW.value,
                    title="WebView content detected",
                    description=f"Activity: {activity}",
                    package=self.package_name,
                    state_id=state_id,
                    severity="MEDIUM",
                ))

        return moments


# ─── Victim journey builder ───────────────────────────────────────────────────

class VictimJourneyBuilder:
    """Reconstruct victim journey from evidence moments only."""

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []

    def add_moment(self, moment: EvidenceMoment) -> None:
        self._entries.append({
            "timestamp": moment.timestamp,
            "event": moment.title,
            "description": moment.description,
            "evidence_moment_id": moment.evidence_moment_id,
            "type": moment.moment_type,
            "severity": moment.severity,
            "state_id": moment.state_id,
            "screenshot_ids": list(moment.screenshot_ids),
            "evidence_ids": list(moment.evidence_ids),
        })

    def add_launch(self, timestamp: str = "00:00") -> None:
        if not any(e.get("event") == "Application launched" for e in self._entries):
            self._entries.insert(0, {
                "timestamp": timestamp,
                "event": "Application launched",
                "description": "User opens application.",
                "evidence_moment_id": "",
                "type": "LAUNCH",
                "severity": "INFO",
            })

    def build_narrative(self) -> List[str]:
        lines: List[str] = []
        for e in self._entries:
            lines.append(f"{e['timestamp']}\n{e['description']}")
        return lines

    def build_chain(self) -> str:
        types = [e.get("type", "") for e in self._entries if e.get("type") not in ("LAUNCH", "")]
        labels = []
        for t in types:
            short = t.replace("_REQUEST", "").replace("_", " ").title()
            if short and short not in labels:
                labels.append(short)
        return " → ".join(labels) if labels else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entries": list(self._entries),
            "narrative": self.build_narrative(),
            "chain": self.build_chain(),
            "moment_count": len(self._entries),
        }


# ─── Exploration graph ──────────────────────────────────────────────────────────

class ExplorationGraph:
    """
    Persistent per-analysis state/action graph with backtracking support.
    """

    def __init__(self, package_name: str = "") -> None:
        self.package_name = package_name
        self.profile = ApplicationProfile()
        self.states: Dict[str, ExplorationState] = {}
        self.edges: List[ExplorationEdge] = []
        self.evidence_moments: List[EvidenceMoment] = []
        self.secondary_apks: List[Dict[str, Any]] = []
        self._state_counter = 0
        self._edge_counter = 0
        self._action_counter = 0
        self._visit_history: Deque[str] = deque(maxlen=100)
        self._backtrack_stack: List[str] = []
        self._current_state_id: str = ""
        self._detector = EvidenceMomentDetector(package_name)
        self._journey = VictimJourneyBuilder()
        self._scroll_depth: Dict[str, int] = {}
        self.stop_reason: Optional[StopReason] = None
        self.action_results: List[Dict[str, Any]] = []
        self._backtrack_count: int = 0
        # Bounded system-boundary excursion (§P1). Actions spent per boundary
        # package, the boundary currently occupied, and whether the graph owes
        # the caller a deterministic return to the sample.
        self._boundary_actions: Dict[str, int] = {}
        self._boundary_package: str = ""
        # The sample's task-root state - the screen the launcher opened. Back
        # exits the app from here rather than traversing the graph.
        self._root_state_id: str = ""
        # Credential-form progress: how many identities have been offered, what
        # the app said about them, and which state hosts the form.
        self.login_attempts: int = 0
        self.login_outcome: str = "not_attempted"
        self._login_state_id: str = ""
        # States whose numeric keypad has already been filled once, so a PIN
        # that is not accepted does not become an infinite re-entry loop.
        self._keypad_entered: Dict[str, bool] = {}
        self._boundary_return_required: bool = False
        self.boundary_transitions: int = 0
        self.boundary_returns: int = 0
        # Visits to a state that produced no newly-resolved action, keyed by
        # state id. Drives MAX_REPEATED_STATE_VISITS enforcement.
        self._unproductive_visits: Dict[str, int] = {}
        # External-app states kept separate from target-app graph
        self.external_states: Dict[str, ExplorationState] = {}
        self._home_observation_count: int = 0
        self._home_screenshot_count: int = 0
        self._crash_events: List[Dict[str, Any]] = []
        self._transition_events: List[Dict[str, Any]] = []
        self.actions_attempted: int = 0
        self.actions_successful: int = 0
        self.actions_failed: int = 0
        self.scroll_regions_explored: int = 0
        self.dialogs_explored: int = 0
        self.menus_explored: int = 0
        self.tabs_explored: int = 0
        self.webviews_explored: int = 0
        self.permissions_observed: int = 0
        self.branches_blocked: int = 0

    def _next_state_id(self) -> str:
        self._state_counter += 1
        return f"STATE-{self._state_counter:03d}"

    def _next_edge_id(self) -> str:
        self._edge_counter += 1
        return f"EDGE-{self._edge_counter:03d}"

    def _next_action_id(self) -> str:
        self._action_counter += 1
        return f"ACT-{self._action_counter:03d}"

    # ── Bounded system-boundary excursion ────────────────────────────────────

    def _boundary_budget_exhausted(self, package: str) -> bool:
        """Whether this boundary package has spent its action allowance."""
        return (
            self._boundary_actions.get(package, 0)
            >= ExplorationBudget.MAX_BOUNDARY_ACTIONS
        )

    def _note_boundary_action(self, state_id: str) -> None:
        """Charge one action against the boundary a state belongs to."""
        state = self._lookup_state(state_id)
        if state is None:
            return
        # Read defensively: the graph legitimately holds states built by
        # fixtures and by other subsystems, which need not carry every field.
        # Book-keeping must never be able to abort a run.
        ownership = getattr(state, "ownership", "") or ""
        if ownership not in _SYSTEM_OWNERSHIP:
            return
        pkg = getattr(state, "foreground_package", "") or ownership
        if not pkg or pkg == self.package_name:
            return
        spent = self._boundary_actions.get(pkg, 0) + 1
        self._boundary_actions[pkg] = spent
        logger.info(
            "[ExplorationGraph] BOUNDARY_ACTION package=%s %d/%d state=%s",
            pkg, spent, ExplorationBudget.MAX_BOUNDARY_ACTIONS, state_id,
        )
        if spent >= ExplorationBudget.MAX_BOUNDARY_ACTIONS:
            self._boundary_return_required = True

    def _return_to_target_action(self) -> Dict[str, Any]:
        """
        Deterministic route home from a system boundary.

        `press_back` is not used: a boundary reached via an intent may have no
        back edge to the sample, and pressing back repeatedly is how a run ends
        up on the launcher. Re-launching the sample's component is unambiguous
        and puts the agent exactly where the analysis needs it.
        """
        self.boundary_returns += 1
        pkg = self._boundary_package or "system"
        logger.info(
            "[ExplorationGraph] BOUNDARY_RETURN_TO_TARGET from=%s to=%s "
            "(actions_spent=%d/%d)",
            pkg, self.package_name, self._boundary_actions.get(pkg, 0),
            ExplorationBudget.MAX_BOUNDARY_ACTIONS,
        )
        return {
            "tool": "start_activity",
            "package": self.package_name,
            "goal": "RETURN_TO_TARGET",
            "reasoning": (
                f"Boundary '{pkg}' exhausted its "
                f"{ExplorationBudget.MAX_BOUNDARY_ACTIONS}-action allowance; "
                f"returning to {self.package_name}"
            ),
            "confidence": 0.95,
            "_source": "exploration_engine",
            "_selected_by": "boundary_return",
            "_state_id": self._current_state_id or "",
        }

    def _build_action_inventory(self, ui_nodes: List[Any]) -> List[ActionItem]:
        """Enumerate all actionable elements from UI nodes."""
        from sudarshan_core.engines.agentic.device_properties import (
            FALLBACK_SCREEN_HEIGHT,
            FALLBACK_SCREEN_WIDTH,
        )
        from sudarshan_core.engines.agentic.semantic_action import SemanticRole, classify_semantic_role

        items: List[ActionItem] = []
        scroll_containers: List[str] = []
        context_text = _visible_text_summary(ui_nodes)
        default_x = FALLBACK_SCREEN_WIDTH // 2
        default_y = int(FALLBACK_SCREEN_HEIGHT * 0.5)
        # Position of each input among the inputs on this screen. The first
        # unlabelled field on a login form is the identifier; see
        # credentials.resolve_field_kind.
        input_index = 0

        for idx, n in enumerate(ui_nodes):
            node_id = getattr(n, "node_id", f"n{idx}")
            text = getattr(n, "text", "") or ""
            desc = getattr(n, "desc", "") or ""
            is_input = _is_input_node(n)
            field_kind = ""
            if is_input:
                from sudarshan_core.engines.agentic.credentials import (
                    resolve_field_kind,
                )
                field_kind = resolve_field_kind(
                    field_label=getattr(n, "field_label", "") or "",
                    resource_id=getattr(n, "resource_id", "") or "",
                    content_desc=desc,
                    class_name=getattr(n, "class_name", "") or "",
                    text=text,
                    is_password=bool(getattr(n, "is_password", False)),
                    index=input_index,
                )
                input_index += 1
                # An input's label must name the FIELD, never its contents.
                # Deriving it from `text` meant the label changed the moment the
                # agent typed, which changed ActionItem.signature(), which made
                # the merge path in observe() append a fresh unexplored copy of
                # the same field on every revisit - 306 action ids for six
                # widgets on one live LoginActivity run. Contents are still
                # available on the node for evidence; they are not identity.
                # Caption first: on the WebView banking apps the field has no
                # id and no desc, and "Username" / "Login Password" is the only
                # human-readable name it has.
                label = (
                    getattr(n, "field_label", "")
                    or desc
                    or getattr(n, "resource_id", "")
                    or (f"{field_kind} field" if field_kind else "")
                    or node_id
                )
            else:
                label = text or desc or getattr(n, "resource_id", "") or node_id
            is_scrollable = getattr(n, "is_scrollable", False)
            is_clickable = getattr(n, "is_clickable", True)
            is_checkable = getattr(n, "is_checkable", False)
            cx = getattr(n, "center_x", 0) or default_x
            cy = getattr(n, "center_y", 0) or default_y
            bounds = getattr(n, "bounds", "")
            existing_role = getattr(n, "semantic_role", SemanticRole.UNKNOWN.value)
            detection_source = getattr(n, "detection_source", "uiautomator")
            classification = classify_semantic_role(
                label=label,
                class_name=getattr(n, "class_name", ""),
                context_text=context_text,
                is_checkable=is_checkable,
                is_clickable=is_clickable,
                is_input=is_input,
                is_scrollable=is_scrollable,
                checked=getattr(n, "checked", None),
                bounds_area=_bounds_area(bounds),
            )
            semantic_role = classification.role.value
            if existing_role and existing_role != SemanticRole.UNKNOWN.value:
                if classification.confidence < 0.6:
                    semantic_role = existing_role
            confidence = float(
                getattr(n, "confidence", 0) or classification.confidence or 0.99
            )

            if is_scrollable:
                scroll_containers.append(node_id)
                items.append(ActionItem(
                    action_id=self._next_action_id(),
                    node_id=node_id,
                    action_type="scroll",
                    label=f"scroll:{label}",
                    resource_id=getattr(n, "resource_id", ""),
                    class_name=getattr(n, "class_name", ""),
                    center_x=cx,
                    center_y=cy,
                    is_scrollable=True,
                    scroll_container_id=node_id,
                    scroll_direction="down",
                    semantic_role=SemanticRole.EXPAND.value,
                    detection_source=detection_source,
                    confidence=confidence,
                    bounds=bounds,
                ))

            if is_input:
                items.append(ActionItem(
                    action_id=self._next_action_id(),
                    node_id=node_id,
                    action_type="input",
                    label=label,
                    resource_id=getattr(n, "resource_id", ""),
                    class_name=getattr(n, "class_name", ""),
                    center_x=cx,
                    center_y=cy,
                    is_input=True,
                    field_kind=field_kind,
                    semantic_role=SemanticRole.INPUT.value,
                    detection_source=detection_source,
                    confidence=confidence,
                    bounds=bounds,
                ))
            elif is_checkable:
                items.append(ActionItem(
                    action_id=self._next_action_id(),
                    node_id=node_id,
                    action_type="check",
                    label=label,
                    resource_id=getattr(n, "resource_id", ""),
                    class_name=getattr(n, "class_name", ""),
                    center_x=cx,
                    center_y=cy,
                    is_checkable=True,
                    is_clickable=is_clickable,
                    semantic_role=semantic_role,
                    detection_source=detection_source,
                    confidence=confidence,
                    bounds=bounds,
                ))
            elif (is_clickable or is_checkable) and not _is_decorative_label(
                label, getattr(n, "resource_id", "") or "", detection_source,
            ):
                action_type = "click"
                label_lower = label.lower()
                if _text_matches(label_lower, _MENU_KEYWORDS):
                    action_type = "menu"
                elif "tab" in getattr(n, "class_name", "").lower():
                    action_type = "tab"

                items.append(ActionItem(
                    action_id=self._next_action_id(),
                    node_id=node_id,
                    action_type=action_type,
                    label=label,
                    resource_id=getattr(n, "resource_id", ""),
                    class_name=getattr(n, "class_name", ""),
                    center_x=cx,
                    center_y=cy,
                    is_clickable=is_clickable,
                    semantic_role=semantic_role,
                    detection_source=detection_source,
                    confidence=confidence,
                    bounds=bounds,
                ))

        return _prune_container_actions(items)

    def _log_action_discovered(self, state: ExplorationState, item: ActionItem) -> None:
        from sudarshan_core.engines.agentic.action_dispatch import pipeline_log
        pipeline_log(
            "ACTION_DISCOVERED",
            action_id=item.action_id,
            state_id=state.state_id,
            semantic_role=item.semantic_role,
            source=item.detection_source,
            text=item.label[:80],
            clickable=item.is_clickable,
            bounds=item.bounds,
        )

    def observe(
        self,
        obs: Any,
        semantic_type: str = "UNKNOWN",
        foreground_package: str = "",
        parent_state_id: str = "",
        entry_action: str = "",
        elapsed_ts: str = "00:00",
        ownership: str = "",
    ) -> ExplorationState:
        """Incorporate an observation into the graph. Returns the state node."""
        from sudarshan_core.engines.agentic.screen_classifier import (
            ScreenType,
            is_explorable_screen_type,
        )

        ui_nodes = getattr(obs, "ui_nodes", [])
        activity = getattr(obs, "activity", "unknown")
        visible = _visible_text_summary(ui_nodes)
        fg = foreground_package or self.package_name

        # Resolve ownership if not provided
        if not ownership:
            from sudarshan_core.engines.agentic.screenshot_policy import (
                resolve_screen_ownership,
            )
            ow = resolve_screen_ownership(fg, self.package_name, activity, semantic_type)
            ownership = ow.value

        # HOME_LAUNCHER: record transition, do NOT add to target graph
        if ownership == "HOME_LAUNCHER" or semantic_type == ScreenType.HOME_LAUNCHER:
            self._home_observation_count += 1
            self._record_transition_event(
                "TARGET_APP_EXITED_TO_HOME",
                fg, activity, elapsed_ts, ownership,
            )
            # Return a lightweight placeholder - not a real exploration state
            return self._placeholder_state(
                semantic_type=ScreenType.HOME_LAUNCHER,
                ownership=ownership,
                activity=activity,
                foreground_package=fg,
            )

        # CRASH_STATE: record crash event, do NOT explore as target branch
        if ownership in ("CRASH_STATE", "APP_NOT_RESPONDING") or semantic_type in (
            ScreenType.CRASH_STATE, ScreenType.APP_NOT_RESPONDING,
        ):
            self._record_crash_event(activity, fg, elapsed_ts, ownership)
            return self._placeholder_state(
                semantic_type=semantic_type,
                ownership=ownership,
                activity=activity,
                foreground_package=fg,
            )

        # EXTERNAL_APP / SYSTEM boundary: keep installer/VPN/permission
        # dialogs in the explorable graph (they have OK/Install/Allow).
        # Unrelated third-party apps stay in the external graph.
        if ownership in _SYSTEM_OWNERSHIP and fg != self.package_name:
            interactive = (
                ownership in _INTERACTIVE_BOUNDARY_OWNERSHIP
                or semantic_type in _INTERACTIVE_BOUNDARY_TYPES
            )
            # Safety-net: screen_classifier may not have had enough UI text to
            # produce an interactive semantic_type (e.g. spinner still loading).
            # Use the confidence-based boundary role detector as a last resort.
            #
            # NOT applied to SYSTEM_SETTINGS. is_safe_interactive_boundary()
            # answers True for com.android.settings on package name alone, so
            # running it here would re-admit the whole Settings application
            # through the back door and undo the frozenset change above. A
            # Settings screen must earn admission via semantic_type, which is
            # how the accessibility and VPN consent flows still get in.
            if not interactive and ownership != "SYSTEM_SETTINGS":
                from sudarshan_core.engines.agentic.screenshot_policy import (
                    is_safe_interactive_boundary,
                )
                interactive = is_safe_interactive_boundary(fg, activity)

            # A boundary the agent is allowed into is still a boundary: it gets
            # a bounded allowance, not the run. Past it the screen is demoted to
            # the external graph and a return to the target is demanded.
            if interactive and self._boundary_budget_exhausted(fg):
                logger.info(
                    "[ExplorationGraph] BOUNDARY_LIMIT_REACHED package=%s "
                    "actions=%d/%d - demoting to external and returning to %s",
                    fg, self._boundary_actions.get(fg, 0),
                    ExplorationBudget.MAX_BOUNDARY_ACTIONS, self.package_name,
                )
                self._record_transition_event(
                    "BOUNDARY_LIMIT_REACHED", fg, activity, elapsed_ts, ownership,
                )
                self._boundary_return_required = True
                interactive = False

            logger.info(
                "[ExplorationGraph] BOUNDARY_TRANSITION "
                "from_package=%s to_package=%s ownership=%s "
                "semantic_type=%s interactive=%s",
                self.package_name, fg, ownership, semantic_type, interactive,
            )
            if not interactive:
                return self._observe_external(
                    obs, semantic_type, fg, activity, visible, ui_nodes,
                    ownership, parent_state_id, entry_action, elapsed_ts,
                )

            if self._boundary_package != fg:
                self._boundary_package = fg
                logger.info(
                    "[ExplorationGraph] BOUNDARY_ENTER package=%s ownership=%s "
                    "semantic_type=%s budget=%d",
                    fg, ownership, semantic_type,
                    ExplorationBudget.MAX_BOUNDARY_ACTIONS,
                )
        elif fg == self.package_name and self._boundary_package:
            # Back on the sample: the excursion is over.
            logger.info(
                "[ExplorationGraph] BOUNDARY_RETURN_TO_TARGET package=%s "
                "after %d action(s)",
                self._boundary_package,
                self._boundary_actions.get(self._boundary_package, 0),
            )
            self._boundary_package = ""
            self._boundary_return_required = False

        screen_hash, ui_tree_hash = compute_composite_state_signature(
            activity, fg, ui_nodes, visible,
            webview_sig="webview" if getattr(obs, "is_webview", False) else "",
        )

        # Deduplicate: find existing state with same signature
        existing_id = None
        for sid, state in self.states.items():
            if state.screen_hash == screen_hash and state.ui_tree_hash == ui_tree_hash:
                existing_id = sid
                break

        if existing_id:
            state = self.states[existing_id]
            state.visit_count += 1
            self._current_state_id = existing_id
            self._visit_history.append(existing_id)
            # Merge new actions not yet in inventory
            existing_sigs = {a.signature() for a in state.actionable_elements}
            for item in self._build_action_inventory(ui_nodes):
                if item.signature() not in existing_sigs:
                    state.actionable_elements.append(item)
                    self._log_action_discovered(state, item)
            return state

        state_id = self._next_state_id()
        actions = self._build_action_inventory(ui_nodes)
        scrollable = [a.node_id for a in actions if a.is_scrollable]

        # Enforce exploration state budget
        real_states = [
            s for s in self.states.values()
            if not s.state_id.startswith("PLACEHOLDER-")
        ]
        if len(real_states) >= ExplorationBudget.MAX_STATES:
            self.stop_reason = StopReason.SAFETY_BOUNDARY_REACHED
            logger.warning(
                "[ExplorationGraph] MAX_STATES (%d) reached",
                ExplorationBudget.MAX_STATES,
            )
            return self._placeholder_state(
                semantic_type=semantic_type,
                ownership=ownership or "TARGET_APP",
                activity=activity,
                foreground_package=fg,
            )

        state = ExplorationState(
            state_id=state_id,
            screen_hash=screen_hash,
            ui_tree_hash=ui_tree_hash,
            activity_name=activity,
            package_name=self.package_name,
            foreground_package=fg,
            visible_text_summary=visible,
            semantic_type=semantic_type,
            ownership=ownership or "TARGET_APP",
            actionable_elements=actions,
            scrollable_regions=scrollable,
            timestamp=elapsed_ts,
            parent_state_id=parent_state_id,
            entry_action=entry_action,
            is_webview=bool(getattr(obs, "is_webview", False)),
        )
        self.states[state_id] = state
        # First target-app screen recorded is the task root (see _at_target_root).
        if not self._root_state_id and (state.ownership or "TARGET_APP") == "TARGET_APP":
            self._root_state_id = state_id
        self._current_state_id = state_id
        self._visit_history.append(state_id)
        if parent_state_id:
            self._backtrack_stack.append(parent_state_id)
        from sudarshan_core.engines.agentic.action_dispatch import pipeline_log
        pipeline_log(
            "STATE_DETECTED",
            state_id=state_id,
            semantic_type=semantic_type,
            ownership=ownership or "TARGET_APP",
            foreground_package=fg,
            actions=len(actions),
        )
        for item in actions:
            self._log_action_discovered(state, item)

        # Update application profile from observation
        self._update_profile(state, semantic_type, visible)

        # Detect evidence moments
        moments = self._detector.detect(obs, semantic_type, state_id, elapsed_ts)
        for m in moments:
            self.evidence_moments.append(m)
            self._journey.add_moment(m)

        if semantic_type == "SYSTEM_PERMISSION":
            self.permissions_observed += 1
        if semantic_type in ("UPDATE_PROMPT", "EXTERNAL_APK", "VPN_REQUEST"):
            self.dialogs_explored += 1
        if getattr(obs, "is_webview", False):
            self.webviews_explored += 1

        return state

    def _update_profile(
        self, state: ExplorationState, semantic_type: str, visible: str
    ) -> None:
        if state.activity_name not in self.profile.discovered_activities:
            self.profile.discovered_activities.append(state.activity_name)
        if semantic_type not in self.profile.discovered_ui_states:
            self.profile.discovered_ui_states.append(semantic_type)

        if _text_matches(visible, _UPDATE_KEYWORDS):
            self.profile.add_workflow("update_flow")
            self.profile.add_suspicious("presents update prompt")
            self.profile.revise_purpose(
                "Application presenting update/download workflow",
                "update keywords observed",
            )
        if _text_matches(visible, _VPN_KEYWORDS):
            self.profile.add_workflow("vpn_flow")
            self.profile.add_suspicious("requests VPN configuration")
        if _text_matches(visible, _APK_KEYWORDS):
            self.profile.add_workflow("external_apk_flow")
            self.profile.add_suspicious("requests external application install")
        if semantic_type == "ACCESSIBILITY_DIALOG":
            self.profile.add_security_capability("accessibility")
            self.profile.add_suspicious("requests accessibility service")
        if semantic_type == "SYSTEM_PERMISSION":
            self.profile.add_feature("runtime_permissions")
        if semantic_type == "SETTINGS":
            self.profile.add_feature("settings_screen")
        if semantic_type == "BANK_LOGIN":
            self.profile.revise_purpose(
                "Application with authentication/login flow",
                "login screen detected",
            )
        if semantic_type == "HOME":
            self.profile.add_feature("home_screen")

        unexplored = state.unexplored_actions()
        self.profile.unexplored_capabilities = [
            a.label for a in unexplored[:20]
        ]

    def record_action(
        self,
        source_state_id: str,
        target_state_id: str,
        action_type: str,
        target_description: str,
        success: bool = True,
        screenshot_id: str = "",
        action_id: str = "",
        verified: Optional[bool] = None,
        dispatched: bool = True,
        executed: bool = False,
        max_attempts: int = 3,
        attempts: int = 0,
        pre_state_hash: str = "",
        post_state_hash: str = "",
        ui_changed: Optional[bool] = None,
        ever_ui_changed: Optional[bool] = None,
        new_actions_found: int = 0,
        runtime_events: int = 0,
        failure_reason: str = "",
    ) -> ExplorationEdge:
        """Record an action edge between states.

        An action is only resolved (removed from the unexplored set) when it is
        verified, failed after bounded attempts, blocked, or unreachable.
        `verified` defaults to `success` for older callers.

        `ever_ui_changed` tracks whether the UI changed at ANY point across all
        retry attempts for this action.  This prevents a successful action from
        being marked `failed` just because the FINAL retry happened to catch the
        screen mid-transition and produced the same hash as the pre-action state.
        When `ever_ui_changed` is not supplied by the caller it falls back to the
        current-attempt `ui_changed` value (backward-compatible).
        """
        if verified is None:
            verified = bool(success)
        if success and action_type in ("input", "type_text"):
            # Same reasoning as the input branch below, applied to the EDGE:
            # text entry does not move the screen hash by design, so a verifier
            # that looks for a screen change can only ever report "unchanged".
            # Without this every accepted keystroke is drawn as a failed edge in
            # the exploration graph the analyst reads.
            verified = True
        # If the caller tracked UI change across all attempts, prefer that over
        # the single-attempt snapshot.  An action that moved the UI on attempt 1
        # must not be marked failed because attempt 3 caught the same hash again.
        any_ui_change = bool(
            ever_ui_changed if ever_ui_changed is not None
            else (ui_changed if ui_changed is not None else False)
        )
        self.actions_attempted += 1
        if success and verified:
            self.actions_successful += 1
        elif not success or not verified:
            self.actions_failed += 1

        status = "success" if (success and verified) else "failed"
        changed = bool(ui_changed) if ui_changed is not None else bool(
            source_state_id != (target_state_id or source_state_id)
        )
        edge = ExplorationEdge(
            edge_id=self._next_edge_id(),
            source_state_id=source_state_id,
            target_state_id=target_state_id or source_state_id,
            action_type=action_type,
            target_description=target_description,
            result=status,
            verified=bool(success and verified),
            timestamp=str(int(time.time())),
            screenshot_ids=[screenshot_id] if screenshot_id else [],
            action_id=action_id,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            ui_changed=changed,
            new_actions_found=new_actions_found,
            runtime_event_count=runtime_events,
            retry_count=attempts,
            failure_reason=failure_reason if status != "success" else "",
            status=status,
        )
        self.edges.append(edge)
        self.action_results.append({
            "action_id": action_id or edge.edge_id,
            "source_state": source_state_id,
            "target_state": target_state_id or source_state_id,
            "action_type": action_type,
            "label": target_description,
            "pre_state_hash": pre_state_hash,
            "post_state_hash": post_state_hash,
            "ui_changed": changed,
            "ever_ui_changed": any_ui_change,
            "new_actions_found": new_actions_found,
            "runtime_events": runtime_events,
            "status": status,
            "failure_reason": failure_reason if status != "success" else "",
            "retry_count": attempts,
        })

        # Resolve against the state that actually OWNS the action.
        #
        # Two ways this used to strand an action permanently unresolved:
        #   - `source_state_id in self.states` skipped external/boundary states
        #     entirely, so nothing taken on an installer or permission screen
        #     was ever marked, and the same button was re-selected forever.
        #   - when the caller's `source_state_id` did not hold `action_id` (the
        #     screen was re-identified between selection and recording), the
        #     loop matched nothing and returned silently.
        #
        # The owning state is located by action_id when one is supplied. Only
        # that state's inventory is touched, so a transition's DESTINATION state
        # keeps its own actions unexplored and stays independently explorable.
        state = self._lookup_state(source_state_id)
        if action_id and (
            state is None
            or not any(a.action_id == action_id for a in state.actionable_elements)
        ):
            owner = self._state_owning_action(action_id)
            if owner is not None:
                if state is not None:
                    logger.debug(
                        "[ExplorationGraph] Action '%s' recorded against %s but "
                        "owned by %s - resolving on the owner",
                        action_id, source_state_id, owner.state_id,
                    )
                state = owner

        if state is not None:
            for a in state.actionable_elements:
                matched = False
                if action_id and a.action_id == action_id:
                    matched = True
                elif action_id:
                    matched = False
                elif a.label == target_description:
                    matched = True
                elif a.node_id and a.node_id in target_description:
                    matched = True
                if matched:
                    if dispatched:
                        a.dispatched = True
                    a.selected = True
                    if attempts:
                        a.execution_attempts = attempts
                    else:
                        a.execution_attempts += 1
                    if success and verified:
                        # ADB succeeded AND the UI hash changed → fully explored.
                        a.explored = True
                        a.verified = True
                        a.executed = True
                        logger.debug(
                            "[ExplorationGraph] Action '%s' EXPLORED (verified, ui_changed)",
                            target_description,
                        )
                    elif success and any_ui_change:
                        # ADB succeeded and the UI changed at some point across
                        # retries, but the final hash happened to match.  The
                        # action WAS effective — do NOT mark it failed.  Mark as
                        # explored so the graph advances past it.
                        a.explored = True
                        a.executed = True
                        logger.debug(
                            "[ExplorationGraph] Action '%s' EXPLORED "
                            "(ever_ui_changed=True, adb_success=True)",
                            target_description,
                        )
                    elif success and action_type in ("input", "type_text"):
                        # Text entry is deliberately NOT a state change: a
                        # field's value is no longer part of screen identity, so
                        # an accepted keystroke leaves the hash where it was.
                        # Judging it by ui_changed would report every successful
                        # type_text as failed, which is both wrong in the report
                        # and wrong for the walk - the field would be retried
                        # instead of the form being completed.
                        a.explored = True
                        a.executed = True
                        a.verified = True
                        logger.debug(
                            "[ExplorationGraph] Input '%s' EXPLORED "
                            "(text entry does not change screen identity)",
                            target_description,
                        )
                    else:
                        # ADB may or may not have succeeded; the UI never changed
                        # across any of the attempts.
                        if executed:
                            a.executed = True
                        if a.execution_attempts >= max_attempts and not any_ui_change:
                            # Only give up after we have truly exhausted retries
                            # AND the UI never moved.  A timing race that clears
                            # on the next observe must not prematurely block the
                            # branch.
                            a.failed = True
                            logger.debug(
                                "[ExplorationGraph] Action '%s' FAILED "
                                "(attempts=%d, ever_ui_changed=False)",
                                target_description, a.execution_attempts,
                            )
                    break
            # Keyed on the OWNING state, so scroll depth and the fully-explored
            # flag describe the screen the action actually belongs to.
            owner_id = state.state_id
            if action_type == "scroll":
                self._scroll_depth[owner_id] = (
                    self._scroll_depth.get(owner_id, 0) + 1
                )
            if not state.unexplored_actions():
                state.explored = True
                logger.debug(
                    "[ExplorationGraph] State '%s' fully explored", owner_id,
                )

        if action_type == "scroll":
            self.scroll_regions_explored += 1
        elif action_type == "menu":
            self.menus_explored += 1
        elif action_type == "tab":
            self.tabs_explored += 1

        # Charge system-boundary excursions against their allowance.
        self._note_boundary_action(source_state_id)

        return edge

    def _lookup_state(self, state_id: str) -> Optional[ExplorationState]:
        if state_id in self.states:
            return self.states[state_id]
        if state_id in self.external_states:
            return self.external_states[state_id]
        return None

    def _state_owning_action(self, action_id: str) -> Optional[ExplorationState]:
        """The state whose inventory contains `action_id`, if any."""
        if not action_id:
            return None
        for pool in (self.states, self.external_states):
            for state in pool.values():
                for a in state.actionable_elements:
                    if a.action_id == action_id:
                        return state
        return None

    def _pending_state_id(self) -> Optional[str]:
        for sid, state in self.states.items():
            if sid.startswith("PLACEHOLDER-"):
                continue
            if state.unexplored_actions():
                return sid
        for sid, state in self.external_states.items():
            if state.unexplored_actions():
                return sid
        return None

    def get_next_action(
        self,
        state_id: Optional[str] = None,
        memory: Any = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Deterministic action selection: highest-priority unexplored action.
        Returns action dict compatible with ToolExecutor.
        """
        # A boundary that has spent its allowance outranks everything: any other
        # action would be taken inside a system app the run has no business in.
        if self._boundary_return_required:
            self._boundary_return_required = False
            return self._return_to_target_action()

        sid = state_id or self._current_state_id
        state = self._lookup_state(sid) if sid else None
        if state is None:
            pending = self._pending_state_id()
            if pending:
                self._current_state_id = pending
                return self.get_next_action(pending, memory)
            return self._backtrack_action(memory)

        unexplored = state.unexplored_actions()
        if not unexplored:
            back = self._backtrack_action(memory)
            if back:
                return back
            pending = self._pending_state_id()
            if pending and pending != sid:
                # The device is on `sid`, not on `pending`. Returning
                # `pending`'s action here would hand the executor a tap for a
                # control that is not on screen: it cannot match, so
                # record_action() never resolves it, and the same action is
                # re-selected forever. Measured on the mock app: 20 of 30
                # actions were spent tapping "Continue" on a Settings screen
                # that has no Continue button, and the Update branch was
                # never reached. Navigate there instead (§13).
                return self._navigate_toward(pending, sid)
            return None

        logger.info(
            "[Explorer] Current state: %s type=%s",
            sid, state.semantic_type,
        )
        logger.info("[Explorer] Actionable elements found: %d", len(unexplored))

        ranked = ActionPrioritizer.rank_actions(
            unexplored, self.profile, state.semantic_type,
            context_text=state.visible_text_summary,
        )

        # ── Numeric keypad: enter the whole PIN in one action ─────────────────
        # A PIN pad is a single credential entry that happens to be spelled with
        # ten buttons. Taken one key per iteration the pad never fills: at ~11s
        # an action six digits cost a minute, and any detour resets the field.
        # The digits are pressed in one dispatch, then the screen is re-read.
        if _is_keypad_state(state) and not self._keypad_entered.get(sid):
            keys = _digit_keys(state.actionable_elements)
            digit = next((d for d in ("1", "2", "3") if d in keys), None)
            if digit is not None:
                self._keypad_entered[sid] = True
                key = keys[digit]
                logger.info(
                    "[Explorer] KEYPAD_ENTRY state=%s digits=%d key='%s' "
                    "(%d keys on screen)",
                    sid, PIN_ENTRY_LENGTH, digit, len(keys),
                )
                return {
                    "tool": "tap_sequence",
                    "text": digit * PIN_ENTRY_LENGTH,
                    "x": key.center_x,
                    "y": key.center_y,
                    "repeat": PIN_ENTRY_LENGTH,
                    "goal": "DEEP_EXPLORATION",
                    "reasoning": (
                        f"Numeric keypad on {sid}: entering a "
                        f"{PIN_ENTRY_LENGTH}-digit PIN in one action rather "
                        f"than one key per iteration"
                    ),
                    "confidence": 0.9,
                    "_source": "exploration_engine",
                    "_selected_by": "keypad_entry",
                    "_action_id": key.action_id,
                    "_state_id": sid,
                    "_bounds": key.bounds,
                }

        # ── Form completion: fill the fields, THEN submit ─────────────────────
        # A login screen only opens if the credentials arrive before the button
        # is pressed. Ranked purely on priority, "Login" outranks the two text
        # boxes above it, so the agent submitted an empty form, watched nothing
        # happen, burned the retry ladder and marked the only way into the app
        # as failed. While any input on this screen is still unfilled, submit
        # controls are held back.
        pending_inputs = [a for a in ranked if a.action_type == "input"]
        if pending_inputs:
            held = [a for a in ranked if _is_submit_action(a)]
            if held:
                logger.info(
                    "[Explorer] FORM_FILL_FIRST state=%s - holding %d submit "
                    "control(s) until %d input(s) are filled: %s",
                    sid, len(held), len(pending_inputs),
                    [a.label for a in pending_inputs],
                )
                rest = [
                    a for a in ranked
                    if a.action_type != "input" and not _is_submit_action(a)
                ]
                ranked = pending_inputs + rest + held

        # ── Fair scheduling: clicks must not starve scroll ────────────────────
        # rank_actions puts clicks above scroll and the loop below returns the
        # first candidate, so on a screen that keeps yielding clickable nodes
        # the scroll entry is never reached. A measured run discovered 13 scroll
        # actions and executed none, leaving everything below the fold unseen.
        #
        # After a state has been worked several times, a pending scroll is
        # promoted to the front ONCE per scroll action. Clicks still lead on
        # first contact, which keeps the natural
        # click -> click -> scroll -> new content -> click order.
        visits = state.visit_count
        if visits > _SCROLL_FAIRNESS_VISITS and not pending_inputs:
            pending_scrolls = [
                a for a in ranked
                if a.action_type == "scroll"
                and self._scroll_depth.get(sid, 0) < ExplorationBudget.MAX_SCROLL_DEPTH
            ]
            if pending_scrolls:
                logger.info(
                    "[Explorer] SCROLL_FAIRNESS state=%s visits=%d - promoting "
                    "%d pending scroll action(s) ahead of clicks",
                    sid, visits, len(pending_scrolls),
                )
                rest = [a for a in ranked if a not in pending_scrolls]
                ranked = pending_scrolls + rest

        # ── Repeated-visit enforcement ────────────────────────────────────────
        # MAX_REPEATED_STATE_VISITS was declared but never read; a live run
        # visited STATE-001 seventeen times. Past the limit this screen stops
        # being offered its own actions and the walk is pushed elsewhere, so a
        # sticky screen cannot absorb the budget. The remaining actions are left
        # unresolved on purpose - they stay available if the walk returns with a
        # different approach, and the run does NOT terminate (invariant 1).
        if visits > ExplorationBudget.MAX_REPEATED_STATE_VISITS:
            logger.info(
                "[Explorer] MAX_REPEATED_STATE_VISITS state=%s visits=%d/%d - "
                "diverting (%d action(s) left pending)",
                sid, visits, ExplorationBudget.MAX_REPEATED_STATE_VISITS,
                len(unexplored),
            )
            # Only a real parent counts as a diversion. _navigate_toward() is
            # deliberately NOT used here: it presses back, and this state still
            # has its own pending actions, so backing out of it risks leaving
            # the app to reach work that is already under the cursor.
            diverted = self._backtrack_action(memory)
            if diverted:
                return diverted
            # Nowhere else to go: fall through and keep working this screen
            # rather than stopping with reachable work outstanding.

        # ── Victim filter ────────────────────────────────────────────────────
        # CANCEL / DENY / CLOSE are held back, not deleted. A victim does not
        # cancel while any affirmative control is still untried; once they are
        # all tried (or blocked) the negatives come back, because a screen with
        # nothing left but Cancel still has to be left somehow, and pressing
        # back would abandon a boundary prompt the sample is waiting on.
        from sudarshan_core.engines.agentic.victim_policy import is_victim_rejected

        rejected = [
            a for a in ranked
            if is_victim_rejected(a.victim_score) and a.action_type != "scroll"
        ]
        if rejected:
            remaining = [a for a in ranked if a not in rejected]
            usable = [
                a for a in remaining
                if not a.blocked
                and not a.unreachable
                and a.execution_attempts < ExplorationBudget.MAX_RETRIES_PER_ACTION
            ]
            if usable:
                logger.info(
                    "[VSE] state=%s deferring %d declining action(s) (%s) - "
                    "%d affirmative option(s) still open",
                    sid, len(rejected),
                    ", ".join(a.label for a in rejected[:4]),
                    len(usable),
                )
                ranked = remaining + rejected
            else:
                logger.info(
                    "[VSE] state=%s affirmative options exhausted - "
                    "declining action(s) released",
                    sid,
                )

        for action in ranked:
            tool = "click_text"
            target = action.label
            if action.action_type == "input":
                tool = "type_text"
            elif action.action_type == "check":
                tool = "click_text"
            elif action.action_type == "scroll":
                depth = self._scroll_depth.get(sid, 0)
                if depth >= ExplorationBudget.MAX_SCROLL_DEPTH:
                    action.blocked = True
                    continue
                self._scroll_depth[sid] = depth  # will increment in record_action
                logger.info("[Explorer] Selected action: SCROLL %s", action.label)
                return {
                    "tool": "scroll",
                    "direction": action.scroll_direction or "down",
                    "goal": "DEEP_EXPLORATION",
                    "reasoning": f"Scroll exploration: {action.label} (depth={depth})",
                    "confidence": action.priority / 100.0,
                    "_source": "exploration_engine",
                    "_action_id": action.action_id,
                    "_state_id": sid,
                }
            elif action.action_type == "menu":
                self.menus_explored += 1

            # Skip escaping actions
            if memory and hasattr(memory, "is_escaping_action"):
                if memory.is_escaping_action(tool, target):
                    action.blocked = True
                    continue

            action.selected = True
            logger.info(
                "[Explorer] Selected action: %s (role=%s priority=%s)",
                target, action.semantic_role, action.priority,
            )
            return {
                "tool": tool,
                "text": target,
                "x": action.center_x,
                "y": action.center_y,
                # Resolved at discovery from the field's password flag and its
                # caption. Without it the executor fell back to the element
                # label, which on a WebView login screen is not a FORM_VALUES
                # key, so every field received the same placeholder and no
                # login could succeed.
                **(
                    {"field_hint": action.field_kind}
                    if action.action_type == "input" and action.field_kind
                    else {}
                ),
                "goal": "DEEP_EXPLORATION",
                "reasoning": (
                    f"Explore {action.action_type} '{target}' "
                    f"(role={action.semantic_role}, priority={action.priority}, "
                    f"source={action.detection_source})"
                ),
                "confidence": action.confidence,
                "_source": "exploration_engine",
                "_selected_by": "exploration_graph",
                "_action_id": action.action_id,
                "_state_id": sid,
                "_semantic_role": action.semantic_role,
                "_detection_source": action.detection_source,
                "_bounds": action.bounds,
                # These coordinates came from the observation of the screen the
                # device is on, so click_text may tap them without re-dumping
                # the hierarchy. Cleared by retry_payload on escalation.
                "_geometry_trusted": bool(
                    action.center_x and action.center_y and action.bounds
                ),
                "_executable_type": (
                    "TYPE_TEXT" if action.action_type == "input" else "TAP"
                ),
                "_pipeline_debug": {
                    "candidate_discovered": True,
                    "semantic_role": action.semantic_role,
                    "confidence": action.confidence,
                    "priority": action.priority,
                    "detection_source": action.detection_source,
                    "enabled": True,
                    "clickable": action.is_clickable,
                    "bounds": action.bounds,
                },
            }

        return self._backtrack_action(memory)

    def _navigate_toward(
        self, target_state_id: str, current_state_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Walk back toward a state that still has unexplored actions.

        An action only means anything on the screen that owns it, so reaching
        `target_state_id` is a navigation problem, not a selection one. We do
        not know the edge sequence back to it, so we press back one step and
        let the next observe() re-identify wherever we land - the graph is
        re-entrant, and the pending state stays pending until it is reached.

        Bounded by MAX_BACKTRACKS so an app that swallows the back key cannot
        turn this into an infinite walk.
        """
        if self._backtrack_count >= ExplorationBudget.MAX_BACKTRACKS:
            logger.info(
                "[Explorer] Navigation budget exhausted (%d/%d); "
                "leaving %s unexplored",
                self._backtrack_count, ExplorationBudget.MAX_BACKTRACKS,
                target_state_id,
            )
            return None
        # Prefer walking the edges we actually recorded. Back is a guess about
        # the task stack; a successful edge is a route we have already driven.
        forward = self._replay_route(current_state_id, target_state_id)
        if forward is not None:
            return forward

        if self._at_target_root(current_state_id):
            # Same reason as _backtrack_action: back exits the app from here,
            # so it cannot navigate toward another of its states.
            logger.info(
                "[Explorer] At target root %s - cannot press back toward %s",
                current_state_id, target_state_id,
            )
            return None
        self._backtrack_count += 1
        # Re-identified from the next observation rather than assumed.
        self._current_state_id = None
        logger.info(
            "[Explorer] NAVIGATE from=%s toward=%s (press_back %d/%d)",
            current_state_id, target_state_id,
            self._backtrack_count, ExplorationBudget.MAX_BACKTRACKS,
        )
        return {
            "tool": "press_back",
            "goal": "BACKTRACK",
            "reasoning": (
                f"Navigate from {current_state_id} toward {target_state_id}, "
                f"which still has unexplored actions"
            ),
            "confidence": 0.8,
            "_source": "exploration_engine",
            "_selected_by": "navigation",
            "_state_id": target_state_id,
        }

    def _replay_route(
        self, from_state_id: str, to_state_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Re-drive the first hop of a known-good route to `to_state_id`.

        The graph records every successful transition as an edge, so when a
        screen's own actions are exhausted but another screen still has pending
        work, there is usually a route already proven by this run: on
        InsecureBankv2, STATE-001 -'More options'-> STATE-002 -'Preferences'->
        STATE-003. Backtracking cannot use it - `press_back` from the launch
        Activity leaves the app - and without it a measured run sat on a fully
        explored root and burned 37 fallback scrolls while FilePrefActivity
        still held six unexplored actions.

        Returns the first hop as a dispatchable action, or None when no
        recorded route exists.
        """
        if not from_state_id or not to_state_id or from_state_id == to_state_id:
            return None

        adjacency: Dict[str, List[ExplorationEdge]] = {}
        for e in self.edges:
            if e.status != "success":
                continue
            if not e.source_state_id or not e.target_state_id:
                continue
            if e.source_state_id == e.target_state_id:
                continue
            adjacency.setdefault(e.source_state_id, []).append(e)

        # Breadth-first: the shortest proven route costs the fewest actions.
        queue: Deque[Tuple[str, Optional[ExplorationEdge]]] = deque(
            [(from_state_id, None)]
        )
        seen = {from_state_id}
        while queue:
            node, first_edge = queue.popleft()
            for edge in adjacency.get(node, []):
                nxt = edge.target_state_id
                if nxt in seen:
                    continue
                hop = first_edge or edge
                if nxt == to_state_id:
                    return self._action_for_edge(hop, to_state_id)
                seen.add(nxt)
                queue.append((nxt, hop))
        return None

    def _action_for_edge(
        self, edge: ExplorationEdge, destination_state_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Rebuild a dispatchable action from a recorded edge."""
        source = self._lookup_state(edge.source_state_id)
        if source is None:
            return None
        item = None
        for a in source.actionable_elements:
            if edge.action_id and a.action_id == edge.action_id:
                item = a
                break
            if not edge.action_id and a.label == edge.target_description:
                item = a
                break
        if item is None:
            return None

        self._backtrack_count += 1
        logger.info(
            "[Explorer] NAVIGATE_ROUTE %s -> %s via '%s' (toward %s)",
            edge.source_state_id, edge.target_state_id, item.label,
            destination_state_id,
        )
        return {
            "tool": "type_text" if item.action_type == "input" else "click_text",
            "text": item.label,
            "x": item.center_x,
            "y": item.center_y,
            "goal": "BACKTRACK",
            "reasoning": (
                f"Replay known route {edge.source_state_id}->"
                f"{edge.target_state_id} via '{item.label}' to reach "
                f"{destination_state_id}, which still has unexplored actions"
            ),
            "confidence": item.confidence,
            "_source": "exploration_engine",
            "_selected_by": "route_replay",
            # Deliberately no _action_id: this is navigation over an already
            # explored edge, not a fresh attempt at that action, and it must not
            # be recorded as one.
            "_state_id": edge.source_state_id,
            "_bounds": item.bounds,
            "_geometry_trusted": bool(
                item.center_x and item.center_y and item.bounds
            ),
        }

    # ── Credential retry ─────────────────────────────────────────────────────

    def note_login_attempt(self, state_id: str) -> None:
        """Record that a submit control was pressed on a credential screen."""
        self.login_attempts += 1
        self._login_state_id = state_id
        logger.info(
            "[ExplorationGraph] LOGIN_ATTEMPT %d on %s",
            self.login_attempts, state_id,
        )

    def note_login_outcome(
        self, screen_text: str, current_state_id: str, activity_changed: bool,
    ) -> str:
        """
        Judge a submitted credential form, and re-arm it if nothing was said.

        The rule the run follows: an app that SAYS the credentials are wrong has
        answered, and the branch is closed. An app that says nothing and stays
        where it was has not - the submit may have raced the keyboard, the field
        may have been cleared, the value may simply not have been accepted yet -
        so a fresh identity is generated and the form is offered again.

        Returns "rejected", "accepted", "retry" or "unknown".
        """
        from sudarshan_core.engines.agentic.credentials import (
            get_vault, login_rejected, login_succeeded_hint,
        )

        if login_rejected(screen_text):
            self.login_outcome = "rejected"
            logger.info(
                "[ExplorationGraph] LOGIN_REJECTED after %d attempt(s) - the "
                "app stated the credentials are invalid; not retrying",
                self.login_attempts,
            )
            self.profile.add_workflow("credential_rejection")
            return "rejected"

        if activity_changed or login_succeeded_hint(screen_text):
            self.login_outcome = "accepted"
            logger.info(
                "[ExplorationGraph] LOGIN_ACCEPTED after %d attempt(s) - "
                "authenticated surface reached",
                self.login_attempts,
            )
            self.profile.add_workflow("authenticated_session")
            return "accepted"

        if self.login_attempts >= ExplorationBudget.MAX_LOGIN_ATTEMPTS:
            self.login_outcome = "exhausted"
            logger.info(
                "[ExplorationGraph] LOGIN_ATTEMPTS_EXHAUSTED (%d/%d) - the app "
                "neither accepted nor rejected the credentials; moving on",
                self.login_attempts, ExplorationBudget.MAX_LOGIN_ATTEMPTS,
            )
            return "unknown"

        # Nothing was said. Re-arm the form with a new identity.
        state = self._lookup_state(self._login_state_id or current_state_id)
        if state is None:
            return "unknown"
        self.login_outcome = "retrying"
        get_vault(self.package_name).regenerate()
        rearmed = 0
        for a in state.actionable_elements:
            if a.action_type == "input" or _is_submit_action(a):
                a.explored = a.verified = a.failed = a.blocked = False
                a.execution_attempts = 0
                rearmed += 1
        if rearmed:
            state.explored = False
        logger.info(
            "[ExplorationGraph] LOGIN_RETRY attempt %d/%d - app said nothing; "
            "re-armed %d form action(s) on %s with new credentials",
            self.login_attempts + 1, ExplorationBudget.MAX_LOGIN_ATTEMPTS,
            rearmed, state.state_id,
        )
        return "retry"

    def _at_target_root(self, state_id: str = "") -> bool:
        """
        Whether `state_id` is the sample's task-root screen.

        Back is a graph edge everywhere else; here it is the exit. Android pops
        the task, so a `press_back` issued from the launch Activity does not
        travel to another state of the sample - it leaves the sample. A measured
        run did this 24 times, and each departure cost a launcher observation
        plus a relaunch (~10s) and explored nothing.

        Root is the FIRST target-app state this graph recorded, which is the
        screen the launcher opened. Deliberately not "has no parent_state_id":
        callers are not required to supply a parent, so that test would make
        every state a root and disable backtracking altogether.
        """
        sid = state_id or self._current_state_id or ""
        if not sid or not self._root_state_id:
            return False
        if sid == self._root_state_id:
            return True

        # Single-Activity WebView apps: back pops the ACTIVITY, not the page.
        #
        # Every app in the banking corpus renders its whole journey inside one
        # WebView in one Activity, so the login screen and the account screen
        # behind it share an activity name and there is no back entry for the
        # transition between them - pressing back from the signed-in screen
        # closes the app. A measured run did exactly that: it reached the
        # post-login keypad, pressed back, landed outside the sample and had to
        # relaunch, losing the session it had just obtained.
        #
        # Narrowed to WebView states on purpose. In a native Activity a dialog
        # is a separate window sharing the Activity name, and back genuinely
        # dismisses it - that is an edge worth walking.
        root = self._lookup_state(self._root_state_id)
        state = self._lookup_state(sid)
        if root is None or state is None:
            return False
        if (state.ownership or "TARGET_APP") != "TARGET_APP":
            return False
        if not (state.is_webview and root.is_webview):
            return False
        return bool(
            state.activity_name
            and state.activity_name == root.activity_name
        )

    def _backtrack_action(self, memory: Any = None) -> Optional[Dict[str, Any]]:
        """Press back to explore remaining branches."""
        if self._at_target_root():
            logger.info(
                "[Explorer] At target root %s - not backtracking (back would "
                "leave the app, not traverse it)",
                self._current_state_id,
            )
            return None
        if self._backtrack_count >= ExplorationBudget.MAX_BACKTRACKS:
            logger.info(
                "[Explorer] Backtracking exhausted (%d/%d)",
                self._backtrack_count, ExplorationBudget.MAX_BACKTRACKS,
            )
            return None
        while self._backtrack_stack:
            parent_id = self._backtrack_stack.pop()
            if parent_id == self._current_state_id:
                # Already here. Pressing back would not travel to this state, it
                # would leave it - and from a root Activity that means leaving
                # the app entirely. A measured run did exactly this: backtracked
                # "to" the LoginActivity it was already on, landed outside the
                # sample, and never got back. Its own actions are still pending,
                # so let the caller select one instead.
                logger.debug(
                    "[Explorer] Backtrack target %s is the current state - "
                    "not pressing back", parent_id,
                )
                continue
            if parent_id in self.states:
                parent = self.states[parent_id]
                if parent.unexplored_actions():
                    self._current_state_id = parent_id
                    self._backtrack_count += 1
                    logger.info(
                        "[Explorer] Backtracking... to %s (%d unexplored)",
                        parent_id, len(parent.unexplored_actions()),
                    )
                    return {
                        "tool": "press_back",
                        "goal": "BACKTRACK",
                        "reasoning": (
                            f"Backtrack to {parent_id} with "
                            f"{len(parent.unexplored_actions())} unexplored actions"
                        ),
                        "confidence": 0.8,
                        "_source": "backtrack",
                        "_state_id": parent_id,
                    }
        return None

    def has_unexplored_work(self) -> bool:
        """True if any state has unresolved actions or backtrack is possible."""
        for state in self.states.values():
            if state.state_id.startswith("PLACEHOLDER-"):
                continue
            if state.unresolved_actions():
                return True
        for state in self.external_states.values():
            if state.unresolved_actions():
                return True
        for parent_id in self._backtrack_stack:
            if parent_id in self.states:
                if self.states[parent_id].unexplored_actions():
                    return True
        return False

    def coverage_metrics(self) -> Dict[str, Any]:
        states_discovered = len([
            s for s in self.states.values()
            if not s.state_id.startswith("PLACEHOLDER-")
        ]) + len(self.external_states)
        states_explored = sum(1 for s in self.states.values() if s.explored)
        actions_discovered = sum(
            len(s.actionable_elements) for s in self.states.values()
        )
        actions_explored = sum(
            sum(1 for a in s.actionable_elements if a.explored)
            for s in self.states.values()
        )
        actions_failed = sum(
            sum(1 for a in s.actionable_elements if a.failed)
            for s in self.states.values()
        )
        actions_blocked = sum(
            sum(1 for a in s.actionable_elements if a.blocked)
            for s in self.states.values()
        )
        actions_unresolved = sum(
            len(s.unresolved_actions()) for s in self.states.values()
        )
        branches_completed = sum(
            1 for s in self.states.values()
            if s.explored or not s.unexplored_actions()
        )
        coverage_pct = 0.0
        if actions_discovered > 0:
            coverage_pct = round(actions_explored / actions_discovered * 100, 1)

        return {
            "states_discovered": states_discovered,
            "states_explored": states_explored,
            "states_blocked": self.branches_blocked,
            "actionable_elements_discovered": actions_discovered,
            "actionable_elements_executed": actions_explored,
            "actionable_elements_explored": actions_explored,
            "actionable_elements_failed": actions_failed,
            "actionable_elements_blocked": actions_blocked,
            "actionable_elements_unresolved": actions_unresolved,
            "actions_attempted": self.actions_attempted,
            "actions_successful": self.actions_successful,
            "actions_failed": self.actions_failed,
            "branches_completed": branches_completed,
            "branches_blocked": self.branches_blocked,
            "scroll_regions_explored": self.scroll_regions_explored,
            "dialogs_explored": self.dialogs_explored,
            "menus_explored": self.menus_explored,
            "tabs_explored": self.tabs_explored,
            "webviews_explored": self.webviews_explored,
            "permissions_observed": self.permissions_observed,
            "suspicious_permissions": sum(
                1 for m in self.evidence_moments
                if m.moment_type == EvidenceMomentType.SUSPICIOUS_PERMISSION.value
            ),
            "external_urls_observed": len(self.profile.discovered_urls),
            "external_apks_detected": len(self.secondary_apks),
            "external_install_requests": sum(
                1 for m in self.evidence_moments
                if m.moment_type == EvidenceMomentType.EXTERNAL_APK_INSTALL_REQUEST.value
            ),
            "vpn_requests": sum(
                1 for m in self.evidence_moments
                if m.moment_type == EvidenceMomentType.VPN_REQUEST.value
            ),
            "evidence_moments": len(self.evidence_moments),
            "exploration_coverage_percent": coverage_pct,
            "exploration_coverage_definition": (
                "actionable_elements_explored / actionable_elements_discovered * 100"
            ),
            "stop_reason": self.stop_reason.value if self.stop_reason else "",
        }

    def record_secondary_apk(
        self,
        filename: str,
        sha256: str,
        source_package: str = "",
        blocked: bool = False,
    ) -> Dict[str, Any]:
        record = {
            "filename": filename,
            "sha256": sha256,
            "source_package": source_package or self.package_name,
            "blocked_by_policy": blocked,
            "parent_package": self.package_name,
        }
        if len(self.secondary_apks) < ExplorationBudget.MAX_SECONDARY_APKS:
            self.secondary_apks.append(record)
        return record

    def link_screenshot_to_moment(
        self, moment_id: str, screenshot_id: str
    ) -> None:
        for m in self.evidence_moments:
            if m.evidence_moment_id == moment_id:
                if screenshot_id not in m.screenshot_ids:
                    m.screenshot_ids.append(screenshot_id)

    def _placeholder_state(
        self,
        semantic_type: str,
        ownership: str,
        activity: str,
        foreground_package: str,
    ) -> ExplorationState:
        """Lightweight state for non-explorable screens (home, crash)."""
        pid = f"PLACEHOLDER-{ownership}"
        if pid not in self.states:
            self.states[pid] = ExplorationState(
                state_id=pid,
                screen_hash="placeholder",
                ui_tree_hash="placeholder",
                activity_name=activity,
                package_name=self.package_name,
                foreground_package=foreground_package,
                visible_text_summary="",
                semantic_type=semantic_type,
                ownership=ownership,
                explored=True,
            )
        self._current_state_id = pid
        return self.states[pid]

    def _record_transition_event(
        self,
        event_type: str,
        fg_package: str,
        activity: str,
        elapsed_ts: str,
        ownership: str,
    ) -> None:
        self._transition_events.append({
            "event_type": event_type,
            "timestamp": elapsed_ts,
            "foreground_package": fg_package,
            "activity": activity,
            "ownership": ownership,
            "target_package": self.package_name,
        })

    def _record_crash_event(
        self,
        activity: str,
        fg_package: str,
        elapsed_ts: str,
        ownership: str,
    ) -> None:
        self._crash_events.append({
            "event_type": "APP_CRASH",
            "timestamp": elapsed_ts,
            "package": self.package_name,
            "activity": activity,
            "foreground_package": fg_package,
            "ownership": ownership,
            "crash_type": ownership,
        })

    def _observe_external(
        self,
        obs: Any,
        semantic_type: str,
        fg: str,
        activity: str,
        visible: str,
        ui_nodes: List[Any],
        ownership: str,
        parent_state_id: str,
        entry_action: str,
        elapsed_ts: str,
    ) -> ExplorationState:
        """Record external-app state in separate external graph."""
        screen_hash, ui_tree_hash = compute_composite_state_signature(
            activity, fg, ui_nodes, visible,
            webview_sig="webview" if getattr(obs, "is_webview", False) else "",
        )

        # Deduplicate external states
        for sid, state in self.external_states.items():
            if state.screen_hash == screen_hash and state.ui_tree_hash == ui_tree_hash:
                state.visit_count += 1
                return state

        ext_id = f"EXT-{len(self.external_states) + 1:03d}"
        state = ExplorationState(
            state_id=ext_id,
            screen_hash=screen_hash,
            ui_tree_hash=ui_tree_hash,
            activity_name=activity,
            package_name=fg,
            foreground_package=fg,
            visible_text_summary=visible,
            semantic_type=semantic_type,
            ownership=ownership,
            actionable_elements=[],
            timestamp=elapsed_ts,
            parent_state_id=parent_state_id,
            entry_action=entry_action,
            explored=True,
        )
        self.external_states[ext_id] = state

        self._record_transition_event(
            f"TARGET_TO_EXTERNAL:{fg}",
            fg, activity, elapsed_ts, ownership,
        )

        # Link from target state if parent known
        if parent_state_id and parent_state_id in self.states:
            self.edges.append(ExplorationEdge(
                edge_id=self._next_edge_id(),
                source_state_id=parent_state_id,
                target_state_id=ext_id,
                action_type="external_transition",
                target_description=f"launched {fg}",
                result="external",
                timestamp=elapsed_ts,
            ))

        # Detect evidence moments on external screens
        moments = self._detector.detect(obs, semantic_type, ext_id, elapsed_ts)
        for m in moments:
            self.evidence_moments.append(m)
            self._journey.add_moment(m)

        return state

    def to_dict(self) -> Dict[str, Any]:
        return {
            "states": [s.to_dict() for s in self.states.values()],
            "external_states": [s.to_dict() for s in self.external_states.values()],
            "edges": [e.to_dict() for e in self.edges],
            "action_results": list(self.action_results),
            "application_profile": self.profile.to_dict(),
            "evidence_moments": [m.to_dict() for m in self.evidence_moments],
            "secondary_apks": list(self.secondary_apks),
            "victim_journey": self._journey.to_dict(),
            "coverage": self.coverage_metrics(),
            "current_state_id": self._current_state_id,
            "home_observations": self._home_observation_count,
            "home_screenshots": self._home_screenshot_count,
            "crash_events": list(self._crash_events),
            "transition_events": list(self._transition_events),
        }

    def to_mermaid(self) -> str:
        if not self.states:
            return "graph TD\n  Empty[No states discovered]"
        lines = ["graph TD"]
        for state in self.states.values():
            short = state.state_id
            act = state.activity_name.split(".")[-1][:20]
            unexplored = len(state.unexplored_actions())
            lines.append(
                f'  {short}["{act} ({state.semantic_type}) u:{unexplored}"]'
            )
        for edge in self.edges:
            lines.append(
                f'  {edge.source_state_id} -->|{edge.action_type}| {edge.target_state_id}'
            )
        return "\n".join(lines)
