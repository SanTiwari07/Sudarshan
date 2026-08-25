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
    priority: int = 50
    explored: bool = False
    failed: bool = False
    blocked: bool = False
    unreachable: bool = False
    scroll_container_id: str = ""
    scroll_direction: str = ""
    scroll_position: int = 0
    semantic_role: str = "UNKNOWN"
    detection_source: str = "uiautomator"
    confidence: float = 0.99
    bounds: str = ""
    selected: bool = False
    dispatched: bool = False
    executed: bool = False
    verified: bool = False
    execution_attempts: int = 0

    def signature(self) -> str:
        return f"{self.action_type}:{self.node_id}:{self.label}:{self.scroll_direction}"

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
    """
    tree_parts: List[str] = [activity, package]
    text_parts: List[str] = []

    for n in ui_nodes:
        cls = getattr(n, "class_name", "") or ""
        text = getattr(n, "text", "") or ""
        desc = getattr(n, "desc", "") or ""
        res_id = getattr(n, "resource_id", "") or ""
        clickable = getattr(n, "is_clickable", False)
        scrollable = getattr(n, "is_scrollable", False)
        tree_parts.append(
            f"{cls}|{text[:30]}|{desc[:30]}|{res_id}|{clickable}|{scrollable}"
        )
        if text or desc:
            text_parts.append(f"{text[:40]}|{desc[:40]}")

    if visible_text:
        text_parts.append(visible_text[:200])
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


def _prune_container_actions(items: List["ActionItem"]) -> List["ActionItem"]:
    """Drop unlabeled full-screen parents when labeled CTAs exist."""
    labeled = [
        i for i in items
        if not _is_unlabeled_action(i) and i.action_type != "scroll"
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
        kept.append(item)
    return kept or items


_INTERACTIVE_BOUNDARY_TYPES = frozenset({
    "SYSTEM_PERMISSION",
    "ACCESSIBILITY_DIALOG",
    "VPN_REQUEST",
    "PACKAGE_INSTALLER",
    "EXTERNAL_APK",
    "UPDATE_PROMPT",
    "DOWNLOAD_PROMPT",
    "SETTINGS",
})
_INTERACTIVE_BOUNDARY_OWNERSHIP = frozenset({
    "SYSTEM_INSTALLER",
    "SYSTEM_SETTINGS",
    "SYSTEM_PERMISSION",
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
        # Boost the inferred affirmative choice for decision dialogs
        if len(ranked) >= 2:
            affirmative = infer_affirmative_choice(ranked, context_text=context_text)
            if affirmative is not None:
                affirmative.priority = min(100, affirmative.priority + 15)
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

        for idx, n in enumerate(ui_nodes):
            node_id = getattr(n, "node_id", f"n{idx}")
            text = getattr(n, "text", "") or ""
            desc = getattr(n, "desc", "") or ""
            label = text or desc or getattr(n, "resource_id", "") or node_id
            is_input = getattr(n, "is_input", False)
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
            elif is_clickable or is_checkable:
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
        if ownership in (
            "EXTERNAL_APP", "SYSTEM_INSTALLER", "SYSTEM_SETTINGS",
        ) and fg != self.package_name:
            interactive = (
                ownership in _INTERACTIVE_BOUNDARY_OWNERSHIP
                or semantic_type in _INTERACTIVE_BOUNDARY_TYPES
            )
            # Safety-net: screen_classifier may not have had enough UI text to
            # produce an interactive semantic_type (e.g. spinner still loading).
            # Use the confidence-based boundary role detector as a last resort.
            if not interactive:
                from sudarshan_core.engines.agentic.screenshot_policy import (
                    is_safe_interactive_boundary,
                )
                interactive = is_safe_interactive_boundary(fg, activity)

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
        )
        self.states[state_id] = state
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

        if source_state_id in self.states:
            state = self.states[source_state_id]
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
            if action_type == "scroll":
                self._scroll_depth[source_state_id] = (
                    self._scroll_depth.get(source_state_id, 0) + 1
                )
            if not state.unexplored_actions():
                state.explored = True
                logger.debug(
                    "[ExplorationGraph] State '%s' fully explored",
                    source_state_id,
                )

        if action_type == "scroll":
            self.scroll_regions_explored += 1
        elif action_type == "menu":
            self.menus_explored += 1
        elif action_type == "tab":
            self.tabs_explored += 1

        return edge

    def _lookup_state(self, state_id: str) -> Optional[ExplorationState]:
        if state_id in self.states:
            return self.states[state_id]
        if state_id in self.external_states:
            return self.external_states[state_id]
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
                self._current_state_id = pending
                return self.get_next_action(pending, memory)
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

    def _backtrack_action(self, memory: Any = None) -> Optional[Dict[str, Any]]:
        """Press back to explore remaining branches."""
        if self._backtrack_count >= ExplorationBudget.MAX_BACKTRACKS:
            logger.info(
                "[Explorer] Backtracking exhausted (%d/%d)",
                self._backtrack_count, ExplorationBudget.MAX_BACKTRACKS,
            )
            return None
        while self._backtrack_stack:
            parent_id = self._backtrack_stack.pop()
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
