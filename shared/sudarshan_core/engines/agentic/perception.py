"""
SUDARSHAN - Agentic Perception Pipeline
=========================================
Implements the 5-level priority observation system for the Agentic Explorer.

Priority order (lower number = higher priority, tried first):
  Level 1 - UI XML via uiautomator dump  (primary, always attempted)
  Level 2 - Current Activity name        (always captured)
  Level 3 - Frida runtime events         (received from EventBus since last observation)
  Level 4 - Logcat tail                  (captured when no XML actionable nodes found)
  Level 5 - Screenshot + Vision          (ONLY when screenshot_needed() returns True)

Screenshot (Level 5) is ONLY triggered when any of:
  - UI XML is empty or parse failed
  - UI XML contains no clickable elements (all nodes are non-interactive)
  - Fraction of labeled nodes < LABELED_NODE_FRACTION_THRESHOLD
  - Current activity is a known WebView or browser class
  - Previous action failed because UI could not be understood

All thresholds are named constants for testability.

Usage::

    pipeline = PerceptionPipeline(device_serial="emulator-5554", adb_path="adb")
    obs = await pipeline.observe(frida_events=[...], last_action_failed=False)
    print(obs.activity, obs.ui_node_count, obs.screenshot_taken)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from sudarshan_core.engines.agentic.sanitizer import sanitize, sanitize_block
from sudarshan_core.sandbox import get_sandbox_provider

logger = logging.getLogger(__name__)

# ─── Perception thresholds (all named - unit-testable) ────────────────────────

# Minimum fraction of UI nodes that must have a non-empty text or content-desc
# label for the XML to be considered "human-readable".
# Below this threshold → Vision (Level 5) is triggered.
LABELED_NODE_FRACTION_THRESHOLD: float = 0.20

# Minimum number of actionable (clickable/checkable/scrollable/input) nodes
# required for XML to be considered usable. Below this → Vision triggered.
MIN_ACTIONABLE_NODES: int = 1

# Activity class substrings that indicate a WebView or browser - trigger Vision.
WEBVIEW_ACTIVITY_PATTERNS: List[str] = [
    "WebViewActivity",
    "BrowserActivity",
    "ChromeActivity",
    "WebActivity",
    "NativeWebActivity",
    "HybridActivity",
    "CordovaActivity",
    "PhoneGapActivity",
    "ReactNativeActivity",
]

# Frida event categories that indicate a fraud-relevant screen is on display.
# These force Vision (Level 5) even when the UI XML parses cleanly, because the
# XML tree does not reveal WebView-rendered or overlay-drawn content.
FRAUD_EVENT_CATEGORIES: Set[str] = {"overlay", "accessibility", "sms"}

# Logcat capture line count
LOGCAT_LINES: int = 40


# ─── Observation dataclass ────────────────────────────────────────────────────

@dataclass
class UINode:
    """A single actionable UI element parsed from the XML hierarchy."""
    node_id:     str
    class_name:  str
    text:        str
    desc:        str           # content-desc attribute
    resource_id: str
    center_x:    int
    center_y:    int
    is_input:    bool
    is_clickable: bool
    is_scrollable: bool
    bounds:      str
    is_checkable: bool = False
    enabled:     bool = True
    checked:     Optional[bool] = None
    semantic_role: str = "UNKNOWN"
    detection_source: str = "uiautomator"
    confidence:  float = 0.99
    #: uiautomator's `password` attribute. On the WebView-based banking apps in
    #: the corpus this is the ONLY reliable way to tell the password box from
    #: the username box: neither carries a resource-id, a text value or a
    #: content-desc, so without it both fields look identical and get filled
    #: with the same string, which can never authenticate.
    is_password: bool = False
    #: Nearest preceding label for an input ("Username", "CRN / Customer ID",
    #: "Login Password"). These apps render the caption as a separate sibling
    #: node above the field rather than as a hint on it, so the field's meaning
    #: only exists in document order.
    field_label: str = ""


@dataclass
class Observation:
    """
    Full structured observation snapshot for one agent iteration.

    Fields:
        activity:         Current foreground Activity class name.
        ui_nodes:         Parsed, actionable UI nodes (Level 1).
        ui_xml_raw:       Raw XML string (for hashing and logging).
        ui_node_count:    Total actionable nodes found.
        screen_hash:      Stable hash of the interactive UI state.
        frida_events:     Frida events received since last observation (Level 3).
        logcat:           Logcat tail (Level 4), empty if not captured.
        screenshot_path:  Local path to screenshot if taken (Level 5), else "".
        screenshot_taken: True if a screenshot was captured this cycle.
        is_webview:       True if activity is identified as a WebView.
        is_empty_ui:      True if no actionable UI nodes found.
        vision_reason:    Why screenshot was triggered (empty if not triggered).
        static_findings:  Optional dict of static analysis signals (passed in).
    """
    activity:         str              = "unknown"
    ui_nodes:         List[UINode]     = field(default_factory=list)
    ui_xml_raw:       str              = ""
    ui_node_count:    int              = 0
    screen_hash:      str              = ""
    frida_events:     List[Dict]       = field(default_factory=list)
    logcat:           str              = ""
    screenshot_path:  str              = ""
    screenshot_taken: bool             = False
    is_webview:       bool             = False
    is_empty_ui:      bool             = False
    vision_reason:    str              = ""
    static_findings:  Dict[str, Any]   = field(default_factory=dict)
    grounding_sources: List[str]       = field(default_factory=list)

    def ui_summary(self, max_nodes: int = 15) -> str:
        """
        Compact string representation of the UI for injection into prompts.
        Truncated to max_nodes elements to manage token budget.
        """
        if not self.ui_nodes:
            return "(no actionable UI elements)"
        lines = [f"Activity: {sanitize(self.activity)}", "UI Elements:"]
        for n in self.ui_nodes[:max_nodes]:
            # Every one of these is chosen by the analysed app and is therefore
            # hostile input - a label may attempt to close the untrusted fence.
            label = n.text or n.desc or n.resource_id or f"[{n.class_name}]"
            kind  = "INPUT" if n.is_input else ("SCROLL" if n.is_scrollable else "BTN")
            lines.append(
                f"  [{n.node_id}] {kind} '{sanitize(label)}' @({n.center_x},{n.center_y})"
            )
        if len(self.ui_nodes) > max_nodes:
            lines.append(f"  ... ({len(self.ui_nodes) - max_nodes} more elements)")
        return "\n".join(lines)

    def to_prompt_block(self) -> str:
        """
        Build the OBSERVATION section for the planner prompt.
        Screenshot path is included only as a filename reference, not embedded.
        """
        lines = [
            "=== CURRENT OBSERVATION ===",
            f"Activity: {sanitize(self.activity)}",
            f"Screen hash: {self.screen_hash}",
            f"Frida events since last action: {len(self.frida_events)}",
            "",
            self.ui_summary(),
        ]
        if self.logcat:
            lines.append("")
            lines.append("--- Recent Logcat (last 10 lines) ---")
            # Logcat is written by the app under analysis - fully attacker
            # controlled, and historically injected verbatim.
            for line in sanitize_block(self.logcat, max_lines=10).splitlines():
                lines.append(f"  {line}")
        if self.screenshot_taken:
            lines.append("")
            lines.append(
                f"Screenshot taken (reason: {sanitize(self.vision_reason)}): "
                f"{sanitize(self.screenshot_path)}"
            )
        if self.frida_events:
            lines.append("")
            lines.append("--- Frida Events (this cycle) ---")
            for e in self.frida_events[:5]:
                # Hook names embed app-supplied class and method names.
                cat  = sanitize(e.get("category", "?"), max_length=64)
                hook = sanitize(e.get("data", {}).get("hook", "?"), max_length=128)
                lines.append(f"  [{cat}] {hook}")
            if len(self.frida_events) > 5:
                lines.append(f"  ... ({len(self.frida_events) - 5} more)")
        return "\n".join(lines)


# ─── Foreground activity parsing ──────────────────────────────────────────────

# An Android component is "<package>/<activity>". The activity half may be a
# bare suffix (".MainActivity") or fully qualified ("com.pkg.MainActivity").
_COMPONENT_RE = r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*/[A-Za-z0-9_.$]+'

# Real dumpsys emits, for example:
#   mResumedActivity: ActivityRecord{a1b2c3 u0 com.pkg/.MainActivity t42}
#   topResumedActivity=ActivityRecord{a1b2c3 u0 com.pkg/.MainActivity t42}
# The component is preceded by the user id ("u0") and followed by the task id.
# Anchoring on the component shape - rather than on whitespace before "}" - # is what keeps the trailing " t42}" from being captured instead.
_ACTIVITY_PATTERNS = (
    # Android <= 12 prints "mResumedActivity:"; Android 13+ prints "ResumedActivity:".
    # \b keeps this from matching inside "topResumedActivity", handled separately.
    re.compile(r'topResumedActivity[=:]\s*ActivityRecord\{[^}]*?\bu\d+\s+(' + _COMPONENT_RE + r')'),
    re.compile(r'\bm?ResumedActivity[=:]\s*ActivityRecord\{[^}]*?\bu\d+\s+(' + _COMPONENT_RE + r')'),
    re.compile(r'mCurrentFocus=Window\{[^}]*?\s(' + _COMPONENT_RE + r')'),
    re.compile(r'mFocusedActivity[=:]\s*ActivityRecord\{[^}]*?\bu\d+\s+(' + _COMPONENT_RE + r')'),
    # Last resort: any ActivityRecord component (multi-display / foldable dumps
    # place the resumed record under a per-display section).
    re.compile(r'ActivityRecord\{[^}]*?\bu\d+\s+(' + _COMPONENT_RE + r')'),
)


def parse_foreground_activity(dumpsys_output: str) -> str:
    """
    Extract the fully-qualified foreground component from `dumpsys activity
    activities` output.

    Returns "<package>/<activity>", or "unknown" when no component is present.

    Pure function - no device access - so it is unit-testable against captured
    dumpsys text from portrait, landscape, split-screen and foldable devices.
    """
    if not dumpsys_output:
        return "unknown"
    for pattern in _ACTIVITY_PATTERNS:
        match = pattern.search(dumpsys_output)
        if match:
            return match.group(1)
    return "unknown"


def package_of(activity: str) -> str:
    """
    Return the package half of a "<package>/<activity>" component string.

    Returns "" when the input is not a well-formed component, so callers can
    distinguish "no reliable foreground reading" from a real package name.
    """
    if not activity or "/" not in activity:
        return ""
    return activity.split("/", 1)[0]


#: Packages that are not the sample but are still part of an investigation.
#:
#: The agent has to be able to reach a runtime permission dialog, the
#: Accessibility settings screen and the package installer - granting
#: Accessibility is itself one of the fraud goals, and a scope guard that
#: bounced the agent back into the app the moment it saw com.android.settings
#: would make that goal permanently unreachable.
#:
#: Everything else - Contacts, Dialer, Chrome, Play Store, the launcher - is out
#: of scope. Exploring those apps produces screenshots of AOSP, not of the
#: sample, and spends the action budget somewhere no evidence can come from.
#: An ancestor at least this large is the page, not a control on it. A caption
#: whose only clickable ancestor is that large is decoration, and promoting it
#: to an action produces a tap on the background.
_FULLSCREEN_ANCESTOR_AREA: int = 900_000

#: Packages that exist only to host boundary prompts. Everything they can show
#: is a prompt the sample raised, so being there is always in scope.
INVESTIGATION_SCOPE_PACKAGES: FrozenSet[str] = frozenset({
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.android.systemui",
    # The VpnService consent dialog. Reaching it means the sample called
    # VpnService.prepare(); answering it is the only way to observe what the
    # sample does with the tunnel, and bouncing off it made the VPN half of a
    # multi-stage journey unobservable.
    "com.android.vpndialogs",
    "com.google.android.vpndialogs",
    # Single-purpose OEM installers.
    "com.samsung.android.packageinstaller",
    "com.miui.packageinstaller",
    "com.transsion.installer",
})

#: Full system applications that HOST boundary prompts among ordinary screens.
#:
#: com.android.settings used to sit in INVESTIGATION_SCOPE_PACKAGES, which made
#: every Settings screen unconditionally in scope and so left the out-of-scope
#: recovery path unreachable: a measured 300s run answered 55 of 55 observations
#: from Settings and never once tried to recover. Being *in* one of these
#: packages is now in scope only while a boundary prompt is actually on screen,
#: which is what keeps the accessibility and VPN consent flows working while
#: denying the rest of the Settings app.
BOUNDARY_HOST_PACKAGES: FrozenSet[str] = frozenset({
    "com.android.settings",
    # OEM security centres / app stores that raise install and permission
    # prompts among hundreds of ordinary screens. Same rule as Settings: in
    # scope while a prompt is up, out of scope otherwise.
    "com.miui.securitycenter",
    "com.coloros.safecenter",
    "com.vivo.safecenter",
    "com.oppo.market",
})

#: Screen types that make a boundary-host package in scope.
_BOUNDARY_PROMPT_TYPES: FrozenSet[str] = frozenset({
    "SYSTEM_PERMISSION",
    "ACCESSIBILITY_DIALOG",
    "VPN_REQUEST",
    "PACKAGE_INSTALLER",
    "EXTERNAL_APK",
    "UPDATE_PROMPT",
    "DOWNLOAD_PROMPT",
})


def in_investigation_scope(
    foreground_package: str,
    target_package: str,
    activity: str = "",
    ui_text: str = "",
    screen_type: str = "",
) -> bool:
    """
    Whether the foreground window is somewhere the agent should keep exploring.

    True for the sample itself, for the prompt-only system surfaces listed in
    :data:`INVESTIGATION_SCOPE_PACKAGES`, and for any screen confidently
    identified as a safe interactive boundary role (e.g. an OEM package
    installer not in the static frozenset).

    For a :data:`BOUNDARY_HOST_PACKAGES` member - a full system app such as
    Settings, which hosts consent screens among hundreds of ordinary ones - the
    answer depends on `screen_type`. A permission, accessibility or VPN prompt
    is in scope; Wi-Fi settings are not. Callers that cannot classify the screen
    pass nothing and get False, which arms recovery: leaving a system app the
    agent has no business in is the safe default, and the sample is one
    relaunch away.

    An empty ``foreground_package`` returns True. An unreadable foreground is
    the absence of a reading, not evidence that the agent has wandered off, and
    treating it as out-of-scope would fire a recovery action every time
    ``uiautomator`` returned a malformed dump mid-transition. The same applies
    to an empty ``target_package``: with no target to compare against, nothing
    can be judged out of scope.
    """
    from sudarshan_core.engines.agentic.screenshot_policy import is_safe_interactive_boundary

    if not foreground_package or not target_package:
        return True
    if foreground_package == target_package:
        return True
    if foreground_package in INVESTIGATION_SCOPE_PACKAGES:
        return True
    if foreground_package in BOUNDARY_HOST_PACKAGES:
        return str(screen_type or "") in _BOUNDARY_PROMPT_TYPES
    # Confidence-based role detection: recognises OEM installers, OEM settings,
    # and OEM permission controllers that are not in the static frozenset.
    if is_safe_interactive_boundary(foreground_package, activity, ui_text):
        return True
    return False


# ─── Perception Pipeline ──────────────────────────────────────────────────────

class PerceptionPipeline:
    """
    Collects and synthesizes the full observation for one agent iteration.

    Applies the 5-level priority system and caches the last screenshot hash
    to avoid re-triggering vision for an unchanged screen.
    """

    def __init__(
        self,
        device_serial: str,
        package_name:  str,
        adb_path:      str = "adb",
        screenshot_manager: Optional[Any] = None,
    ) -> None:
        self.device_serial = device_serial
        self.package_name  = package_name
        self.adb_path      = adb_path
        self.screenshot_manager = screenshot_manager

        # Cache: last screen hash for which a screenshot was taken
        self._last_vision_hash: str = ""
        self._screen_size: Optional[Tuple[int, int]] = None

    # ── Main observe() entry point ─────────────────────────────────────────────

    async def observe(
        self,
        frida_events:        List[Dict]       = (),
        last_action_failed:  bool             = False,
        static_findings:     Dict[str, Any]   = None,
    ) -> Observation:
        """
        Collect a full observation snapshot.

        Parameters:
            frida_events:       Events received from EventBus since last cycle.
            last_action_failed: If True, treat as a vision trigger condition.
            static_findings:    Optional static analysis signals for context.

        Returns:
            Observation dataclass ready for injection into the planner.
        """
        obs = Observation(
            frida_events=list(frida_events),
            static_findings=static_findings or {},
        )

        from sudarshan_core.engines.agentic.exploration_engine import (
            compute_composite_state_signature,
        )

        # ── Level 2: Current Activity (always captured) ──────────────────────
        obs.activity = await self._get_current_activity()
        obs.is_webview = self._is_webview_activity(obs.activity)
        foreground_pkg = package_of(obs.activity)

        # ── Level 1: UI XML dump ─────────────────────────────────────────────
        xml_raw = await self._dump_ui_xml()
        obs.ui_xml_raw = xml_raw or ""

        if xml_raw:
            obs.ui_nodes   = self._parse_ui_nodes(xml_raw)
            obs.ui_node_count = len(obs.ui_nodes)
            obs.is_empty_ui   = obs.ui_node_count < MIN_ACTIONABLE_NODES

        # Unified state hash (matches ExplorationGraph)
        sh, _ = compute_composite_state_signature(
            obs.activity,
            foreground_pkg or self.package_name,
            obs.ui_nodes,
        )
        obs.screen_hash = sh

        # ── Determine if Level 5 (screenshot/vision) is needed ───────────────
        # Skip vision for home launcher - policy handles home screenshots
        from sudarshan_core.engines.agentic.screenshot_policy import (
            resolve_screen_ownership,
            ScreenOwnership,
        )
        ownership = resolve_screen_ownership(
            foreground_pkg, self.package_name, obs.activity, "",
        )
        if ownership == ScreenOwnership.HOME_LAUNCHER:
            logger.debug("[Perception] Skipping vision for HOME_LAUNCHER")
            reason = ""
        else:
            reason = self._screenshot_needed(obs, last_action_failed)

        if reason:
            # Fraud-relevant Frida events bypass the dedupe gate: an overlay
            # drawn above the app often leaves the XML-derived screen_hash
            # unchanged, so hash equality is not evidence the screen is the same.
            forced = reason.startswith("frida_event_fraud_category")
            # Otherwise only capture if screen state changed since last vision call
            if forced or obs.screen_hash != self._last_vision_hash:
                # Map the fraud category onto a ScreenshotReason so the manifest
                # caption names the real trigger instead of a generic one.
                cap_reason, cap_category = "SUSPICIOUS_UI", "ui"
                fraud_cats = self._fraud_event_categories(obs) if forced else set()
                if fraud_cats:
                    cat = sorted(fraud_cats)[0]
                    cap_category = cat
                    cap_reason = {
                        "overlay": "OVERLAY",
                        "accessibility": "ACCESSIBILITY",
                        "sms": "HOOK_TRIGGER",
                    }.get(cat, "SUSPICIOUS_UI")
                path = await self._take_screenshot(
                    force=forced,
                    reason=cap_reason,
                    category=cap_category,
                    foreground_package=foreground_pkg,
                    screen_hash=obs.screen_hash,
                )
                obs.screenshot_path  = path or ""
                obs.screenshot_taken = bool(path)
                obs.vision_reason    = reason
                self._last_vision_hash = obs.screen_hash
                logger.info(f"[Perception] Screenshot captured (reason: {reason})")
            else:
                logger.debug("[Perception] Screenshot skipped - screen unchanged since last vision")

        # ── Level 4: Logcat (when XML provides no actionable information) ────
        if obs.is_empty_ui or obs.is_webview:
            obs.logcat = await self._capture_logcat()

        # Structural recovery always: a clickable unlabeled parent must not
        # prevent recovering the labeled CTA child.
        grounded, sources = self._apply_grounding_fallback(obs, foreground_pkg)
        if sources or len(grounded) != len(obs.ui_nodes):
            obs.ui_nodes = grounded
            obs.grounding_sources = sources
            obs.ui_node_count = len(obs.ui_nodes)
            obs.is_empty_ui = obs.ui_node_count < MIN_ACTIONABLE_NODES
            sh, _ = compute_composite_state_signature(
                obs.activity,
                foreground_pkg or self.package_name,
                obs.ui_nodes,
            )
            obs.screen_hash = sh

        return obs

    def _screen_dimensions(self) -> Tuple[int, int]:
        if self._screen_size:
            return self._screen_size
        from sudarshan_core.engines.agentic.device_properties import get_screen_size
        w, h = get_screen_size(self.adb_path, self.device_serial)
        self._screen_size = (w, h)
        return w, h

    def _apply_grounding_fallback(
        self,
        obs: Observation,
        foreground_pkg: str,
    ) -> Tuple[List[UINode], List[str]]:
        from sudarshan_core.engines.agentic.visual_grounding import augment_observation_nodes

        sw, sh = self._screen_dimensions()
        context = " ".join(
            (n.text or n.desc or "") for n in obs.ui_nodes[:20]
        )
        merged, sources = augment_observation_nodes(
            obs.ui_xml_raw,
            obs.ui_nodes,
            screenshot_path=obs.screenshot_path,
            screen_width=sw,
            screen_height=sh,
            context_text=context,
            min_nodes=MIN_ACTIONABLE_NODES,
        )
        if sources:
            logger.info(
                "[Perception] Grounding recovered %d nodes via %s",
                len(merged) - len(obs.ui_nodes),
                ", ".join(sources),
            )
        return merged, sources

    async def _adb(self, *args: str) -> tuple[bool, str]:
        """Policy-enforced ADB via SandboxProvider (same choke point as ToolExecutor)."""
        provider = get_sandbox_provider()
        return await asyncio.to_thread(
            provider.adb, "-s", self.device_serial, *args, timeout=30
        )

    # ── Level 1: UI XML ───────────────────────────────────────────────────────

    async def _dump_ui_xml(self) -> Optional[str]:
        """Dump the UI hierarchy XML from the device."""
        try:
            await self._adb("shell", "uiautomator", "dump", "/data/local/tmp/ui_dump.xml")
            ok, output = await self._adb("shell", "cat", "/data/local/tmp/ui_dump.xml")
            if not ok:
                return None
            m = re.search(r"(<\?xml.*)", output, re.DOTALL)
            return m.group(1) if m else None
        except asyncio.TimeoutError:
            logger.warning("[Perception] UI dump timed out")
            return None
        except Exception as e:
            logger.warning(f"[Perception] UI dump error: {e}")
            return None

    def _parse_ui_nodes(self, xml_content: str) -> List[UINode]:
        """
        Parse the XML hierarchy into a flat list of actionable UINode objects.

        Direct UIAutomator flags (clickable/checkable/scrollable/input) are the
        primary source. Labeled non-clickable children of a clickable ancestor
        are recovered as the same control: tap the ancestor, keep the child's
        semantic label.
        """
        from sudarshan_core.engines.agentic.semantic_action import classify_semantic_role

        nodes: List[UINode] = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.warning(f"[Perception] XML parse error: {e}")
            return nodes

        parent_map = {child: parent for parent in root.iter() for child in list(parent)}

        def _elem_area(elem: ET.Element) -> int:
            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                         elem.attrib.get("bounds", "") or "")
            if not m:
                return 0
            x1, y1, x2, y2 = map(int, m.groups())
            return max(0, (x2 - x1) * (y2 - y1))

        def _clickable_ancestor(elem: ET.Element) -> Optional[ET.Element]:
            """
            The nearest clickable ancestor that is a CONTROL, not the page.

            This recovery exists so a caption inside a clickable list row is
            still tappable. It is not meant to promote every piece of static
            text on a page whose root container happens to be clickable - which
            is exactly what a WebView is. On the banking corpus the WebView
            hosting the login form is clickable, so a heading like "YONO SBI"
            and a static "New user? Register" both resolved to a full-screen
            ancestor; tapping either hit the page background and did nothing,
            and a measured run spent five actions and ~25s on them.
            """
            cur = parent_map.get(elem)
            while cur is not None:
                if cur.attrib.get("clickable") == "true":
                    if _elem_area(cur) >= _FULLSCREEN_ANCESTOR_AREA:
                        # The page itself. Recovering through it is meaningless.
                        return None
                    return cur
                cur = parent_map.get(cur)
            return None

        # The caption of an input is a separate node rendered just above it, so
        # the last text we walked past in document order is that caption. Held
        # here and consumed by _emit() for input nodes only.
        pending_label = {"text": ""}

        def _emit(
            elem: ET.Element,
            *,
            bounds_elem: ET.Element,
            is_clickable: bool,
            source: str,
        ) -> None:
            bounds_str = bounds_elem.attrib.get("bounds", "")
            m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds_str)
            if not m:
                return
            x1, y1, x2, y2 = map(int, m.groups())
            text = elem.attrib.get("text", "").strip()
            desc = elem.attrib.get("content-desc", "").strip()
            res_id = elem.attrib.get("resource-id", "")
            res_id = res_id.split("/")[-1] if "/" in res_id else res_id
            cls_full = elem.attrib.get("class", "")
            cls_name = cls_full.split(".")[-1]
            enabled = elem.attrib.get("enabled", "true") != "false"
            is_checkable = elem.attrib.get("checkable") == "true"
            is_scrollable = elem.attrib.get("scrollable") == "true"
            is_input = elem.attrib.get("class", "") == "android.widget.EditText"
            is_password = elem.attrib.get("password") == "true"
            field_label = pending_label["text"] if is_input else ""
            checked_attr = elem.attrib.get("checked", "")
            checked: Optional[bool] = None
            if checked_attr == "true":
                checked = True
            elif checked_attr == "false":
                checked = False
            area = max(0, (x2 - x1) * (y2 - y1))
            label = text or desc or res_id
            classification = classify_semantic_role(
                label=label,
                class_name=cls_name,
                is_checkable=is_checkable,
                is_clickable=is_clickable or source == "clickable_parent_recovery",
                is_input=is_input,
                is_scrollable=is_scrollable,
                checked=checked,
                bounds_area=area,
            )
            nodes.append(UINode(
                node_id=f"n{len(nodes)}",
                class_name=cls_name,
                text=text,
                desc=desc,
                resource_id=res_id,
                center_x=(x1 + x2) // 2,
                center_y=(y1 + y2) // 2,
                is_input=is_input,
                is_clickable=is_clickable or source == "clickable_parent_recovery",
                is_scrollable=is_scrollable,
                bounds=bounds_str,
                is_checkable=is_checkable,
                enabled=enabled,
                checked=checked,
                semantic_role=classification.role.value,
                detection_source=source,
                confidence=classification.confidence,
                is_password=is_password,
                field_label=field_label,
            ))

        seen_labels: Set[str] = set()
        for elem in root.iter():
            is_clickable = elem.attrib.get("clickable") == "true"
            is_checkable = elem.attrib.get("checkable") == "true"
            is_scrollable = elem.attrib.get("scrollable") == "true"
            is_input = elem.attrib.get("class", "") == "android.widget.EditText"
            bounds_str = elem.attrib.get("bounds", "")
            if not bounds_str:
                continue

            # Remember the caption we just walked past, so the next input can
            # claim it. Captions are non-interactive text nodes; an input never
            # captions another input, and a button's own text is not a caption.
            own_text = (
                elem.attrib.get("text", "").strip()
                or elem.attrib.get("content-desc", "").strip()
            )
            if (
                own_text
                and not is_input
                and not is_clickable
                and not is_checkable
            ):
                pending_label["text"] = own_text

            if is_clickable or is_checkable or is_scrollable or is_input:
                _emit(
                    elem,
                    bounds_elem=elem,
                    is_clickable=is_clickable,
                    source="uiautomator",
                )
                if is_input:
                    # Consumed: the next field must not inherit this caption.
                    pending_label["text"] = ""
                label = (
                    elem.attrib.get("text", "").strip()
                    or elem.attrib.get("content-desc", "").strip()
                )
                if label:
                    seen_labels.add(label.lower())
                continue

            # Layered recovery: labeled non-clickable → clickable ancestor
            label = (
                elem.attrib.get("text", "").strip()
                or elem.attrib.get("content-desc", "").strip()
            )
            if not label or label.lower() in seen_labels:
                continue
            if elem.attrib.get("enabled", "true") == "false":
                continue
            ancestor = _clickable_ancestor(elem)
            if ancestor is None:
                continue
            _emit(
                elem,
                bounds_elem=ancestor,
                is_clickable=True,
                source="clickable_parent_recovery",
            )
            seen_labels.add(label.lower())

        return nodes

    def _compute_screen_hash(self, nodes: List[UINode], activity: str) -> str:
        """
        Compute a stable hash representing the current interactive screen state.
        Based on class, text, desc, resource_id, and activity - not raw positions.
        """
        parts = [activity]
        for n in nodes:
            parts.append(f"{n.class_name}|{n.text}|{n.desc}|{n.resource_id}|{n.is_input}")
        raw = ";".join(parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    # ── Level 2: Activity ─────────────────────────────────────────────────────

    async def _get_current_activity(self) -> str:
        """Return the fully-qualified name of the foreground Activity."""
        try:
            ok, output = await self._adb("shell", "dumpsys", "activity", "activities")
            if ok:
                return parse_foreground_activity(output)
        except Exception as e:
            logger.warning(
                f"[Perception] Activity fetch failed ({type(e).__name__}: {e}) "
                f" - returning 'unknown'"
            )
        return "unknown"

    def _is_webview_activity(self, activity: str) -> bool:
        """Return True if the activity name suggests a WebView or browser."""
        return any(p.lower() in activity.lower() for p in WEBVIEW_ACTIVITY_PATTERNS)

    # ── Screenshot trigger decision ───────────────────────────────────────────

    @staticmethod
    def _fraud_event_categories(obs: Observation) -> Set[str]:
        """
        Return the fraud-relevant Frida event categories seen this cycle.

        Tolerates malformed events: anything that is not a dict, or carries no
        recognised category, is ignored rather than raising.
        """
        found: Set[str] = set()
        for ev in obs.frida_events or []:
            if not isinstance(ev, dict):
                continue
            cat = ev.get("category")
            if isinstance(cat, str) and cat.lower() in FRAUD_EVENT_CATEGORIES:
                found.add(cat.lower())
        return found

    def _screenshot_needed(self, obs: Observation, last_action_failed: bool) -> str:
        """
        Apply the 5-trigger decision tree for Level 5 (Vision).

        Returns a non-empty reason string if a screenshot should be taken,
        or empty string if XML is sufficient.

        All triggers map to named constants - this method is fully unit-testable.
        """
        fraud_cats = self._fraud_event_categories(obs)
        if fraud_cats:
            return f"frida_event_fraud_category ({', '.join(sorted(fraud_cats))})"

        if obs.ui_xml_raw == "":
            return "ui_xml_empty"

        if obs.ui_node_count < MIN_ACTIONABLE_NODES:
            return f"no_actionable_nodes (found {obs.ui_node_count}, threshold {MIN_ACTIONABLE_NODES})"

        # Check labeled node fraction
        if obs.ui_nodes:
            labeled = sum(
                1 for n in obs.ui_nodes if (n.text or n.desc or n.resource_id)
            )
            fraction = labeled / len(obs.ui_nodes)
            if fraction < LABELED_NODE_FRACTION_THRESHOLD:
                return (
                    f"insufficient_labels "
                    f"({fraction:.0%} labeled, threshold {LABELED_NODE_FRACTION_THRESHOLD:.0%})"
                )

        if obs.is_webview:
            return f"webview_activity ({obs.activity})"

        if last_action_failed:
            return "previous_action_failed"

        return ""

    # ── Level 4: Logcat ───────────────────────────────────────────────────────

    async def _capture_logcat(self) -> str:
        """Capture recent logcat lines from the target package."""
        try:
            ok, output = await self._adb(
                "shell", "logcat", "-d", "-t", str(LOGCAT_LINES)
            )
            if not ok:
                return ""
            lines = output.splitlines()
            pkg_short = self.package_name.split(".")[-1]
            relevant = [line for line in lines if pkg_short in line]
            return "\n".join(relevant[-LOGCAT_LINES:] if relevant else lines[-LOGCAT_LINES:])
        except Exception as e:
            logger.warning(
                f"[Perception] Logcat capture failed "
                f"({type(e).__name__}: {e}) - observation continues without it"
            )
            return ""

    # ── Level 5: Screenshot ───────────────────────────────────────────────────

    async def _take_screenshot(
        self,
        *,
        force: bool = False,
        reason: str = "SUSPICIOUS_UI",
        category: str = "ui",
        foreground_package: str = "",
        screen_hash: str = "",
    ) -> Optional[str]:
        """Capture a screenshot and return the local file path, or None on failure."""
        if self.screenshot_manager is not None:
            ref = self.screenshot_manager.capture(
                label="perception_vision",
                category=category,
                source="explorer",
                reason=reason,
                activity="",
                force=force,
                foreground_package=foreground_package,
                layout_hash=screen_hash,
            )
            if ref:
                return str(self.screenshot_manager.output_dir / Path(ref).name)
            return None

        import time
        import os as _os

        ts = int(time.time() * 1000)
        remote = f"/data/local/tmp/percept_{ts}.png"
        local = f"/tmp/percept_{ts}.png"

        try:
            await self._adb("shell", "screencap", "-p", remote)
            await self._adb("pull", remote, local)
            await self._adb("shell", "rm", remote)
            return local if _os.path.exists(local) else None
        except Exception as e:
            logger.warning(f"[Perception] Screenshot failed: {e}")
            return None
