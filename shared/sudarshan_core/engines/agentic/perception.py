"""
SUDARSHAN — Agentic Perception Pipeline
=========================================
Implements the 5-level priority observation system for the Agentic Explorer.

Priority order (lower number = higher priority, tried first):
  Level 1 — UI XML via uiautomator dump  (primary, always attempted)
  Level 2 — Current Activity name        (always captured)
  Level 3 — Frida runtime events         (received from EventBus since last observation)
  Level 4 — Logcat tail                  (captured when no XML actionable nodes found)
  Level 5 — Screenshot + Vision          (ONLY when screenshot_needed() returns True)

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
from typing import Any, Dict, List, Optional, Set

from sudarshan_core.engines.agentic.sanitizer import sanitize, sanitize_block
from sudarshan_core.sandbox import get_sandbox_provider

logger = logging.getLogger(__name__)

# ─── Perception thresholds (all named — unit-testable) ────────────────────────

# Minimum fraction of UI nodes that must have a non-empty text or content-desc
# label for the XML to be considered "human-readable".
# Below this threshold → Vision (Level 5) is triggered.
LABELED_NODE_FRACTION_THRESHOLD: float = 0.20

# Minimum number of actionable (clickable/checkable/scrollable/input) nodes
# required for XML to be considered usable. Below this → Vision triggered.
MIN_ACTIONABLE_NODES: int = 1

# Activity class substrings that indicate a WebView or browser — trigger Vision.
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
            # hostile input — a label may attempt to close the untrusted fence.
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
            # Logcat is written by the app under analysis — fully attacker
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
# Anchoring on the component shape — rather than on whitespace before "}" —
# is what keeps the trailing " t42}" from being captured instead.
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

    Pure function — no device access — so it is unit-testable against captured
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

        # ── Level 2: Current Activity (always captured) ──────────────────────
        obs.activity = await self._get_current_activity()
        obs.is_webview = self._is_webview_activity(obs.activity)

        # ── Level 1: UI XML dump ─────────────────────────────────────────────
        xml_raw = await self._dump_ui_xml()
        obs.ui_xml_raw = xml_raw or ""

        if xml_raw:
            obs.ui_nodes   = self._parse_ui_nodes(xml_raw)
            obs.ui_node_count = len(obs.ui_nodes)
            obs.screen_hash   = self._compute_screen_hash(obs.ui_nodes, obs.activity)
            obs.is_empty_ui   = obs.ui_node_count < MIN_ACTIONABLE_NODES

        # ── Determine if Level 5 (screenshot/vision) is needed ───────────────
        reason = self._screenshot_needed(obs, last_action_failed)
        if reason:
            # Only capture if screen state has changed since last vision call
            if obs.screen_hash != self._last_vision_hash:
                path = await self._take_screenshot()
                obs.screenshot_path  = path or ""
                obs.screenshot_taken = bool(path)
                obs.vision_reason    = reason
                self._last_vision_hash = obs.screen_hash
                logger.info(f"[Perception] Screenshot captured (reason: {reason})")
            else:
                logger.debug("[Perception] Screenshot skipped — screen unchanged since last vision")

        # ── Level 4: Logcat (when XML provides no actionable information) ────
        if obs.is_empty_ui or obs.is_webview:
            obs.logcat = await self._capture_logcat()

        return obs

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

        A node is actionable if it is: clickable, checkable, scrollable, or EditText.
        Nodes without bounds are skipped.
        """
        nodes: List[UINode] = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.warning(f"[Perception] XML parse error: {e}")
            return nodes

        for elem in root.iter():
            is_clickable  = elem.attrib.get("clickable")  == "true"
            is_checkable  = elem.attrib.get("checkable")  == "true"
            is_scrollable = elem.attrib.get("scrollable") == "true"
            is_input      = elem.attrib.get("class", "") == "android.widget.EditText"

            if not (is_clickable or is_checkable or is_scrollable or is_input):
                continue

            bounds_str = elem.attrib.get("bounds", "")
            if not bounds_str:
                continue

            m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
            if not m:
                continue

            x1, y1, x2, y2 = map(int, m.groups())
            text     = elem.attrib.get("text", "").strip()
            desc     = elem.attrib.get("content-desc", "").strip()
            res_id   = elem.attrib.get("resource-id", "")
            res_id   = res_id.split("/")[-1] if "/" in res_id else res_id
            cls_full = elem.attrib.get("class", "")
            cls_name = cls_full.split(".")[-1]

            nodes.append(UINode(
                node_id      = f"n{len(nodes)}",
                class_name   = cls_name,
                text         = text,
                desc         = desc,
                resource_id  = res_id,
                center_x     = (x1 + x2) // 2,
                center_y     = (y1 + y2) // 2,
                is_input     = is_input,
                is_clickable = is_clickable,
                is_scrollable= is_scrollable,
                bounds       = bounds_str,
            ))

        return nodes

    def _compute_screen_hash(self, nodes: List[UINode], activity: str) -> str:
        """
        Compute a stable hash representing the current interactive screen state.
        Based on class, text, desc, resource_id, and activity — not raw positions.
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
                f"— returning 'unknown'"
            )
        return "unknown"

    def _is_webview_activity(self, activity: str) -> bool:
        """Return True if the activity name suggests a WebView or browser."""
        return any(p.lower() in activity.lower() for p in WEBVIEW_ACTIVITY_PATTERNS)

    # ── Screenshot trigger decision ───────────────────────────────────────────

    def _screenshot_needed(self, obs: Observation, last_action_failed: bool) -> str:
        """
        Apply the 5-trigger decision tree for Level 5 (Vision).

        Returns a non-empty reason string if a screenshot should be taken,
        or empty string if XML is sufficient.

        All triggers map to named constants — this method is fully unit-testable.
        """
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
                f"({type(e).__name__}: {e}) — observation continues without it"
            )
            return ""

    # ── Level 5: Screenshot ───────────────────────────────────────────────────

    async def _take_screenshot(self) -> Optional[str]:
        """Capture a screenshot and return the local file path, or None on failure."""
        if self.screenshot_manager is not None:
            ref = self.screenshot_manager.capture(
                label="perception_vision",
                category="ui",
                source="explorer",
                reason="SUSPICIOUS_UI",
                activity="",
                force=False,
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
