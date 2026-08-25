"""
Canonical action dispatch: semantic role → executable Android interaction.

Planners and prioritizers may propose candidates. Only ActionDispatcher
produces the payload ToolExecutor sends through SandboxProvider/ADB.

No planner performs ADB. Semantic roles are metadata, never executor verbs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Privileged planner tools that may outrank a graph UI tap (device-state work).
PLANNER_OVERRIDE_TOOLS = frozenset({
    "grant_permission",
    "deny_permission",
    "start_activity",
    "inject_test_sms",
    "broadcast_intent",
    "fast_forward_time",
    "enable_wifi",
    "disable_wifi",
})

# Planner outputs that must not starve a discovered UI control.
PLANNER_NON_INTERACTIVE = frozenset({
    "dump_ui",
    "take_screenshot",
    "capture_logcat",
    "list_packages",
    "scroll",
    "press_back",
    "press_home",
    "",
})

MAX_EXECUTION_ATTEMPTS: int = 3


@dataclass
class ExecutableAction:
    """Generic executable interaction. Semantic role is metadata only."""

    action_id: str
    state_id: str
    action_type: str  # TAP / TYPE_TEXT / SCROLL / PRESS_BACK
    semantic_role: str = "UNKNOWN"
    target: str = ""
    bounds: str = ""
    x: Optional[int] = None
    y: Optional[int] = None
    source: str = "uiautomator"
    confidence: float = 0.5
    tool: str = "tap"
    detection_source: str = "uiautomator"
    package: str = ""
    enabled: bool = True
    clickable: bool = True
    prioritization_score: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_executor_payload(self, attempt: int = 1) -> Dict[str, Any]:
        """Translate to a ToolExecutor action dict."""
        tool = self.tool
        if attempt == 1 and self.action_type == "TAP" and self.target:
            tool = "click_text"
        elif self.action_type == "TAP":
            tool = "tap"
        elif self.action_type == "TYPE_TEXT":
            tool = "type_text"
        elif self.action_type == "SCROLL":
            tool = "scroll"
        elif self.action_type == "PRESS_BACK":
            tool = "press_back"

        payload: Dict[str, Any] = {
            "tool": tool,
            "text": self.target,
            "goal": self.extra.get("goal", "DEEP_EXPLORATION"),
            "reasoning": self.extra.get(
                "reasoning",
                f"{self.action_type} role={self.semantic_role} target={self.target!r}",
            ),
            "confidence": self.confidence,
            "_source": "action_dispatcher",
            "_selected_by": self.extra.get("selected_by", "exploration_graph"),
            "_action_id": self.action_id,
            "_state_id": self.state_id,
            "_semantic_role": self.semantic_role,
            "_detection_source": self.detection_source,
            "_bounds": self.bounds,
            "_executable_type": self.action_type,
            "_retry_attempt": attempt,
            "_pipeline_debug": {
                "discovered": True,
                "selected": True,
                "semantic_role": self.semantic_role,
                "confidence": self.confidence,
                "priority": self.prioritization_score,
                "detection_source": self.detection_source,
                "attempt": attempt,
            },
        }
        if self.x is not None:
            payload["x"] = self.x
        if self.y is not None:
            payload["y"] = self.y
        if self.action_type == "SCROLL":
            payload["direction"] = self.extra.get("direction", "down")
        if self.action_type == "TYPE_TEXT":
            payload["field_hint"] = self.extra.get("field_hint", self.target or "text")
            # The semantic type and its length window ride ALONGSIDE the legacy
            # field_hint, never instead of it, so an executor that has only
            # ever read field_hint is unaffected. They are what lets the
            # executor size the value: field_hint="password" is the same string
            # for a 4-digit MPIN and a 12-character login password.
            for key in (
                "field_type", "field_min_length", "field_max_length",
                "field_numeric_only", "resource_id", "node_id",
            ):
                if key in self.extra and self.extra[key] is not None:
                    payload[key] = self.extra[key]
        return payload


@dataclass
class ActionTrace:
    """End-to-end trace so discovery cannot be confused with execution."""

    action_id: str = ""
    state_id: str = ""
    discovered: bool = False
    detection_source: str = ""
    text: str = ""
    semantic_role: str = ""
    confidence: float = 0.0
    enabled: bool = True
    clickable: bool = True
    bounds: str = ""
    selected_by: str = ""
    prioritization_score: int = 0
    planner_selected: bool = False
    executor_received: bool = False
    executor_method: str = ""
    coordinate_generated: bool = False
    coordinate_validation: str = ""
    adb_command_generated: bool = False
    adb_command_executed: bool = False
    adb_return_code: Optional[int] = None
    adb_stdout: str = ""
    adb_stderr: str = ""
    action_verification: str = ""
    state_before: str = ""
    state_after: str = ""
    foreground_package_before: str = ""
    foreground_package_after: str = ""
    ui_changed: bool = False
    attempts: int = 0
    lifecycle: List[str] = field(default_factory=list)

    def mark(self, stage: str) -> None:
        if stage not in self.lifecycle:
            self.lifecycle.append(stage)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "state_id": self.state_id,
            "discovered": self.discovered,
            "detection_source": self.detection_source,
            "text": self.text,
            "semantic_role": self.semantic_role,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "clickable": self.clickable,
            "bounds": self.bounds,
            "selected_by": self.selected_by,
            "prioritization_score": self.prioritization_score,
            "planner_selected": self.planner_selected,
            "executor_received": self.executor_received,
            "executor_method": self.executor_method,
            "coordinate_generated": self.coordinate_generated,
            "coordinate_validation": self.coordinate_validation,
            "adb_command_generated": self.adb_command_generated,
            "adb_command_executed": self.adb_command_executed,
            "adb_return_code": self.adb_return_code,
            "adb_stdout": (self.adb_stdout or "")[:500],
            "adb_stderr": (self.adb_stderr or "")[:500],
            "action_verification": self.action_verification,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "foreground_package_before": self.foreground_package_before,
            "foreground_package_after": self.foreground_package_after,
            "UI_changed": self.ui_changed,
            "attempts": self.attempts,
            "lifecycle": list(self.lifecycle),
        }


def pipeline_log(event: str, **fields: Any) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    parts = [f"{k}={v}" for k, v in fields.items() if v is not None and v != ""]
    logger.info("[%s] %s %s", ts, event, " ".join(parts))


def semantic_role_to_executable(action_type: str, semantic_role: str = "") -> str:
    """Map inventory/semantic metadata to an Android interaction verb."""
    at = (action_type or "").lower()
    if at in ("input", "type", "type_text"):
        return "TYPE_TEXT"
    if at == "scroll":
        return "SCROLL"
    if at in ("back", "press_back"):
        return "PRESS_BACK"
    return "TAP"


def screenshot_coords_to_device(
    x: int,
    y: int,
    *,
    image_width: int,
    image_height: int,
    device_width: int,
    device_height: int,
) -> Tuple[int, int]:
    """Map screenshot pixels onto `wm size` device coordinates."""
    if image_width <= 0 or image_height <= 0:
        return x, y
    if image_width == device_width and image_height == device_height:
        return x, y
    dx = int(round(x * device_width / image_width))
    dy = int(round(y * device_height / image_height))
    return dx, dy


def png_image_size(path: str) -> Optional[Tuple[int, int]]:
    """Read width/height from a PNG header. Returns None if not a PNG."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(24)
    except OSError:
        return None
    if len(header) < 24 or header[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    width = int.from_bytes(header[16:20], "big")
    height = int.from_bytes(header[20:24], "big")
    if width <= 0 or height <= 0:
        return None
    return width, height


def executable_from_action_item(
    action: Any,
    state_id: str,
    *,
    selected_by: str = "exploration_graph",
    package: str = "",
) -> ExecutableAction:
    executable = semantic_role_to_executable(
        getattr(action, "action_type", "click"),
        getattr(action, "semantic_role", ""),
    )
    tool = "click_text"
    if executable == "TYPE_TEXT":
        tool = "type_text"
    elif executable == "SCROLL":
        tool = "scroll"
    elif executable == "PRESS_BACK":
        tool = "press_back"
    return ExecutableAction(
        action_id=getattr(action, "action_id", ""),
        state_id=state_id,
        action_type=executable,
        semantic_role=getattr(action, "semantic_role", "UNKNOWN"),
        target=getattr(action, "label", "") or "",
        bounds=getattr(action, "bounds", "") or "",
        x=int(getattr(action, "center_x", 0) or 0),
        y=int(getattr(action, "center_y", 0) or 0),
        source=getattr(action, "detection_source", "uiautomator"),
        confidence=float(getattr(action, "confidence", 0.5) or 0.5),
        tool=tool,
        detection_source=getattr(action, "detection_source", "uiautomator"),
        package=package,
        clickable=bool(getattr(action, "is_clickable", True)),
        prioritization_score=int(getattr(action, "priority", 0) or 0),
        extra={
            "selected_by": selected_by,
            "goal": "DEEP_EXPLORATION",
            "direction": getattr(action, "scroll_direction", "down") or "down",
            "field_hint": getattr(action, "label", "") or "text",
            "reasoning": (
                f"Dispatch {executable} '{getattr(action, 'label', '')}' "
                f"(role={getattr(action, 'semantic_role', '')}, "
                f"priority={getattr(action, 'priority', 0)}, "
                f"source={getattr(action, 'detection_source', '')})"
            ),
        },
    )


def select_canonical_action(
    graph_action: Optional[Dict[str, Any]],
    planner_action: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    One selector: graph UI interactions win over planner no-ops/scrolls.

    Returns (action_or_none, selected_by).
    """
    ptool = (planner_action or {}).get("tool", "") if planner_action else ""
    if planner_action and ptool in PLANNER_OVERRIDE_TOOLS:
        planner_action = dict(planner_action)
        planner_action["_selected_by"] = "planner_privileged"
        return planner_action, "planner_privileged"

    if graph_action:
        gtool = graph_action.get("tool", "")
        # `tap_sequence` belongs here: it is the graph entering a whole PIN on a
        # numeric keypad, which the planner cannot express. Without it the
        # planner's single "tap 1" won the selection, the pad never filled, and
        # the screen behind it was never reached - the AI silently reducing
        # coverage, which is the one thing selection must not allow.
        if gtool in ("click_text", "tap", "tap_sequence", "type_text", "check"):
            chosen = dict(graph_action)
            chosen["_selected_by"] = "exploration_graph"
            return chosen, "exploration_graph"
        if ptool in PLANNER_NON_INTERACTIVE or planner_action is None:
            chosen = dict(graph_action)
            chosen["_selected_by"] = "exploration_graph"
            return chosen, "exploration_graph"
        if planner_action:
            planner_action = dict(planner_action)
            planner_action["_selected_by"] = "planner"
            return planner_action, "planner"
        chosen = dict(graph_action)
        chosen["_selected_by"] = "exploration_graph"
        return chosen, "exploration_graph"

    if planner_action:
        planner_action = dict(planner_action)
        planner_action["_selected_by"] = "planner"
        return planner_action, "planner"
    return None, "no_action"


class ActionDispatcher:
    """Single execution boundary between selection and ToolExecutor."""

    def __init__(self) -> None:
        self.last_trace: Optional[ActionTrace] = None
        self.traces: List[ActionTrace] = []

    def begin_trace(self, action: Dict[str, Any], *, state_id: str = "") -> ActionTrace:
        trace = ActionTrace(
            action_id=str(action.get("_action_id") or ""),
            state_id=str(action.get("_state_id") or state_id or ""),
            discovered=True,
            detection_source=str(action.get("_detection_source") or ""),
            text=str(action.get("text") or ""),
            semantic_role=str(action.get("_semantic_role") or ""),
            confidence=float(action.get("confidence") or 0.0),
            bounds=str(action.get("_bounds") or ""),
            selected_by=str(action.get("_selected_by") or action.get("_source") or ""),
            prioritization_score=int(
                (action.get("_pipeline_debug") or {}).get("priority") or 0
            ),
            planner_selected=str(action.get("_source") or "") in (
                "ai", "fallback", "goal_planner", "cache",
            ),
            coordinate_generated=action.get("x") is not None and action.get("y") is not None,
        )
        trace.mark("ACTION_DISCOVERED")
        trace.mark("ACTION_SELECTED")
        self.last_trace = trace
        self.traces.append(trace)
        return trace

    def retry_payload(self, action: Dict[str, Any], attempt: int) -> Optional[Dict[str, Any]]:
        """
        Bounded retry ladder:
          1. structured click_text (already attempted)
          2. geometry / clickable-parent tap  (if x, y present)
             OR text-only semantic retry      (if only text present)
          3. visual-grounded coordinate tap   (if x, y present)

        Previously returned None immediately when x/y were missing, silently
        abandoning any action that had text but no computed coordinates.  Now
        a text-only semantic retry is attempted as step 2 so that discoverd
        UI elements that were not assigned coordinates during inventory building
        still get a second attempt via the XML text matcher.
        """
        if attempt >= MAX_EXECUTION_ATTEMPTS:
            return None
        x, y = action.get("x"), action.get("y")
        text = (action.get("text") or "").strip()

        retry = dict(action)
        retry["_retry_attempt"] = attempt + 1
        source = str(action.get("_detection_source") or "")
        # Attempt 1 may have tapped the graph's coordinates without consulting
        # the hierarchy. If it did not land, those coordinates are exactly what
        # is in doubt, so every escalation re-resolves the element by text.
        geometry_was_trusted = bool(action.pop("_geometry_trusted", False))
        retry.pop("_geometry_trusted", None)

        if geometry_was_trusted and text:
            retry["tool"] = "click_text"
            retry["reasoning"] = (
                f"Retry {attempt + 1}: geometry tap did not land - "
                f"re-resolving '{text}' from the hierarchy"
            )
            retry["_pipeline_debug"] = {
                **(action.get("_pipeline_debug") or {}),
                "retry_strategy": "text_after_geometry",
                "retry_attempt": attempt + 1,
            }
            return retry

        if x is not None and y is not None:
            # Coordinate-based retry ladder (original behaviour).
            retry["tool"] = "tap"
            if attempt == 1:
                retry["reasoning"] = f"Retry 2: resolved geometry tap @({x},{y})"
                retry["_pipeline_debug"] = {
                    **(action.get("_pipeline_debug") or {}),
                    "retry_strategy": "clickable_parent_or_geometry",
                    "retry_attempt": 2,
                }
            else:
                retry["reasoning"] = f"Retry 3: visual/current-screen tap @({x},{y})"
                retry["_pipeline_debug"] = {
                    **(action.get("_pipeline_debug") or {}),
                    "retry_strategy": "visual_grounding_tap",
                    "retry_attempt": 3,
                }
                if source:
                    retry["_detection_source"] = source
            return retry

        if text:
            # No coordinates available — fall back to a semantic text retry.
            # click_text uses XML text/content-desc matching, so it does not
            # require pre-computed coordinates and may succeed where a raw tap
            # could not.
            retry["tool"] = "click_text"
            retry["reasoning"] = f"Retry {attempt + 1}: semantic text retry for '{text}' (no coords)"
            retry["_pipeline_debug"] = {
                **(action.get("_pipeline_debug") or {}),
                "retry_strategy": "text_semantic_retry",
                "retry_attempt": attempt + 1,
            }
            logger.debug(
                "[ActionDispatcher] retry_payload: no coordinates, "
                "semantic text retry for '%s' (attempt %d)",
                text, attempt + 1,
            )
            return retry

        # Neither coordinates nor text — truly no retry possible.
        logger.debug(
            "[ActionDispatcher] RETRY_UNAVAILABLE: "
            "no x/y and no text for action_id=%s",
            action.get("_action_id"),
        )
        return None
