"""
Canonical action dispatch: semantic role → executable Android interaction.

Planners and prioritizers may propose candidates. Only ActionDispatcher
produces the payload ToolExecutor sends through SandboxProvider/ADB.

No planner performs ADB. Semantic roles are metadata, never executor verbs.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
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

#: Confidence a planner must express before its `field_hint` may replace one
#: the graph could not resolve. High on purpose: the graph's hint is wrong here
#: by admission (UNKNOWN), but a hesitant model guess is not obviously better,
#: and a wrong hint types the wrong value into a real form.
PLANNER_FIELD_HINT_MIN_CONFIDENCE: float = 0.75

#: Rungs of the deterministic action ladder that may be spent on ONE semantic
#: action before it is given up on.
#:
#: The ladder is longer than it used to be (three rungs: click_text, tap, tap)
#: because the three it had all failed the same way - they all resolved the
#: element by the same means. A control that cannot be found by text is not
#: found by tapping the coordinates text lookup produced either. The rungs
#: below are ordered by how much they trust, from the most specific identity
#: the hierarchy offers down to a blind geometric guess.
#:
#: The number stays SMALL on purpose. Each rung costs a dispatch plus a
#: verification round-trip - measured at ~7s - so a generous ladder multiplied
#: across a form is how a run spends its whole window on one screen. Six rungs
#: is the whole ladder; MAX_EXECUTION_ATTEMPTS is what any single action may
#: actually spend, and the per-action time budget cuts it shorter still.
MAX_EXECUTION_ATTEMPTS: int = int(
    os.getenv("SUDARSHAN_MAX_ACTION_LADDER_ATTEMPTS", "5")
)

#: Wall-clock an action may spend across its whole ladder. Consulted against
#: the ONE global deadline, never against a clock of its own (§P25).
MAX_ACTION_SECONDS: float = float(
    os.getenv("SUDARSHAN_MAX_ACTION_SECONDS", "15")
)

#: How far a re-aimed tap moves when the original coordinate appears to be
#: obstructed. A control that did not respond may be underneath a banner, a
#: snackbar or a transparent scrim; nudging inside the same bounds is the
#: cheapest way to find out. Sized as a fraction of the element's own height so
#: it stays inside a small control and does not leave a large one.
OBSTRUCTED_TAP_OFFSET_FRACTION: float = 0.3


class ActionStrategy(str, Enum):
    """
    One rung of the deterministic action ladder.

    Ordered most-specific-identity first. Recorded on every trace so a failure
    report can say WHICH resolutions were tried, rather than "3 attempts".
    """

    #: The element's own resource-id. The strongest identity Android offers and
    #: the only one that survives a re-layout.
    RESOURCE_ID = "resource_id"
    #: The accessibility/uiautomator node, addressed by its parsed node id.
    NODE = "uiautomator_node"
    #: Visible text or content-description lookup in a fresh hierarchy dump.
    TEXT = "text_or_content_desc"
    #: The centre of the bounds the observation reported for this element.
    BOUNDS_CENTER = "bounds_center"
    #: Normalised (fraction-of-screen) coordinates mapped onto the live device
    #: resolution. Survives a device whose screenshot and `wm size` differ.
    NORMALIZED_COORDS = "normalized_coordinates"
    #: A coordinate derived from the screenshot by the visual grounder.
    VISION = "vision_coordinate"
    #: The same element, aimed slightly off-centre, on the theory that the
    #: original point is obstructed.
    NEARBY_COORD = "nearby_coordinate"
    #: Give up on resolution; re-read the screen and let selection choose again.
    REPERCEIVE = "reperceive"


#: The ladder, in order. `retry_payload` walks this list and skips any rung it
#: has no data for, so an action with only text does not burn attempts on
#: resource-id and node rungs that could never be built.
ACTION_LADDER: Tuple[str, ...] = (
    ActionStrategy.RESOURCE_ID.value,
    ActionStrategy.NODE.value,
    ActionStrategy.TEXT.value,
    ActionStrategy.BOUNDS_CENTER.value,
    ActionStrategy.NORMALIZED_COORDS.value,
    ActionStrategy.VISION.value,
    ActionStrategy.NEARBY_COORD.value,
)


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
            # One narrow exception: the graph knows WHERE to type, the planner
            # may know WHAT. When the graph could not name the field - an
            # unlabelled WebView box that fell through to the positional guess
            # - a confident planner hint replaces the hint ONLY. The
            # coordinates, action id and state id stay the graph's, because
            # those are what record_action resolves against and what keeps
            # coverage bookkeeping honest.
            #
            # Without this the graph's type_text won unconditionally and the
            # model had no way to correct a field it could see was an email
            # box, so every unnamed field on a form received the same generic
            # value and the form could never be submitted.
            if (
                gtool == "type_text"
                and str(graph_action.get("field_type", "")) in ("", "UNKNOWN")
                and ptool == "type_text"
                and planner_action
                and planner_action.get("field_hint")
                and float(planner_action.get("confidence") or 0.0)
                >= PLANNER_FIELD_HINT_MIN_CONFIDENCE
            ):
                chosen["field_hint"] = planner_action["field_hint"]
                chosen["_field_hint_source"] = "planner"
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

    def retry_payload(
        self,
        action: Dict[str, Any],
        attempt: int,
        *,
        tried: Optional[List[str]] = None,
        remaining_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        The next rung of the deterministic action ladder, or None when spent.

        The ladder, in order of how much identity it trusts:

          1. ``resource_id``          - the element's own id
          2. ``uiautomator_node``     - the parsed accessibility node
          3. ``text_or_content_desc`` - text / content-description lookup
          4. ``bounds_center``        - centre of the reported bounds
          5. ``normalized_coordinates`` - fraction-of-screen, re-mapped live
          6. ``vision_coordinate``    - the visual grounder's point
          7. ``nearby_coordinate``    - the same control, aimed off-centre

        Rungs the action has no data for are SKIPPED rather than spent, so an
        element with only text does not burn its whole budget on resource-id
        and node rungs that could never have been built. That is the difference
        between "five attempts" and "five DIFFERENT attempts", and the old
        three-rung ladder failed the same way three times: it resolved the
        element by text, then tapped the coordinates the text lookup produced,
        then tapped them again.

        Every rung is built from the ORIGINAL action, never from the previous
        rung's payload: rung 1 rewrites ``text`` to the resource-id so the
        executor matches on it, and building rung 3 on top of that would make
        the "resolve by visible text" rung a second resource-id lookup. The
        caller therefore passes the same `action` each time and carries the
        `tried` list forward, which is the only state the ladder has.

        `remaining_seconds` is the ONE global deadline's answer, passed in
        rather than read here so this function stays pure and testable. A rung
        that cannot finish inside the remaining budget is not started - see
        MAX_ACTION_SECONDS.

        Returns None when the ladder is exhausted, the budget is spent, or the
        action carries nothing further to try. None means "this action failed",
        which is an ACTION outcome; it is never by itself a goal outcome and
        never a run outcome (§P18).
        """
        if attempt >= MAX_EXECUTION_ATTEMPTS:
            return None
        # A rung costs roughly one dispatch plus one verification round-trip.
        # Refusing to start one that cannot complete is what stops a run
        # dribbling past its deadline one retry at a time.
        if remaining_seconds is not None and remaining_seconds < _RUNG_COST_SECONDS:
            logger.debug(
                "[ActionDispatcher] LADDER_STOPPED_FOR_TIME action_id=%s "
                "remaining=%.1fs",
                action.get("_action_id"), remaining_seconds,
            )
            return None

        tried: List[str] = list(
            tried if tried is not None else (action.get("_strategies_tried") or [])
        )
        # Attempt 1 may have tapped the graph's coordinates without consulting
        # the hierarchy. If it did not land, those coordinates are exactly what
        # is in doubt, so the geometry rungs are marked spent and every
        # escalation re-resolves the element from the hierarchy first.
        geometry_was_trusted = bool(action.pop("_geometry_trusted", False))
        if geometry_was_trusted:
            for spent in (
                ActionStrategy.BOUNDS_CENTER.value,
                ActionStrategy.NORMALIZED_COORDS.value,
            ):
                if spent not in tried:
                    tried.append(spent)

        for strategy in ACTION_LADDER:
            if strategy in tried:
                continue
            payload = self._payload_for_strategy(action, strategy, attempt)
            if payload is None:
                # No data for this rung. Mark it spent so the next call does
                # not re-consider it, but do NOT count it as an attempt.
                tried.append(strategy)
                continue
            payload["_strategies_tried"] = tried + [strategy]
            payload["_action_strategy"] = strategy
            payload["_retry_attempt"] = attempt + 1
            payload.pop("_geometry_trusted", None)
            payload["_pipeline_debug"] = {
                **(action.get("_pipeline_debug") or {}),
                "retry_strategy": strategy,
                "retry_attempt": attempt + 1,
                "strategies_tried": tried + [strategy],
            }
            logger.debug(
                "[ActionDispatcher] LADDER attempt=%d strategy=%s action_id=%s",
                attempt + 1, strategy, action.get("_action_id"),
            )
            return payload

        logger.debug(
            "[ActionDispatcher] LADDER_EXHAUSTED action_id=%s tried=%s",
            action.get("_action_id"), tried,
        )
        return None

    # -- Ladder rungs --------------------------------------------------------
    #
    # Each returns a payload or None. None means "this action carries no data
    # for this rung", never "this rung failed" - failure is decided by the
    # verifier, from device state, after the payload has been dispatched.

    @staticmethod
    def _payload_for_strategy(
        action: Dict[str, Any], strategy: str, attempt: int
    ) -> Optional[Dict[str, Any]]:
        text = (action.get("text") or "").strip()
        resource_id = str(action.get("resource_id") or "").strip()
        node_id = str(action.get("node_id") or "").strip()
        content_desc = str(action.get("content_desc") or "").strip()
        bounds = str(action.get("_bounds") or action.get("bounds") or "").strip()
        x, y = action.get("x"), action.get("y")

        retry = dict(action)

        if strategy == ActionStrategy.RESOURCE_ID.value:
            if not resource_id:
                return None
            retry["tool"] = "click_text"
            # `text` is what click_text matches on, and its third pattern is a
            # resource-id lookup. Handing it the id makes the id the thing that
            # is matched, which is the strongest identity available.
            retry["text"] = resource_id
            retry["resource_id"] = resource_id
            retry["reasoning"] = (
                f"Retry {attempt + 1}: resolving by resource-id {resource_id!r}"
            )
            return retry

        if strategy == ActionStrategy.NODE.value:
            if not node_id:
                return None
            retry["tool"] = "click_node"
            retry["node_id"] = node_id
            retry["reasoning"] = (
                f"Retry {attempt + 1}: resolving accessibility node {node_id!r}"
            )
            return retry

        if strategy == ActionStrategy.TEXT.value:
            target = text or content_desc
            if not target:
                return None
            retry["tool"] = "click_text"
            retry["text"] = target
            retry["reasoning"] = (
                f"Retry {attempt + 1}: re-resolving {target!r} from a fresh "
                f"hierarchy dump"
            )
            return retry

        if strategy == ActionStrategy.BOUNDS_CENTER.value:
            centre = _bounds_center(bounds)
            if centre is None:
                return None
            cx, cy = centre
            retry["tool"] = "tap"
            retry["x"], retry["y"] = cx, cy
            retry["reasoning"] = (
                f"Retry {attempt + 1}: centre of reported bounds {bounds} "
                f"@({cx},{cy})"
            )
            return retry

        if strategy == ActionStrategy.NORMALIZED_COORDS.value:
            if x is None or y is None:
                return None
            try:
                ix, iy = int(x), int(y)
            except (TypeError, ValueError):
                return None
            retry["tool"] = "tap"
            retry["x"], retry["y"] = ix, iy
            # The executor re-maps against the LIVE `wm size`, so this rung is
            # what recovers an element whose coordinates were computed against
            # a screenshot of a different resolution.
            retry["_normalize_to_device"] = True
            retry["reasoning"] = (
                f"Retry {attempt + 1}: normalised coordinate tap @({ix},{iy})"
            )
            return retry

        if strategy == ActionStrategy.VISION.value:
            vx, vy = action.get("_vision_x"), action.get("_vision_y")
            if vx is None or vy is None:
                return None
            try:
                retry["x"], retry["y"] = int(vx), int(vy)
            except (TypeError, ValueError):
                return None
            retry["tool"] = "tap"
            retry["_detection_source"] = "visual_grounding"
            retry["reasoning"] = (
                f"Retry {attempt + 1}: screenshot-derived coordinate "
                f"@({retry['x']},{retry['y']})"
            )
            return retry

        if strategy == ActionStrategy.NEARBY_COORD.value:
            nearby = _obstructed_alternate(bounds, x, y)
            if nearby is None:
                return None
            nx, ny = nearby
            retry["tool"] = "tap"
            retry["x"], retry["y"] = nx, ny
            retry["reasoning"] = (
                f"Retry {attempt + 1}: original point appears obstructed - "
                f"re-aimed inside the same control @({nx},{ny})"
            )
            return retry

        return None


#: Rough cost of one ladder rung: dispatch plus the verification round-trip
#: that follows it. Measured at ~7s on the reference emulator; used only to
#: decline a rung that cannot finish before the global deadline.
_RUNG_COST_SECONDS: float = float(
    os.getenv("SUDARSHAN_ACTION_RUNG_COST_SECONDS", "7")
)


def _parse_bounds(bounds: str) -> Optional[Tuple[int, int, int, int]]:
    """`[x1,y1][x2,y2]` -> the four ints, or None when unparseable."""
    match = re.match(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]", bounds or "")
    if not match:
        return None
    x1, y1, x2, y2 = (int(g) for g in match.groups())
    if x2 <= x1 or y2 <= y1:
        return None
    return x1, y1, x2, y2


def _bounds_center(bounds: str) -> Optional[Tuple[int, int]]:
    """
    The centre of an element's reported bounds.

    Deliberately a separate rung from the action's own x/y. Those two are
    usually the same point but not always: a container whose clickable child
    sits at one end has a centre that misses the child, and the inventory's x/y
    may have been resolved against the child instead. Trying both is trying two
    different hypotheses, not the same one twice.
    """
    parsed = _parse_bounds(bounds)
    if parsed is None:
        return None
    x1, y1, x2, y2 = parsed
    return (x1 + x2) // 2, (y1 + y2) // 2


def _obstructed_alternate(
    bounds: str, x: Any, y: Any
) -> Optional[Tuple[int, int]]:
    """
    A second point inside the same control, for when the first is obstructed.

    A tap that reports success and changes nothing is most often a tap that
    landed on something else: a snackbar, a scrim, a banner that was still
    animating in. Re-aiming inside the element's own bounds - never outside
    them - is the cheapest way to distinguish "the control is inert" from
    "something was on top of it".

    Returns None when there are no bounds to stay inside, because a blind
    offset from a bare coordinate could land on an unrelated control, and
    tapping an unrelated control is worse than not retrying.
    """
    parsed = _parse_bounds(bounds)
    if parsed is None:
        return None
    x1, y1, x2, y2 = parsed
    height = y2 - y1
    offset = max(1, int(height * OBSTRUCTED_TAP_OFFSET_FRACTION))

    try:
        base_x = int(x) if x is not None else (x1 + x2) // 2
        base_y = int(y) if y is not None else (y1 + y2) // 2
    except (TypeError, ValueError):
        base_x, base_y = (x1 + x2) // 2, (y1 + y2) // 2

    # Aim lower first - a banner or system bar obstructs from above far more
    # often than from below - and fall back to higher when there is no room.
    candidate_y = base_y + offset
    if candidate_y >= y2:
        candidate_y = base_y - offset
    if candidate_y <= y1 or candidate_y >= y2:
        return None
    if candidate_y == base_y:
        return None
    return max(x1 + 1, min(base_x, x2 - 1)), candidate_y
