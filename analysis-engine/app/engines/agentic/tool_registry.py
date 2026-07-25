"""
SUDARSHAN — Agentic Tool Registry
===================================
Centralized registry of every tool the Agentic Explorer is permitted to execute.

Architecture rules:
  - The planner is ONLY allowed to invoke tools listed in TOOL_REGISTRY.
  - If the LLM requests a tool not in this registry, the action is REJECTED.
  - Each tool definition is versioned and includes supported Android API levels.
  - Tool parameters are schema-validated before execution.

Tool Definition fields:
    name:               Unique tool identifier (used in LLM JSON output).
    description:        What the tool does (injected into the planner prompt).
    params:             Required and optional parameters with types.
    timeout_seconds:    Hard timeout enforced by ToolExecutor.
    retry_count:        How many times to retry on transient failure.
    failure_strategy:   "log_and_continue" | "abort_iteration" | "fallback_action"
    min_android_api:    Minimum Android API level this tool supports.
    return_type:        Structure of the ToolResult this tool produces.
    is_destructive:     If True, requires extra validation before execution.

Usage::

    from app.engines.agentic.tool_registry import TOOL_REGISTRY, ToolDef, ToolParam
    tool = TOOL_REGISTRY.get("tap")
    if tool:
        print(tool.description)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ─── Tool Parameter Descriptor ────────────────────────────────────────────────

@dataclass
class ToolParam:
    """Describes a single parameter for a tool."""
    name:        str
    type:        str            # "int" | "str" | "float" | "bool"
    required:    bool
    description: str
    min_val:     Optional[float] = None   # For numeric bounds validation
    max_val:     Optional[float] = None


# ─── Tool Definition ──────────────────────────────────────────────────────────

@dataclass
class ToolDef:
    """
    Complete metadata record for a single registered tool.
    """
    name:               str
    description:        str
    params:             List[ToolParam]
    timeout_seconds:    int
    retry_count:        int
    failure_strategy:   str         # "log_and_continue" | "abort_iteration"
    min_android_api:    int
    is_destructive:     bool        = False
    notes:              str         = ""

    def param_schema(self) -> Dict[str, Any]:
        """Return JSON-schema-like dict for validator use."""
        return {
            p.name: {
                "type": p.type,
                "required": p.required,
                "description": p.description,
                "min": p.min_val,
                "max": p.max_val,
            }
            for p in self.params
        }

    def required_params(self) -> List[str]:
        return [p.name for p in self.params if p.required]

    def to_prompt_description(self) -> str:
        """One-line description for injection into the planner prompt."""
        param_str = ", ".join(
            f"{p.name}: {p.type}{'?' if not p.required else ''}"
            for p in self.params
        )
        return f"{self.name}({param_str}) — {self.description}"


# ─── Screen Dimension Constants ───────────────────────────────────────────────
# Declarative DEFAULTS only — used for the per-parameter min/max metadata below
# and as documentation of a typical emulator.
#
# They are NOT the validation bounds: the planner validates coordinates against
# the real device via device_properties.get_screen_size(). Treating these as
# authoritative is what previously rejected the bottom 480px of a 1080x2400
# screen. Do not reintroduce that coupling.

DEFAULT_SCREEN_WIDTH:  int = 1080
DEFAULT_SCREEN_HEIGHT: int = 1920


# ─── Centralized Tool Registry ────────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, ToolDef] = {

    # ── Touch / Gesture ────────────────────────────────────────────────────────

    "tap": ToolDef(
        name="tap",
        description="Tap a specific pixel coordinate on the screen.",
        params=[
            ToolParam("x", "int", required=True,  description="X coordinate in pixels",
                      min_val=0, max_val=DEFAULT_SCREEN_WIDTH),
            ToolParam("y", "int", required=True,  description="Y coordinate in pixels",
                      min_val=0, max_val=DEFAULT_SCREEN_HEIGHT),
        ],
        timeout_seconds=5,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "click_text": ToolDef(
        name="click_text",
        description=(
            "Find a UI element by its visible text and tap it. "
            "Preferred over `tap` when a text label is known."
        ),
        params=[
            ToolParam("text", "str", required=True,
                      description="Exact or partial visible text of the element to click"),
        ],
        timeout_seconds=8,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
        notes="Resolved via UI XML node matching before fallback to tap.",
    ),

    "swipe": ToolDef(
        name="swipe",
        description="Swipe from one coordinate to another (scroll, dismiss, navigate).",
        params=[
            ToolParam("x1", "int", required=True,  description="Start X",
                      min_val=0, max_val=DEFAULT_SCREEN_WIDTH),
            ToolParam("y1", "int", required=True,  description="Start Y",
                      min_val=0, max_val=DEFAULT_SCREEN_HEIGHT),
            ToolParam("x2", "int", required=True,  description="End X",
                      min_val=0, max_val=DEFAULT_SCREEN_WIDTH),
            ToolParam("y2", "int", required=True,  description="End Y",
                      min_val=0, max_val=DEFAULT_SCREEN_HEIGHT),
            ToolParam("duration_ms", "int", required=False,
                      description="Swipe duration in ms (default 300)", min_val=50, max_val=3000),
        ],
        timeout_seconds=5,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "scroll": ToolDef(
        name="scroll",
        description="Scroll the screen up or down to reveal more content.",
        params=[
            ToolParam("direction", "str", required=True,
                      description="'up' or 'down'"),
            ToolParam("amount", "int", required=False,
                      description="Pixels to scroll (default 600)", min_val=100, max_val=2000),
        ],
        timeout_seconds=5,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "press_back": ToolDef(
        name="press_back",
        description="Press the Android Back button to return to the previous screen.",
        params=[],
        timeout_seconds=3,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "press_home": ToolDef(
        name="press_home",
        description=(
            "Press the Home button. Use this to background the app and check "
            "if the app continues running services (Background Services goal)."
        ),
        params=[],
        timeout_seconds=3,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    # ── Text Input ─────────────────────────────────────────────────────────────

    "type_text": ToolDef(
        name="type_text",
        description=(
            "Focus an input field and type text into it. "
            "The `field_hint` identifies the field (username, password, email, otp, etc.). "
            "The executor will look up the appropriate safe test value from FORM_VALUES."
        ),
        params=[
            ToolParam("field_hint", "str", required=True,
                      description=(
                          "Semantic hint for the field: one of "
                          "'username', 'email', 'password', 'phone', 'otp', "
                          "'amount', 'account', 'name', 'address', 'search'"
                      )),
            ToolParam("x", "int", required=True,
                      description="X coordinate of the input field",
                      min_val=0, max_val=DEFAULT_SCREEN_WIDTH),
            ToolParam("y", "int", required=True,
                      description="Y coordinate of the input field",
                      min_val=0, max_val=DEFAULT_SCREEN_HEIGHT),
        ],
        timeout_seconds=8,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
        notes=(
            "Actual values are resolved from FORM_VALUES dict. "
            "Values are never stored in memory or audit logs — only field_hint is recorded."
        ),
    ),

    # ── Permissions ────────────────────────────────────────────────────────────

    "grant_permission": ToolDef(
        name="grant_permission",
        description=(
            "Grant a specific Android permission to the target package via ADB. "
            "Use this to proactively grant permissions without navigating Settings UI."
        ),
        params=[
            ToolParam("permission", "str", required=True,
                      description=(
                          "Full permission name, e.g. 'android.permission.READ_SMS' "
                          "or shorthand: 'accessibility', 'overlay', 'device_admin'"
                      )),
        ],
        timeout_seconds=10,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=23,
    ),

    "deny_permission": ToolDef(
        name="deny_permission",
        description=(
            "Deny a runtime permission dialog. Tap 'Deny' or 'Don't allow'. "
            "Use when testing app behaviour after permission denial."
        ),
        params=[],
        timeout_seconds=5,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=23,
    ),

    # ── UI Introspection ───────────────────────────────────────────────────────

    "dump_ui": ToolDef(
        name="dump_ui",
        description="Dump the current UI hierarchy XML via uiautomator. Returns XML string.",
        params=[],
        timeout_seconds=10,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "take_screenshot": ToolDef(
        name="take_screenshot",
        description=(
            "Capture a screenshot of the current screen. "
            "ONLY use when UI XML is empty, contains a WebView, Canvas, or has no "
            "clickable elements. Prefer dump_ui for all other cases."
        ),
        params=[
            ToolParam("label", "str", required=False,
                      description="Label for the screenshot filename (alphanumeric only)"),
        ],
        timeout_seconds=10,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "capture_logcat": ToolDef(
        name="capture_logcat",
        description=(
            "Capture recent logcat output from the target package. "
            "Use to detect hidden errors, initialization events, or deferred activity."
        ),
        params=[
            ToolParam("lines", "int", required=False,
                      description="Number of recent log lines to capture (default 50)",
                      min_val=10, max_val=500),
        ],
        timeout_seconds=8,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    # ── App / Intent Control ───────────────────────────────────────────────────

    "start_activity": ToolDef(
        name="start_activity",
        description=(
            "Launch a specific Activity or deep link via ADB am start. "
            "Use for navigating to Settings screens (Accessibility, Overlay) "
            "or triggering exported activities found in static analysis."
        ),
        params=[
            ToolParam("action",    "str", required=False,
                      description="Intent action, e.g. android.settings.ACCESSIBILITY_SETTINGS"),
            ToolParam("component", "str", required=False,
                      description="Component in format 'package/activity', e.g. com.example/.MainActivity"),
            ToolParam("data_uri",  "str", required=False,
                      description="Data URI for deep links, e.g. myapp://home"),
        ],
        timeout_seconds=10,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
        notes="At least one of action, component, or data_uri must be provided.",
    ),

    "broadcast_intent": ToolDef(
        name="broadcast_intent",
        description=(
            "Send a broadcast intent via ADB am broadcast. "
            "Use to trigger exported BroadcastReceivers (BOOT_COMPLETED, "
            "SMS_RECEIVED, PACKAGE_REPLACED, etc.)."
        ),
        params=[
            ToolParam("action", "str", required=True,
                      description="Broadcast action string, e.g. android.intent.action.BOOT_COMPLETED"),
            ToolParam("component", "str", required=False,
                      description="Explicit receiver component if known"),
        ],
        timeout_seconds=10,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "list_packages": ToolDef(
        name="list_packages",
        description=(
            "List installed packages on the device via ADB pm list packages. "
            "Use to confirm banking apps are installed for the Banking Detection goal."
        ),
        params=[
            ToolParam("filter_str", "str", required=False,
                      description="Optional filter string to grep installed packages"),
        ],
        timeout_seconds=10,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "clear_app_data": ToolDef(
        name="clear_app_data",
        description=(
            "Clear application data and cache via ADB pm clear. "
            "Use to reset the app to a fresh state between analysis stages. "
            "WARNING: Destructive — only use if explicitly required."
        ),
        params=[
            ToolParam("package_name", "str", required=True,
                      description="Full package name to clear"),
        ],
        timeout_seconds=15,
        retry_count=1,
        failure_strategy="log_and_continue",
        min_android_api=21,
        is_destructive=True,
    ),

    # ── Network Control ────────────────────────────────────────────────────────

    "enable_wifi": ToolDef(
        name="enable_wifi",
        description="Enable WiFi on the device via ADB svc wifi enable.",
        params=[],
        timeout_seconds=8,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "disable_wifi": ToolDef(
        name="disable_wifi",
        description=(
            "Disable WiFi on the device via ADB svc wifi disable. "
            "Use to test app behaviour when network is unavailable "
            "(anti-analysis evasion detection)."
        ),
        params=[],
        timeout_seconds=8,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),

    "enable_mobile_data": ToolDef(
        name="enable_mobile_data",
        description="Enable mobile data on the device via ADB svc data enable.",
        params=[],
        timeout_seconds=8,
        retry_count=2,
        failure_strategy="log_and_continue",
        min_android_api=21,
    ),
}


# ─── Registry Access Helpers ──────────────────────────────────────────────────

def get_tool(tool_name: str) -> Optional[ToolDef]:
    """Return the ToolDef for `tool_name`, or None if not registered."""
    return TOOL_REGISTRY.get(tool_name)


def is_registered(tool_name: str) -> bool:
    """Return True if the tool name exists in the registry."""
    return tool_name in TOOL_REGISTRY


def all_tool_names() -> List[str]:
    """Return sorted list of all registered tool names."""
    return sorted(TOOL_REGISTRY.keys())


def prompt_tool_catalog() -> str:
    """
    Build a concise tool catalog string for injection into the planner prompt.
    Lists each tool with its parameters and description.
    """
    lines = ["=== AVAILABLE TOOLS ==="]
    for name, tool in sorted(TOOL_REGISTRY.items()):
        lines.append(f"  {tool.to_prompt_description()}")
    return "\n".join(lines)
