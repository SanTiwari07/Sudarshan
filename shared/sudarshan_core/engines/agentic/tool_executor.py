"""
SUDARSHAN - Agentic Tool Executor
===================================
Real ADB-backed implementations for every tool in the Tool Registry.

Architecture rules:
  - Every tool is implemented as an async method returning a ToolResult.
  - All implementations enforce the timeout and retry count from ToolDef.
  - Failure is always graceful: returns ToolResult(success=False, error=...).
  - No tool raises unhandled exceptions - exceptions are caught and returned.
  - Credential VALUES are looked up from FORM_VALUES but NEVER returned in
    ToolResult.data - only field_hint is echoed back.

FORM_VALUES contains safe, synthetic test credentials only.
These values are used for form filling during security analysis and
do not represent any real user data.

Usage::

    executor = ToolExecutor(device_serial="emulator-5554", adb_path="adb",
                            package_name="com.example.app")
    result = await executor.execute({"tool": "tap", "x": 540, "y": 960})
    print(result.success, result.output)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from sudarshan_core.engines.agentic.device_properties import get_screen_size
from sudarshan_core.engines.agentic.tool_registry import get_tool
from sudarshan_core.sandbox import get_sandbox_provider

logger = logging.getLogger(__name__)

# ─── Safe synthetic test credentials (analysis-only, not real user data) ─────
FORM_VALUES: Dict[str, str] = {
    "username": "demo_user",
    "email":    "demo@sudarshan-analysis.test",
    "password": "Analysis@Secure99",
    "phone":    "9000000001",
    "otp":      "123456",
    "amount":   "100",
    "account":  "000000000000",
    "name":     "Analysis Bot",
    "address":  "1 Security Lab, Cyber District",
    "search":   "search_query",
}

# ─── Screen dimensions ────────────────────────────────────────────────────────
# Module-level defaults, kept for backwards compatibility with callers that
# import SCREEN_WIDTH/SCREEN_HEIGHT directly. The AUTHORITATIVE values come from
# device_properties.get_screen_size() at run time, via ToolExecutor.screen_size
# - the same provider the planner's coordinate validator uses, so the two can
# never disagree again.
SCREEN_WIDTH:  int = int(os.getenv("SUDARSHAN_SCREEN_WIDTH",  "1080"))
SCREEN_HEIGHT: int = int(os.getenv("SUDARSHAN_SCREEN_HEIGHT", "1920"))

# ─── Default scroll amounts ───────────────────────────────────────────────────
#: Upper bound on tap_sequence repeats, so a bad `repeat` cannot become an
#: unbounded input storm. Longest realistic PIN/MPIN is 8 digits.
MAX_TAP_SEQUENCE: int = 12

DEFAULT_SCROLL_AMOUNT: int = 600
DEFAULT_SWIPE_DURATION_MS: int = 300


# ─── Action pacing ────────────────────────────────────────────────────────────
#
# The agent used to drive the device as fast as ADB would accept input: each
# tool slept a fixed 0.4-1.0 s and the explorer loop went straight from ACT back
# to OBSERVE. With the deterministic FallbackPlanner there is no LLM round trip
# either, so taps landed back-to-back THROUGH activity transitions - tapping a
# view that was already being torn down, and running `uiautomator dump` while
# the window was still animating. On a slower emulator that reliably crashed or
# ANR'd the app under analysis, which then reads as "no behaviour observed"
# rather than as a harness fault.
#
# Two changes: every delay is now scaled by one env-tunable factor, and
# navigational actions wait for the window to actually settle instead of
# guessing a constant. Raise the scale on a slow or contended emulator:
#
#   SUDARSHAN_ACTION_DELAY_SCALE=2.0   docker compose up
#
ACTION_DELAY_SCALE: float = max(0.1, float(os.getenv("SUDARSHAN_ACTION_DELAY_SCALE", "1.0")))

# Floor applied after any input event, before we even begin polling for idle.
# Input dispatch is asynchronous: `input tap` returns as soon as the event is
# queued, not when the app has handled it.
POST_INPUT_SETTLE_SECONDS: float = float(os.getenv("SUDARSHAN_POST_INPUT_SETTLE", "0.6"))

# Upper bound on waiting for the window to stop changing. A cold Activity start
# on an emulator is routinely 2-4 s.
IDLE_WAIT_TIMEOUT_SECONDS: float = float(os.getenv("SUDARSHAN_IDLE_WAIT_TIMEOUT", "6.0"))

# How often to sample window focus while waiting.
IDLE_POLL_INTERVAL_SECONDS: float = 0.35

# Consecutive identical focus samples required to call the UI settled.
IDLE_STABLE_SAMPLES: int = 2


def _paced(seconds: float) -> float:
    """Apply the global pacing scale to a delay."""
    return seconds * ACTION_DELAY_SCALE


# Tools that can change what is on screen. Only these need an idle wait; making
# a screenshot or a logcat read pay for one would waste most of the time budget.
NAVIGATIONAL_TOOLS: frozenset = frozenset({
    "tap", "tap_sequence", "click_text", "swipe", "scroll", "long_press",
    "press_back", "press_home", "press_enter",
    # "am_start" used to be listed here, but no tool of that name exists in
    # TOOL_REGISTRY or on this class - the real one is "start_activity", which
    # was missing. The effect was that relaunching the app never waited for the
    # window to settle, so the next observation read a half-started Activity.
    "start_activity", "open_notifications", "grant_permission",
})


# ─── Result type ──────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """
    Structured result from a single tool execution.

    success:   True if the tool ran without error.
    tool:      Tool name that was executed.
    output:    Primary output string (ADB stdout, XML, logcat, etc.).
    data:      Optional structured data (parsed XML, screenshot path, etc.).
    error:     Error description if success=False.
    duration:  Wall-clock execution time in seconds.
    retries:   Number of retries that were needed.
    """
    success:  bool
    tool:     str
    output:   str                        = ""
    data:     Dict[str, Any]             = field(default_factory=dict)
    error:    Optional[str]              = None
    duration: float                      = 0.0
    retries:  int                        = 0
    adb_command: str = ""
    adb_return_code: Optional[int] = None

    def to_log_line(self) -> str:
        status = "✓" if self.success else "✗"
        err = f" ERROR={self.error[:60]}" if self.error else ""
        return f"[{status}] {self.tool} ({self.duration:.2f}s, retries={self.retries}){err}"


# ─── Tool Executor ────────────────────────────────────────────────────────────

class ToolExecutor:
    """
    Executes tools from the Tool Registry against a connected Android device.

    All ADB calls are async (asyncio.create_subprocess_exec).
    Each tool method enforces the ToolDef timeout and retry policy.
    """

    def __init__(
        self,
        device_serial: str,
        package_name: str,
        adb_path: str = "adb",
        accessibility_service_class: Optional[str] = None,
        screenshot_manager: Optional[Any] = None,
    ) -> None:
        self.device_serial              = device_serial
        self.package_name               = package_name
        self.adb_path                   = adb_path
        self.screenshot_manager         = screenshot_manager
        # Real accessibility service class name extracted from the APK manifest
        # (e.g. ".zWPzgfI" for Cerberus). None means unknown - do not guess.
        self.accessibility_service_class: Optional[str] = accessibility_service_class

    @property
    def screen_size(self) -> tuple[int, int]:
        """
        Authoritative (width, height) for this device.

        Shares the cached device-properties provider with the planner's
        coordinate validator, so an action the planner accepts is always one
        this executor can actually perform.
        """
        return get_screen_size(adb_path=self.adb_path, device_serial=self.device_serial)

    # ── Dispatch ───────────────────────────────────────────────────────────────

    async def execute(self, action: Dict[str, Any]) -> ToolResult:
        """
        Dispatch an action dict from the planner to the correct tool implementation.

        action must contain "tool" key. All other keys are parameters.
        Returns ToolResult - never raises.
        """
        tool_name = action.get("tool", "")
        # Alias resolution for fallback / LLM variations
        if tool_name == "click":
            tool_name = "click_text" if action.get("text") else "tap"
            action["tool"] = tool_name
        elif tool_name == "input_text":
            tool_name = "type_text"
            action["tool"] = tool_name
            if "field_hint" not in action:
                action["field_hint"] = action.get("text") or "text"

        tool_def  = get_tool(tool_name)

        if not tool_def:
            return ToolResult(
                success=False,
                tool=tool_name,
                error=f"Tool '{tool_name}' is not registered in TOOL_REGISTRY.",
            )

        handler_name = f"_tool_{tool_name.replace('-', '_')}"
        handler = getattr(self, handler_name, None)
        if not handler:
            return ToolResult(
                success=False,
                tool=tool_name,
                error=f"Tool '{tool_name}' has no implementation in ToolExecutor.",
            )

        start = time.monotonic()
        retries = 0
        last_result: Optional[ToolResult] = None

        for attempt in range(tool_def.retry_count + 1):
            if attempt > 0:
                retries += 1
                await asyncio.sleep(0.5 * attempt)   # exponential-ish backoff
                logger.debug(f"[ToolExecutor] Retry {attempt} for {tool_name}")

            try:
                result = await asyncio.wait_for(
                    handler(action),
                    timeout=tool_def.timeout_seconds,
                )
                result.duration = time.monotonic() - start
                result.retries  = retries
                if result.success:
                    return result
                last_result = result

            except asyncio.TimeoutError:
                last_result = ToolResult(
                    success=False,
                    tool=tool_name,
                    error=f"Timed out after {tool_def.timeout_seconds}s",
                    duration=time.monotonic() - start,
                    retries=retries,
                )
            except Exception as exc:
                last_result = ToolResult(
                    success=False,
                    tool=tool_name,
                    error=f"{type(exc).__name__}: {exc}",
                    duration=time.monotonic() - start,
                    retries=retries,
                )

        # All retries exhausted
        if last_result:
            logger.warning(f"[ToolExecutor] {tool_name} failed after {retries} retries: {last_result.error}")
            return last_result

        return ToolResult(success=False, tool=tool_name, error="Unknown failure")

    # ── ADB Helper ─────────────────────────────────────────────────────────────

    async def _adb(self, *args: str) -> tuple[bool, str]:
        """Run an ADB command asynchronously via SandboxProvider (policy-enforced)."""
        provider = get_sandbox_provider()
        loop = asyncio.get_event_loop()
        cmd = "adb " + " ".join(str(a) for a in ("-s", self.device_serial, *args))
        logger.info("[ToolExecutor] ADB_CMD %s", cmd)
        ok, out = await loop.run_in_executor(
            None,
            lambda: provider.adb("-s", self.device_serial, *args, timeout=30),
        )
        logger.info(
            "[ToolExecutor] ADB_RESULT ok=%s rc=%s out=%s",
            ok, 0 if ok else 1, (out or "")[:200],
        )
        return ok, out

    async def _input_tap(self, x: int, y: int) -> ToolResult:
        from sudarshan_core.engines.agentic.semantic_action import (
            validate_coordinates_for_screen,
        )
        sw, sh = self.screen_size
        ok_coord, reason = validate_coordinates_for_screen(
            x, y, screen_width=sw, screen_height=sh,
        )
        if not ok_coord:
            return ToolResult(
                success=False, tool="tap",
                error=f"coordinate_validation:{reason}",
                data={"coordinate_validation": "FAIL", "reason": reason, "x": x, "y": y},
            )
        logger.info("[ToolExecutor] ADB_TAP x=%s y=%s", x, y)
        ok, out = await self._adb("shell", "input", "tap", str(x), str(y))
        await asyncio.sleep(_paced(0.8))
        return ToolResult(
            success=ok, tool="tap", output=out,
            error=out if not ok else None,
            adb_command=f"input tap {x} {y}",
            adb_return_code=0 if ok else 1,
            data={
                "x": x, "y": y,
                "coordinate_validation": "PASS",
                "adb_command_generated": True,
                "adb_command_executed": True,
                "adb_return_code": 0 if ok else 1,
                "adb_stdout": out or "",
            },
        )

    async def _tool_tap(self, action: Dict) -> ToolResult:
        x, y = int(action["x"]), int(action["y"])
        result = await self._input_tap(x, y)
        result.tool = "tap"
        return result

    async def _tool_tap_sequence(self, action: Dict) -> ToolResult:
        """
        Tap one coordinate several times in a row, as one action.

        Exists for numeric PIN pads. A six-digit MPIN is one credential, not six
        explorations: entered a key per iteration it costs ~66s at the measured
        per-iteration cost, and any detour in between clears the field so the
        pad is never filled at all.

        Bounded by MAX_TAP_SEQUENCE so a malformed `repeat` cannot turn into an
        unbounded input storm against the device.
        """
        x, y = int(action["x"]), int(action["y"])
        repeat = max(1, min(int(action.get("repeat", 1)), MAX_TAP_SEQUENCE))
        ok = True
        for _ in range(repeat):
            res = await self._input_tap(x, y)
            ok = ok and res.success
            await asyncio.sleep(_paced(0.25))
        # The pad usually auto-submits on the last digit; give it a moment.
        await asyncio.sleep(_paced(0.8))
        return ToolResult(
            success=ok,
            tool="tap_sequence",
            data={"x": x, "y": y, "repeat": repeat},
            error=None if ok else "one or more taps failed",
        )

    # ── Device settling ────────────────────────────────────────────────────────

    async def _focus_signature(self) -> Optional[str]:
        """
        Cheap proxy for 'what is on screen right now'.

        mCurrentFocus / mFocusedApp change the moment a transition starts and
        stop changing once it completes, so comparing consecutive samples tells
        us whether the window is still moving. Returns None if the probe fails,
        which the caller treats as 'cannot tell' rather than 'settled'.
        """
        ok, out = await self._adb(
            "shell", "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'"
        )
        if not ok or not out:
            return None
        return " ".join(out.split())

    async def wait_for_idle(
        self,
        timeout: Optional[float] = None,
        stable_samples: int = IDLE_STABLE_SAMPLES,
    ) -> bool:
        """
        Block until the window stops changing, or `timeout` elapses.

        Returns True if the UI was observed to settle, False on timeout or if
        the device could not be probed after MAX_PROBE_FAILURES retries.
        NEVER raises and never waits forever - a settling wait that can hang
        would be worse than the crash it prevents.

        Probe-failure behaviour (changed from old: immediate False return):
          A single None from _focus_signature() is a transient ADB hiccup,
          NOT evidence that the UI has settled.  The old code returned False
          immediately, causing the next OBSERVE to run before the activity
          transition had finished.  Now we retry within the remaining budget
          and only give up after MAX_PROBE_FAILURES consecutive failures.
        """
        _MAX_PROBE_FAILURES = 3

        # Input dispatch is async - `input tap` returns when the event is queued.
        # Poll only after giving the app a chance to begin reacting, otherwise
        # the first two samples match trivially and we declare victory early.
        await asyncio.sleep(_paced(POST_INPUT_SETTLE_SECONDS))

        deadline = time.monotonic() + (
            timeout if timeout is not None else _paced(IDLE_WAIT_TIMEOUT_SECONDS)
        )
        last_sig: Optional[str] = None
        stable = 0
        probe_failures = 0

        while time.monotonic() < deadline:
            sig = await self._focus_signature()
            if sig is None:
                # Transient probe failure — increment counter and retry.
                # Do NOT declare idle: a failed probe is not a stable signal.
                probe_failures += 1
                if probe_failures >= _MAX_PROBE_FAILURES:
                    logger.debug(
                        "[ToolExecutor] wait_for_idle: %d consecutive probe "
                        "failures — giving up (probe_failed)",
                        probe_failures,
                    )
                    return False
                logger.debug(
                    "[ToolExecutor] wait_for_idle: probe failure %d/%d — retrying",
                    probe_failures, _MAX_PROBE_FAILURES,
                )
                await asyncio.sleep(_paced(IDLE_POLL_INTERVAL_SECONDS))
                continue

            # Successful probe — reset failure counter.
            probe_failures = 0

            if sig == last_sig:
                stable += 1
                if stable >= stable_samples:
                    return True
            else:
                stable = 0
                last_sig = sig

            await asyncio.sleep(IDLE_POLL_INTERVAL_SECONDS)

        logger.debug(
            "[ToolExecutor] wait_for_idle timed out after %.1fs - UI still changing",
            (timeout if timeout is not None else _paced(IDLE_WAIT_TIMEOUT_SECONDS)),
        )
        return False

    # ── Tool Implementations ───────────────────────────────────────────────────

    async def _get_ui_xml(self) -> str:
        """Helper to reliably fetch UI dump XML from device via tmp file."""
        await self._adb("shell", "uiautomator", "dump", "/data/local/tmp/ui_dump.xml")
        ok, xml = await self._adb("shell", "cat", "/data/local/tmp/ui_dump.xml")
        if ok and xml:
            m = re.search(r'(<\?xml.*)', xml, re.DOTALL)
            if m:
                return m.group(1)
        return ""

    async def _tool_click_text(self, action: Dict) -> ToolResult:
        """
        Click a UI element by visible text / content-desc / resource-id.
        First tries XML lookup for text/desc/resource_id matching.
        If XML lookup fails or XML is unavailable, falls back to (x, y) if present in action.
        """
        text = action.get("text", "").strip()
        x_param = action.get("x")
        y_param = action.get("y")

        # ── Geometry-first ────────────────────────────────────────────────────
        # When the caller vouches for the coordinates - the exploration graph
        # read them from the observation of the screen we are looking at right
        # now - there is nothing for an XML lookup to discover. Dumping the
        # hierarchy again cost a measured ~2.2s of a ~3.12s click_text, on every
        # click, to rediscover a button whose bounds were already in the action.
        #
        # The retry ladder clears `_geometry_trusted` on escalation, so an
        # element that moved between selection and dispatch still gets resolved
        # by text on the next attempt.
        if (
            action.get("_geometry_trusted")
            and x_param is not None
            and y_param is not None
        ):
            try:
                x, y = int(x_param), int(y_param)
            except (ValueError, TypeError):
                x = y = None
            if x is not None:
                result = await self._input_tap(x, y)
                result.tool = "click_text"
                result.data = {
                    **(result.data or {}),
                    "geometry_first": True,
                    "x": x, "y": y, "target_text": text,
                }
                return result

        xml = await self._get_ui_xml()
        if xml and text:
            escaped = re.escape(text)
            patterns = [
                rf'text="{escaped}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                rf'content-desc="{escaped}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                rf'resource-id="[^"]*{escaped}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                rf'(?:text|content-desc)="[^"]*{escaped}[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
            ]
            for pattern in patterns:
                m = re.search(pattern, xml, re.IGNORECASE)
                if m:
                    x = (int(m.group(1)) + int(m.group(3))) // 2
                    y = (int(m.group(2)) + int(m.group(4))) // 2
                    result = await self._input_tap(x, y)
                    result.tool = "click_text"
                    result.data = {
                        **(result.data or {}),
                        "matched_text": text, "x": x, "y": y,
                    }
                    return result

        # Fallback to (x, y) if coordinates were provided (geometry / parent recovery)
        if x_param is not None and y_param is not None:
            try:
                x, y = int(x_param), int(y_param)
                result = await self._input_tap(x, y)
                result.tool = "click_text"
                result.data = {
                    **(result.data or {}),
                    "fallback_coord_used": True,
                    "x": x, "y": y, "target_text": text,
                }
                return result
            except (ValueError, TypeError):
                pass

        return ToolResult(success=False, tool="click_text",
                          error=f"Text '{text}' not found in UI hierarchy and no valid coordinates provided")

    async def _tool_swipe(self, action: Dict) -> ToolResult:
        x1 = int(action.get("x1", 500))
        y1 = int(action.get("y1", 1500))
        x2 = int(action.get("x2", 500))
        y2 = int(action.get("y2", 500))
        dur = int(action.get("duration_ms", DEFAULT_SWIPE_DURATION_MS))
        ok, out = await self._adb(
            "shell", "input", "swipe",
            str(x1), str(y1), str(x2), str(y2), str(dur)
        )
        await asyncio.sleep(_paced(0.5))
        return ToolResult(success=ok, tool="swipe", output=out,
                          error=out if not ok else None)

    async def _tool_scroll(self, action: Dict) -> ToolResult:
        direction = action.get("direction", "down")
        amount    = int(action.get("amount", DEFAULT_SCROLL_AMOUNT))
        sw, sh = self.screen_size
        cx = sw // 2
        if direction == "down":
            y1, y2 = sh // 2 + amount // 2, sh // 2 - amount // 2
        else:
            y1, y2 = sh // 2 - amount // 2, sh // 2 + amount // 2
        ok, out = await self._adb(
            "shell", "input", "swipe",
            str(cx), str(y1), str(cx), str(y2), "300"
        )
        await asyncio.sleep(_paced(0.5))
        return ToolResult(success=ok, tool="scroll", output=out,
                          error=out if not ok else None)

    async def _tool_press_back(self, action: Dict) -> ToolResult:
        ok, out = await self._adb("shell", "input", "keyevent", "4")
        await asyncio.sleep(_paced(0.6))
        return ToolResult(success=ok, tool="press_back", output=out,
                          error=out if not ok else None)

    async def _tool_press_home(self, action: Dict) -> ToolResult:
        ok, out = await self._adb("shell", "input", "keyevent", "3")
        await asyncio.sleep(_paced(1.0))
        return ToolResult(success=ok, tool="press_home", output=out,
                          error=out if not ok else None)

    async def _tool_type_text(self, action: Dict) -> ToolResult:
        """
        Type text into a focused input field.
        Looks up the actual value from FORM_VALUES using field_hint.
        The value is used for ADB input but is NOT stored in ToolResult.data.
        Only field_hint is echoed back - never the actual text value.
        """
        sw, sh = self.screen_size
        x = int(action.get("x", sw // 2))
        y = int(action.get("y", sh // 2))
        field_hint = action.get("field_hint", "search")

        # Resolve actual value (not stored in result).
        #
        # The per-run vault leads: its values are regenerated for every run and
        # every fresh login attempt, so a sample never sees the same identity
        # twice and a retry presents genuinely new credentials. FORM_VALUES
        # remains the fallback for callers that pass a legacy hint, and the
        # final "test" catches an unrecognised one.
        from sudarshan_core.engines.agentic.credentials import get_vault

        vault = get_vault(self.package_name)
        actual_value = vault.values.get(field_hint) or FORM_VALUES.get(
            field_hint, "test"
        )
        safe_text    = actual_value.replace(" ", "%s")

        # Tap the field first to focus it
        await self._adb("shell", "input", "tap", str(x), str(y))
        await asyncio.sleep(_paced(0.4))
        # Clear existing content
        await self._adb("shell", "input", "keyevent", "KEYCODE_CTRL_A")
        await asyncio.sleep(_paced(0.2))
        ok, out = await self._adb("shell", "input", "text", shlex.quote(safe_text))
        await asyncio.sleep(_paced(0.6))

        return ToolResult(
            success=ok,
            tool="type_text",
            output=out,
            # field_hint stored, actual value is NOT
            data={"field_hint": field_hint},
            error=out if not ok else None,
        )

    async def _tool_grant_permission(self, action: Dict) -> ToolResult:
        permission = action.get("permission", "")
        output_lines = []

        # Handle shorthand aliases
        if permission == "accessibility":
            out = await self._grant_accessibility()
            return ToolResult(success=True, tool="grant_permission",
                              output=out, data={"permission": "accessibility"})

        elif permission == "overlay":
            ok, out = await self._adb(
                "shell", "appops", "set", self.package_name,
                "SYSTEM_ALERT_WINDOW", "allow"
            )
            return ToolResult(success=ok, tool="grant_permission",
                              output=out, data={"permission": "overlay"},
                              error=out if not ok else None)

        elif permission == "device_admin":
            # Best-effort: attempt dpm set-active-admin
            ok, out = await self._adb(
                "shell", "dpm", "set-active-admin",
                f"{self.package_name}/.DeviceAdminReceiver"
            )
            return ToolResult(success=ok, tool="grant_permission",
                              output=out, data={"permission": "device_admin"},
                              error=out if not ok else None)

        else:
            # Standard android.permission.* grant
            ok, out = await self._adb(
                "shell", "pm", "grant", self.package_name, permission
            )
            return ToolResult(
                success=ok, tool="grant_permission",
                output=out, data={"permission": permission},
                error=out if not ok else None
            )

    async def _grant_accessibility(self) -> str:
        """
        Grant accessibility service via settings secure.

        Uses the manifest-parsed service class stored in
        ``self.accessibility_service_class`` (set by the caller from
        :func:`permission_orchestrator.extract_accessibility_service_class`).
        If no class is known we log a warning and skip the command rather than
        writing a fabricated component name that Android will silently ignore.
        """
        svc_class = self.accessibility_service_class
        if svc_class is None:
            logger.warning(
                "[ToolExecutor] accessibility_service_class is not set - "
                "cannot grant accessibility without a manifest-parsed class name. "
                "This sample may not declare an accessibility service."
            )
            return "SKIPPED: no accessibility_service_class set"

        # Build the fully-qualified component name
        if svc_class.startswith("."):
            component = f"{self.package_name}{svc_class}"
        else:
            component = svc_class

        logger.info(
            f"[ToolExecutor] Granting accessibility for component: {component}"
        )
        _, out1 = await self._adb(
            "shell", "settings", "put", "secure",
            "enabled_accessibility_services",
            component,
        )
        _, out2 = await self._adb(
            "shell", "settings", "put", "secure",
            "accessibility_enabled", "1"
        )
        return f"{out1}\n{out2}".strip()

    async def _tool_deny_permission(self, action: Dict) -> ToolResult:
        # Tap 'Deny' button - look for it in UI XML
        xml = await self._get_ui_xml()
        if xml:
            for keyword in ["Deny", "Don't allow", "DENY", "Cancel"]:
                escaped = re.escape(keyword)
                pattern = rf'(?:text|content-desc)="{escaped}"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
                m = re.search(pattern, xml, re.IGNORECASE)
                if m:
                    x = (int(m.group(1)) + int(m.group(3))) // 2
                    y = (int(m.group(2)) + int(m.group(4))) // 2
                    tap_ok, tap_out = await self._adb("shell", "input", "tap", str(x), str(y))
                    await asyncio.sleep(_paced(0.6))
                    return ToolResult(success=tap_ok, tool="deny_permission", output=tap_out)
        return ToolResult(success=False, tool="deny_permission",
                          error="No deny button found in UI")

    async def _tool_dump_ui(self, action: Dict) -> ToolResult:
        xml_content = await self._get_ui_xml()
        if xml_content:
            return ToolResult(success=True, tool="dump_ui",
                              output=xml_content, data={"xml": xml_content})
        return ToolResult(success=False, tool="dump_ui",
                          error="UI dump produced no XML content")

    async def _tool_take_screenshot(self, action: Dict) -> ToolResult:
        label = re.sub(r'[^a-zA-Z0-9_]', '', action.get("label", "agent"))[:32]
        if self.screenshot_manager is not None:
            ref = self.screenshot_manager.capture(
                label=label,
                category="ui",
                source="explorer",
                reason="EXPLORER_ACTION",
                explorer_action=label,
            )
            if ref:
                local = str(
                    self.screenshot_manager.output_dir / Path(ref).name
                )
                return ToolResult(
                    success=True, tool="take_screenshot",
                    output=local, data={"local_path": local, "label": label},
                )
            return ToolResult(
                success=False, tool="take_screenshot",
                error="ScreenshotManager capture failed",
            )

        ts    = int(time.time() * 1000)
        remote = f"/data/local/tmp/agent_{label}_{ts}.png"
        local  = f"/tmp/agent_{label}_{ts}.png"

        await self._adb("shell", "screencap", "-p", remote)
        ok, out = await self._adb("pull", remote, local)
        await self._adb("shell", "rm", remote)

        import os
        if ok and os.path.exists(local):
            return ToolResult(success=True, tool="take_screenshot",
                              output=local, data={"local_path": local, "label": label})
        return ToolResult(success=False, tool="take_screenshot",
                          error=f"Screenshot pull failed: {out}")

    async def _tool_capture_logcat(self, action: Dict) -> ToolResult:
        lines = int(action.get("lines", 50))
        ok, out = await self._adb(
            "shell", "logcat", "-d",
            f"--pid=$(pidof {self.package_name} 2>/dev/null)",
            f"-t", str(lines)
        )
        if not out.strip():
            # Fallback: general logcat tail
            ok, out = await self._adb("shell", "logcat", "-d", "-t", str(lines))
        return ToolResult(success=ok, tool="capture_logcat", output=out,
                          error=out if not ok else None)

    async def _tool_start_activity(self, action: Dict) -> ToolResult:
        cmd_parts = ["shell", "am", "start"]
        action_str    = action.get("action", "")
        component     = action.get("component", "")
        data_uri      = action.get("data_uri", "")
        package       = action.get("package", "")

        if not (action_str or component or data_uri):
            # Launch by package alone. `am start` cannot do this - it needs a
            # component - so the launcher intent is fired through monkey, which
            # resolves the entry Activity itself.
            #
            # This is the route home from a system boundary: the exploration
            # graph knows which package it wants back in the foreground but not
            # which Activity, and pressing back out of an installer or a
            # Settings sub-screen is not guaranteed to reach the sample at all.
            if package:
                ok, out = await self._adb(
                    "shell", "monkey", "-p", shlex.quote(package),
                    "-c", "android.intent.category.LAUNCHER", "1",
                )
                await asyncio.sleep(_paced(1.5))
                # monkey exits 0 and prints its error, so the text decides.
                launched = ok and "No activities found" not in (out or "")
                return ToolResult(
                    success=launched, tool="start_activity", output=out,
                    error=None if launched else (out or "monkey launch failed"),
                    data={"launched_package": package, "via": "monkey"},
                )
            return ToolResult(success=False, tool="start_activity",
                              error="At least one of action, component, data_uri, "
                                    "or package required")

        if action_str:
            cmd_parts += ["-a", shlex.quote(action_str)]
        if component:
            cmd_parts += ["-n", shlex.quote(component)]
        if data_uri:
            cmd_parts += ["-d", shlex.quote(data_uri)]

        ok, out = await self._adb(*cmd_parts)
        await asyncio.sleep(_paced(1.5))
        return ToolResult(success=ok, tool="start_activity", output=out,
                          error=out if not ok else None)

    async def _tool_broadcast_intent(self, action: Dict) -> ToolResult:
        intent_action = action.get("action", "")
        component     = action.get("component", "")

        cmd_parts = ["shell", "am", "broadcast", "-a", shlex.quote(intent_action)]
        if component:
            cmd_parts += ["-n", shlex.quote(component)]

        ok, out = await self._adb(*cmd_parts)
        await asyncio.sleep(_paced(0.8))
        return ToolResult(success=ok, tool="broadcast_intent", output=out,
                          error=out if not ok else None)

    async def _tool_list_packages(self, action: Dict) -> ToolResult:
        filter_str = action.get("filter_str", "")
        ok, out = await self._adb("shell", "pm", "list", "packages")
        packages = [
            line.replace("package:", "").strip()
            for line in out.splitlines()
            if line.startswith("package:")
        ]
        if filter_str:
            packages = [p for p in packages if filter_str.lower() in p.lower()]
        return ToolResult(
            success=ok, tool="list_packages",
            output="\n".join(packages),
            data={"packages": packages, "count": len(packages)},
        )

    async def _tool_clear_app_data(self, action: Dict) -> ToolResult:
        pkg = action.get("package_name", self.package_name)
        ok, out = await self._adb("shell", "pm", "clear", pkg)
        await asyncio.sleep(_paced(1.0))
        return ToolResult(success=ok, tool="clear_app_data", output=out,
                          error=out if not ok else None)

    async def _tool_enable_wifi(self, action: Dict) -> ToolResult:
        ok, out = await self._adb("shell", "svc", "wifi", "enable")
        await asyncio.sleep(_paced(1.0))
        return ToolResult(success=ok, tool="enable_wifi", output=out,
                          error=out if not ok else None)

    async def _tool_disable_wifi(self, action: Dict) -> ToolResult:
        ok, out = await self._adb("shell", "svc", "wifi", "disable")
        await asyncio.sleep(_paced(1.0))
        return ToolResult(success=ok, tool="disable_wifi", output=out,
                          error=out if not ok else None)

    async def _tool_enable_mobile_data(self, action: Dict) -> ToolResult:
        ok, out = await self._adb("shell", "svc", "data", "enable")
        await asyncio.sleep(_paced(1.0))
        return ToolResult(success=ok, tool="enable_mobile_data", output=out,
                          error=out if not ok else None)

    # ── Investigation resilience ───────────────────────────────────────────────

    async def _tool_fast_forward_time(self, action: Dict) -> ToolResult:
        """
        Advance the device clock and release deferred work.

        The engine is synchronous and does several slow ADB round-trips
        (dumpsys jobscheduler alone can take seconds), so it runs in a worker
        thread rather than blocking the agent's event loop.
        """
        from sudarshan_core.engines.time_warp import TimeWarpEngine

        try:
            hours = float(action.get("hours", 24.0))
        except (TypeError, ValueError):
            hours = 24.0
        force_jobs = bool(action.get("force_jobs", True))

        engine = TimeWarpEngine(self.device_serial)
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: engine.fast_forward_time(
                hours, force_jobs, package_name=self.package_name
            ),
        )
        payload = result.to_dict()
        summary = (
            f"clock {result.observed_shift_hours:+.2f}h via {result.method or 'n/a'}, "
            f"{len(result.jobs_forced)} job(s) forced"
        )
        return ToolResult(
            success=result.ok,
            tool="fast_forward_time",
            output=f"{summary} | {payload}",
            error="; ".join(result.errors) if result.errors else None,
        )

    async def _tool_inject_test_sms(self, action: Dict) -> ToolResult:
        """
        Deliver a synthetic SMS so interception hooks have an event to catch.

        Two delivery paths, because neither works everywhere: `emu sms send`
        is the emulator console command and produces a genuine SMS_RECEIVED
        broadcast (what a receiver-based stealer actually waits for), while a
        direct provider insert only populates the inbox. The broadcast path is
        tried first for that reason.
        """
        sender = str(action.get("sender") or "AD-BANKSM")
        body = str(action.get("body") or "OTP 481902 is valid for 10 minutes. Do not share it.")

        ok, out = await self._adb("emu", "sms", "send", sender, body)
        if ok and "KO" not in (out or ""):
            await asyncio.sleep(_paced(2.0))
            return ToolResult(
                success=True,
                tool="inject_test_sms",
                output=f"emu sms send -> {out or 'OK'}",
            )

        # Provider insert: no broadcast, but a sample that polls the inbox or
        # reads it on demand will still see the message.
        from sudarshan_core.engines.device_state_simulator import sh_quote

        timestamp_ms = int(time.time() * 1000)
        command = (
            f"content insert --uri content://sms/inbox "
            f"--bind address:s:{sh_quote(sender)} "
            f"--bind body:s:{sh_quote(body)} "
            f"--bind date:l:{timestamp_ms} "
            f"--bind read:i:0 --bind type:i:1"
        )
        ok2, out2 = await self._adb("shell", command)
        await asyncio.sleep(_paced(1.5))
        return ToolResult(
            success=ok2,
            tool="inject_test_sms",
            output=f"provider insert -> {out2}",
            error=None if ok2 else (out2 or "SMS injection refused by the device"),
        )
