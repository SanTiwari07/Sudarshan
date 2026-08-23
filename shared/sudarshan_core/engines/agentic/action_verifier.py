"""
Did the action actually do what it was supposed to do?

`ToolResult.success` answers a narrower question than it appears to: it means
the ADB command exited zero. A `click_text` that matched nothing, a `pm grant`
for a permission the manifest never declared, a relaunch of an activity that
immediately died - all of them return success. And the agent is never asked; the
planner proposes an action and the loop moves on.

Two concrete defects this exists to catch, both found by reading the code:

* `ToolExecutor._tool_grant_permission("accessibility")` returns
  ``success=True`` unconditionally - including when `_grant_accessibility`
  returned the string ``"SKIPPED: no accessibility_service_class set"`` and
  issued no command at all.
* `PermissionOrchestrator.grant_accessibility` hardcodes ``success = True``
  before returning.

The fix is not to trust a return value harder. It is to compare device state
before and after, and to let the device answer.


DESIGN
------
The decision is a pure function of two snapshots and the action. All device I/O
lives in `DeviceStateProbe` and is injected, so every verification rule is
unit-testable with no emulator - which is the difference between this logic
being verified and being hoped about.

INCONCLUSIVE is a first-class outcome and is not FAILED. If the probe could not
read the state, we do not know whether the action worked, and reporting failure
would be as wrong as reporting success. This is the same discipline the risk
engine applies to an axis it cannot run: an unreadable result is excluded, not
scored as zero.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)


class VerificationOutcome(str, Enum):
    """The verdict on one executed action."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    #: The state needed to judge could not be read. Never treat as failure.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: No rule models this action, so nothing was checked.
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class StateSnapshot:
    """
    Device state at one instant, as far as we could read it.

    Every field is optional in the sense that "" / empty means "not read". A
    verification rule must distinguish that from a genuine empty value, which
    is why `granted_permissions` and friends carry a companion `*_read` flag
    rather than relying on emptiness.
    """

    foreground_package: str = ""
    activity: str = ""
    screen_hash: str = ""
    granted_permissions: FrozenSet[str] = frozenset()
    permissions_read: bool = False
    accessibility_components: FrozenSet[str] = frozenset()
    accessibility_read: bool = False
    accessibility_enabled: bool = False
    appops: Dict[str, str] = field(default_factory=dict)
    process_alive: Optional[bool] = None

    def has_permission(self, permission: str) -> bool:
        return permission in self.granted_permissions


@dataclass
class VerificationResult:
    """What was expected, what was observed, and whether they agree."""

    action: str
    # Defaults to INCONCLUSIVE, not SUCCESS. Every rule builds the result before
    # it has decided, and a rule that returns early without setting an outcome
    # must not thereby report that the action worked.
    outcome: str = VerificationOutcome.INCONCLUSIVE.value
    expected: str = ""
    observed: str = ""
    detail: str = ""
    target: str = ""

    @property
    def succeeded(self) -> bool:
        return self.outcome == VerificationOutcome.SUCCESS.value

    @property
    def failed(self) -> bool:
        """
        Only a positive FAILED counts. INCONCLUSIVE and UNVERIFIED must not be
        routed into failure handling - doing so would make an unreadable device
        look like a misbehaving one.
        """
        return self.outcome == VerificationOutcome.FAILED.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
            "expected": self.expected,
            "observed": self.observed,
            "detail": self.detail,
        }

    def log_line(self) -> str:
        """The [Verifier] block from the observability spec."""
        return (
            f"[Verifier] action={self.action}"
            f"{f'({self.target})' if self.target else ''} "
            f"expected={self.expected or '-'} observed={self.observed or '-'} "
            f"result={self.outcome}"
        )


# ─── Device output parsers ────────────────────────────────────────────────────
#
# Formats captured from a live Android 17 / API 37 emulator rather than assumed.

#: `dumpsys package <pkg>` prints, under "runtime permissions:" and
#: "install permissions:":
#:     android.permission.CAMERA: granted=false, flags=[ ... ]
#:     android.permission.USE_CREDENTIALS: granted=true
_PERMISSION_LINE = re.compile(
    r"^\s*(?P<perm>[A-Za-z0-9_.]+\.[A-Za-z0-9_]+):\s*granted=(?P<granted>true|false)",
    re.MULTILINE,
)


def parse_granted_permissions(dumpsys_output: str) -> FrozenSet[str]:
    """
    Permissions reported as granted by `dumpsys package <pkg>`.

    Both the runtime and install permission blocks are read: a permission
    granted at install time is just as granted, and only checking the runtime
    block would report INTERNET as missing on every app that has it.
    """
    if not dumpsys_output:
        return frozenset()
    return frozenset(
        match.group("perm")
        for match in _PERMISSION_LINE.finditer(dumpsys_output)
        if match.group("granted") == "true"
    )


def parse_accessibility_components(settings_output: str) -> FrozenSet[str]:
    """
    Components from `settings get secure enabled_accessibility_services`.

    Android returns the literal string "null" when unset - not an empty line -
    and separates multiple components with ":". Treating "null" as a component
    name would make every verification pass.
    """
    value = (settings_output or "").strip()
    if not value or value.lower() == "null":
        return frozenset()
    return frozenset(part.strip() for part in value.split(":") if part.strip())


def parse_appop(appops_output: str) -> str:
    """
    The mode from `appops get <pkg> <OP>`, e.g. "allow", "deny", "default".

    Real output: ``SYSTEM_ALERT_WINDOW: default; rejectTime=+8h9m39s350ms ago``
    """
    text = (appops_output or "").strip()
    if not text or ":" not in text:
        return ""
    mode = text.split(":", 1)[1].strip()
    return mode.split(";", 1)[0].strip().lower()


def accessibility_enabled_for(
    components: FrozenSet[str], package_name: str
) -> bool:
    """Whether any enabled accessibility component belongs to this package."""
    if not package_name:
        return False
    return any(c.split("/", 1)[0] == package_name for c in components)


# ─── Verification rules ───────────────────────────────────────────────────────

#: Actions whose effect is "the screen changed". Grouped because the rule is
#: identical and only the expectation text differs.
_SCREEN_CHANGING = frozenset({
    "tap", "click_text", "swipe", "scroll", "long_press",
    "press_back", "press_home", "press_enter", "type_text",
})


def _verify_permission_grant(
    action: Dict[str, Any], before: StateSnapshot, after: StateSnapshot
) -> VerificationResult:
    permission = str(action.get("permission") or action.get("target") or "")
    result = VerificationResult(
        action="grant_permission", target=permission, expected="GRANTED"
    )

    # Special permissions are not in the package permission table; they are
    # verified through their own subsystem.
    if permission == "accessibility":
        if not after.accessibility_read:
            result.outcome = VerificationOutcome.INCONCLUSIVE.value
            result.detail = "accessibility settings could not be read"
            return result
        result.observed = "ENABLED" if after.accessibility_enabled else "NOT_ENABLED"
        result.outcome = (
            VerificationOutcome.SUCCESS.value
            if after.accessibility_enabled
            else VerificationOutcome.FAILED.value
        )
        if not after.accessibility_enabled:
            result.detail = (
                "no accessibility component for this package is enabled - the "
                "grant reported success without taking effect"
            )
        return result

    if permission == "overlay":
        mode = after.appops.get("SYSTEM_ALERT_WINDOW", "")
        if not mode:
            result.outcome = VerificationOutcome.INCONCLUSIVE.value
            result.detail = "appops state could not be read"
            return result
        result.observed = mode.upper()
        result.outcome = (
            VerificationOutcome.SUCCESS.value
            if mode == "allow"
            else VerificationOutcome.FAILED.value
        )
        return result

    if not after.permissions_read:
        result.outcome = VerificationOutcome.INCONCLUSIVE.value
        result.detail = "package permission state could not be read"
        return result

    granted = after.has_permission(permission)
    result.observed = "GRANTED" if granted else "NOT_GRANTED"
    result.outcome = (
        VerificationOutcome.SUCCESS.value if granted
        else VerificationOutcome.FAILED.value
    )
    if not granted:
        result.detail = (
            f"{permission} is still not held after the grant - it is most "
            "likely not declared in the manifest, so Android refused it"
        )
    return result


def _verify_permission_denial(
    action: Dict[str, Any], before: StateSnapshot, after: StateSnapshot
) -> VerificationResult:
    permission = str(action.get("permission") or action.get("target") or "")
    result = VerificationResult(
        action="deny_permission", target=permission, expected="NOT_GRANTED"
    )
    if not after.permissions_read:
        result.outcome = VerificationOutcome.INCONCLUSIVE.value
        result.detail = "package permission state could not be read"
        return result
    granted = after.has_permission(permission)
    result.observed = "GRANTED" if granted else "NOT_GRANTED"
    result.outcome = (
        VerificationOutcome.FAILED.value if granted
        else VerificationOutcome.SUCCESS.value
    )
    return result


def _verify_launch(
    action: Dict[str, Any], before: StateSnapshot, after: StateSnapshot,
    package_name: str,
) -> VerificationResult:
    component = str(action.get("component") or action.get("target") or "")
    expected_package = component.split("/", 1)[0] if "/" in component else package_name
    result = VerificationResult(
        action="start_activity", target=component,
        expected=f"foreground={expected_package or '?'}",
    )
    if not after.foreground_package:
        result.outcome = VerificationOutcome.INCONCLUSIVE.value
        result.detail = "foreground activity could not be read"
        return result
    result.observed = f"foreground={after.foreground_package}"
    if not expected_package:
        result.outcome = VerificationOutcome.UNVERIFIED.value
        result.detail = "no target package to compare against"
        return result
    result.outcome = (
        VerificationOutcome.SUCCESS.value
        if after.foreground_package == expected_package
        else VerificationOutcome.FAILED.value
    )
    if result.failed:
        result.detail = (
            f"relaunch did not bring {expected_package} to the foreground"
        )
    return result


def _verify_screen_change(
    action: Dict[str, Any], before: StateSnapshot, after: StateSnapshot
) -> VerificationResult:
    tool = str(action.get("tool") or "")
    target = str(action.get("text") or action.get("target") or "")
    result = VerificationResult(
        action=tool, target=target, expected="screen_changed"
    )

    if not before.screen_hash or not after.screen_hash:
        result.outcome = VerificationOutcome.INCONCLUSIVE.value
        result.detail = "screen state could not be read on both sides"
        return result

    changed = after.screen_hash != before.screen_hash
    activity_changed = bool(after.activity) and after.activity != before.activity
    result.observed = "screen_changed" if changed else "screen_unchanged"

    if changed or activity_changed:
        result.outcome = VerificationOutcome.SUCCESS.value
        return result

    # An unchanged screen is genuinely ambiguous, not a clear failure: typing
    # into a field, toggling a checkbox and dismissing a transient toast can all
    # leave the hash identical. Reporting FAILED here would poison the loop's
    # failure counters with actions that worked.
    result.outcome = VerificationOutcome.INCONCLUSIVE.value
    result.detail = (
        "screen is unchanged; the action may have had no visible effect or no "
        "effect at all"
    )
    return result


def verify_action(
    action: Dict[str, Any],
    before: StateSnapshot,
    after: StateSnapshot,
    package_name: str = "",
) -> VerificationResult:
    """
    Compare device state before and after an action against what it claimed.

    Pure: no device access, no clock, no randomness. Everything it knows comes
    from the two snapshots.
    """
    tool = str(action.get("tool") or "")

    if tool == "grant_permission":
        return _verify_permission_grant(action, before, after)
    if tool == "deny_permission":
        return _verify_permission_denial(action, before, after)
    if tool == "start_activity":
        return _verify_launch(action, before, after, package_name)
    if tool in _SCREEN_CHANGING:
        return _verify_screen_change(action, before, after)

    # Reads and device-config tools change nothing observable by design.
    return VerificationResult(
        action=tool or "unknown",
        outcome=VerificationOutcome.UNVERIFIED.value,
        detail="no verification rule models this action",
    )


# ─── Device probe ─────────────────────────────────────────────────────────────

class DeviceStateProbe:
    """
    Builds a :class:`StateSnapshot` by querying the device.

    The ADB callable is injected rather than constructed here, so this class
    carries no transport of its own and tests can drive it with canned output.
    Callers pass `ToolExecutor._adb`, which routes through the policy-enforcing
    SandboxProvider - the probe must never open its own channel to the device,
    or it would sidestep the sandbox controls the rest of the engine relies on.
    """

    def __init__(
        self,
        adb: Callable[..., Any],
        package_name: str = "",
    ) -> None:
        self._adb = adb
        self.package_name = package_name

    async def _run(self, *args: str) -> Tuple[bool, str]:
        try:
            ok, out = await self._adb(*args)
            return bool(ok), out or ""
        except Exception as exc:
            # A probe failure must degrade to "not read", never to an exception
            # that aborts the investigation loop.
            logger.debug("[Probe] %s failed: %s", " ".join(args), exc)
            return False, ""

    async def snapshot(self, screen_hash: str = "", activity: str = "") -> StateSnapshot:
        """Read the state needed to verify any modelled action."""
        from sudarshan_core.engines.agentic.perception import (
            package_of,
            parse_foreground_activity,
        )

        if not activity:
            ok, out = await self._run("shell", "dumpsys", "activity", "activities")
            activity = parse_foreground_activity(out) if ok else ""

        permissions: FrozenSet[str] = frozenset()
        permissions_read = False
        if self.package_name:
            ok, out = await self._run("shell", "dumpsys", "package", self.package_name)
            if ok and out:
                permissions = parse_granted_permissions(out)
                permissions_read = True

        ok, out = await self._run(
            "shell", "settings", "get", "secure", "enabled_accessibility_services"
        )
        components = parse_accessibility_components(out) if ok else frozenset()
        accessibility_read = bool(ok)

        appops: Dict[str, str] = {}
        if self.package_name:
            ok, out = await self._run(
                "shell", "appops", "get", self.package_name, "SYSTEM_ALERT_WINDOW"
            )
            if ok:
                mode = parse_appop(out)
                if mode:
                    appops["SYSTEM_ALERT_WINDOW"] = mode

        return StateSnapshot(
            foreground_package=package_of(activity),
            activity=activity,
            screen_hash=screen_hash,
            granted_permissions=permissions,
            permissions_read=permissions_read,
            accessibility_components=components,
            accessibility_read=accessibility_read,
            accessibility_enabled=accessibility_enabled_for(
                components, self.package_name
            ),
            appops=appops,
        )
