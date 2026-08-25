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


@dataclass(frozen=True)
class FieldSnapshot:
    """
    What could be read back from an input node after typing into it.

    Every attribute is "as far as we could read it". `text_read` distinguishes
    "the field is empty" from "we could not read the field", which is the whole
    difference between a failed type and an unreadable one - and a masked
    password field is legitimately unreadable by design.
    """

    found: bool = False
    text: str = ""
    text_read: bool = False
    text_length: Optional[int] = None
    is_password: bool = False
    focused: Optional[bool] = None
    enabled: bool = True
    resource_id: str = ""
    node_id: str = ""
    content_desc: str = ""

    @property
    def populated(self) -> bool:
        """
        Whether this field now holds something.

        A masked field reports its length (or a run of bullets) without
        revealing content; either is proof of population.
        """
        if self.text_length is not None:
            return self.text_length > 0
        return bool(self.text.strip())


def verify_field_population(
    action: Dict[str, Any],
    field_after: Optional[FieldSnapshot],
    *,
    expected_length: Optional[int] = None,
    before: Optional[FieldSnapshot] = None,
) -> VerificationResult:
    """
    Verify that typed text actually reached the field it was aimed at.

    The existing screen-change rule cannot do this. Typing rarely changes the
    screen hash, so ``_verify_screen_change`` returns INCONCLUSIVE for every
    type_text, and a tap that missed the field by twenty pixels - or landed on
    a field that silently rejected the input - was indistinguishable from a
    successful one. The walk then pressed Login on an empty form and read the
    resulting error as "credentials refused".

    The value is NEVER compared and never logged. For a masked field there is
    nothing to compare anyway, so the same safe signals are used for every
    field and the password case needs no separate, weaker path:

      · the node exists and is the one we aimed at (resource-id / node-id)
      · it reports content - a length, or non-empty text
      · that length is consistent with what we typed, when both are known
      · it is enabled, and focused where focus is reported

    A field that cannot be read is INCONCLUSIVE, never FAILED: an unreadable
    device must not look like a misbehaving one.
    """
    target = str(action.get("field_hint") or action.get("target") or "")
    result = VerificationResult(
        action="type_text", target=target, expected="field_populated",
    )

    if field_after is None or not field_after.found:
        result.outcome = VerificationOutcome.INCONCLUSIVE.value
        result.observed = "field_not_found"
        result.detail = (
            "the target input node could not be re-read after typing; the "
            "field may have scrolled away or the screen may have moved on"
        )
        return result

    # Identity: verify we are looking at the field we aimed at, not a
    # same-shaped one next to it.
    intended_id = str(action.get("resource_id") or "")
    intended_node = str(action.get("node_id") or "")
    if intended_id and field_after.resource_id and intended_id != field_after.resource_id:
        result.outcome = VerificationOutcome.FAILED.value
        result.observed = "wrong_field"
        result.detail = (
            f"typed into resource_id={field_after.resource_id!r} but the action "
            f"targeted {intended_id!r}"
        )
        return result
    if intended_node and field_after.node_id and intended_node != field_after.node_id:
        result.outcome = VerificationOutcome.FAILED.value
        result.observed = "wrong_field"
        result.detail = (
            f"typed into node {field_after.node_id} but the action targeted "
            f"{intended_node}"
        )
        return result

    if not field_after.enabled:
        result.outcome = VerificationOutcome.FAILED.value
        result.observed = "field_disabled"
        result.detail = "the target field is disabled and cannot accept input"
        return result

    if not field_after.populated:
        # A masked field reporting no content is genuinely ambiguous. Most
        # Android builds render a filled password box as a run of bullets, but
        # some expose nothing at all - so "empty" and "hidden" look identical.
        # Calling that FAILED would make every password field on such a device
        # look like a missed tap and send the walk into a retry it cannot win,
        # which is the failure mode this verification exists to prevent.
        #
        # Focus is the one safe signal that still separates them: `input text`
        # goes to the focused node, so a field we typed into that is NOT
        # focused did not receive it, whatever its content reads as.
        if field_after.is_password:
            if field_after.focused is False:
                result.outcome = VerificationOutcome.FAILED.value
                result.observed = "field_empty_and_unfocused"
                result.detail = (
                    "password field holds no content and does not have focus; "
                    "the typed value did not reach it"
                )
                return result
            result.outcome = VerificationOutcome.INCONCLUSIVE.value
            result.observed = "masked_field_unreadable"
            result.detail = (
                "password field exposes neither text nor length; population "
                "could not be confirmed from accessibility state"
            )
            return result
        result.outcome = VerificationOutcome.FAILED.value
        result.observed = "field_empty"
        result.detail = "the field is still empty after typing"
        return result

    # Populated. Where both lengths are known, they should agree - a field with
    # a maxlength shorter than the value silently truncates, and a walk that
    # does not notice submits a half-entered secret.
    observed_len = (
        field_after.text_length
        if field_after.text_length is not None
        else len(field_after.text)
    )
    result.observed = f"field_populated(len={observed_len})"

    if expected_length is not None and observed_len != expected_length:
        # `before` non-empty means we appended to existing content rather than
        # replacing it, which explains a longer field without it being a fault.
        pre_len = 0
        if before is not None and before.populated:
            pre_len = (
                before.text_length
                if before.text_length is not None
                else len(before.text)
            )
        if observed_len != expected_length + pre_len:
            result.outcome = VerificationOutcome.FAILED.value
            result.detail = (
                f"field holds {observed_len} characters but {expected_length} "
                f"were typed; the field likely truncated or rejected the value"
            )
            return result

    if field_after.focused is False:
        # Populated but focus moved on - an IME auto-advance, or a form that
        # submitted itself. The text landed, which is what was being verified.
        result.detail = "field populated; focus has since moved elsewhere"

    result.outcome = VerificationOutcome.SUCCESS.value
    return result


def verify_action(
    action: Dict[str, Any],
    before: StateSnapshot,
    after: StateSnapshot,
    package_name: str = "",
    field_after: Optional[FieldSnapshot] = None,
    expected_length: Optional[int] = None,
) -> VerificationResult:
    """
    Compare device state before and after an action against what it claimed.

    Pure: no device access, no clock, no randomness. Everything it knows comes
    from the two snapshots.

    `field_after` is the re-read of the input node for a type_text, supplied by
    the caller because reading it requires a device. When it is absent,
    type_text falls back to the previous screen-change behaviour, so an
    existing caller that does not pass it is unaffected.
    """
    tool = str(action.get("tool") or "")

    if tool == "grant_permission":
        return _verify_permission_grant(action, before, after)
    if tool == "deny_permission":
        return _verify_permission_denial(action, before, after)
    if tool == "start_activity":
        return _verify_launch(action, before, after, package_name)
    if tool == "type_text" and field_after is not None:
        return verify_field_population(
            action, field_after, expected_length=expected_length,
        )
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

    async def field_snapshot(
        self,
        *,
        resource_id: str = "",
        node_id: str = "",
        center_x: Optional[int] = None,
        center_y: Optional[int] = None,
        ui_xml: str = "",
    ) -> FieldSnapshot:
        """
        Re-read one input node so a type_text can be verified.

        `ui_xml` is accepted so a caller that has just dumped the hierarchy for
        its own post-action observation can hand it over rather than making the
        device dump twice - a second `uiautomator dump` costs ~700ms per typed
        field and would roughly double the cost of filling a login form.

        Identification is by resource-id first, then by which input node
        contains the tapped point. Matching on coordinates is what makes this
        work on the WebView forms in the corpus, where no field has an id.

        Returns ``FieldSnapshot(found=False)`` when the node cannot be located.
        That is INCONCLUSIVE upstream, not a failure.
        """
        xml = ui_xml
        if not xml:
            ok, out = await self._run("shell", "uiautomator", "dump", "/dev/tty")
            xml = out if ok else ""
        if not xml:
            return FieldSnapshot(found=False)

        return parse_field_snapshot(
            xml,
            resource_id=resource_id,
            node_id=node_id,
            center_x=center_x,
            center_y=center_y,
        )


def parse_field_snapshot(
    ui_xml: str,
    *,
    resource_id: str = "",
    node_id: str = "",
    center_x: Optional[int] = None,
    center_y: Optional[int] = None,
) -> FieldSnapshot:
    """
    Pull one input node's post-typing state out of a uiautomator dump.

    Pure, so the matching rules are testable without a device.

    ``text`` is captured for length and emptiness only. The caller compares
    lengths; it never logs the value, and for a masked field the platform
    reports bullets rather than content in any case.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(ui_xml)
    except ET.ParseError:
        return FieldSnapshot(found=False)

    def _bounds(elem: Any) -> Optional[Tuple[int, int, int, int]]:
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", elem.attrib.get("bounds", ""))
        if not m:
            return None
        x1, y1, x2, y2 = map(int, m.groups())
        return x1, y1, x2, y2

    def _short_id(raw: str) -> str:
        return raw.split("/")[-1] if "/" in raw else raw

    inputs = [
        e for e in root.iter()
        if e.attrib.get("class", "") == "android.widget.EditText"
    ]

    match: Optional[Any] = None

    if resource_id:
        wanted = _short_id(resource_id)
        for e in inputs:
            if _short_id(e.attrib.get("resource-id", "")) == wanted:
                match = e
                break

    if match is None and center_x is not None and center_y is not None:
        for e in inputs:
            b = _bounds(e)
            if b and b[0] <= center_x <= b[2] and b[1] <= center_y <= b[3]:
                match = e
                break

    if match is None and node_id:
        # node_id is assigned positionally by the perception parser ("n7"), so
        # it only resolves against a hierarchy parsed the same way. Fall back
        # to index within the input list, which is stable for a screen that has
        # not re-laid-out.
        m = re.match(r"n(\d+)$", node_id)
        if m:
            idx = int(m.group(1))
            if 0 <= idx < len(inputs):
                match = inputs[idx]

    if match is None:
        return FieldSnapshot(found=False)

    text = match.attrib.get("text", "") or ""
    is_password = match.attrib.get("password") == "true"
    focused_attr = match.attrib.get("focused", "")
    focused: Optional[bool] = None
    if focused_attr == "true":
        focused = True
    elif focused_attr == "false":
        focused = False

    # Some builds expose a masked field's length as a run of bullets rather
    # than as its content. Either way the length is what we verify against.
    stripped = text.strip()
    length: Optional[int] = len(stripped) if stripped else None
    if is_password and stripped and set(stripped) <= {"•", "*", "·"}:
        length = len(stripped)

    return FieldSnapshot(
        found=True,
        text=text,
        text_read=True,
        text_length=length if length is not None else (0 if not stripped else None),
        is_password=is_password,
        focused=focused,
        enabled=match.attrib.get("enabled", "true") != "false",
        resource_id=_short_id(match.attrib.get("resource-id", "")),
        node_id=node_id,
        content_desc=match.attrib.get("content-desc", ""),
    )
