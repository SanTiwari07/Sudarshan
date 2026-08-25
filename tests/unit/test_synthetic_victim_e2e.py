"""
SUDARSHAN - Synthetic victim: end-to-end journey over a scripted app.

Drives the twenty-step flow from the brief:

    LOGIN -> USER ID -> PASSWORD -> LOGIN -> OTP -> VERIFY -> ACCESSIBILITY
    -> SYSTEM SETTINGS -> RETURN TO APP -> SECONDARY APK -> CHILD APP

The application is a fixture: a scripted sequence of uiautomator hierarchies
with an ADB gateway that answers from the script. Everything ABOVE the device
is the real thing - the real XML parser, the real classifier, the real
constraint extraction, the real CredentialVault, the real ToolExecutor, the
real ActionVerifier, the real AuthStateMachine, ProgressTracker, AdaptiveBudget
and SecondaryPayloadTracker. Nothing here reimplements a component in order to
make it pass.

What this does NOT do is prove the flow on a device. There is no emulator in
the unit environment, so the ADB gateway is canned. It establishes that the
components compose correctly and that the contracts between them hold; a live
emulator run is a separate exercise and is reported separately.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.action_verifier import (  # noqa: E402
    VerificationOutcome,
    accessibility_enabled_for,
    parse_accessibility_components,
    parse_field_snapshot,
    verify_field_population,
)
from sudarshan_core.engines.agentic.adaptive_budget import AdaptiveBudget  # noqa: E402
from sudarshan_core.engines.agentic.auth_state import (  # noqa: E402
    AuthState,
    AuthStateMachine,
)
from sudarshan_core.engines.agentic.credentials import get_vault  # noqa: E402
from sudarshan_core.engines.agentic.field_classifier import classify_field  # noqa: E402
from sudarshan_core.engines.agentic.field_constraints import (  # noqa: E402
    extract_constraints,
)
from sudarshan_core.engines.agentic.field_taxonomy import FieldType  # noqa: E402
from sudarshan_core.engines.agentic.perception import PerceptionPipeline  # noqa: E402
from sudarshan_core.engines.agentic.progress_tracker import ProgressTracker  # noqa: E402
from sudarshan_core.engines.agentic.secondary_payload import (  # noqa: E402
    HOOK_APK_WRITE,
    HOOK_INSTALL_REQUEST,
    SecondaryPayloadTracker,
)
from sudarshan_core.engines.agentic.tool_executor import ToolExecutor  # noqa: E402

PARENT_PKG = "com.sudarshan.fixture.bank"
CHILD_PKG = "com.sudarshan.fixture.payload"


# ─── The fixture application ─────────────────────────────────────────────────

def _login_screen(user_text: str = "", pw_text: str = "") -> str:
    """Login form. Captions are siblings, as the WebView corpus renders them."""
    return f"""<hierarchy rotation="0">
  <node class="android.widget.TextView" text="User ID" bounds="[0,100][400,140]"/>
  <node class="android.widget.EditText" resource-id="{PARENT_PKG}:id/user_id"
        text="{user_text}" password="false" enabled="true"
        focused="true" bounds="[0,150][400,200]"/>
  <node class="android.widget.TextView" text="Login Password"
        bounds="[0,220][400,260]"/>
  <node class="android.widget.EditText" resource-id="{PARENT_PKG}:id/password"
        text="{pw_text}" password="true" enabled="true"
        focused="false" bounds="[0,270][400,320]"/>
  <node class="android.widget.Button" resource-id="{PARENT_PKG}:id/login_btn"
        text="LOGIN" clickable="true" enabled="true" bounds="[0,350][400,400]"/>
</hierarchy>"""


def _otp_screen(otp_text: str = "") -> str:
    return f"""<hierarchy rotation="0">
  <node class="android.widget.TextView" text="Enter 6 digit OTP"
        bounds="[0,100][400,140]"/>
  <node class="android.widget.EditText" resource-id="{PARENT_PKG}:id/otp"
        text="{otp_text}" password="false" enabled="true" focused="true"
        bounds="[0,150][400,200]"/>
  <node class="android.widget.Button" resource-id="{PARENT_PKG}:id/verify_btn"
        text="VERIFY" clickable="true" enabled="true" bounds="[0,250][400,300]"/>
</hierarchy>"""


_DASHBOARD = f"""<hierarchy rotation="0">
  <node class="android.widget.TextView" text="Account Summary"
        bounds="[0,100][400,140]"/>
  <node class="android.widget.TextView" text="Available Balance"
        bounds="[0,150][400,190]"/>
  <node class="android.widget.Button" text="Log Out" clickable="true"
        bounds="[0,200][400,250]"/>
  <node class="android.widget.Button" text="Enable Accessibility"
        clickable="true" bounds="[0,300][400,350]"/>
</hierarchy>"""

def _child_screen(mpin_text: str = "") -> str:
    """The dropped payload's own login. The caption states the MPIN length."""
    return f"""<hierarchy rotation="0">
  <node class="android.widget.TextView" text="Secure Update Service"
        bounds="[0,20][400,60]"/>
  <node class="android.widget.TextView" text="Enter 4-digit MPIN"
        bounds="[0,80][400,120]"/>
  <node class="android.widget.EditText" resource-id="{CHILD_PKG}:id/mpin"
        text="{mpin_text}" password="true" enabled="true" focused="true"
        bounds="[0,150][400,200]"/>
</hierarchy>"""


class FixtureDevice:
    """
    A scripted device. Answers `uiautomator dump` from a caller-driven script.

    Deliberately dumb: it holds no logic about the flow, so a test that passes
    does so because the components under test drove it, not because the fixture
    helped them along.
    """

    def __init__(self) -> None:
        self.screen = _login_screen()
        self.activity = f"{PARENT_PKG}/.LoginActivity"
        self.typed: list[tuple[str, str]] = []
        self.accessibility_services = ""
        self.commands: list[tuple[str, ...]] = []

    async def adb(self, *args: str):
        self.commands.append(args)
        joined = " ".join(args)
        if "uiautomator" in joined and "dump" in joined:
            return True, self.screen
        if "dumpsys activity activities" in joined:
            return True, f"mResumedActivity: ActivityRecord{{u0 {self.activity} t1}}"
        if "input" in args and "text" in args:
            self.typed.append((self.activity, args[-1]))
            return True, ""
        if "enabled_accessibility_services" in joined and "get" in args:
            return True, self.accessibility_services or "null"
        if "enabled_accessibility_services" in joined and "put" in args:
            self.accessibility_services = args[-1]
            return True, ""
        return True, ""


def _executor(device: FixtureDevice, package: str) -> ToolExecutor:
    ex = ToolExecutor(device_serial="fixture-5554", package_name=package)
    ex._adb = AsyncMock(side_effect=device.adb)
    return ex


def _inputs(xml: str):
    """Parse with the REAL perception parser."""
    pipeline = PerceptionPipeline.__new__(PerceptionPipeline)
    return [n for n in pipeline._parse_ui_nodes(xml) if n.is_input]


def _classify(node, index: int, screen_type: str):
    return classify_field(
        field_label=node.field_label,
        resource_id=node.resource_id,
        content_desc=node.desc,
        class_name=node.class_name,
        text=node.text,
        hint=node.hint,
        input_type=node.input_type,
        is_password=node.is_password,
        index=index,
        screen_type=screen_type,
    )


def _fill(device, executor, node, classification, render):
    """
    Type into one field and verify it landed, using the real chain.

    `render(field_text)` rebuilds the screen with the field now holding
    `field_text`, which is how a real device behaves: the hierarchy reflects
    what was actually typed. The content is a filler of the RIGHT LENGTH
    (bullets for a masked field, as Android renders them) rather than the value
    itself, because the value never leaves the executor - which is the property
    the whole design rests on, and the reason the verifier checks length.
    """
    constraints = extract_constraints(
        field_type=classification.field_type,
        field_label=node.field_label,
        hint=node.hint,
        resource_id=node.resource_id,
        is_password=node.is_password,
        max_length=node.max_length,
        input_type=node.input_type,
    )
    result = asyncio.run(executor.execute({
        "tool": "type_text",
        "field_hint": classification.legacy_kind,
        "field_type": classification.field_type.value,
        "field_min_length": constraints.min_length,
        "field_max_length": constraints.max_length,
        "field_numeric_only": constraints.numeric_only,
        "resource_id": node.resource_id,
        "node_id": node.node_id,
        "x": node.center_x, "y": node.center_y,
    }))

    typed_length = result.data.get("typed_length") or 0
    filler = ("•" if node.is_password else "x") * typed_length
    device.screen = render(filler)

    snapshot = parse_field_snapshot(device.screen, resource_id=node.resource_id)
    return result, verify_field_population(
        {"tool": "type_text", "field_hint": classification.legacy_kind,
         "resource_id": node.resource_id},
        snapshot, expected_length=typed_length,
    )


# ─── The journey ─────────────────────────────────────────────────────────────

def test_full_synthetic_victim_journey():
    """
    Steps 1-20 of the brief, in order, over the real component chain.

    Each assertion names the step it covers so a failure says which part of the
    journey broke rather than only that something did.
    """
    device = FixtureDevice()
    executor = _executor(device, PARENT_PKG)
    auth = AuthStateMachine()
    progress = ProgressTracker()
    budget = AdaptiveBudget(initial_seconds=300, max_seconds=900)
    payloads = SecondaryPayloadTracker(parent_package=PARENT_PKG)
    vault = get_vault(PARENT_PKG)

    # ── 1. Detect User ID ────────────────────────────────────────────────────
    fields = _inputs(device.screen)
    assert len(fields) == 2, "login form should expose two inputs"
    user_node, pw_node = fields
    user_cls = _classify(user_node, 0, "BANK_LOGIN")
    assert user_cls.field_type is FieldType.USER_ID, "step 1: detect User ID"
    assert user_cls.legacy_kind == "username", "wire format preserved"

    pw_cls = _classify(pw_node, 1, "BANK_LOGIN")
    assert pw_cls.field_type is FieldType.PASSWORD, "step 4: detect Password"

    auth.on_screen(
        screen_type="BANK_LOGIN",
        required_fields={user_cls.field_type.value, pw_cls.field_type.value},
    )
    assert auth.state is AuthState.CREDENTIALS_REQUIRED

    # ── 2-3. Insert synthetic User ID, verify input ──────────────────────────
    user_filled = {"text": ""}
    result, verification = _fill(
        device, executor, user_node, user_cls,
        render=lambda t: (user_filled.__setitem__("text", t)
                          or _login_screen(user_text=t)),
    )
    assert verification.outcome == VerificationOutcome.SUCCESS.value, "step 3"
    auth.on_field_filled(user_cls.field_type.value, verified=True)
    assert auth.state is AuthState.CREDENTIALS_PARTIALLY_FILLED
    progress.record(screen_hash="login", state_id="S1", auth_state=auth.state.value)

    # ── 5-6. Insert synthetic Password, verify input ─────────────────────────
    # The masked field reports bullets, so population is confirmed by LENGTH -
    # the value itself never leaves the executor and is never compared.
    result, verification = _fill(
        device, executor, pw_node, pw_cls,
        render=lambda t: _login_screen(user_text=user_filled["text"], pw_text=t),
    )
    assert verification.outcome == VerificationOutcome.SUCCESS.value, "step 6"
    auth.on_field_filled(pw_cls.field_type.value, verified=True)
    assert auth.state is AuthState.CREDENTIALS_FILLED

    # ── 7. Click Login ───────────────────────────────────────────────────────
    asyncio.run(executor.execute({"tool": "click_text", "text": "LOGIN",
                                  "x": 200, "y": 375}))
    auth.on_submit()
    assert auth.state is AuthState.SUBMISSION_PENDING, "a click is not a login"

    # ── 8. Verify transition ─────────────────────────────────────────────────
    device.screen = _otp_screen()
    device.activity = f"{PARENT_PKG}/.OtpActivity"
    auth.on_submit_result(screen_type="OTP")
    assert auth.state is AuthState.OTP_REQUIRED, "step 8: OTP means factor one passed"
    verdict = progress.record(
        screen_hash="otp", state_id="S2", activity=device.activity,
        auth_state=auth.state.value,
    )
    assert verdict.meaningful, "reaching the OTP screen is progress"

    # ── 9-11. Detect OTP, insert synthetic OTP, verify ───────────────────────
    otp_node = _inputs(device.screen)[0]
    otp_cls = _classify(otp_node, 0, "OTP")
    assert otp_cls.field_type is FieldType.OTP, "step 9: detect OTP"

    otp_constraints = extract_constraints(
        field_type=FieldType.OTP, field_label=otp_node.field_label,
    )
    assert otp_constraints.exact_length == 6, "'Enter 6 digit OTP' is six digits"

    result, verification = _fill(
        device, executor, otp_node, otp_cls, render=_otp_screen,
    )
    assert result.data["typed_length"] == 6, "step 10: exactly six digits"
    assert verification.outcome == VerificationOutcome.SUCCESS.value, "step 11"
    auth.on_field_filled(otp_cls.field_type.value, verified=True)
    assert auth.state is AuthState.OTP_FILLED

    # ── 12. Continue ─────────────────────────────────────────────────────────
    asyncio.run(executor.execute({"tool": "click_text", "text": "VERIFY",
                                  "x": 200, "y": 275}))
    auth.on_submit()
    assert auth.state is AuthState.MFA_PENDING

    device.screen = _DASHBOARD
    device.activity = f"{PARENT_PKG}/.DashboardActivity"
    auth.on_submit_result(screen_text="Account Summary Available Balance Log Out")
    assert auth.state is AuthState.AUTHENTICATED, "authenticated on a real landmark"
    progress.record(screen_hash="dash", state_id="S3", activity=device.activity,
                    auth_state=auth.state.value)

    # ── 13-15. Accessibility: navigate, enable, verify ───────────────────────
    # Manifest-driven service class, not a hardcoded name.
    executor.accessibility_service_class = f"{PARENT_PKG}.EvilService"
    grant = asyncio.run(executor.execute({
        "tool": "grant_permission", "permission": "accessibility",
    }))
    assert grant.success, "step 14: enable target service"

    components = parse_accessibility_components(device.accessibility_services)
    assert accessibility_enabled_for(components, PARENT_PKG), "step 15: verify"
    progress.record(screen_hash="settings", state_id="S4",
                    permission_state="accessibility=enabled")

    # ── 16. Return to app ────────────────────────────────────────────────────
    device.screen = _DASHBOARD
    device.activity = f"{PARENT_PKG}/.DashboardActivity"
    auth.on_session_activity()
    assert auth.state is AuthState.SESSION_ACTIVE

    # ── 17-18. Detect child APK, track the relationship ──────────────────────
    payload = payloads.observe_event({
        "hook": HOOK_APK_WRITE,
        "data": {"path": "/sdcard/Download/update.apk"},
    })
    assert payload is not None, "step 17: detect child APK"
    payloads.observe_event({
        "hook": HOOK_INSTALL_REQUEST,
        "data": {"path": "/sdcard/Download/update.apk"},
    })
    payload.package_name = CHILD_PKG
    payload.trigger = "dashboard 'Secure Update' download"
    payloads.confirm_installed(CHILD_PKG)

    relationship = payloads.relationship_for(CHILD_PKG)
    assert relationship["parent_package"] == PARENT_PKG, "step 18: parent tracked"
    assert relationship["child_package"] == CHILD_PKG
    assert relationship["installation_event"]["install_confirmed"] is True

    # ── 19. Explore the child APK ────────────────────────────────────────────
    assert payloads.is_child_package(CHILD_PKG), (
        "the child must be IN scope; treating it as a departure would navigate "
        "back out of the surface worth looking at"
    )
    device.screen = _child_screen()
    device.activity = f"{CHILD_PKG}/.MainActivity"
    payloads.mark_child_exploration(CHILD_PKG, state="exploring")

    child_executor = _executor(device, CHILD_PKG)
    child_node = _inputs(device.screen)[0]
    child_cls = _classify(child_node, 0, "BANK_LOGIN")
    assert child_cls.field_type is FieldType.MPIN, "child app asks for an MPIN"

    result, verification = _fill(
        device, child_executor, child_node, child_cls, render=_child_screen,
    )
    assert verification.outcome == VerificationOutcome.SUCCESS.value
    assert result.data["typed_length"] == 4, (
        "a 4-digit MPIN field must receive exactly 4 digits, not 6"
    )
    payloads.mark_child_exploration(
        CHILD_PKG, state="explored", states_explored=1, actions_taken=1,
    )

    # ── 20. Evidence stays attached to the parent investigation ──────────────
    assert payloads.parent_package == PARENT_PKG, "step 20: parent context kept"
    record = payloads.to_records()[0]
    assert record["parent_package"] == PARENT_PKG
    assert record["exploration_state"] == "explored"

    # ── Whole-run invariants ─────────────────────────────────────────────────
    assert auth.legacy_outcome == "accepted", "legacy report key still populated"
    assert progress.coverage()["screens"] >= 4
    assert not budget.at_hard_maximum
    assert budget.remaining() > 0, "the run finished inside its time budget"


def test_no_typed_value_ever_leaks_during_the_journey():
    """
    The whole journey, re-run, auditing every place a value could escape.

    Covers ToolResult.data, the ADB argv the executor built, and the audit
    log's view of each action.
    """
    from sudarshan_core.engines.agentic.audit_log import AuditLog

    device = FixtureDevice()
    executor = _executor(device, PARENT_PKG)
    vault = get_vault(PARENT_PKG)

    user_node, pw_node = _inputs(device.screen)
    for index, node in enumerate((user_node, pw_node)):
        cls = _classify(node, index, "BANK_LOGIN")
        result, _ = _fill(
            device, executor, node, cls,
            render=(_login_screen if index == 0
                    else lambda t: _login_screen(pw_text=t)),
        )
        blob = str(result.data) + str(result.output or "") + str(result.error or "")
        for secret in vault.secrets():
            assert secret not in blob, f"value leaked into ToolResult for {cls.field_type}"

        safe = AuditLog._sanitize_action({
            "tool": "type_text", "field_hint": cls.legacy_kind,
            "text": vault.values.get(cls.legacy_kind, ""),
        })
        assert "REDACTED" in str(safe) or not vault.values.get(cls.legacy_kind)


def test_the_journey_never_brute_forces_a_field():
    """
    A field is offered ONE value per identity, not a sequence of guesses.

    Repeatedly submitting different values into the same box is brute forcing,
    which this tool must not do.
    """
    vault = get_vault("com.example.nobrute")
    constraints = extract_constraints(field_type=FieldType.MPIN,
                                      field_label="Enter 4-digit MPIN")
    issued = {vault.value_for_field(constraints) for _ in range(25)}
    assert len(issued) == 1, "the same field must get the same value within a run"


def test_the_run_is_always_bounded():
    """No configuration makes exploration unlimited."""
    budget = AdaptiveBudget(initial_seconds=1, max_seconds=3,
                            extension_seconds=1)
    for _ in range(500):
        budget.note_progress(meaningful=True)
    assert budget.deadline_seconds <= 3
