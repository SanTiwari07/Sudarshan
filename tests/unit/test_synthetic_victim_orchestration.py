"""
SUDARSHAN - Synthetic victim: state, progress, budget, children, verification.

Covers G5 (AuthState), G6 (ProgressTracker), G7 (adaptive budget), G8 (child
APK exploration) and G9 (field population verification), plus the credential
redaction and containment properties that must survive all of it.

The recurring theme in these assertions is refusing to accept a proxy for the
thing itself: a click is not a login, an activity change is not authentication,
an executed action is not a filled field, and a screen we have already seen is
not progress.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.action_verifier import (  # noqa: E402
    FieldSnapshot,
    VerificationOutcome,
    parse_field_snapshot,
    verify_action,
    verify_field_population,
)
from sudarshan_core.engines.agentic.adaptive_budget import AdaptiveBudget  # noqa: E402
from sudarshan_core.engines.agentic.auth_state import (  # noqa: E402
    AuthState,
    AuthStateMachine,
)
from sudarshan_core.engines.agentic.progress_tracker import (  # noqa: E402
    ProgressKind,
    ProgressTracker,
)
from sudarshan_core.engines.agentic.secondary_payload import (  # noqa: E402
    PayloadStatus,
    SecondaryPayloadTracker,
)


# ─── G5: AuthState ───────────────────────────────────────────────────────────

REQUIRED_AUTH_STATES = [
    "UNKNOWN", "CREDENTIALS_REQUIRED", "CREDENTIALS_PARTIALLY_FILLED",
    "CREDENTIALS_FILLED", "SUBMISSION_PENDING", "AUTHENTICATION_FAILED",
    "OTP_REQUIRED", "OTP_FILLED", "MFA_PENDING", "AUTHENTICATED",
    "SESSION_ACTIVE", "AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE",
]


@pytest.mark.parametrize("name", REQUIRED_AUTH_STATES)
def test_every_required_auth_state_exists(name):
    assert AuthState(name).value == name


def test_the_documented_bank_login_journey():
    """BANK_LOGIN -> CREDENTIALS_FILLED -> SUBMISSION -> OTP -> AUTHENTICATED."""
    m = AuthStateMachine()

    m.on_screen(screen_type="BANK_LOGIN", required_fields={"USER_ID", "PASSWORD"})
    assert m.state is AuthState.CREDENTIALS_REQUIRED

    m.on_field_filled("USER_ID")
    assert m.state is AuthState.CREDENTIALS_PARTIALLY_FILLED

    m.on_field_filled("PASSWORD")
    assert m.state is AuthState.CREDENTIALS_FILLED

    m.on_submit()
    assert m.state is AuthState.SUBMISSION_PENDING

    m.on_submit_result(screen_type="OTP")
    assert m.state is AuthState.OTP_REQUIRED

    m.on_field_filled("OTP")
    assert m.state is AuthState.OTP_FILLED

    m.on_submit()
    assert m.state is AuthState.MFA_PENDING

    m.on_submit_result(screen_text="Logout  Available Balance")
    assert m.state is AuthState.AUTHENTICATED
    assert m.is_authenticated


def test_pressing_login_does_not_authenticate():
    """
    The rule this model exists to enforce.

    A changed activity is equally consistent with an error screen, so it must
    not be read as a successful login.
    """
    m = AuthStateMachine()
    m.on_screen(screen_type="BANK_LOGIN", required_fields={"USERNAME", "PASSWORD"})
    m.on_field_filled("USERNAME")
    m.on_field_filled("PASSWORD")
    m.on_submit()
    m.on_submit_result(activity_changed=True, screen_text="Something went wrong")
    assert m.state is AuthState.SUBMISSION_PENDING
    assert not m.is_authenticated


def test_an_observable_landmark_does_authenticate():
    m = AuthStateMachine()
    m.on_submit()
    m.on_submit_result(activity_changed=True, screen_text="Log Out | Account Summary")
    assert m.state is AuthState.AUTHENTICATED


def test_explicit_rejection_is_terminal_and_clears_the_form():
    m = AuthStateMachine()
    m.on_screen(screen_type="BANK_LOGIN", required_fields={"USERNAME", "PASSWORD"})
    m.on_field_filled("USERNAME")
    m.on_field_filled("PASSWORD")
    m.on_submit()
    m.on_submit_result(rejected=True, screen_text="Invalid credentials")
    assert m.state is AuthState.AUTHENTICATION_FAILED
    assert m.is_terminal
    assert m.filled_fields == set()


def test_unverified_field_does_not_advance_the_state():
    """An action that did not fill a field did not fill a field."""
    m = AuthStateMachine()
    m.on_screen(screen_type="BANK_LOGIN", required_fields={"USERNAME", "PASSWORD"})
    m.on_field_filled("USERNAME", verified=False)
    m.on_field_filled("PASSWORD", verified=False)
    assert m.state is AuthState.CREDENTIALS_REQUIRED


def test_external_block_is_distinct_from_rejection():
    m = AuthStateMachine()
    m.on_submit()
    m.on_submit_result(external_block=True, screen_text="SMS service unavailable")
    assert m.state is AuthState.AUTHENTICATION_BLOCKED_EXTERNAL_SERVICE
    assert m.is_terminal


def test_otp_screen_alone_advances_past_the_first_factor():
    """An app does not send a code to someone it has already turned away."""
    m = AuthStateMachine()
    m.on_screen(screen_type="BANK_LOGIN", required_fields={"PASSWORD"})
    m.on_screen(screen_type="OTP", required_fields={"OTP"})
    assert m.state is AuthState.OTP_REQUIRED


def test_legacy_login_outcome_is_preserved_for_every_state():
    legal = {"not_attempted", "retrying", "rejected", "accepted", "exhausted"}
    for state in AuthState:
        m = AuthStateMachine(state=state)
        assert m.legacy_outcome in legal, state


def test_transitions_are_recorded_with_reasons():
    m = AuthStateMachine()
    m.on_screen(screen_type="BANK_LOGIN", required_fields={"PASSWORD"})
    m.on_field_filled("PASSWORD")
    assert m.history
    assert all(t.reason for t in m.history)
    assert m.to_dict()["auth_state"] == m.state.value


def test_session_active_follows_authenticated():
    m = AuthStateMachine(state=AuthState.AUTHENTICATED)
    m.on_session_activity()
    assert m.state is AuthState.SESSION_ACTIVE
    assert m.is_authenticated


# ─── G6: ProgressTracker ─────────────────────────────────────────────────────

def test_same_state_twice_is_not_progress():
    """STATE_A -> click -> STATE_A = no progress."""
    t = ProgressTracker()
    assert t.record(screen_hash="h1", state_id="A").kind is ProgressKind.MEANINGFUL_PROGRESS
    second = t.record(screen_hash="h1", state_id="A")
    assert second.kind is ProgressKind.NO_PROGRESS
    assert not second.meaningful


def test_new_state_is_progress():
    """STATE_A -> click -> STATE_B = meaningful progress."""
    t = ProgressTracker()
    t.record(screen_hash="h1", state_id="A")
    assert t.record(screen_hash="h2", state_id="B").meaningful


@pytest.mark.parametrize("kwargs", [
    {"screen_hash": "new"},
    {"state_id": "S9"},
    {"activity": "com.x/.NewActivity"},
    {"package": "com.other"},
    {"actionable_element_ids": {"A-1"}},
    {"runtime_events": 1},
    {"new_evidence": 1},
    {"workflow_stage": "ACCESSIBILITY_ANALYSIS"},
    {"auth_state": "OTP_REQUIRED"},
    {"permission_state": "SYSTEM_ALERT_WINDOW=allow"},
    {"child_package": "com.dropped.payload"},
])
def test_each_tracked_signal_counts_as_progress(kwargs):
    assert ProgressTracker().record(**kwargs).meaningful


def test_a_new_element_on_an_unchanged_screen_is_still_progress():
    """
    Novelty is the authority, not the score.

    score_progress weights a repeated screen at -2, so an action that revealed
    a new control would otherwise be scored as a regression.
    """
    t = ProgressTracker()
    t.record(screen_hash="h1", actionable_element_ids={"A-1"})
    verdict = t.record(screen_hash="h1", actionable_element_ids={"A-1", "A-2"})
    assert verdict.meaningful
    assert any("A-2" in n for n in verdict.novelty)


def test_stagnation_trips_after_the_limit():
    t = ProgressTracker(stagnation_limit=3)
    t.record(screen_hash="h1")
    for _ in range(3):
        t.record(screen_hash="h1")
    assert t.is_stagnant
    assert t.stagnant_streak == 3


def test_progress_resets_the_stagnation_streak():
    t = ProgressTracker(stagnation_limit=3)
    t.record(screen_hash="h1")
    t.record(screen_hash="h1")
    assert t.stagnant_streak == 1
    t.record(screen_hash="h2")
    assert t.stagnant_streak == 0


def test_crash_is_never_progress():
    assert not ProgressTracker().record(screen_hash="new", crashed=True).meaningful


def test_progress_rate_and_coverage_are_reported():
    t = ProgressTracker()
    t.record(screen_hash="h1", state_id="A")
    t.record(screen_hash="h1", state_id="A")
    assert t.progress_rate == pytest.approx(0.5)
    assert t.coverage()["screens"] == 1
    assert t.to_dict()["total_actions"] == 2


def test_history_is_bounded():
    t = ProgressTracker()
    for i in range(700):
        t.record(screen_hash=f"h{i}")
    assert len(t.history) <= 500


def test_progress_is_orchestration_only_and_does_not_touch_risk():
    """
    A run that navigated well is not a more dangerous app.

    Letting navigation luck move BFCI or FRS would be a scoring bug, so the
    tracker must expose nothing either engine consumes.
    """
    surface = set(ProgressTracker().to_dict())
    assert not (surface & {"bfci", "frs", "risk_score", "verdict", "severity"})


# ─── G7: adaptive budget ─────────────────────────────────────────────────────

def test_budget_starts_at_the_callers_duration():
    b = AdaptiveBudget(initial_seconds=300, max_seconds=900)
    assert b.deadline_seconds == 300


def test_hard_maximum_outranks_a_larger_starting_budget():
    b = AdaptiveBudget(initial_seconds=1200, max_seconds=900)
    assert b.max_seconds == 1200
    assert b.deadline_seconds == 1200


def test_progress_near_the_deadline_extends_within_the_maximum():
    b = AdaptiveBudget(initial_seconds=10, max_seconds=100, extension_seconds=20)
    b.started_monotonic = time.monotonic() - 9      # 1s remaining
    assert b.note_progress(meaningful=True)
    assert b.deadline_seconds == 30
    assert b.extensions == 1


def test_progress_far_from_the_deadline_does_not_inflate_the_budget():
    b = AdaptiveBudget(initial_seconds=300, max_seconds=900, extension_seconds=60)
    assert not b.note_progress(meaningful=True)
    assert b.deadline_seconds == 300


def test_no_progress_never_extends():
    b = AdaptiveBudget(initial_seconds=10, max_seconds=100, extension_seconds=20)
    b.started_monotonic = time.monotonic() - 9
    assert not b.note_progress(meaningful=False)
    assert b.deadline_seconds == 10


def test_the_budget_can_never_exceed_the_hard_maximum():
    """The guarantee that no run is unbounded."""
    b = AdaptiveBudget(initial_seconds=10, max_seconds=50, extension_seconds=20)
    for _ in range(100):
        b.started_monotonic = time.monotonic() - (b.deadline_seconds - 1)
        b.note_progress(meaningful=True)
    assert b.deadline_seconds == 50
    assert b.at_hard_maximum


def test_deadline_arrival_always_finishes():
    b = AdaptiveBudget(initial_seconds=10, max_seconds=900)
    b.started_monotonic = time.monotonic() - 11
    assert b.should_finish(work_remaining=True)
    assert b.finish_reason == "time_budget_exhausted"


def test_stagnation_with_no_work_left_finishes_early():
    b = AdaptiveBudget(initial_seconds=300, max_seconds=900, stagnation_limit=5)
    assert b.should_finish(
        stagnant_streak=6, recovery_exhausted=True, work_remaining=False,
    )
    assert b.finish_reason == "no_progress_and_no_work_remaining"


def test_stagnation_with_work_left_keeps_going():
    b = AdaptiveBudget(initial_seconds=300, max_seconds=900, stagnation_limit=5)
    assert not b.should_finish(
        stagnant_streak=6, recovery_exhausted=True, work_remaining=True,
    )


def test_disabling_adaptation_restores_the_fixed_deadline():
    b = AdaptiveBudget(initial_seconds=10, max_seconds=900, enabled=False)
    b.started_monotonic = time.monotonic() - 9
    assert not b.note_progress(meaningful=True)
    assert b.deadline_seconds == 10
    assert not b.should_finish(
        stagnant_streak=99, recovery_exhausted=True, work_remaining=False,
    )


def test_config_follows_the_repository_env_style(monkeypatch):
    import importlib

    monkeypatch.setenv("INITIAL_EXPLORATION_BUDGET_SECONDS", "120")
    monkeypatch.setenv("MAX_EXPLORATION_BUDGET_SECONDS", "600")
    monkeypatch.setenv("ADAPTIVE_EXPLORATION_ENABLED", "false")
    mod = importlib.reload(
        importlib.import_module("sudarshan_core.engines.agentic.adaptive_budget")
    )
    try:
        assert mod.INITIAL_EXPLORATION_BUDGET_SECONDS == 120
        assert mod.MAX_EXPLORATION_BUDGET_SECONDS == 600
        assert mod.ADAPTIVE_EXPLORATION_ENABLED is False
    finally:
        monkeypatch.undo()
        importlib.reload(mod)


def test_a_malformed_env_value_does_not_stop_a_run(monkeypatch):
    import importlib

    monkeypatch.setenv("MAX_EXPLORATION_BUDGET_SECONDS", "not-a-number")
    mod = importlib.reload(
        importlib.import_module("sudarshan_core.engines.agentic.adaptive_budget")
    )
    try:
        assert isinstance(mod.MAX_EXPLORATION_BUDGET_SECONDS, int)
    finally:
        monkeypatch.undo()
        importlib.reload(mod)


# ─── G8: child applications as exploration surfaces ──────────────────────────

def _tracker_with_installed_child():
    """
    A dropper that wrote an APK and then asked Android to install it.

    Driven through the real hook vocabulary rather than a hand-made event, so
    this exercises the tracker's actual entry contract.
    """
    from sudarshan_core.engines.agentic.secondary_payload import (
        HOOK_APK_WRITE,
        HOOK_INSTALL_REQUEST,
    )

    t = SecondaryPayloadTracker(parent_package="com.parent.dropper")
    payload = t.observe_event({
        "hook": HOOK_APK_WRITE,
        "data": {"path": "/sdcard/Download/payload.apk"},
    })
    assert payload is not None
    t.observe_event({
        "hook": HOOK_INSTALL_REQUEST,
        "data": {"path": "/sdcard/Download/payload.apk"},
    })
    payload.package_name = "com.child.payload"
    payload.trigger = "downloaded via WebView then installed"
    t.confirm_installed("com.child.payload")
    return t, payload


def test_installed_child_is_recognised_as_a_child_package():
    t, _ = _tracker_with_installed_child()
    assert t.is_child_package("com.child.payload")
    assert not t.is_child_package("com.unrelated.app")
    assert not t.is_child_package("")


def test_the_parent_child_relationship_is_tracked():
    t, _ = _tracker_with_installed_child()
    rel = t.relationship_for("com.child.payload")
    assert rel["parent_package"] == "com.parent.dropper"
    assert rel["child_package"] == "com.child.payload"
    assert rel["trigger"]
    assert rel["installation_event"]["install_confirmed"] is True
    assert rel["relationship"] == "installed_by"


def test_the_original_apk_context_is_never_lost():
    t, _ = _tracker_with_installed_child()
    t.mark_child_exploration("com.child.payload", state="explored")
    assert t.parent_package == "com.parent.dropper"
    assert t.relationship_for("com.child.payload")["parent_package"] == (
        "com.parent.dropper"
    )


def test_child_exploration_progress_is_recorded():
    t, _ = _tracker_with_installed_child()
    t.mark_child_exploration(
        "com.child.payload", state="explored",
        states_explored=4, actions_taken=11,
    )
    record = t.to_records()[0]
    assert record["exploration_state"] == "explored"
    assert record["child_states_explored"] == 4
    assert record["child_actions_taken"] == 11
    assert record["status"] == PayloadStatus.ANALYZED.value


def test_an_uninstalled_payload_is_not_an_exploration_candidate():
    from sudarshan_core.engines.agentic.secondary_payload import HOOK_APK_WRITE

    t = SecondaryPayloadTracker(parent_package="com.parent")
    t.observe_event({"hook": HOOK_APK_WRITE, "data": {"path": "/sdcard/x.apk"}})
    assert t.exploration_candidates() == []


def test_a_policy_blocked_payload_is_never_launched():
    """Launching it anyway would contradict a containment decision already taken."""
    t, payload = _tracker_with_installed_child()
    payload.blocked_by_policy = True
    assert payload not in t.exploration_candidates()


def test_an_explored_child_is_not_a_candidate_again():
    t, _ = _tracker_with_installed_child()
    assert len(t.exploration_candidates()) == 1
    t.mark_child_exploration("com.child.payload", state="explored")
    assert t.exploration_candidates() == []


# ─── G9: field population verification ───────────────────────────────────────

LOGIN_XML = """<hierarchy>
  <node class="android.widget.EditText" resource-id="com.x:id/user"
        text="userabc" password="false" enabled="true" focused="true"
        bounds="[0,0][100,50]"/>
  <node class="android.widget.EditText" resource-id="com.x:id/pw"
        text="" password="true" enabled="true" focused="false"
        bounds="[0,60][100,110]"/>
</hierarchy>"""


def test_a_populated_field_verifies():
    snap = parse_field_snapshot(LOGIN_XML, resource_id="user")
    result = verify_field_population(
        {"tool": "type_text", "field_hint": "username", "resource_id": "user"},
        snap, expected_length=7,
    )
    assert result.outcome == VerificationOutcome.SUCCESS.value


def test_an_empty_field_fails_verification():
    """The bug this catches: a tap that missed, then Login pressed anyway."""
    snap = FieldSnapshot(found=True, text="", text_read=True, text_length=0)
    result = verify_field_population({"tool": "type_text"}, snap)
    assert result.outcome == VerificationOutcome.FAILED.value
    assert result.observed == "field_empty"


def test_a_field_that_cannot_be_found_is_inconclusive_not_failed():
    """An unreadable device must not look like a misbehaving one."""
    result = verify_field_population({"tool": "type_text"}, None)
    assert result.outcome == VerificationOutcome.INCONCLUSIVE.value
    result = verify_field_population({"tool": "type_text"}, FieldSnapshot(found=False))
    assert result.outcome == VerificationOutcome.INCONCLUSIVE.value


def test_typing_into_the_wrong_field_is_detected():
    snap = parse_field_snapshot(LOGIN_XML, resource_id="pw")
    result = verify_field_population(
        {"tool": "type_text", "resource_id": "user"}, snap,
    )
    assert result.outcome == VerificationOutcome.FAILED.value
    assert result.observed == "wrong_field"


def test_truncation_is_detected():
    """A field with a shorter maxlength silently truncates; the walk must notice."""
    snap = FieldSnapshot(found=True, text="1234", text_read=True, text_length=4)
    result = verify_field_population(
        {"tool": "type_text"}, snap, expected_length=6,
    )
    assert result.outcome == VerificationOutcome.FAILED.value
    assert "truncated" in result.detail


def test_a_disabled_field_fails():
    snap = FieldSnapshot(found=True, text="x", text_read=True, text_length=1,
                         enabled=False)
    result = verify_field_population({"tool": "type_text"}, snap)
    assert result.outcome == VerificationOutcome.FAILED.value
    assert result.observed == "field_disabled"


def test_a_masked_field_verifies_by_length_without_the_value():
    """Bullets prove population without revealing anything."""
    snap = FieldSnapshot(found=True, text="••••••", text_read=True,
                         text_length=6, is_password=True)
    result = verify_field_population({"tool": "type_text"}, snap,
                                     expected_length=6)
    assert result.outcome == VerificationOutcome.SUCCESS.value


def test_an_unreadable_masked_field_is_inconclusive_not_failed():
    """
    Some builds expose nothing for a password box, so empty and hidden look
    identical. Calling that FAILED would send the walk into a retry it cannot
    win on every such device.
    """
    snap = FieldSnapshot(found=True, text="", text_read=True, text_length=0,
                         is_password=True, focused=True)
    result = verify_field_population({"tool": "type_text"}, snap)
    assert result.outcome == VerificationOutcome.INCONCLUSIVE.value


def test_an_unfocused_empty_masked_field_does_fail():
    """`input text` goes to the focused node, so this one really did not land."""
    snap = FieldSnapshot(found=True, text="", text_read=True, text_length=0,
                         is_password=True, focused=False)
    result = verify_field_population({"tool": "type_text"}, snap)
    assert result.outcome == VerificationOutcome.FAILED.value


def test_verification_never_contains_the_typed_value():
    secret = "Pw9SecretValue!"
    snap = FieldSnapshot(found=True, text=secret, text_read=True,
                         text_length=len(secret), is_password=True)
    result = verify_field_population(
        {"tool": "type_text", "field_hint": "password"}, snap,
        expected_length=len(secret),
    )
    blob = " ".join([
        result.log_line(), result.detail, result.observed, result.expected,
        str(result.to_dict()),
    ])
    assert secret not in blob


def test_field_matching_falls_back_to_coordinates_for_webview_forms():
    """WebView fields carry no resource-id; the tapped point is all there is."""
    xml = """<hierarchy>
      <node class="android.widget.EditText" text="typed" bounds="[0,0][100,50]"/>
      <node class="android.widget.EditText" text="" bounds="[0,60][100,110]"/>
    </hierarchy>"""
    snap = parse_field_snapshot(xml, center_x=50, center_y=25)
    assert snap.found and snap.populated
    assert parse_field_snapshot(xml, center_x=50, center_y=80).populated is False


def test_malformed_xml_is_inconclusive():
    assert parse_field_snapshot("<not-xml").found is False


def test_verify_action_routes_type_text_to_field_verification():
    """The integration point: the existing entry point gains the new rule."""
    from sudarshan_core.engines.agentic.action_verifier import StateSnapshot

    before = StateSnapshot(screen_hash="a")
    after = StateSnapshot(screen_hash="a")
    snap = FieldSnapshot(found=True, text="abc", text_read=True, text_length=3)
    result = verify_action(
        {"tool": "type_text"}, before, after,
        field_after=snap, expected_length=3,
    )
    assert result.outcome == VerificationOutcome.SUCCESS.value


def test_verify_action_without_a_field_snapshot_keeps_old_behaviour():
    """An existing caller that does not pass the new argument is unaffected."""
    from sudarshan_core.engines.agentic.action_verifier import StateSnapshot

    before = StateSnapshot(screen_hash="a")
    after = StateSnapshot(screen_hash="a")
    result = verify_action({"tool": "type_text"}, before, after)
    assert result.outcome == VerificationOutcome.INCONCLUSIVE.value
