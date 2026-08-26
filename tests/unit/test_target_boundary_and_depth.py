"""
The target APK is the world; everything else is a boundary.

These cover the three things the Dynamic Analysis Engine is judged on and had
no coverage for:

* how deep inside the SAMPLE the victim got (`max_target_app_depth`),
* that Settings, Accessibility, unknown-app-install and foreign applications
  are recorded and left rather than explored,
* that evidence collected before a boundary survives it.

The mock screens are deliberately generic. Nothing here keys off a package
name, an app label or a screen coordinate: a boundary is recognised from
ownership and screen type, which is what makes the behaviour hold for a sample
nobody has seen before.
"""

import sys
from pathlib import Path
from typing import List

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.exploration_engine import (  # noqa: E402
    BoundaryReason,
    BranchStatus,
    DynamicStatus,
    ExplorationGraph,
    compute_composite_state_signature,
)
from sudarshan_core.engines.agentic.perception import (  # noqa: E402
    Observation,
    UINode,
    in_investigation_scope,
)

TARGET = "com.example.echallan"


# ─── Fixtures ────────────────────────────────────────────────────────────────

def _node(
    node_id: str,
    text: str,
    *,
    clickable: bool = True,
    is_input: bool = False,
    resource_id: str = "",
) -> UINode:
    return UINode(
        node_id=node_id,
        class_name=(
            "android.widget.EditText" if is_input else "android.widget.Button"
        ),
        text=text,
        desc="",
        resource_id=resource_id,
        center_x=100 + len(node_id) * 10,
        center_y=200,
        is_input=is_input,
        is_clickable=clickable,
        is_scrollable=False,
        bounds="[0,0][200,100]",
    )


def _obs(activity: str, nodes: List[UINode], package: str = TARGET) -> Observation:
    obs = Observation(
        activity=activity, ui_nodes=nodes, ui_node_count=len(nodes),
    )
    obs.screen_hash, _ = compute_composite_state_signature(
        activity, package, nodes,
    )
    return obs


def _target(graph: ExplorationGraph, activity: str, nodes: List[UINode]):
    return graph.observe(
        _obs(activity, nodes),
        semantic_type="UNKNOWN",
        foreground_package=TARGET,
        ownership="TARGET_APP",
    )


def _boundary(
    graph: ExplorationGraph,
    activity: str,
    nodes: List[UINode],
    *,
    package: str,
    ownership: str,
    semantic_type: str,
):
    return graph.observe(
        _obs(activity, nodes, package=package),
        semantic_type=semantic_type,
        foreground_package=package,
        ownership=ownership,
    )


@pytest.fixture
def graph() -> ExplorationGraph:
    return ExplorationGraph(package_name=TARGET)


# ─── Target boundary ─────────────────────────────────────────────────────────

def test_target_package_ownership(graph):
    """The screen the launcher opened is the root of the world, at depth 0."""
    root = _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Continue")])
    assert root.ownership == "TARGET_APP"
    assert root.depth == 0
    assert root.state_id in graph.states


def test_system_ui_not_target(graph):
    assert in_investigation_scope("com.android.systemui", TARGET) is True
    assert in_investigation_scope("com.android.settings", TARGET) is False


def test_external_app_not_target(graph):
    """A foreign application never becomes a screen of the sample's graph."""
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Share")])
    state = _boundary(
        graph, "com.android.contacts/.ContactsActivity",
        [_node("n0", "Alice"), _node("n1", "Bob")],
        package="com.android.contacts",
        ownership="EXTERNAL_APP",
        semantic_type="EXTERNAL_APP",
    )
    assert state.state_id not in graph.states
    assert state.state_id in graph.external_states
    assert graph.coverage_metrics()["target_app_states_explored"] == 1


def test_settings_not_exploration_state(graph):
    """
    A generic Settings screen is recorded and left, never explored.

    The failure this guards against is not hypothetical: a measured 300s run
    answered 55 of 55 observations from com.android.settings and made zero
    observations of the sample.
    """
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Grant access")])
    state = _boundary(
        graph, "com.android.settings/.WifiSettingsActivity",
        [_node("n0", "Wi-Fi"), _node("n1", "Bluetooth"), _node("n2", "Display")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    assert state.state_id not in graph.states
    # The decisive assertion: no action inventory was built, so not one of
    # those Settings rows can ever be selected.
    assert state.actionable_elements == []


def test_no_settings_exploration_consumes_no_actions(graph):
    """Settings contributes nothing to the target-app action count."""
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Go")])
    for i in range(5):
        _boundary(
            graph, f"com.android.settings/.Page{i}",
            [_node("n0", f"Setting {i}"), _node("n1", "Next")],
            package="com.android.settings",
            ownership="SYSTEM_SETTINGS",
            semantic_type="SETTINGS",
        )
    metrics = graph.coverage_metrics()
    assert metrics["target_app_states_explored"] == 1
    assert metrics["target_app_actions_executed"] == 0


# ─── Boundary evidence ───────────────────────────────────────────────────────

def test_accessibility_boundary(graph):
    """
    Accessibility Settings is recorded as a request and the branch stops.

    §P4: the run's job here is to say the sample asked for accessibility, not
    to go and grant it by walking Settings.
    """
    root = _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Enable")])
    _boundary(
        graph, "com.android.settings/.AccessibilitySettingsActivity",
        [_node("n0", "Installed services")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    assert len(graph.boundary_events) == 1
    event = graph.boundary_events[0]
    assert event["type"] == "EXTERNAL_BOUNDARY_REACHED"
    assert event["reason"] == BoundaryReason.ACCESSIBILITY_REQUEST.value
    assert event["target_package"] == TARGET
    assert event["foreground_package"] == "com.android.settings"
    assert event["previous_target_state"] == root.state_id
    assert event["branch_status"] == BranchStatus.BLOCKED_EXTERNAL.value


def test_install_unknown_apps_boundary(graph):
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Update")])
    _boundary(
        graph, "com.android.settings/.ManageAppExternalSourcesActivity",
        [_node("n0", "Allow from this source")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    assert graph.boundary_events[0]["reason"] == (
        BoundaryReason.INSTALL_SOURCE_REQUEST.value
    )


def test_settings_boundary_reason_is_not_guessed(graph):
    """An ordinary Settings page is reported as SETTINGS, nothing more."""
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Go")])
    _boundary(
        graph, "com.android.settings/.DisplaySettings",
        [_node("n0", "Brightness")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    assert graph.boundary_events[0]["reason"] == BoundaryReason.SETTINGS.value


def test_external_boundary_evidence_records_provenance(graph):
    """Every field an analyst needs to reconstruct the departure is present."""
    _target(graph, f"{TARGET}/.MainActivity", [_node("n0", "Pay")])
    _boundary(
        graph, "com.android.chrome/.Main", [_node("n0", "Search")],
        package="com.android.chrome",
        ownership="EXTERNAL_APP",
        semantic_type="EXTERNAL_APP",
    )
    event = graph.boundary_events[0]
    for key in (
        "timestamp", "target_package", "foreground_package", "activity",
        "screen_type", "previous_target_state", "last_action", "depth",
        "reason", "screenshot_ref", "branch_status",
    ):
        assert key in event, f"boundary event is missing '{key}'"


def test_evidence_preserved_after_boundary(graph):
    """
    §P22 / §P25: what was collected before the departure stays collected.

    A boundary blocks a BRANCH. It must not be able to discard the states,
    edges or depth the run had already established.
    """
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Start")])
    _target(graph, f"{TARGET}/.Form", [_node("n0", "Name", is_input=True)])
    _target(graph, f"{TARGET}/.Otp", [_node("n0", "Verify")])
    before = graph.coverage_metrics()

    _boundary(
        graph, "com.android.settings/.AccessibilitySettings",
        [_node("n0", "Services")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    after = graph.coverage_metrics()

    assert after["target_app_states_explored"] == before["target_app_states_explored"]
    assert after["max_target_app_depth"] == before["max_target_app_depth"] == 2
    assert after["external_boundaries_reached"] == 1


def test_a_boundary_does_not_deadlock_the_scan(graph):
    """
    §P24: after a boundary, a target branch with work left is still reachable.

    This is the property that stops Settings from ending a run.
    """
    root = _target(
        graph, f"{TARGET}/.Main", [_node("n0", "A"), _node("n1", "B")],
    )
    _boundary(
        graph, "com.android.settings/.Accessibility", [_node("n0", "Services")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    assert graph.has_unexplored_work() is True
    assert graph._pending_state_id() == root.state_id


# ─── Depth ───────────────────────────────────────────────────────────────────

def test_depth_increment(graph):
    a = _target(graph, f"{TARGET}/.Main", [_node("n0", "Continue")])
    b = _target(graph, f"{TARGET}/.Details", [_node("n0", "Next")])
    c = _target(graph, f"{TARGET}/.Confirm", [_node("n0", "Submit")])
    assert (a.depth, b.depth, c.depth) == (0, 1, 2)
    assert graph.coverage_metrics()["max_target_app_depth"] == 2


def test_multiple_target_states(graph):
    for i in range(6):
        _target(graph, f"{TARGET}/.Screen{i}", [_node("n0", f"Go {i}")])
    assert graph.coverage_metrics()["target_app_states_explored"] == 6


def test_a_boundary_screen_does_not_increase_target_depth(graph):
    """
    Answering a permission prompt is a prerequisite, not progress.

    Without this a sample could inflate the run's headline metric simply by
    asking for permissions.
    """
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Continue")])
    _boundary(
        graph, "com.android.permissioncontroller/.GrantActivity",
        [_node("n0", "Allow")],
        package="com.android.permissioncontroller",
        ownership="SYSTEM_PERMISSION",
        semantic_type="SYSTEM_PERMISSION",
    )
    assert graph.coverage_metrics()["max_target_app_depth"] == 0


def test_depth_first_exploration_prefers_the_deepest_pending_state(graph):
    """
    §P13: a dead end resumes the deepest branch, not the oldest.

    Insertion order used to decide this, which sent the agent back to the
    launch screen every time a branch ended and made the walk breadth-first.
    """
    shallow = _target(graph, f"{TARGET}/.Main", [_node("n0", "A")])
    _target(graph, f"{TARGET}/.Mid", [_node("n0", "B")])
    deep = _target(graph, f"{TARGET}/.Deep", [_node("n0", "C")])
    assert deep.depth > shallow.depth
    assert graph._pending_state_id() == deep.state_id


def test_returning_to_a_known_screen_restores_its_depth(graph):
    """
    Depth is a property of the screen, not a high-water mark.

    A screen discovered after backtracking to the root is one deep, not one
    deeper than the deepest point the run has ever seen.
    """
    root_obs = _obs(f"{TARGET}/.Main", [_node("n0", "A")])
    graph.observe(
        root_obs, semantic_type="UNKNOWN",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    _target(graph, f"{TARGET}/.Mid", [_node("n0", "B")])
    _target(graph, f"{TARGET}/.Deep", [_node("n0", "C")])

    graph.observe(                       # back at the root
        root_obs, semantic_type="UNKNOWN",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    sibling = _target(graph, f"{TARGET}/.Sibling", [_node("n0", "D")])
    assert sibling.depth == 1


def test_branch_backtracking_stays_inside_the_target_app(graph):
    """
    §P19: back is a way of moving around inside the SAMPLE.

    Pressed from a system surface it is one step through somebody else's
    navigation stack, and a run that keeps pressing it is the Settings-recovery
    loop §P24 forbids. The boundary return path owns that case instead, so the
    graph asks for a relaunch rather than a back press.
    """
    _target(graph, f"{TARGET}/.Main", [_node("n0", "A")])
    _target(graph, f"{TARGET}/.Deep", [_node("n0", "B")])
    # Standing on a boundary screen admitted to the target graph.
    boundary = _boundary(
        graph, "com.android.permissioncontroller/.GrantActivity",
        [_node("n0", "Allow")],
        package="com.android.permissioncontroller",
        ownership="SYSTEM_PERMISSION",
        semantic_type="SYSTEM_PERMISSION",
    )
    graph._current_state_id = boundary.state_id

    assert graph._backtrack_action() is None
    assert graph._boundary_return_required is True
    # And the recovery it does offer is a relaunch of the sample, not a back.
    recovery = graph.get_next_action()
    assert recovery["tool"] == "start_activity"
    assert recovery["package"] == TARGET


# ─── Form state identity ─────────────────────────────────────────────────────

def _floating_label_form(filled: bool) -> List[UINode]:
    """
    A Material-style WebView form, as really dumped from a live e-challan APK.

    The caption is a separate non-input node rendered over the field, and it
    SHRINKS AND RISES when the field is filled - measured at 231x50 empty and
    194x42 filled.
    """
    field = UINode(
        node_id="f0", class_name="android.widget.EditText",
        text="Vikram Nair" if filled else "",
        desc="", resource_id="fullName",
        center_x=540, center_y=712, is_input=True, is_clickable=True,
        is_scrollable=False, bounds="[91,648][987,777]", hint="Full Name*",
    )
    label = UINode(
        node_id="l0", class_name="android.view.View", text="Full Name*",
        desc="", resource_id="",
        center_x=240, center_y=712, is_input=False, is_clickable=False,
        is_scrollable=False,
        bounds="[126,627][320,669]" if filled else "[126,687][357,737]",
    )
    return [field, label]


def test_filling_a_field_does_not_fork_a_floating_label_form():
    """
    A form must stay ONE state as it is filled.

    Excluding the typed value from state identity was not enough: the floating
    caption is a separate node, so its size change forked the screen on the
    first keystroke. Every fork rebuilt the action inventory with all fields
    unexplored, so a measured run re-filled field one five times and never
    reached fields three and four or the submit button - five states, one form,
    nothing completed.
    """
    empty = compute_composite_state_signature(
        f"{TARGET}/.MainActivity", TARGET, _floating_label_form(filled=False),
    )
    filled = compute_composite_state_signature(
        f"{TARGET}/.MainActivity", TARGET, _floating_label_form(filled=True),
    )
    assert empty == filled


def test_a_caption_that_really_changes_still_forks_the_state():
    """
    Only the floating label's GEOMETRY is discounted, never its text.

    "Sign in" becoming "Welcome back" is a real transition and has to stay one.
    """
    base = _floating_label_form(filled=False)
    changed = _floating_label_form(filled=False)
    changed[1].text = "Registered Name*"
    assert compute_composite_state_signature(
        f"{TARGET}/.MainActivity", TARGET, base,
    ) != compute_composite_state_signature(
        f"{TARGET}/.MainActivity", TARGET, changed,
    )


def test_a_form_keeps_its_fields_explored_across_a_refill_visit(graph):
    """
    The consequence that actually matters: progress survives.

    The fields already filled must not be offered again when the screen is
    re-observed, or the walk can never get to the submit button.
    """
    state = graph.observe(
        _obs(f"{TARGET}/.MainActivity", _floating_label_form(filled=False)),
        semantic_type="DATA_ENTRY_FORM",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    field = next(a for a in state.actionable_elements if a.action_type == "input")
    graph.record_action(
        state.state_id, state.state_id, "input", field.label,
        success=True, verified=True, action_id=field.action_id,
    )
    again = graph.observe(
        _obs(f"{TARGET}/.MainActivity", _floating_label_form(filled=True)),
        semantic_type="DATA_ENTRY_FORM",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    assert again.state_id == state.state_id
    assert not [
        a for a in again.actionable_elements
        if a.action_type == "input" and not a.resolved
    ]


def test_a_form_committed_by_an_affirmative_button_counts_as_completed(graph):
    """
    A real form's submit button is not always a submit VERB.

    The e-challan form commits with "Get Details" - no word any submit list
    contains, but semantic_role=ACCEPT and unambiguously the button that sends
    the form. It filled every box, pressed it twice, and still reported
    forms_completed=0.
    """
    nodes = _floating_label_form(filled=False) + [
        _node("btn", "Get Details"),
    ]
    state = graph.observe(
        _obs(f"{TARGET}/.MainActivity", nodes),
        semantic_type="DATA_ENTRY_FORM",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    field = next(a for a in state.actionable_elements if a.action_type == "input")
    graph.record_action(
        state.state_id, state.state_id, "input", field.label,
        success=True, verified=True, action_id=field.action_id,
    )
    button = next(
        a for a in state.actionable_elements if a.label == "Get Details"
    )
    button.semantic_role = "ACCEPT"
    graph.record_action(
        state.state_id, state.state_id, "click", "Get Details",
        success=True, verified=True, action_id=button.action_id,
    )
    assert graph.coverage_metrics()["target_app_forms_completed"] == 1


def test_an_affirmative_click_on_a_half_filled_form_is_not_a_completion(graph):
    """The filled-form guard is what keeps the role rule honest."""
    nodes = _floating_label_form(filled=False) + [_node("btn", "Get Details")]
    state = graph.observe(
        _obs(f"{TARGET}/.MainActivity", nodes),
        semantic_type="DATA_ENTRY_FORM",
        foreground_package=TARGET, ownership="TARGET_APP",
    )
    button = next(
        a for a in state.actionable_elements if a.label == "Get Details"
    )
    button.semantic_role = "ACCEPT"
    graph.record_action(
        state.state_id, state.state_id, "click", "Get Details",
        success=True, verified=True, action_id=button.action_id,
    )
    assert graph.coverage_metrics()["target_app_forms_completed"] == 0


# ─── Companion packages (launch hand-off) ────────────────────────────────────

def test_a_package_the_sample_launched_is_a_target_surface(graph):
    """
    A loader whose journey lives in a second package must be explorable.

    Measured on an e-challan sample: launching it started its process and,
    211ms later, `START cmp=<other>/.MainActivity from uid <sample>`. Without
    adoption the payload's screens are EXTERNAL_APP, get no action inventory,
    and the run reports that the app never rendered a screen while a four-field
    form sits on the emulator.
    """
    payload = "com.example.payload"
    graph.companion_packages.add(payload)
    state = graph.observe(
        _obs(f"{payload}/.MainActivity", [_node("n0", "Get Details")],
             package=payload),
        semantic_type="DATA_ENTRY_FORM",
        foreground_package=payload,
        ownership="EXTERNAL_APP",      # as classified BEFORE adoption
    )
    # Normalised by the graph, so the payload's first screen - usually its most
    # interesting - is not filed outside the target graph.
    assert state.ownership == "TARGET_APP"
    assert state.state_id in graph.states
    assert state.actionable_elements, "a companion screen must get an inventory"
    assert graph.coverage_metrics()["target_app_states_explored"] == 1


def test_an_unadopted_foreign_package_is_still_a_boundary(graph):
    """Adoption is opt-in evidence, not a blanket amnesty for foreign apps."""
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Share")])
    state = _boundary(
        graph, "com.android.chrome/.Main", [_node("n0", "Search")],
        package="com.android.chrome",
        ownership="EXTERNAL_APP", semantic_type="EXTERNAL_APP",
    )
    assert state.state_id in graph.external_states
    assert graph.coverage_metrics()["external_boundaries_reached"] == 1


# ─── Loops ───────────────────────────────────────────────────────────────────

def test_loop_detection(graph):
    a = _obs(f"{TARGET}/.A", [_node("n0", "toB")])
    b = _obs(f"{TARGET}/.B", [_node("n0", "toA")])
    for obs in (a, b, a, b):
        graph.observe(
            obs, semantic_type="UNKNOWN",
            foreground_package=TARGET, ownership="TARGET_APP",
        )
    assert len(graph.loop_events) == 1
    event = graph.loop_events[0]
    assert event["type"] == "LOOP_DETECTED"
    assert event["cycle_length"] == 2


def test_loop_reported_once_per_cycle_not_per_iteration(graph):
    """A ping-pong reports one loop, however long it ping-pongs."""
    a = _obs(f"{TARGET}/.A", [_node("n0", "toB")])
    b = _obs(f"{TARGET}/.B", [_node("n0", "toA")])
    for obs in (a, b) * 6:
        graph.observe(
            obs, semantic_type="UNKNOWN",
            foreground_package=TARGET, ownership="TARGET_APP",
        )
    assert graph.coverage_metrics()["loop_events"] == 1


def test_a_repeatedly_observed_single_screen_is_not_a_loop(graph):
    """A static screen is not a cycle; repeated-visit enforcement owns it."""
    a = _obs(f"{TARGET}/.A", [_node("n0", "Nothing")])
    for _ in range(8):
        graph.observe(
            a, semantic_type="UNKNOWN",
            foreground_package=TARGET, ownership="TARGET_APP",
        )
    assert graph.loop_events == []


# ─── Dynamic status ──────────────────────────────────────────────────────────

def test_dynamic_incomplete_when_the_victim_never_got_past_the_first_screen(graph):
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Login")])
    assert graph.dynamic_status() is DynamicStatus.INCOMPLETE


def test_dynamic_partial_after_a_boundary(graph):
    """
    Depth was reached and a branch was blocked: PARTIAL, not FAILED.

    §P25 is explicit that this must not collapse to a failure, and §P31 that
    it must never be read as the sample being safe.
    """
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Go")])
    _target(graph, f"{TARGET}/.Deep", [_node("n0", "More")])
    _boundary(
        graph, "com.android.settings/.Accessibility", [_node("n0", "Services")],
        package="com.android.settings",
        ownership="SYSTEM_SETTINGS",
        semantic_type="SETTINGS",
    )
    status = graph.dynamic_status()
    assert status is DynamicStatus.PARTIAL
    assert status.value == "DYNAMIC_PARTIAL"
    assert "SAFE" not in status.value


def test_dynamic_instrumentation_failed_is_distinct_from_no_behaviour(graph):
    """
    Nothing observed because nothing ran is not the same claim as nothing
    happened. Only the second says anything at all about the sample.
    """
    assert graph.dynamic_status(instrumentation_ok=False) is (
        DynamicStatus.INSTRUMENTATION_FAILED
    )
    _target(graph, f"{TARGET}/.Main", [])
    assert graph.dynamic_status() is DynamicStatus.NO_BEHAVIOR


def test_a_self_hiding_sample_is_incomplete_not_instrumentation_failure(graph):
    """
    A sample that backgrounds itself was observed; it just never showed a
    screen.

    Measured on a real sample that returns to the launcher on every relaunch.
    Reporting that as INSTRUMENTATION_FAILED would say the run learned nothing,
    when what it learned is that the app hides itself.
    """
    graph.observe(
        _obs("com.google.android.apps.nexuslauncher/.NexusLauncherActivity", []),
        semantic_type="HOME_LAUNCHER",
        foreground_package="com.google.android.apps.nexuslauncher",
        ownership="HOME_LAUNCHER",
    )
    assert graph.coverage_metrics()["target_app_states_explored"] == 0
    assert graph.dynamic_status(instrumentation_ok=False) is (
        DynamicStatus.INCOMPLETE
    )


# ─── Metrics ─────────────────────────────────────────────────────────────────

def test_every_documented_metric_is_reported(graph):
    """§P26 names these; a report that omits one cannot be graded against it."""
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Go")])
    metrics = graph.coverage_metrics()
    for key in (
        "max_target_app_depth",
        "target_app_states_explored",
        "target_app_branches_explored",
        "target_app_actions_executed",
        "target_app_forms_completed",
        "target_app_permissions_handled",
        "external_boundaries_reached",
        "blocked_branches",
        "completed_branches",
        "loop_events",
        "runtime_events",
    ):
        assert key in metrics, f"coverage metrics are missing '{key}'"


def test_target_metrics_exclude_external_states(graph):
    """
    The headline figure counts the sample's screens only.

    `states_discovered` deliberately folds in external screens and is left
    alone for compatibility; the target figure must not.
    """
    _target(graph, f"{TARGET}/.Main", [_node("n0", "Go")])
    for i in range(3):
        _boundary(
            graph, f"com.android.contacts/.C{i}", [_node("n0", f"c{i}")],
            package="com.android.contacts",
            ownership="EXTERNAL_APP",
            semantic_type="EXTERNAL_APP",
        )
    metrics = graph.coverage_metrics()
    assert metrics["target_app_states_explored"] == 1
    assert metrics["states_discovered"] == 4
