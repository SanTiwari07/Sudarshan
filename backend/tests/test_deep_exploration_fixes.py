"""
Regression tests for the deep-exploration fixes.

Each test here corresponds to a defect proven by an instrumented run of the real
AgenticExplorer against a real emulator, not to a hypothesis. The measured
baseline the fixes were written against:

    21 iterations / 310s      (~14.8s each)
    34.3% exploration coverage
    5 structural states for ONE LoginActivity
    0 scroll actions executed (13 discovered)
    55/55 observations inside com.android.settings on an excursion
    STATE-001 visited 17 times against MAX_REPEATED_STATE_VISITS=5

Run with either runner:
    python -m pytest backend/tests/test_deep_exploration_fixes.py
    python -m unittest backend.tests.test_deep_exploration_fixes
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace as NS

_SHARED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "shared",
)
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from sudarshan_core.engines.agentic.exploration_engine import (  # noqa: E402
    ExplorationBudget,
    ExplorationGraph,
    _is_decorative_label,
    compute_composite_state_signature,
)
from sudarshan_core.engines.agentic.perception import (  # noqa: E402
    in_investigation_scope,
)
from sudarshan_core.engines.agentic.action_dispatch import (  # noqa: E402
    ActionDispatcher,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

def node(
    cls="android.widget.Button",
    text="",
    desc="",
    rid="",
    clickable=True,
    scrollable=False,
    is_input=False,
    enabled=True,
    checkable=False,
    bounds="[0,0][320,120]",
    source="uiautomator",
    node_id=None,
):
    """A UINode-shaped stand-in carrying only what the graph reads."""
    return NS(
        node_id=node_id or f"n-{rid or text or cls}",
        class_name=cls,
        text=text,
        desc=desc,
        content_desc=desc,
        resource_id=rid,
        center_x=160,
        center_y=60,
        is_input=is_input,
        is_clickable=clickable,
        is_scrollable=scrollable,
        is_checkable=checkable,
        enabled=enabled,
        checked=None,
        bounds=bounds,
        semantic_role="UNKNOWN",
        detection_source=source,
        confidence=0.99,
    )


def obs(nodes, activity, webview=False):
    return NS(ui_nodes=nodes, activity=activity, is_webview=webview)


def login_screen(username="", password=""):
    return [
        node("android.widget.EditText", text=username,
             rid="loginscreen_username", is_input=True, bounds="[0,200][320,280]"),
        node("android.widget.EditText", text=password,
             rid="loginscreen_password", is_input=True, bounds="[0,300][320,380]"),
        node("android.widget.Button", text="Login", rid="login_button",
             bounds="[0,400][320,480]"),
    ]


TARGET = "com.android.insecurebankv2"
LOGIN = f"{TARGET}/.LoginActivity"


# ─── P0-2: structural state identity ─────────────────────────────────────────

class TestStateIdentity(unittest.TestCase):
    """Typing must not fork a screen; different screens must stay different."""

    def test_typing_does_not_fork_state(self):
        g = ExplorationGraph(package_name=TARGET)
        s1 = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        s2 = g.observe(obs(login_screen(username="dinesh"), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        s3 = g.observe(obs(login_screen(username="dinesh", password="hunter2"), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)

        self.assertEqual(s1.state_id, s2.state_id)
        self.assertEqual(s2.state_id, s3.state_id)
        self.assertEqual(len(g.states), 1, f"forked into {list(g.states)}")

    def test_typing_preserves_explored_flags(self):
        """The whole point: work done on a screen survives typing into it."""
        g = ExplorationGraph(package_name=TARGET)
        s = g.observe(obs(login_screen(), LOGIN),
                      semantic_type="BANK_LOGIN", foreground_package=TARGET)
        for a in s.actionable_elements:
            a.explored = True
            a.verified = True
        self.assertEqual(len(s.unexplored_actions()), 0)

        after = g.observe(obs(login_screen(username="dinesh"), LOGIN),
                          semantic_type="BANK_LOGIN", foreground_package=TARGET)
        self.assertEqual(after.state_id, s.state_id)
        self.assertEqual(
            len(after.unexplored_actions()), 0,
            "typing resurrected already-explored actions",
        )

    def test_input_value_changes_do_not_create_unbounded_state_growth(self):
        """Character-by-character entry must not grow states or the inventory."""
        g = ExplorationGraph(package_name=TARGET)
        typed = ""
        for ch in "correcthorsebatterystaple":
            typed += ch
            g.observe(obs(login_screen(username=typed), LOGIN),
                      semantic_type="BANK_LOGIN", foreground_package=TARGET)

        self.assertEqual(len(g.states), 1, f"{len(g.states)} states for one screen")
        only = next(iter(g.states.values()))
        self.assertEqual(
            len(only.actionable_elements), 3,
            "action inventory grew with each keystroke: "
            f"{[a.label for a in only.actionable_elements]}",
        )

    def test_distinct_screens_still_distinct(self):
        """Over-merging is the opposite failure and must not happen."""
        g = ExplorationGraph(package_name=TARGET)
        login = g.observe(obs(login_screen(), LOGIN),
                          semantic_type="BANK_LOGIN", foreground_package=TARGET)
        prefs = g.observe(
            obs([node("android.widget.Button", text="Submit", rid="submitPref_button"),
                 node("android.widget.EditText", text="10.0.2.2",
                      rid="edittext_serverip", is_input=True)],
                f"{TARGET}/.FilePrefActivity"),
            semantic_type="UNKNOWN", foreground_package=TARGET,
        )
        self.assertNotEqual(login.state_id, prefs.state_id)
        self.assertEqual(len(g.states), 2)

    def test_real_activity_transition_creates_new_state(self):
        g = ExplorationGraph(package_name=TARGET)
        a = g.observe(obs(login_screen(), LOGIN),
                      semantic_type="BANK_LOGIN", foreground_package=TARGET)
        b = g.observe(obs(login_screen(), f"{TARGET}/.TransferActivity"),
                      semantic_type="UNKNOWN", foreground_package=TARGET)
        self.assertNotEqual(a.state_id, b.state_id)

    def test_non_input_text_change_is_still_a_new_state(self):
        """A label change is a real transition and must not be merged away."""
        before = compute_composite_state_signature(
            LOGIN, TARGET, [node("android.widget.TextView", text="Sign in")])
        after = compute_composite_state_signature(
            LOGIN, TARGET, [node("android.widget.TextView", text="Welcome back")])
        self.assertNotEqual(before[0], after[0])

    def test_structural_change_is_a_new_state(self):
        """Same texts, different affordances -> different state."""
        enabled = compute_composite_state_signature(
            LOGIN, TARGET, [node(text="Login", rid="login_button", enabled=True)])
        disabled = compute_composite_state_signature(
            LOGIN, TARGET, [node(text="Login", rid="login_button", enabled=False)])
        self.assertNotEqual(enabled[0], disabled[0])


# ─── P0-3: Settings is not target work ───────────────────────────────────────

class TestBoundaryModel(unittest.TestCase):

    def _settings_state(self, graph, semantic_type="SETTINGS"):
        nodes = [node(text=f"Setting {i}", rid=f"opt{i}") for i in range(18)]
        return graph.observe(
            obs(nodes, "com.android.settings/.spa.SpaActivity"),
            semantic_type=semantic_type,
            foreground_package="com.android.settings",
            ownership="SYSTEM_SETTINGS",
        )

    def test_settings_is_not_a_target_state(self):
        g = ExplorationGraph(package_name=TARGET)
        st = self._settings_state(g)
        self.assertNotIn(st.state_id, g.states,
                         "Android Settings was admitted as target work")
        self.assertIn(st.state_id, g.external_states)

    def test_settings_generic_screen_is_out_of_scope(self):
        self.assertFalse(
            in_investigation_scope("com.android.settings", TARGET,
                                   screen_type="SETTINGS"),
            "out-of-scope recovery would never arm for Settings",
        )

    def test_permission_dialog_is_still_explorable(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([node(text="Allow"), node(text="Deny")],
                "com.android.permissioncontroller/.GrantPermissionsActivity"),
            semantic_type="SYSTEM_PERMISSION",
            foreground_package="com.android.permissioncontroller",
            ownership="SYSTEM_PERMISSION",
        )
        self.assertIn(st.state_id, g.states)
        self.assertGreaterEqual(len(st.unexplored_actions()), 2)
        self.assertTrue(
            in_investigation_scope("com.android.permissioncontroller", TARGET))

    def test_package_installer_is_still_explorable(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([node(text="Install"), node(text="Cancel")],
                "com.android.packageinstaller/.PackageInstallerActivity"),
            semantic_type="PACKAGE_INSTALLER",
            foreground_package="com.android.packageinstaller",
            ownership="SYSTEM_INSTALLER",
        )
        self.assertIn(st.state_id, g.states)
        labels = {a.label for a in st.unexplored_actions()}
        self.assertIn("Install", labels)

    def test_accessibility_prompt_inside_settings_is_explorable(self):
        """INVARIANT 4: the consent flow Settings hosts must still work."""
        g = ExplorationGraph(package_name=TARGET)
        st = self._settings_state(g, semantic_type="ACCESSIBILITY_DIALOG")
        self.assertIn(st.state_id, g.states)
        self.assertTrue(
            in_investigation_scope("com.android.settings", TARGET,
                                   screen_type="ACCESSIBILITY_DIALOG"))

    def test_vpn_prompt_inside_settings_is_explorable(self):
        g = ExplorationGraph(package_name=TARGET)
        st = self._settings_state(g, semantic_type="VPN_REQUEST")
        self.assertIn(st.state_id, g.states)


# ─── P1: bounded boundary excursion ──────────────────────────────────────────

class TestBoundedBoundaryExcursion(unittest.TestCase):

    def _enter_installer(self, g):
        return g.observe(
            obs([node(text="Install"), node(text="Cancel"), node(text="More")],
                "com.android.packageinstaller/.PackageInstallerActivity"),
            semantic_type="PACKAGE_INSTALLER",
            foreground_package="com.android.packageinstaller",
            ownership="SYSTEM_INSTALLER",
        )

    def test_boundary_excursion_is_bounded(self):
        g = ExplorationGraph(package_name=TARGET)
        st = self._enter_installer(g)
        for i in range(ExplorationBudget.MAX_BOUNDARY_ACTIONS):
            g.record_action(st.state_id, st.state_id, "click", f"probe{i}",
                            success=True, ui_changed=False)
        self.assertTrue(g._boundary_return_required)

    def test_boundary_limit_returns_to_target(self):
        """INVARIANT 7: the explorer must come back, deterministically."""
        g = ExplorationGraph(package_name=TARGET)
        st = self._enter_installer(g)
        for i in range(ExplorationBudget.MAX_BOUNDARY_ACTIONS):
            g.record_action(st.state_id, st.state_id, "click", f"probe{i}",
                            success=True, ui_changed=False)

        action = g.get_next_action(st.state_id)
        self.assertIsNotNone(action)
        self.assertEqual(action["tool"], "start_activity")
        self.assertEqual(action["package"], TARGET)
        self.assertEqual(action["_selected_by"], "boundary_return")
        self.assertEqual(g.boundary_returns, 1)

    def test_return_action_is_executable_by_the_tool(self):
        """
        The route home must be a payload start_activity actually accepts.

        A first cut emitted only {"tool": "start_activity", "package": ...};
        `am start` needs a component, so every return failed with "At least one
        of action, component, or data_uri required" and a live run issued 28
        futile returns while stuck in Settings. The tool now launches by package
        via the launcher intent, and this test pins that contract.
        """
        import asyncio
        from sudarshan_core.engines.agentic.tool_executor import ToolExecutor

        g = ExplorationGraph(package_name=TARGET)
        st = self._enter_installer(g)
        for i in range(ExplorationBudget.MAX_BOUNDARY_ACTIONS):
            g.record_action(st.state_id, st.state_id, "click", f"probe{i}",
                            success=True, ui_changed=False)
        action = g.get_next_action(st.state_id)

        calls = []

        class _Executor(ToolExecutor):
            async def _adb(self, *args, **kwargs):
                calls.append(args)
                return True, ""

        ex = _Executor(device_serial="emulator-5554", package_name=TARGET)
        result = asyncio.run(ex.execute(action))

        self.assertTrue(result.success, result.error)
        self.assertTrue(calls, "start_activity issued no ADB command")
        self.assertIn(TARGET, " ".join(calls[0]))

    def test_boundary_under_budget_still_explores(self):
        """A prompt answered in one or two taps must not be cut short."""
        g = ExplorationGraph(package_name=TARGET)
        st = self._enter_installer(g)
        g.record_action(st.state_id, st.state_id, "click", "Cancel",
                        success=True, ui_changed=False)
        self.assertFalse(g._boundary_return_required)
        action = g.get_next_action(st.state_id)
        self.assertIsNotNone(action)
        self.assertNotEqual(action.get("_selected_by"), "boundary_return")

    def test_target_actions_never_charged_to_a_boundary(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        for i in range(10):
            g.record_action(st.state_id, st.state_id, "click", f"x{i}",
                            success=True, ui_changed=True)
        self.assertFalse(g._boundary_return_required)
        self.assertEqual(g._boundary_actions, {})


# ─── P1: scroll fairness ─────────────────────────────────────────────────────

class TestScrollFairness(unittest.TestCase):

    def _scrollable_screen(self):
        return [
            node("android.widget.ScrollView", rid="container", scrollable=True,
                 clickable=False, bounds="[0,0][320,600]"),
            node(text="Alpha", rid="a"),
            node(text="Beta", rid="b"),
            node(text="Gamma", rid="c"),
        ]

    def test_scroll_action_is_discovered(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(self._scrollable_screen(), LOGIN),
                       semantic_type="UNKNOWN", foreground_package=TARGET)
        self.assertTrue(any(a.action_type == "scroll"
                            for a in st.actionable_elements))

    def test_scroll_eventually_selected_after_repeated_visits(self):
        """INVARIANT 5: clicks must not starve scroll forever."""
        g = ExplorationGraph(package_name=TARGET)
        nodes = self._scrollable_screen()
        st = g.observe(obs(nodes, LOGIN), semantic_type="UNKNOWN",
                       foreground_package=TARGET)

        tools = []
        for _ in range(6):
            g.observe(obs(nodes, LOGIN), semantic_type="UNKNOWN",
                      foreground_package=TARGET)
            action = g.get_next_action(st.state_id)
            if action is None:
                break
            tools.append(action["tool"])
            # Resolve whatever was chosen so the walk advances.
            g.record_action(st.state_id, st.state_id,
                            "scroll" if action["tool"] == "scroll" else "click",
                            action.get("text", ""), success=True,
                            ui_changed=True,
                            action_id=action.get("_action_id", ""))
        self.assertIn("scroll", tools,
                      f"scroll never selected across visits; got {tools}")

    def test_clicks_lead_on_first_contact(self):
        """Fairness must not become 'scroll first, always'."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(self._scrollable_screen(), LOGIN),
                       semantic_type="UNKNOWN", foreground_package=TARGET)
        first = g.get_next_action(st.state_id)
        self.assertIsNotNone(first)
        self.assertNotEqual(first["tool"], "scroll")


# ─── P1: repeated-visit enforcement ──────────────────────────────────────────

class TestRepeatedStateVisits(unittest.TestCase):

    def test_repeated_state_visits_enforced(self):
        """INVARIANT 6: a sticky screen must not absorb the budget."""
        g = ExplorationGraph(package_name=TARGET)
        parent_nodes = [node(text="Open", rid="open"), node(text="Other", rid="other")]
        parent = g.observe(obs(parent_nodes, f"{TARGET}/.MainActivity"),
                           semantic_type="UNKNOWN", foreground_package=TARGET)

        sticky_nodes = [node(text=f"Btn{i}", rid=f"b{i}") for i in range(6)]
        sticky = g.observe(obs(sticky_nodes, LOGIN), semantic_type="BANK_LOGIN",
                           foreground_package=TARGET,
                           parent_state_id=parent.state_id)

        for _ in range(ExplorationBudget.MAX_REPEATED_STATE_VISITS + 2):
            g.observe(obs(sticky_nodes, LOGIN), semantic_type="BANK_LOGIN",
                      foreground_package=TARGET)

        self.assertGreater(sticky.visit_count,
                           ExplorationBudget.MAX_REPEATED_STATE_VISITS)
        action = g.get_next_action(sticky.state_id)
        self.assertIsNotNone(action, "enforcement must divert, never terminate")
        self.assertEqual(action["goal"], "BACKTRACK")

    def test_backtrack_never_presses_back_from_the_current_state(self):
        """
        Backtracking "to" the state you are on means leaving it.

        A live run diverted a sticky LoginActivity to its own state id, pressed
        back from the sample's root Activity, landed outside the app, and spent
        190s of a 300s window stranded on the launcher with 8 actions pending.
        """
        g = ExplorationGraph(package_name=TARGET)
        nodes = [node(text=f"Btn{i}", rid=f"b{i}") for i in range(4)]
        st = g.observe(obs(nodes, LOGIN), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        # Root state is its own parent on the stack, as a re-entrant walk leaves it.
        g._backtrack_stack.append(st.state_id)
        g._current_state_id = st.state_id

        self.assertIsNone(
            g._backtrack_action(),
            "pressed back from the state the device is already on",
        )

    def test_route_replay_reaches_pending_state_from_the_root(self):
        """
        A fully explored root must re-drive a proven route, not sit and scroll.

        Mirrors the live topology: root -'More options'-> menu -'Preferences'->
        FilePrefActivity. A measured run stranded on the root issued 37 fallback
        scrolls while FilePrefActivity still held six unexplored actions.
        """
        g = ExplorationGraph(package_name=TARGET)
        root = g.observe(obs([node(text="More options", rid="more"),
                              node(text="Login", rid="login")], LOGIN),
                         semantic_type="BANK_LOGIN", foreground_package=TARGET)
        menu = g.observe(obs([node(text="Preferences", rid="prefs")],
                             f"{TARGET}/.LoginActivity#menu"),
                         semantic_type="BANK_LOGIN", foreground_package=TARGET)
        prefs = g.observe(obs([node(text="Submit", rid="submit"),
                               node(text="Reset", rid="reset")],
                              f"{TARGET}/.FilePrefActivity"),
                          semantic_type="UNKNOWN", foreground_package=TARGET)

        more = next(a for a in root.actionable_elements if a.label == "More options")
        pref = next(a for a in menu.actionable_elements if a.label == "Preferences")
        g.record_action(root.state_id, menu.state_id, "click", "More options",
                        success=True, ui_changed=True, action_id=more.action_id)
        g.record_action(menu.state_id, prefs.state_id, "click", "Preferences",
                        success=True, ui_changed=True, action_id=pref.action_id)

        # Root exhausted; prefs still pending.
        for a in root.actionable_elements:
            a.explored = True
        g._current_state_id = root.state_id

        action = g.get_next_action(root.state_id)
        self.assertIsNotNone(action, "stranded on an exhausted root")
        self.assertNotEqual(action["tool"], "press_back")
        self.assertEqual(action["_selected_by"], "route_replay")
        self.assertEqual(action["text"], "More options")

    def test_route_replay_does_not_reresolve_the_edge_action(self):
        """Navigation must not be recorded as a fresh attempt at that action."""
        g = ExplorationGraph(package_name=TARGET)
        root = g.observe(obs([node(text="Open", rid="open")],
                             f"{TARGET}/.MainActivity"),
                         semantic_type="UNKNOWN", foreground_package=TARGET)
        deep = g.observe(obs([node(text="X", rid="x"), node(text="Y", rid="y")],
                             f"{TARGET}/.DeepActivity"),
                         semantic_type="UNKNOWN", foreground_package=TARGET)
        opener = root.actionable_elements[0]
        g.record_action(root.state_id, deep.state_id, "click", "Open",
                        success=True, ui_changed=True, action_id=opener.action_id)
        for a in root.actionable_elements:
            a.explored = True
        g._current_state_id = root.state_id

        action = g.get_next_action(root.state_id)
        self.assertIsNotNone(action)
        self.assertNotIn("_action_id", action)

    def test_never_presses_back_from_the_target_root(self):
        """Back is the exit at a root Activity, not a graph edge."""
        g = ExplorationGraph(package_name=TARGET)
        root = g.observe(obs([node(text="Only", rid="only")], LOGIN),
                         semantic_type="BANK_LOGIN", foreground_package=TARGET)
        child = g.observe(obs([node(text="Deep", rid="deep")],
                              f"{TARGET}/.FilePrefActivity"),
                          semantic_type="UNKNOWN", foreground_package=TARGET,
                          parent_state_id=root.state_id)
        # Device walks back to the root; the child still holds pending work.
        g._current_state_id = root.state_id
        for a in root.actionable_elements:
            a.explored = True

        action = g.get_next_action(root.state_id)
        self.assertTrue(
            action is None or action["tool"] != "press_back",
            f"issued press_back from the app root: {action}",
        )
        self.assertTrue(child.unexplored_actions(), "child work vanished")

    def test_back_still_used_from_a_non_root_state(self):
        """The guard must not disable backtracking generally."""
        g = ExplorationGraph(package_name=TARGET)
        root = g.observe(obs([node(text="A", rid="a"), node(text="B", rid="b")],
                             f"{TARGET}/.MainActivity"),
                         semantic_type="UNKNOWN", foreground_package=TARGET)
        child = g.observe(obs([node(text="Deep", rid="deep")],
                              f"{TARGET}/.DeepActivity"),
                          semantic_type="UNKNOWN", foreground_package=TARGET,
                          parent_state_id=root.state_id)
        for a in child.actionable_elements:
            a.explored = True

        action = g.get_next_action(child.state_id)
        self.assertIsNotNone(action)
        self.assertEqual(action["tool"], "press_back")

    def test_sticky_root_state_keeps_working_rather_than_leaving_the_app(self):
        g = ExplorationGraph(package_name=TARGET)
        nodes = [node(text=f"Btn{i}", rid=f"b{i}") for i in range(4)]
        st = g.observe(obs(nodes, LOGIN), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        for _ in range(ExplorationBudget.MAX_REPEATED_STATE_VISITS + 3):
            g.observe(obs(nodes, LOGIN), semantic_type="BANK_LOGIN",
                      foreground_package=TARGET)
        g._backtrack_stack.append(st.state_id)

        action = g.get_next_action(st.state_id)
        self.assertIsNotNone(action)
        self.assertNotEqual(
            action["tool"], "press_back",
            "left a root Activity that still had unexplored actions",
        )

    def test_enforcement_does_not_terminate_when_nowhere_to_divert(self):
        """INVARIANT 1: no other option means keep working, not stop."""
        g = ExplorationGraph(package_name=TARGET)
        nodes = [node(text=f"Btn{i}", rid=f"b{i}") for i in range(4)]
        st = g.observe(obs(nodes, LOGIN), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        for _ in range(ExplorationBudget.MAX_REPEATED_STATE_VISITS + 3):
            g.observe(obs(nodes, LOGIN), semantic_type="BANK_LOGIN",
                      foreground_package=TARGET)

        action = g.get_next_action(st.state_id)
        self.assertIsNotNone(
            action,
            "terminated while a safe unexplored action was still reachable",
        )


# ─── P2: non-interactive text nodes ──────────────────────────────────────────

class TestActionInventoryFiltering(unittest.TestCase):

    def test_noninteractive_textview_not_actionable(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([
                node("android.widget.TextView", text="InsecureBankv2",
                     rid="action_bar_title", source="clickable_parent_recovery"),
                node("android.widget.Button", text="Login", rid="login_button"),
            ], LOGIN),
            semantic_type="BANK_LOGIN", foreground_package=TARGET,
        )
        labels = {a.label for a in st.actionable_elements}
        self.assertNotIn("InsecureBankv2", labels)
        self.assertIn("Login", labels)

    def test_form_label_not_actionable(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([
                node("android.widget.TextView", text="Server IP:",
                     rid="textview_serverip", source="clickable_parent_recovery"),
                node("android.widget.Button", text="Submit", rid="submitPref_button"),
            ], f"{TARGET}/.FilePrefActivity"),
            semantic_type="UNKNOWN", foreground_package=TARGET,
        )
        labels = {a.label for a in st.actionable_elements}
        self.assertNotIn("Server IP:", labels)
        self.assertIn("Submit", labels)

    def test_legitimate_text_button_survives(self):
        """A menu item reached by parent recovery is a real control."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([
                node("android.widget.TextView", text="Preferences", rid="title",
                     source="clickable_parent_recovery"),
                node("android.widget.TextView", text="Restart", rid="title",
                     source="clickable_parent_recovery"),
            ], LOGIN),
            semantic_type="BANK_LOGIN", foreground_package=TARGET,
        )
        labels = {a.label for a in st.actionable_elements}
        self.assertIn("Preferences", labels)
        self.assertIn("Restart", labels)

    def test_declared_clickable_textview_always_survives(self):
        """An app may legitimately make a TextView a button."""
        self.assertFalse(
            _is_decorative_label("InsecureBankv2", "action_bar_title", "uiautomator"))


# ─── P2: action resolution across transitions ────────────────────────────────

class TestActionResolutionAcrossTransition(unittest.TestCase):

    def test_successful_text_entry_is_explored_not_failed(self):
        """
        Text entry no longer moves the screen hash, so ui_changed cannot judge it.

        Without this, every accepted keystroke was recorded as a failed action:
        wrong in the report, and it kept the field pending instead of letting
        the walk move on to submitting the form.
        """
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        field = next(a for a in st.actionable_elements if a.action_type == "input")

        g.record_action(st.state_id, st.state_id, "type_text", field.label,
                        success=True, ui_changed=False, ever_ui_changed=False,
                        action_id=field.action_id)

        self.assertTrue(field.explored)
        self.assertFalse(field.failed)

    def test_successful_text_entry_records_a_success_edge(self):
        """The graph an analyst reads must not draw accepted input as failed."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        field = next(a for a in st.actionable_elements if a.action_type == "input")
        edge = g.record_action(st.state_id, st.state_id, "type_text", field.label,
                               success=True, verified=False, ui_changed=False,
                               action_id=field.action_id)
        self.assertEqual(edge.status, "success")

    def test_failed_text_entry_still_records_failure(self):
        """The exemption is for ADB success only, not for a failed keystroke."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        field = next(a for a in st.actionable_elements if a.action_type == "input")
        edge = g.record_action(st.state_id, st.state_id, "type_text", field.label,
                               success=False, ui_changed=False,
                               action_id=field.action_id)
        self.assertEqual(edge.status, "failed")

    def test_failed_click_still_marked_failed(self):
        """The input exemption must not excuse inert clicks."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(login_screen(), LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        btn = next(a for a in st.actionable_elements if a.label == "Login")
        g.record_action(st.state_id, st.state_id, "click", "Login",
                        success=True, verified=False, ui_changed=False,
                        ever_ui_changed=False, attempts=3,
                        action_id=btn.action_id)
        self.assertTrue(btn.failed)
        self.assertFalse(btn.verified)

    def test_action_resolution_after_state_transition(self):
        """Resolve on the source; leave the destination independently explorable."""
        g = ExplorationGraph(package_name=TARGET)
        a = g.observe(obs([node(text="Go", rid="go"), node(text="Stay", rid="stay")],
                          f"{TARGET}/.MainActivity"),
                      semantic_type="UNKNOWN", foreground_package=TARGET)
        go = next(x for x in a.actionable_elements if x.label == "Go")

        b = g.observe(obs([node(text="Deep1", rid="d1"), node(text="Deep2", rid="d2")],
                          f"{TARGET}/.DeepActivity"),
                      semantic_type="UNKNOWN", foreground_package=TARGET,
                      parent_state_id=a.state_id)

        g.record_action(a.state_id, b.state_id, "click", "Go",
                        success=True, ui_changed=True, action_id=go.action_id)

        self.assertTrue(go.explored, "source action not resolved")
        self.assertEqual(
            len(b.unexplored_actions()), 2,
            "destination actions were wrongly marked explored",
        )
        self.assertFalse(b.explored)

    def test_action_resolved_on_owner_when_source_is_stale(self):
        """A re-identified screen must not strand the action forever."""
        g = ExplorationGraph(package_name=TARGET)
        a = g.observe(obs([node(text="Go", rid="go")], f"{TARGET}/.MainActivity"),
                      semantic_type="UNKNOWN", foreground_package=TARGET)
        go = a.actionable_elements[0]

        # Caller names a state that does not own the action.
        g.record_action("STATE-999", a.state_id, "click", "Go",
                        success=True, ui_changed=True, action_id=go.action_id)
        self.assertTrue(go.explored)

    def test_admitted_boundary_actions_are_resolvable(self):
        """
        An installer prompt IS explored, so its actions must resolve.

        (Demoted-to-external states are deliberately created with an empty
        inventory - they are not explored, so there is nothing to resolve.)
        """
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([node(text="Install"), node(text="Cancel")],
                "com.android.packageinstaller/.PackageInstallerActivity"),
            semantic_type="PACKAGE_INSTALLER",
            foreground_package="com.android.packageinstaller",
            ownership="SYSTEM_INSTALLER",
        )
        self.assertIn(st.state_id, g.states)
        target = st.actionable_elements[0]
        g.record_action(st.state_id, st.state_id, "click", target.label,
                        success=True, ui_changed=True, action_id=target.action_id)
        self.assertTrue(target.explored)

    def test_demoted_settings_state_carries_no_explorable_work(self):
        """A demoted boundary must not add unexplored work to the graph."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(
            obs([node(text="Wifi", rid="w"), node(text="Bluetooth", rid="b")],
                "com.android.settings/.spa.SpaActivity"),
            semantic_type="SETTINGS", foreground_package="com.android.settings",
            ownership="SYSTEM_SETTINGS",
        )
        self.assertIn(st.state_id, g.external_states)
        self.assertEqual(st.actionable_elements, [])
        self.assertFalse(
            g.has_unexplored_work(),
            "Settings contributed unexplored work and would absorb the run",
        )


# ─── P1: retry economics ─────────────────────────────────────────────────────

class TestRetryBudget(unittest.TestCase):

    def test_geometry_trusted_action_carries_coordinates(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs([node(text="Login", rid="login_button")], LOGIN),
                       semantic_type="BANK_LOGIN", foreground_package=TARGET)
        action = g.get_next_action(st.state_id)
        self.assertTrue(action.get("_geometry_trusted"))
        self.assertIsNotNone(action.get("x"))

    def test_retry_after_geometry_falls_back_to_text(self):
        """Coordinates are what is in doubt, so escalation re-resolves by text."""
        d = ActionDispatcher()
        action = {
            "tool": "click_text", "text": "Login", "x": 160, "y": 60,
            "_geometry_trusted": True, "_action_id": "ACT-001",
        }
        retry = d.retry_payload(action, 1)
        self.assertIsNotNone(retry)
        self.assertEqual(retry["tool"], "click_text")
        self.assertNotIn("_geometry_trusted", retry)
        self.assertEqual(
            retry["_pipeline_debug"]["retry_strategy"], "text_after_geometry")

    def test_retry_ladder_unchanged_without_trusted_geometry(self):
        d = ActionDispatcher()
        retry = d.retry_payload(
            {"tool": "click_text", "text": "Login", "x": 10, "y": 20}, 1)
        self.assertEqual(retry["tool"], "tap")

    def test_noop_retry_budget_is_below_full_ladder(self):
        from sudarshan_core.engines.agentic_explorer import NOOP_RETRY_ATTEMPTS
        from sudarshan_core.engines.agentic.action_dispatch import (
            MAX_EXECUTION_ATTEMPTS,
        )
        self.assertLess(NOOP_RETRY_ATTEMPTS, MAX_EXECUTION_ATTEMPTS)
        self.assertGreaterEqual(NOOP_RETRY_ATTEMPTS, 2)


# ─── Config ──────────────────────────────────────────────────────────────────

class TestDeploymentBudget(unittest.TestCase):

    def test_compose_and_source_agree_on_duration(self):
        import re
        root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        compose = open(os.path.join(root, "docker-compose.yml"),
                       encoding="utf-8").read()
        m = re.search(
            r"FRIDA_ANALYSIS_DURATION=\$\{FRIDA_ANALYSIS_DURATION:-(\d+)\}", compose)
        self.assertIsNotNone(m, "compose no longer sets FRIDA_ANALYSIS_DURATION")
        self.assertGreaterEqual(
            int(m.group(1)), 300,
            "deployed dynamic-analysis window is shorter than the source default",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
