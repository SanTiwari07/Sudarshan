"""
Regression tests for credential handling and in-app evidence capture.

Written against the real shape of the banking corpus in tests/apks/VIDE_testapks:
WebView-hosted login screens whose EditText nodes carry no resource-id, no text
and no content-desc. The only signals available are uiautomator's `password`
attribute and the caption node rendered above the field. Every fixture here is
taken from an actual `uiautomator dump` of one of those apps.
"""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace as NS

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SHARED = os.path.join(_ROOT, "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

from sudarshan_core.engines.agentic.credentials import (  # noqa: E402
    CredentialVault,
    get_vault,
    login_rejected,
    login_succeeded_hint,
    resolve_field_kind,
)
from sudarshan_core.engines.agentic.exploration_engine import (  # noqa: E402
    ExplorationBudget,
    ExplorationGraph,
    _is_submit_label,
)
from sudarshan_core.engines.agentic.perception import PerceptionPipeline  # noqa: E402


TARGET = "com.baseline.sbi"
ACT = f"{TARGET}/.MainActivity"


def node(cls, text="", rid="", clickable=True, is_input=False, is_password=False,
         field_label="", bounds="[63,437][1018,555]", source="uiautomator"):
    return NS(
        node_id=f"{cls}-{rid}-{text}-{field_label}", class_name=cls, text=text,
        desc="", content_desc="", resource_id=rid, center_x=540, center_y=496,
        is_input=is_input, is_clickable=clickable, is_scrollable=False,
        is_checkable=False, enabled=True, checked=None, bounds=bounds,
        semantic_role="UNKNOWN", detection_source=source, confidence=0.99,
        is_password=is_password, field_label=field_label,
    )


def webview_login():
    """The SBI baseline login screen, as uiautomator reports it."""
    return [
        node("android.widget.EditText", is_input=True, field_label="Username"),
        node("android.widget.EditText", is_input=True, is_password=True,
             field_label="Password", bounds="[63,616][1018,734]"),
        node("android.widget.Button", text="Login", bounds="[63,794][1018,920]"),
        node("android.widget.Button", text="Forgot MPIN?",
             bounds="[63,2012][1018,2141]"),
    ]


def obs(nodes, activity=ACT, xml=""):
    return NS(ui_nodes=nodes, activity=activity, is_webview=True, ui_xml_raw=xml)


# ─── Field identification ────────────────────────────────────────────────────

class TestFieldKind(unittest.TestCase):

    def test_password_attribute_is_authoritative(self):
        """The only signal that separates the two boxes on a WebView form."""
        self.assertEqual(
            resolve_field_kind(field_label="", is_password=True, index=1),
            "password",
        )

    def test_caption_identifies_the_identifier_field(self):
        for caption in ("Username", "User ID", "Customer ID", "CRN / Customer ID",
                        "Login ID"):
            with self.subTest(caption=caption):
                self.assertEqual(
                    resolve_field_kind(field_label=caption, index=0), "username")

    def test_corpus_captions_resolve(self):
        cases = {
            "Mobile Number / Customer ID": "phone",
            "Login Password": "password",
            "Enter OTP": "otp",
            "Email address": "email",
            "Amount": "amount",
        }
        for caption, expected in cases.items():
            with self.subTest(caption=caption):
                self.assertEqual(
                    resolve_field_kind(field_label=caption, index=0), expected)

    def test_resource_id_used_when_no_caption(self):
        self.assertEqual(
            resolve_field_kind(resource_id="loginscreen_username", index=0),
            "username")
        self.assertEqual(
            resolve_field_kind(resource_id="loginscreen_password",
                               is_password=True, index=1),
            "password")

    def test_unlabelled_first_field_is_the_identifier(self):
        self.assertEqual(resolve_field_kind(index=0), "username")
        self.assertNotEqual(resolve_field_kind(index=1), "username")

    def test_two_fields_never_receive_the_same_value(self):
        """The defect that made login impossible: both fields got 'test'."""
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(webview_login()), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        kinds = [a.field_kind for a in st.actionable_elements
                 if a.action_type == "input"]
        self.assertEqual(kinds, ["username", "password"])

        vault = CredentialVault()
        self.assertNotEqual(vault.value_for("username"),
                            vault.value_for("password"))


# ─── Perception of WebView forms ─────────────────────────────────────────────

class TestWebViewPerception(unittest.TestCase):

    XML = """<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
 <node class="android.webkit.WebView" text="app" clickable="true" password="false"
       bounds="[0,128][1080,2337]">
  <node class="android.view.View" text="YONO SBI" clickable="false"
        password="false" bounds="[63,191][1018,290]" />
  <node class="android.view.View" text="Username" clickable="false"
        password="false" bounds="[63,372][1018,419]" />
  <node class="android.widget.EditText" text="" clickable="true"
        password="false" bounds="[63,437][1018,555]" />
  <node class="android.view.View" text="Password" clickable="false"
        password="false" bounds="[63,553][1018,597]" />
  <node class="android.widget.EditText" text="" clickable="true"
        password="true" bounds="[63,616][1018,734]" />
  <node class="android.widget.Button" text="Login" clickable="true"
        password="false" bounds="[63,794][1018,920]" />
  <node class="android.view.View" text="New user? Register" clickable="false"
        password="false" bounds="[63,2180][1018,2233]" />
 </node>
</hierarchy>"""

    def setUp(self):
        self.p = PerceptionPipeline(device_serial="x", package_name=TARGET)
        self.nodes = self.p._parse_ui_nodes(self.XML)

    def test_password_flag_is_parsed(self):
        pw = [n for n in self.nodes if n.is_password]
        self.assertEqual(len(pw), 1)
        self.assertTrue(pw[0].is_input)

    def test_caption_is_attached_to_its_field(self):
        inputs = [n for n in self.nodes if n.is_input]
        self.assertEqual([n.field_label for n in inputs], ["Username", "Password"])

    def test_static_text_is_not_promoted_through_the_page(self):
        """A clickable WebView must not make every heading a button."""
        labels = {n.text for n in self.nodes}
        self.assertNotIn("YONO SBI", labels)
        self.assertNotIn("New user? Register", labels)

    def test_real_controls_survive(self):
        labels = {n.text for n in self.nodes}
        self.assertIn("Login", labels)


# ─── Form completion order ───────────────────────────────────────────────────

class TestFormOrdering(unittest.TestCase):

    def test_fields_are_filled_before_submit(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(webview_login()), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        order = []
        for _ in range(4):
            a = g.get_next_action(st.state_id)
            if a is None:
                break
            order.append((a["tool"], a.get("field_hint") or a.get("text")))
            for item in st.actionable_elements:
                if item.action_id == a.get("_action_id"):
                    item.explored = True
        self.assertEqual(order[0], ("type_text", "username"))
        self.assertEqual(order[1], ("type_text", "password"))
        self.assertEqual(order[2][0], "click_text")
        self.assertEqual(order[2][1], "Login")

    def test_submit_label_matching_is_word_bounded(self):
        """'Forgot MPIN?' contains 'go'; it is not a submit control."""
        self.assertTrue(_is_submit_label("Login"))
        self.assertTrue(_is_submit_label("Continue"))
        self.assertFalse(_is_submit_label("Forgot MPIN?"))
        self.assertFalse(_is_submit_label("Forgot Password?"))
        self.assertFalse(_is_submit_label("New user? Register"))
        self.assertFalse(_is_submit_label("Open a Digital Account"))

    def test_field_hint_reaches_the_action(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(webview_login()), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        a = g.get_next_action(st.state_id)
        self.assertEqual(a["field_hint"], "username")


# ─── Login retry ─────────────────────────────────────────────────────────────

class TestLoginRetry(unittest.TestCase):

    def _login_state(self):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(webview_login()), semantic_type="BANK_LOGIN",
                       foreground_package=TARGET)
        for a in st.actionable_elements:
            a.explored = True
        g.note_login_attempt(st.state_id)
        return g, st

    def test_silence_triggers_a_retry_with_new_credentials(self):
        """The directive: do not stop until the app says the details are wrong."""
        g, st = self._login_state()
        before = dict(get_vault(TARGET).values)
        outcome = g.note_login_outcome("", st.state_id, activity_changed=False)
        self.assertEqual(outcome, "retry")
        self.assertTrue(st.unexplored_actions(), "form was not re-armed")
        self.assertNotEqual(get_vault(TARGET).values["password"],
                            before["password"])

    def test_explicit_rejection_stops_retrying(self):
        g, st = self._login_state()
        outcome = g.note_login_outcome(
            "Invalid credentials. Please try again.", st.state_id,
            activity_changed=False)
        self.assertEqual(outcome, "rejected")
        self.assertEqual(g.login_outcome, "rejected")
        self.assertEqual(st.unexplored_actions(), [],
                         "form re-armed after an explicit rejection")

    def test_activity_change_counts_as_acceptance(self):
        g, st = self._login_state()
        outcome = g.note_login_outcome("", st.state_id, activity_changed=True)
        self.assertEqual(outcome, "accepted")

    def test_authenticated_landmark_counts_as_acceptance(self):
        g, st = self._login_state()
        outcome = g.note_login_outcome(
            "Available Balance 12,340.00  Fund Transfer  Log out",
            st.state_id, activity_changed=False)
        self.assertEqual(outcome, "accepted")

    def test_retries_are_bounded(self):
        g, st = self._login_state()
        for _ in range(ExplorationBudget.MAX_LOGIN_ATTEMPTS + 2):
            g.note_login_outcome("", st.state_id, activity_changed=False)
            g.login_attempts += 1
        self.assertEqual(g.login_outcome, "exhausted")

    def test_rejection_phrases_from_real_apps(self):
        for text in ("Invalid credentials", "Incorrect password",
                     "Login failed", "User not found",
                     "Authentication failed", "Username is invalid",
                     "Please enter valid credentials"):
            with self.subTest(text=text):
                self.assertTrue(login_rejected(text))

    def test_ordinary_screens_are_not_rejections(self):
        for text in ("Welcome to Vyom", "Enter your CRN or Customer ID",
                     "Forgot Password?", "Available Balance", ""):
            with self.subTest(text=text):
                self.assertFalse(login_rejected(text))

    def test_success_hints_do_not_fire_on_a_login_screen(self):
        self.assertFalse(login_succeeded_hint("Username Password Login"))


# ─── Single-Activity (WebView) navigation ────────────────────────────────────

class TestWebViewBackNavigation(unittest.TestCase):
    """
    Back pops the Activity. In a one-Activity WebView app that means leaving.

    Every app in the corpus renders its whole journey in one WebView, so the
    signed-in screen shares an activity name with the login screen. A measured
    run reached the post-login keypad, pressed back, and landed outside the
    sample with the session it had just obtained thrown away.
    """

    def test_back_is_refused_between_states_of_one_activity(self):
        g = ExplorationGraph(package_name=TARGET)
        login = g.observe(obs(webview_login()), semantic_type="BANK_LOGIN",
                          foreground_package=TARGET)
        inside = g.observe(
            obs([node("android.widget.Button", text=str(d),
                      bounds=f"[{d * 60},900][{d * 60 + 100},1000]")
                 for d in range(1, 6)]),
            semantic_type="UNKNOWN", foreground_package=TARGET,
            parent_state_id=login.state_id,
        )
        self.assertEqual(inside.activity_name, login.activity_name)
        for a in inside.actionable_elements:
            a.explored = True
        g._current_state_id = inside.state_id

        action = g.get_next_action(inside.state_id)
        self.assertTrue(
            action is None or action["tool"] != "press_back",
            f"pressed back out of a single-Activity app: {action}",
        )

    def test_back_still_allowed_across_real_activities(self):
        g = ExplorationGraph(package_name=TARGET)
        root = g.observe(
            obs([node("android.widget.Button", text="Open", rid="open"),
                 node("android.widget.Button", text="Other", rid="other")],
                activity=f"{TARGET}/.MainActivity"),
            semantic_type="UNKNOWN", foreground_package=TARGET)
        child = g.observe(
            obs([node("android.widget.Button", text="Deep", rid="deep")],
                activity=f"{TARGET}/.DetailActivity"),
            semantic_type="UNKNOWN", foreground_package=TARGET,
            parent_state_id=root.state_id)
        for a in child.actionable_elements:
            a.explored = True
        g._current_state_id = child.state_id

        action = g.get_next_action(child.state_id)
        self.assertIsNotNone(action)
        self.assertEqual(action["tool"], "press_back")


# ─── Numeric PIN pads ────────────────────────────────────────────────────────

class TestKeypadEntry(unittest.TestCase):
    """
    The MPIN pad behind the password login on most of the banking corpus.

    Explored one key per iteration it is a wall, not a screen: at the measured
    ~11s per action six digits cost a minute, and any detour in between clears
    the field so the pad never fills at all.
    """

    def _keypad(self, extra=()):
        keys = [
            node("android.widget.Button", text=str(d), rid=f"k{d}",
                 bounds=f"[{100 + d * 60},900][{150 + d * 60},960]")
            for d in range(10)
        ]
        return list(extra) + keys

    def _state(self, nodes):
        g = ExplorationGraph(package_name=TARGET)
        st = g.observe(obs(nodes), semantic_type="HOME",
                       foreground_package=TARGET)
        return g, st

    def test_keypad_is_detected(self):
        from sudarshan_core.engines.agentic.exploration_engine import (
            _is_keypad_state,
        )
        _, st = self._state(self._keypad(
            [node("android.widget.TextView", text="Enter MPIN", clickable=False)]))
        self.assertTrue(_is_keypad_state(st))

    def test_whole_pin_entered_in_one_action(self):
        from sudarshan_core.engines.agentic.exploration_engine import (
            PIN_ENTRY_LENGTH,
        )
        g, st = self._state(self._keypad())
        a = g.get_next_action(st.state_id)
        self.assertEqual(a["tool"], "tap_sequence")
        self.assertEqual(a["repeat"], PIN_ENTRY_LENGTH)
        self.assertEqual(a["_selected_by"], "keypad_entry")

    def test_pin_entry_happens_once_per_screen(self):
        """A PIN that is not accepted must not become an infinite loop."""
        g, st = self._state(self._keypad())
        first = g.get_next_action(st.state_id)
        second = g.get_next_action(st.state_id)
        self.assertEqual(first["tool"], "tap_sequence")
        self.assertNotEqual(second["tool"], "tap_sequence")

    def test_ordinary_screen_is_not_a_keypad(self):
        from sudarshan_core.engines.agentic.exploration_engine import (
            _is_keypad_state,
        )
        _, st = self._state([
            node("android.widget.Button", text="Accounts", rid="a"),
            node("android.widget.Button", text="1 Transfer", rid="b"),
            node("android.widget.Button", text="Settings", rid="c"),
        ])
        self.assertFalse(_is_keypad_state(st))

    def test_tap_sequence_is_registered_and_implemented(self):
        from sudarshan_core.engines.agentic.tool_registry import get_tool
        from sudarshan_core.engines.agentic.tool_executor import (
            NAVIGATIONAL_TOOLS, ToolExecutor,
        )
        self.assertIsNotNone(get_tool("tap_sequence"))
        self.assertTrue(hasattr(ToolExecutor, "_tool_tap_sequence"))
        self.assertIn("tap_sequence", NAVIGATIONAL_TOOLS)

    def test_keypad_action_is_not_overridden_by_the_planner(self):
        """
        The planner cannot express "enter a whole PIN", so it must not win here.

        A live run showed the planner's single `tap 1` beating the graph's
        `tap_sequence`: the pad never filled and the screen behind it was never
        reached - the AI silently reducing coverage.
        """
        from sudarshan_core.engines.agentic.action_dispatch import (
            select_canonical_action,
        )
        graph_action = {"tool": "tap_sequence", "text": "111111", "repeat": 6}
        planner_action = {"tool": "click_text", "text": "1", "_source": "ai"}
        chosen, by = select_canonical_action(graph_action, planner_action)
        self.assertEqual(chosen["tool"], "tap_sequence")
        self.assertEqual(by, "exploration_graph")

    def test_tap_sequence_repeat_is_bounded(self):
        import asyncio
        from sudarshan_core.engines.agentic.tool_executor import (
            MAX_TAP_SEQUENCE, ToolExecutor, ToolResult,
        )
        taps = []

        class _Executor(ToolExecutor):
            async def _input_tap(self, x, y):
                taps.append((x, y))
                return ToolResult(success=True, tool="tap")

        ex = _Executor(device_serial="emulator-5554", package_name=TARGET)
        asyncio.run(ex._tool_tap_sequence(
            {"x": 100, "y": 900, "repeat": 9999}))
        self.assertEqual(len(taps), MAX_TAP_SEQUENCE)


# ─── In-app evidence for VIDE ────────────────────────────────────────────────

class TestInAppHierarchiesReachVIDE(unittest.TestCase):
    """
    VIDE judges a clone on view structure, so it needs the screens BEHIND the
    login. It used to receive exactly one hierarchy - whichever screen the run
    ended on, which for a login-gated app is the login form: the one screen a
    clone and the app it imitates necessarily look alike on.
    """

    def test_all_state_hierarchies_are_collected(self):
        from sudarshan_core.engines.vide.pipeline import _dynamic_ui_hierarchies
        result = {
            "ui_hierarchies": [
                {"state_id": "STATE-001", "xml": "<hierarchy>login</hierarchy>"},
                {"state_id": "STATE-002", "xml": "<hierarchy>dashboard</hierarchy>"},
            ],
            "ui_hierarchy_xml": "<hierarchy>last</hierarchy>",
        }
        self.assertEqual(len(_dynamic_ui_hierarchies(result)), 3)

    def test_legacy_single_hierarchy_still_works(self):
        """A UIExplorer fallback run supplies only the old key."""
        from sudarshan_core.engines.vide.pipeline import _dynamic_ui_hierarchies
        out = _dynamic_ui_hierarchies({"ui_hierarchy_xml": "<hierarchy/>"})
        self.assertEqual(out, ["<hierarchy/>"])

    def test_duplicates_are_collapsed(self):
        from sudarshan_core.engines.vide.pipeline import _dynamic_ui_hierarchies
        out = _dynamic_ui_hierarchies({
            "ui_hierarchies": [{"xml": "<a/>"}],
            "ui_hierarchy_xml": "<a/>",
        })
        self.assertEqual(len(out), 1)

    def test_empty_result_is_safe(self):
        from sudarshan_core.engines.vide.pipeline import _dynamic_ui_hierarchies
        self.assertEqual(_dynamic_ui_hierarchies({}), [])

    def test_profile_uses_every_screen(self):
        """Strings from a post-login screen must reach the UI profile."""
        from sudarshan_core.engines.vide.pipeline import profile_from_dynamic_result
        profile = profile_from_dynamic_result({
            "ui_hierarchies": [
                {"state_id": "STATE-001", "xml":
                 '<hierarchy><node class="android.widget.Button" '
                 'text="Login"/></hierarchy>'},
                {"state_id": "STATE-002", "xml":
                 '<hierarchy><node class="android.widget.TextView" '
                 'text="Available Balance"/></hierarchy>'},
            ],
        })
        self.assertIn("Login", profile.strings)
        self.assertIn(
            "Available Balance", profile.strings,
            "post-login screen did not reach the VIDE profile",
        )


# ─── Credential hygiene ──────────────────────────────────────────────────────

class TestCredentialHygiene(unittest.TestCase):

    def test_values_differ_between_runs(self):
        a, b = CredentialVault(), CredentialVault()
        self.assertNotEqual(a.values["username"], b.values["username"])
        self.assertNotEqual(a.values["password"], b.values["password"])

    def test_values_are_stable_within_a_run(self):
        v = CredentialVault()
        self.assertEqual(v.value_for("password"), v.value_for("password"))

    def test_regenerate_changes_the_identity(self):
        v = CredentialVault()
        before = v.values["username"]
        v.regenerate()
        self.assertNotEqual(v.values["username"], before)

    def test_password_satisfies_common_policies(self):
        for _ in range(20):
            pw = CredentialVault().values["password"]
            self.assertGreaterEqual(len(pw), 8)
            self.assertTrue(any(c.isupper() for c in pw))
            self.assertTrue(any(c.islower() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw))

    def test_secrets_are_exposed_for_redaction(self):
        from sudarshan_core.engines.agentic.credentials import all_secret_values
        v = get_vault("com.example.redaction")
        self.assertIn(v.values["password"], all_secret_values())

    def test_generated_password_is_redacted_from_the_audit_log(self):
        """
        The static FORM_VALUES table is no longer the only source of secrets.

        Redacting it alone would have left every credential the run actually
        used sitting in plain text in audit_log.json.
        """
        from sudarshan_core.engines.agentic.audit_log import AuditLog
        v = get_vault("com.example.audit")
        secret = v.values["password"]
        safe = AuditLog._sanitize_action({"tool": "type_text", "text": secret})
        self.assertEqual(safe["text"], "[REDACTED_CREDENTIAL_VALUE]")

    def test_regenerated_password_is_still_redacted(self):
        from sudarshan_core.engines.agentic.audit_log import AuditLog
        v = get_vault("com.example.audit2")
        old_secret = v.values["password"]
        v.regenerate()
        safe = AuditLog._sanitize_action({"tool": "type_text", "text": old_secret})
        self.assertEqual(safe["text"], "[REDACTED_CREDENTIAL_VALUE]")

    def test_ordinary_text_is_not_redacted(self):
        from sudarshan_core.engines.agentic.audit_log import AuditLog
        safe = AuditLog._sanitize_action({"tool": "click_text", "text": "Login"})
        self.assertEqual(safe["text"], "Login")


if __name__ == "__main__":
    unittest.main(verbosity=2)
