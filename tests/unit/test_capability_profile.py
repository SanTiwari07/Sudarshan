"""
Tests for the expected-capability model.

The load-bearing behaviour here is restraint: the module must stay silent when
it does not know what an app is, because a category we guessed and then judged
permissions against would manufacture findings out of our own uncertainty.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.capability_profile import (  # noqa: E402
    AppCategory,
    Expectation,
    build_profile,
    expectation_for,
    group_of,
    infer_category,
    is_special,
)

P = "android.permission."


# ── permission grouping ──────────────────────────────────────────────────────

@pytest.mark.parametrize("perm,group", [
    (P + "READ_SMS", "SMS"),
    (P + "CAMERA", "CAMERA"),
    (P + "BIND_ACCESSIBILITY_SERVICE", "ACCESSIBILITY"),
    (P + "SYSTEM_ALERT_WINDOW", "OVERLAY"),
    (P + "BIND_DEVICE_ADMIN", "DEVICE_ADMIN"),
    (P + "ACCESS_FINE_LOCATION", "LOCATION"),
])
def test_permissions_map_to_their_group(perm, group):
    assert group_of(perm) == group


def test_bare_permission_names_are_accepted():
    """MobSF and androguard disagree on qualification; callers should not care."""
    assert group_of("CAMERA") == "CAMERA"
    assert group_of("read_sms") == "SMS"


def test_an_unmodelled_permission_has_no_group():
    assert group_of(P + "SET_WALLPAPER") == ""
    assert group_of("") == ""


@pytest.mark.parametrize("perm", [
    P + "BIND_ACCESSIBILITY_SERVICE",
    P + "SYSTEM_ALERT_WINDOW",
    P + "BIND_DEVICE_ADMIN",
    P + "BIND_NOTIFICATION_LISTENER_SERVICE",
])
def test_settings_gated_permissions_are_special(perm):
    assert is_special(perm) is True


def test_runtime_dialog_permissions_are_not_special():
    assert is_special(P + "CAMERA") is False


# ── category inference ───────────────────────────────────────────────────────

def test_label_identifies_the_category():
    inf = infer_category("com.whatever.xyz", "Calculator")
    assert inf.category is AppCategory.CALCULATOR
    assert inf.confidence == "HIGH"
    assert inf.signals


def test_package_name_identifies_the_category_with_lower_confidence():
    inf = infer_category("com.example.calculator", "")
    assert inf.category is AppCategory.CALCULATOR
    assert inf.confidence == "MEDIUM"


def test_label_outranks_the_package_name():
    """
    The label is what the app claims to be to the user - the claim worth
    testing against observed behaviour.
    """
    inf = infer_category("com.evil.smsstealer", "Calculator")
    assert inf.category is AppCategory.CALCULATOR


def test_a_token_must_be_a_whole_word_not_a_substring():
    """"recalculation" must not read as a calculator."""
    assert infer_category("com.example.recalculation", "").category is AppCategory.UNKNOWN


def test_conflicting_signals_stay_unknown():
    """Two categories matched is not a reason to pick one."""
    inf = infer_category("com.example.camera", "Bank Messenger")
    assert inf.category is AppCategory.UNKNOWN
    assert "ambiguous" in inf.signals[0]


def test_no_signal_is_unknown_and_says_so():
    inf = infer_category("com.a.b", "")
    assert inf.category is AppCategory.UNKNOWN
    assert inf.signals


def test_permissions_alone_never_establish_a_category():
    """
    Deducing "SMS app" from SMS permissions and then calling those permissions
    expected would launder every SMS stealer into a messaging app.
    """
    inf = infer_category("com.a.b", "", [P + "READ_SMS", P + "RECEIVE_SMS"])
    assert inf.category is AppCategory.UNKNOWN


# ── expectations ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("perm", [
    P + "CAMERA", P + "READ_SMS", P + "RECEIVE_SMS",
    P + "BIND_ACCESSIBILITY_SERVICE", P + "SYSTEM_ALERT_WINDOW",
])
def test_the_brief_s_calculator_case(perm):
    """The worked example: none of these belong in a calculator."""
    assert expectation_for(AppCategory.CALCULATOR, perm) is Expectation.UNEXPECTED


def test_a_camera_app_needs_the_camera():
    assert expectation_for(AppCategory.CAMERA, P + "CAMERA") is Expectation.EXPECTED


def test_an_sms_app_needs_sms():
    assert expectation_for(AppCategory.MESSAGING, P + "READ_SMS") is Expectation.EXPECTED


def test_banking_apps_expect_network_and_biometrics():
    assert expectation_for(AppCategory.BANKING, P + "INTERNET") is Expectation.EXPECTED
    assert expectation_for(AppCategory.BANKING, P + "USE_BIOMETRIC") is Expectation.EXPECTED


def test_accessibility_is_unexpected_even_for_a_banking_app():
    """No category in the model legitimises Accessibility."""
    for category in AppCategory:
        if category is AppCategory.UNKNOWN:
            continue
        assert expectation_for(
            category, P + "BIND_ACCESSIBILITY_SERVICE"
        ) is Expectation.UNEXPECTED


def test_ubiquitous_permissions_are_plausible_not_unexpected():
    """Flagging INTERNET on every app produces noise, not findings."""
    assert expectation_for(AppCategory.CALCULATOR, P + "INTERNET") is Expectation.PLAUSIBLE
    assert expectation_for(AppCategory.CALCULATOR, P + "WAKE_LOCK") is Expectation.PLAUSIBLE


def test_everything_is_plausible_for_an_unknown_app():
    """Judging against a category we never established would invent findings."""
    for perm in (P + "READ_SMS", P + "CAMERA", P + "BIND_ACCESSIBILITY_SERVICE"):
        assert expectation_for(AppCategory.UNKNOWN, perm) is Expectation.PLAUSIBLE


def test_an_unmodelled_permission_is_plausible_not_unexpected():
    """Silence about a permission is our gap, not the app's fault."""
    assert expectation_for(AppCategory.CALCULATOR, P + "SET_WALLPAPER") is Expectation.PLAUSIBLE


# ── profile ──────────────────────────────────────────────────────────────────

def test_profile_lists_only_the_unexpected_permissions():
    profile = build_profile("com.example.calc", "Calculator")
    unexpected = profile.unexpected([
        P + "CAMERA", P + "READ_SMS", P + "INTERNET", P + "WAKE_LOCK",
    ])
    assert set(unexpected) == {P + "CAMERA", P + "READ_SMS"}


def test_profile_serialises_its_reasoning():
    profile = build_profile("com.example.calc", "Calculator")
    data = profile.to_dict()
    assert data["category"] == "CALCULATOR"
    assert data["confidence"] == "HIGH"
    assert data["signals"], "a category decision must carry why it was made"


def test_an_uncategorised_profile_reports_nothing_unexpected():
    profile = build_profile("com.a.b", "")
    assert profile.category is AppCategory.UNKNOWN
    assert profile.unexpected([P + "READ_SMS", P + "CAMERA"]) == []
