"""
SUDARSHAN - Rule-Based Semantic Screen Classifier
===================================================
Classifies Android UI screen states into security-relevant categories
without requiring external LLM API calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class ScreenType:
    BANK_LOGIN           = "BANK_LOGIN"
    OTP_SCREEN           = "OTP_SCREEN"
    #: A screen whose purpose is to collect several pieces of information -
    #: registration, KYC, personal details, a beneficiary. It has no name of
    #: its own before this: such screens carry none of the words the rules
    #: below look for, so they fell through to UNKNOWN and nothing downstream
    #: could model "a form that must be completed before it means anything".
    #: Distinct from BANK_LOGIN, which is credential entry and drives the
    #: authentication state; this is data entry and deliberately does not.
    DATA_ENTRY_FORM      = "DATA_ENTRY_FORM"
    ACCESSIBILITY_DIALOG = "ACCESSIBILITY_DIALOG"
    SYSTEM_PERMISSION    = "SYSTEM_PERMISSION"
    OVERLAY_ATTACK       = "OVERLAY_ATTACK"
    HOME                 = "HOME"
    HOME_LAUNCHER        = "HOME_LAUNCHER"
    SETTINGS             = "SETTINGS"
    UPDATE_PROMPT        = "UPDATE_PROMPT"
    VPN_REQUEST          = "VPN_REQUEST"
    EXTERNAL_APK         = "EXTERNAL_APK"
    DOWNLOAD_PROMPT      = "DOWNLOAD_PROMPT"
    PACKAGE_INSTALLER    = "PACKAGE_INSTALLER"
    DIALOG               = "DIALOG"
    WEBVIEW              = "WEBVIEW"
    EXTERNAL_APP         = "EXTERNAL_APP"
    CRASH_STATE          = "CRASH_STATE"
    APP_NOT_RESPONDING   = "APP_NOT_RESPONDING"
    TRANSITION           = "TRANSITION"
    UNKNOWN              = "UNKNOWN"


# Screen types that, when detected by the UI classifier on an EXTERNAL_APP
# ownership screen, indicate a safe interactive boundary.  The semantic type
# is PRESERVED (not overridden by EXTERNAL_APP) so that ExplorationGraph
# routes the screen to its interactive branch and builds an action inventory.
_SAFE_INTERACTIVE_TYPES: frozenset = frozenset({
    ScreenType.SYSTEM_PERMISSION,
    ScreenType.ACCESSIBILITY_DIALOG,
    ScreenType.VPN_REQUEST,
    ScreenType.PACKAGE_INSTALLER,
    ScreenType.EXTERNAL_APK,
    ScreenType.UPDATE_PROMPT,
    ScreenType.DOWNLOAD_PROMPT,
    ScreenType.SETTINGS,
    # A bare consent dialog raised over an external surface is still a decision
    # the sample forced. Without this the "Do you want to install this app?"
    # sheet that classify_screen() reads as DIALOG (short text, OK/Cancel)
    # collapsed to EXTERNAL_APP and the journey stopped one tap short.
    ScreenType.DIALOG,
})

#: Safe-boundary role → the screen type it implies, used only when the text
#: classifier could not name the screen itself. An installer showing nothing
#: but an unreadable progress spinner is still an installer.
_ROLE_TO_SCREEN_TYPE: dict = {
    "VPN_DIALOG": ScreenType.VPN_REQUEST,
    "VPN_SETTINGS": ScreenType.VPN_REQUEST,
    "SYSTEM_INSTALLER": ScreenType.PACKAGE_INSTALLER,
    "SYSTEM_PERMISSION": ScreenType.SYSTEM_PERMISSION,
    "ACCESSIBILITY": ScreenType.ACCESSIBILITY_DIALOG,
}


@dataclass
class ScreenClassification:
    screen_type: str
    confidence: str        # HIGH / MED / LOW
    matched_rules: List[str]
    ownership: str = ""    # ScreenOwnership value when resolved


def classify_screen(
    activity_name: str,
    ui_nodes: List[Any],
    raw_xml: str = "",
    package_name: str = ""
) -> ScreenClassification:
    """
    Classify screen semantics based on Activity class name, UI node text, and attributes.
    """
    activity_lower = activity_name.lower()
    matched_rules = []

    # Combine text labels across UI nodes
    texts = []
    has_inputs = False
    has_password_field = False
    input_count = 0

    for n in ui_nodes:
        # Accept dataclass or dict
        t = getattr(n, "text", "") or (n.get("text") if isinstance(n, dict) else "")
        d = getattr(n, "desc", "") or (n.get("desc") if isinstance(n, dict) else "")
        cls = getattr(n, "class_name", "") or (n.get("class_name") if isinstance(n, dict) else "")
        is_input = getattr(n, "is_input", False) or (n.get("is_input") if isinstance(n, dict) else False)

        if t: texts.append(t.lower())
        if d: texts.append(d.lower())
        if is_input or "edittext" in cls.lower():
            has_inputs = True
            input_count += 1
            if "pass" in t.lower() or "pin" in t.lower() or "edittext" in cls.lower():
                has_password_field = True

    combined_text = " ".join(texts)

    # 1. ACCESSIBILITY_DIALOG
    acc_keywords = ["accessibility", "installed services", "enable service", "accessibilityservice"]
    if any(k in activity_lower for k in acc_keywords) or any(k in combined_text for k in acc_keywords):
        matched_rules.append("accessibility_keyword_match")
        return ScreenClassification(ScreenType.ACCESSIBILITY_DIALOG, "HIGH", matched_rules)

    # 2. SYSTEM_PERMISSION
    perm_keywords = ["grant permission", "allow access", "permission request", "allow", "deny"]
    if "grantpermissionsactivity" in activity_lower or (hasattr(ui_nodes, "__len__") and any(k in combined_text for k in ["allow", "deny"]) and "permission" in combined_text):
        matched_rules.append("system_permission_match")
        return ScreenClassification(ScreenType.SYSTEM_PERMISSION, "HIGH", matched_rules)

    # 3. OTP_SCREEN
    otp_keywords = ["otp", "verification code", "enter code", "resend code", "one time password", "2fa"]
    if any(k in combined_text for k in otp_keywords) or "otp" in activity_lower:
        matched_rules.append("otp_keyword_match")
        return ScreenClassification(ScreenType.OTP_SCREEN, "HIGH", matched_rules)

    # 4. OVERLAY_ATTACK
    overlay_keywords = ["overlay", "draw over", "display over other apps", "alertwindow"]
    if any(k in activity_lower for k in overlay_keywords) or any(k in combined_text for k in overlay_keywords):
        matched_rules.append("overlay_activity_match")
        return ScreenClassification(ScreenType.OVERLAY_ATTACK, "HIGH", matched_rules)

    # 5. BANK_LOGIN
    bank_keywords = ["login", "sign in", "user id", "password", "netbanking", "mpin", "account", "bank"]
    if (has_inputs and any(k in combined_text for k in bank_keywords)) or "loginactivity" in activity_lower:
        matched_rules.append("bank_login_fields_match")
        return ScreenClassification(ScreenType.BANK_LOGIN, "HIGH", matched_rules)

    # 6. UPDATE_PROMPT / DOWNLOAD_PROMPT (before APK - "install update" is update not APK)
    update_keywords = [
        "update available", "new update", "install update", "download update",
        "update now", "new version", "upgrade required",
    ]
    download_keywords = ["download", "downloading", "fetch update"]
    if any(k in combined_text for k in update_keywords):
        matched_rules.append("update_prompt_match")
        return ScreenClassification(ScreenType.UPDATE_PROMPT, "HIGH", matched_rules)
    if any(k in combined_text for k in download_keywords):
        matched_rules.append("download_prompt_match")
        return ScreenClassification(ScreenType.DOWNLOAD_PROMPT, "MED", matched_rules)

    # 7. PACKAGE_INSTALLER / EXTERNAL_APK
    apk_keywords = [
        "package installer", "unknown sources", "install application",
        "install security app", "install this app",
        "do you want to install", "staging app", "allow from this source",
        "install unknown apps", "install anyway", "harmful app blocked",
    ]
    if (
        "packageinstaller" in activity_lower
        or any(k in combined_text for k in apk_keywords)
    ):
        matched_rules.append("external_apk_match")
        return ScreenClassification(ScreenType.EXTERNAL_APK, "HIGH", matched_rules)

    # 8. VPN_REQUEST
    vpn_keywords = [
        "vpn", "vpn connection", "connection request",
        "wants to set up a vpn", "allow connection",
        "monitoring network traffic", "monitor network traffic",
        "configure vpn", "set up a vpn", "enable vpn", "install vpn",
        "vpn required",
    ]
    if any(k in combined_text for k in vpn_keywords) or "vpn" in activity_lower:
        matched_rules.append("vpn_request_match")
        return ScreenClassification(ScreenType.VPN_REQUEST, "HIGH", matched_rules)

    # 8b. DATA_ENTRY_FORM
    #
    # Placed after every security-relevant screen and after BANK_LOGIN/OTP, so
    # it only claims screens that would otherwise have gone unnamed. It sits
    # BEFORE the WEBVIEW and DIALOG rules because a registration form rendered
    # in a WebView is still a registration form, and "what the screen is for"
    # is more useful to the walk than "what widget hosts it".
    #
    # Counted, not read: plain TextView captions never reach this function -
    # the perception parser emits only interactive nodes and consumes captions
    # as field labels - so "Full Name" and "Date of Birth" are not in
    # combined_text. Three or more fields is the reliable signal; two is enough
    # when the activity or the visible text says what the form is for.
    form_activity_keywords = [
        "register", "signup", "sign_up", "kyc", "onboard", "enroll",
        "profile", "details", "beneficiary", "addpayee",
    ]
    form_text_keywords = [
        "register", "sign up", "create account", "personal details",
        "your details", "kyc", "full name", "date of birth", "beneficiary",
    ]
    is_settings_surface = (
        "settings" in activity_lower or "preferences" in activity_lower
    )
    if has_inputs and input_count >= 2 and not is_settings_surface:
        if input_count >= 3:
            matched_rules.append(f"data_entry_form_{input_count}_fields")
            return ScreenClassification(
                ScreenType.DATA_ENTRY_FORM, "HIGH", matched_rules,
            )
        if any(k in activity_lower for k in form_activity_keywords) or any(
            k in combined_text for k in form_text_keywords
        ):
            matched_rules.append("data_entry_form_keyword_match")
            return ScreenClassification(
                ScreenType.DATA_ENTRY_FORM, "MED", matched_rules,
            )

    # 9. WEBVIEW
    webview_keywords = ["webview", "browser", "chrome", "http", "https", "www."]
    if any(k in activity_lower for k in webview_keywords) or any(
        k in combined_text for k in webview_keywords
    ):
        matched_rules.append("webview_match")
        return ScreenClassification(ScreenType.WEBVIEW, "MED", matched_rules)

    # 10. DIALOG (bottom sheets, alert dialogs)
    dialog_keywords = ["dialog", "alert", "confirm", "are you sure", "bottom sheet"]
    if any(k in activity_lower for k in dialog_keywords) or (
        any(k in combined_text for k in ["ok", "cancel", "yes", "no"])
        and len(texts) <= 6
    ):
        matched_rules.append("dialog_match")
        return ScreenClassification(ScreenType.DIALOG, "MED", matched_rules)

    # 11. SETTINGS
    if "settings" in activity_lower or "preferences" in activity_lower:
        matched_rules.append("settings_activity_match")
        return ScreenClassification(ScreenType.SETTINGS, "MED", matched_rules)

    # 12. HOME
    if "mainactivity" in activity_lower or "homeactivity" in activity_lower or "launcher" in activity_lower:
        matched_rules.append("main_home_match")
        return ScreenClassification(ScreenType.HOME, "MED", matched_rules)

    return ScreenClassification(ScreenType.UNKNOWN, "LOW", ["default_fallback"])


def classify_screen_with_ownership(
    activity_name: str,
    ui_nodes: List[Any],
    raw_xml: str = "",
    package_name: str = "",
    foreground_package: str = "",
) -> ScreenClassification:
    """
    Classify screen semantics AND ownership relative to the target APK.

    Ownership (package/activity context) takes priority over UI appearance
  for HOME_LAUNCHER, EXTERNAL_APP, and CRASH_STATE classification.
    """
    from sudarshan_core.engines.agentic.screenshot_policy import (
        resolve_screen_ownership,
        ScreenOwnership,
        LAUNCHER_PACKAGES,
        CRASH_ACTIVITY_MARKERS,
    )

    fg = foreground_package or ""
    if not fg and activity_name and "/" in activity_name:
        fg = activity_name.split("/", 1)[0]

    act_lower = activity_name.lower()

    # Package-first ownership resolution
    ownership = resolve_screen_ownership(fg, package_name, activity_name, "")

    if ownership == ScreenOwnership.HOME_LAUNCHER:
        return ScreenClassification(
            ScreenType.HOME_LAUNCHER, "HIGH",
            ["foreground_is_launcher", f"fg={fg}"],
            ownership=ownership.value,
        )

    if ownership == ScreenOwnership.CRASH_STATE:
        return ScreenClassification(
            ScreenType.CRASH_STATE, "HIGH",
            ["crash_activity_detected"],
            ownership=ownership.value,
        )

    if ownership == ScreenOwnership.APP_NOT_RESPONDING:
        return ScreenClassification(
            ScreenType.APP_NOT_RESPONDING, "HIGH",
            ["anr_detected"],
            ownership=ownership.value,
        )

    if ownership == ScreenOwnership.EXTERNAL_APP:
        base = classify_screen(activity_name, ui_nodes, raw_xml, package_name)
        # SAFE INTERACTIVE BOUNDARY: when the UI classifier finds a safe
        # interactive type on an EXTERNAL_APP ownership screen, preserve that
        # semantic type.  If we return EXTERNAL_APP here, the ExplorationGraph
        # receives semantic_type=EXTERNAL_APP, which is NOT in
        # _INTERACTIVE_BOUNDARY_TYPES, so it routes to _observe_external() with
        # actionable_elements=[] and exploration stops.
        if base.screen_type in _SAFE_INTERACTIVE_TYPES:
            return ScreenClassification(
                base.screen_type, base.confidence,
                ["external_interactive_boundary", f"fg={fg}"] + base.matched_rules,
                ownership=ownership.value,
            )
        return ScreenClassification(
            ScreenType.EXTERNAL_APP, "HIGH",
            ["foreground_external_app", f"fg={fg}"] + base.matched_rules,
            ownership=ownership.value,
        )

    if ownership in (
        ScreenOwnership.SYSTEM_INSTALLER,
        ScreenOwnership.SYSTEM_SETTINGS,
        ScreenOwnership.SYSTEM_PERMISSION,
    ):
        base = classify_screen(activity_name, ui_nodes, raw_xml, package_name)
        if base.screen_type in _SAFE_INTERACTIVE_TYPES:
            return ScreenClassification(
                base.screen_type, base.confidence,
                ["system_boundary", f"fg={fg}"] + base.matched_rules,
                ownership=ownership.value,
            )
        # The text classifier could not name this screen (an installer mid
        # progress bar, a consent dialog whose body failed to dump). Ownership
        # already established WHICH system surface it is, and dropping that to
        # UNKNOWN loses the one fact we are certain of - the ExplorationGraph
        # then reads a non-interactive type and stops building actions for a
        # screen the victim still has to answer.
        from sudarshan_core.engines.agentic.screenshot_policy import classify_safe_boundary

        role = classify_safe_boundary(fg, activity_name, "")
        implied = _ROLE_TO_SCREEN_TYPE.get(role.value, "")
        if implied:
            return ScreenClassification(
                implied, "MED",
                ["system_boundary_role_inferred", f"fg={fg}", f"role={role.value}"]
                + base.matched_rules,
                ownership=ownership.value,
            )
        return ScreenClassification(
            base.screen_type, base.confidence,
            ["system_boundary", f"fg={fg}"] + base.matched_rules,
            ownership=ownership.value,
        )

    # Target app or unknown: use UI-based classification
    base = classify_screen(activity_name, ui_nodes, raw_xml, package_name)
    base.ownership = ownership.value if ownership != ScreenOwnership.UNKNOWN else ScreenOwnership.TARGET_APP.value
    return base


def is_explorable_screen_type(screen_type: str) -> bool:
    """
    Whether the explorer should treat this screen as target-app exploration.

    HOME_LAUNCHER, CRASH_STATE, and EXTERNAL_APP are NOT normal exploration
    surfaces for the target APK graph.
    """
    non_explorable = {
        ScreenType.HOME_LAUNCHER,
        ScreenType.CRASH_STATE,
        ScreenType.APP_NOT_RESPONDING,
        ScreenType.EXTERNAL_APP,
        ScreenType.TRANSITION,
    }
    return screen_type not in non_explorable


def should_invoke_planner(screen_type: str) -> bool:
    """Whether Gemini planner should be invoked for this screen type."""
    skip_planner = {
        ScreenType.HOME_LAUNCHER,
        ScreenType.CRASH_STATE,
        ScreenType.APP_NOT_RESPONDING,
        ScreenType.TRANSITION,
    }
    return screen_type not in skip_planner
