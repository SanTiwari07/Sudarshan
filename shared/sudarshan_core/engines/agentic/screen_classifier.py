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
    ]
    if (
        "packageinstaller" in activity_lower
        or any(k in combined_text for k in apk_keywords)
    ):
        matched_rules.append("external_apk_match")
        return ScreenClassification(ScreenType.EXTERNAL_APK, "HIGH", matched_rules)

    # 8. VPN_REQUEST
    vpn_keywords = ["enable vpn", "install vpn", "vpn required", "configure vpn", "vpn connection"]
    if any(k in combined_text for k in vpn_keywords) or "vpn" in activity_lower:
        matched_rules.append("vpn_request_match")
        return ScreenClassification(ScreenType.VPN_REQUEST, "HIGH", matched_rules)

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
