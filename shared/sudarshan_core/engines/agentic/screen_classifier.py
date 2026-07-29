"""
SUDARSHAN — Rule-Based Semantic Screen Classifier
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
    SETTINGS             = "SETTINGS"
    UNKNOWN              = "UNKNOWN"


@dataclass
class ScreenClassification:
    screen_type: str
    confidence: str        # HIGH / MED / LOW
    matched_rules: List[str]


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

    # 6. SETTINGS
    if "settings" in activity_lower:
        matched_rules.append("settings_activity_match")
        return ScreenClassification(ScreenType.SETTINGS, "MED", matched_rules)

    # 7. HOME
    if "mainactivity" in activity_lower or "homeactivity" in activity_lower or "launcher" in activity_lower:
        matched_rules.append("main_home_match")
        return ScreenClassification(ScreenType.HOME, "MED", matched_rules)

    return ScreenClassification(ScreenType.UNKNOWN, "LOW", ["default_fallback"])
