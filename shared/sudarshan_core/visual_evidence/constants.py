"""Constants for visual evidence linking and claim generation."""

from __future__ import annotations

import os

SCHEMA_VERSION = 1

VISUAL_LINK_DELTA_MS_CRITICAL = int(os.getenv("SUDARSHAN_VISUAL_LINK_DELTA_CRITICAL_MS", "5000"))
VISUAL_LINK_DELTA_MS_DEFAULT = int(os.getenv("SUDARSHAN_VISUAL_LINK_DELTA_DEFAULT_MS", "8000"))
VISUAL_LINK_DELTA_MS_VIDE = int(os.getenv("SUDARSHAN_VISUAL_LINK_DELTA_VIDE_MS", "120000"))

VISUAL_LINK_MAX_EVID_PER_SCR = 3
VISUAL_LINK_MIN_EVID_SEVERITY_FOR_A = {"HIGH", "CRITICAL"}

MAX_EXECUTIVE_KEY_SCREENSHOTS = 2

# Claim types (canonical strings)
CLAIM_VISUAL_IMPERSONATION = "visual_impersonation"
CLAIM_OVERLAY_OBSERVED = "overlay_observed"
CLAIM_FAKE_LOGIN_UI = "fake_login_ui"
CLAIM_CREDENTIAL_COLLECTION_UI = "credential_collection_ui"
CLAIM_ACCESSIBILITY_GUIDANCE = "accessibility_guidance"
CLAIM_OTP_UI = "otp_ui"
CLAIM_PAYMENT_UI = "payment_ui"
CLAIM_BANKING_TARGET_UI = "banking_target_ui"
CLAIM_ANTI_ANALYSIS_UI = "anti_analysis_ui"
CLAIM_DROPPER_UI = "dropper_ui"
CLAIM_BENIGN_NEGATIVE_PROOF = "benign_negative_proof"
CLAIM_LAUNCH_CONTEXT = "launch_context"
CLAIM_FINAL_STATE = "final_state"
CLAIM_INCONCLUSIVE_VISUAL = "inconclusive_visual"

ALL_CLAIM_TYPES = frozenset({
    CLAIM_VISUAL_IMPERSONATION,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_FAKE_LOGIN_UI,
    CLAIM_CREDENTIAL_COLLECTION_UI,
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_OTP_UI,
    CLAIM_PAYMENT_UI,
    CLAIM_BANKING_TARGET_UI,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_DROPPER_UI,
    CLAIM_BENIGN_NEGATIVE_PROOF,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
})

QUALITY_A = "A"
QUALITY_B = "B"
QUALITY_C = "C"
QUALITY_D = "D"

TIER_EXECUTIVE_KEY = "executive_key"
TIER_TECHNICAL = "technical"
TIER_APPENDIX_ONLY = "appendix_only"
TIER_EXCLUDE = "exclude"

CORRELATION_CAUSAL = "causal"
CORRELATION_LINKED = "linked"
CORRELATION_TEMPORAL = "temporal"
CORRELATION_UNRESOLVED = "unresolved"
CORRELATION_NOT_APPLICABLE = "not_applicable"

# Strongest → weakest (for picking record-level status when multiple EVID links exist).
CORRELATION_STRENGTH_ORDER = (
    CORRELATION_CAUSAL,
    CORRELATION_LINKED,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
    CORRELATION_NOT_APPLICABLE,
)

PRIORITY_P0 = "P0"
PRIORITY_P1 = "P1"
PRIORITY_P2 = "P2"
PRIORITY_P3 = "P3"

# Substrings that must not appear in generated investigative claims (lowercase match).
FORBIDDEN_CLAIM_SUBSTRINGS = (
    "proves malware",
    "proves hacked",
    "user was compromised",
    "definitely malicious",
    "confirmed malware",
    "proves the user was hacked",
)

OVERLAY_API_MARKERS = (
    "WindowManager.addView",
    "View.setType/TYPE_APPLICATION_OVERLAY",
    "Settings.canDrawOverlays",
)

ACCESSIBILITY_SETTINGS_MARKERS = (
    "AccessibilityManager.isEnabled",
)

ACCESSIBILITY_SCRAPE_MARKERS = (
    "AccessibilityNodeInfo.getText",
    "AccessibilityNodeInfo.performAction",
)

SMS_API_MARKERS = (
    "SmsMessage.getMessageBody",
    "SmsManager.sendTextMessage",
    "SmsManager.sendMultipartTextMessage",
    "ContentResolver.query",
)

BANKING_DETECTION_MARKERS = (
    "PackageManager.getInstalledPackages",
    "QUERY_ALL_PACKAGES",
)

DEX_INSTALL_MARKERS = (
    "DexClassLoader.<init>",
    "InMemoryDexClassLoader",
    "PathClassLoader",
)

# Capture reasons that indicate a suspicious UI stimulus (not generic OVERLAY hook captures).
SUSPICIOUS_UI_REASONS = frozenset({
    "SUSPICIOUS_UI",
})

LIFECYCLE_REASON = "LIFECYCLE"
