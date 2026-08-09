"""
Deterministic verdict fixtures - shared by the replay regression test.

These fixtures pin a set of representative inputs to the Risk Engine so that
any change to the planner, perception, executor or memory layers can be proven
NOT to alter the deterministic verdict.

The Risk Engine is the single source of truth for STEI, BFCI, FRS, severity and
recommended action. If a change to AI/exploration code alters any value below,
that is a determinism regression and must be rejected.
"""

from __future__ import annotations

from typing import Any, Dict, List

# ─── Frozen input scenarios ───────────────────────────────────────────────────
# Each scenario is (name, kwargs for calculate_risk_score).
# Values are literals only - never derived from the environment, clock or RNG,
# so the replay is reproducible on any machine.

BENIGN_FLAGS: Dict[str, Any] = {
    "has_accessibility_abuse": False,
    "has_sms_read_write": False,
    "has_system_alert_window": False,
    "dangerous_apis_found": [],
    "hardcoded_urls_ips": [],
    "targets_indian_banks": False,
    "obfuscation_score": 0.0,
    "has_reflection": False,
    "has_dynamic_loading": False,
}

TROJAN_FLAGS: Dict[str, Any] = {
    "has_accessibility_abuse": True,
    "has_sms_read_write": True,
    "has_system_alert_window": True,
    "dangerous_apis_found": ["addJavascriptInterface", "DexClassLoader"],
    "hardcoded_urls_ips": ["http://198.51.100.7/gate.php"],
    "targets_indian_banks": True,
    "obfuscation_score": 0.8,
    "has_reflection": True,
    "has_dynamic_loading": True,
}

# A recorded dynamic result - mirrors the shape frida_sandbox.py emits.
RECORDED_DYNAMIC: Dict[str, Any] = {
    "available": True,
    "engine": "frida",
    "bfci": 61.25,
    "bfci_components": {
        "accessibility": 100.0,
        "sms": 50.0,
        "overlay": 50.0,
        "banking": 33.33,
        "network": 20.0,
        "persistence": 0.0,
    },
    "bfci_evidence": ["accessibility hook fired", "sms hook fired"],
    "api_calls": ["SmsManager.sendTextMessage"],
    "network_logs": ["http://198.51.100.7/gate.php"],
    "files_accessed": ["/data/data/com.example/shared_prefs/creds.xml"],
    "screenshots": [],
}

RECORDED_CORRELATION: Dict[str, Any] = {
    "available": True,
    "threat_score": 55.0,
    "known_family": "Anubis",
}


def replay_scenarios() -> List[Dict[str, Any]]:
    """
    Return the frozen scenario set used by the determinism replay test.

    Each entry is a dict of keyword arguments accepted by
    ``calculate_risk_score``. Adding a scenario is safe; changing an existing
    one invalidates the recorded baseline and must be done deliberately.
    """
    return [
        {
            "_name": "benign_static_only",
            "flags": dict(BENIGN_FLAGS),
            "ai_confidence": 1.0,
            "dynamic_result": None,
            "correlation_result": None,
            "family": "Unknown",
            "all_permissions": [],
        },
        {
            "_name": "trojan_static_only",
            "flags": dict(TROJAN_FLAGS),
            "ai_confidence": 1.2,
            "dynamic_result": None,
            "correlation_result": dict(RECORDED_CORRELATION),
            "family": "Anubis",
            "all_permissions": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
        },
        {
            "_name": "trojan_with_recorded_dynamic",
            "flags": dict(TROJAN_FLAGS),
            "ai_confidence": 1.2,
            "dynamic_result": dict(RECORDED_DYNAMIC),
            "correlation_result": dict(RECORDED_CORRELATION),
            "family": "Anubis",
            "all_permissions": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.RECEIVE_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
            ],
        },
    ]


# Fields that constitute "the verdict". Any drift in these is a regression.
VERDICT_FIELDS = (
    "base_score",
    "ai_confidence_multiplier",
    "final_risk_score",
    "risk_band",
    "confidence",
    "severity",
    "recommended_action",
)
