"""
Frozen static-analysis profiles mirroring docs/evaluation/CASE_STUDIES.md.

Used by scripts/validate_static_only_frs.py and regression tests. Values are
literals only — never derived from environment, clock, or RNG.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from sudarshan_core.models.schemas import StaticAnalysisFlags

# Sentinel used when threat-intel correlation ran but found nothing.
# Step 0 of validate_static_only_frs.py proves this is equivalent to None
# for axes_excluded / axes_used / scores.
CORRELATION_UNAVAILABLE: Dict[str, Any] = {"available": False}

DRINIK_PERMISSIONS: List[str] = [
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
]

XENOMORPH_PERMISSIONS: List[str] = [
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
]

INSECUREBANKV2_PERMISSIONS: List[str] = [
    "android.permission.INTERNET",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
]


def drinik_flags() -> StaticAnalysisFlags:
    """Case Study 2 — Drinik Banking Trojan (Indian Banking Target)."""
    return StaticAnalysisFlags(
      has_accessibility_abuse=True,
      has_sms_read_write=True,
      has_system_alert_window=True,
      targets_indian_banks=True,
      indian_bank_packages_found=[
          "com.sbi.lotusintouch",
          "com.icicibank.mobilebanking",
      ],
      dangerous_apis_found=["DexClassLoader"],
      hardcoded_urls_ips=["http://194.163.142.89/drinik/gate.php"],
      obfuscation_score=0.68,
        has_reflection=True,
    )


def xenomorph_flags() -> StaticAnalysisFlags:
    """Case Study 3 — Xenomorph (ATS automation; no SMS to avoid Drinik overlap)."""
    return StaticAnalysisFlags(
      has_accessibility_abuse=True,
      has_sms_read_write=False,
      has_system_alert_window=True,
      targets_indian_banks=True,
      indian_bank_packages_found=["com.hdfcbank.mobilebanking"],
      dangerous_apis_found=["Runtime.exec"],
      hardcoded_urls_ips=[],
      obfuscation_score=0.85,
        has_reflection=True,
    )


def insecurebankv2_flags() -> StaticAnalysisFlags:
    """Case Study 1 — InsecureBankv2 training app."""
    return StaticAnalysisFlags(
      has_accessibility_abuse=False,
      has_sms_read_write=False,
      has_system_alert_window=False,
      targets_indian_banks=False,
      indian_bank_packages_found=[],
      dangerous_apis_found=[],
      hardcoded_urls_ips=["http://192.168.1.1/debug"],
      obfuscation_score=0.1,
        has_reflection=False,
    )


def case_study_scenarios() -> List[Dict[str, Any]]:
    """Return labelled scenarios for static-only FRS validation."""
    return [
        {
          "id": "drinik",
          "label": "Drinik Banking Trojan",
          "flags": drinik_flags(),
          "permissions": DRINIK_PERMISSIONS,
          "case_study_claimed_frs": 79.51,
          "case_study_claimed_band": "HIGH RISK",
      },
      {
          "id": "xenomorph",
          "label": "Xenomorph Banking Trojan",
          "flags": xenomorph_flags(),
          "permissions": XENOMORPH_PERMISSIONS,
          "case_study_claimed_frs": 50.82,
          "case_study_claimed_band": "SUSPICIOUS",
      },
      {
          "id": "insecurebankv2",
          "label": "InsecureBankv2 Training App",
          "flags": insecurebankv2_flags(),
          "permissions": INSECUREBANKV2_PERMISSIONS,
          "case_study_claimed_frs": 9.17,
          "case_study_claimed_band": "SAFE",
        },
    ]


def engine_band_to_case_study_label(band: str) -> str:
    """Map engine risk_band to case-study severity vocabulary."""
    mapping = {
      "Safe": "LOW",
      "Suspicious": "MEDIUM",
      "High Risk": "HIGH",
        "Critical": "CRITICAL",
    }
    return mapping.get(band, band.upper())
