"""
SUDARSHAN — Investigation Manifest Model
==========================================
Formal data contract representing the output of Static Intelligence that drives
the Dynamic Analysis Engine configuration.

The InvestigationManifest is generated from static findings BEFORE sandbox
execution and serialized to `manifest.json` inside the per-sample artifact
directory. The dynamic analysis layer reads it to:
  - Determine which fraud goals to activate (goal_priorities)
  - Know which APK capabilities were detected (capability_flags)
  - Reference static IOC baseline for de-duplication with runtime discoveries

All fields are optional-safe so the manifest is valid even in Androguard-only
mode (when MobSF is unavailable).

Usage::

    from app.models.manifest import InvestigationManifest, build_manifest

    manifest = build_manifest(
        sha256=sha256_hash,
        package_name=package_name,
        flags_dict=flags_dict,
        analysis_mode="mobsf",
        mobsf_report=mobsf_report,
    )
    manifest.to_file(artifact_dir / "manifest.json")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ─── Sub-models ───────────────────────────────────────────────────────────────

class StaticCapabilityFlags(BaseModel):
    """
    Capability flags extracted from static analysis, used to activate
    specific Frida hooks and fraud investigation goals.
    """
    has_accessibility_abuse: bool = False
    has_sms_read_write: bool = False
    has_system_alert_window: bool = False
    has_device_admin: bool = False
    has_dynamic_code_loading: bool = False
    has_reflection: bool = False
    has_native_libraries: bool = False
    targets_indian_banks: bool = False
    indian_bank_packages: List[str] = Field(default_factory=list)
    obfuscation_score: float = 0.0

    # Recommended hook profiles derived from flags — used by the sandbox
    # to activate only relevant Frida hook bundles.
    recommended_hook_profiles: List[str] = Field(default_factory=list)

    def derive_hook_profiles(self) -> List[str]:
        """
        Derive the minimal set of hook profiles to load based on detected
        capability flags. Minimising hook surface reduces performance overhead
        and reduces the risk of hook-detection triggers.
        """
        profiles = ["canary"]  # Always include canary hook for instrumentation verification
        if self.has_accessibility_abuse:
            profiles.append("accessibility")
        if self.has_sms_read_write:
            profiles.append("sms")
        if self.has_system_alert_window:
            profiles.append("overlay")
        if self.targets_indian_banks:
            profiles.append("banking")
        if self.has_dynamic_code_loading or self.has_native_libraries:
            profiles.append("dynamic_code")
        if self.has_device_admin:
            profiles.append("persistence")
        # Network hooks are always included — C2 detection is baseline
        profiles.append("network")
        return list(dict.fromkeys(profiles))  # Deduplicate, preserving order


class StaticIOCBaseline(BaseModel):
    """IOCs extracted during static analysis for de-duplication at runtime."""
    hardcoded_urls: List[str] = Field(default_factory=list)
    hardcoded_ips: List[str] = Field(default_factory=list)
    hardcoded_domains: List[str] = Field(default_factory=list)
    hardcoded_secrets: List[str] = Field(default_factory=list)
    suspicious_strings: List[str] = Field(default_factory=list)


class GoalPriorityConfig(BaseModel):
    """
    Prioritization configuration derived from static findings.
    The Goal DAG reads this to reorder and skip goals during dynamic analysis.
    """
    accessibility_priority: int = 1     # 1=highest. 0=disabled.
    sms_priority: int = 2
    overlay_priority: int = 3
    banking_detection_priority: int = 4
    network_c2_priority: int = 5
    persistence_priority: int = 6
    skip_login_flow: bool = False       # True when no login screen was detected in static

    @classmethod
    def from_flags(cls, flags: StaticCapabilityFlags) -> "GoalPriorityConfig":
        """
        Derive a GoalPriorityConfig from detected static capability flags by
        boosting goals matching detected capabilities.
        """
        cfg = cls()
        # Accessibility is the lead capability in Indian banking trojans
        if flags.has_accessibility_abuse:
            cfg.accessibility_priority = 1
        if flags.has_sms_read_write:
            cfg.sms_priority = 1 if not flags.has_accessibility_abuse else 2
        if flags.has_system_alert_window:
            cfg.overlay_priority = 1 if not (flags.has_accessibility_abuse or flags.has_sms_read_write) else 3
        return cfg


# ─── InvestigationManifest ────────────────────────────────────────────────────

class InvestigationManifest(BaseModel):
    """
    Formal pre-sandbox data contract produced from Static Intelligence.

    This manifest is serialized to manifest.json in the sample artifact
    directory before the dynamic analysis sandbox executes. It is the
    authoritative definition of what static analysis found, and what the
    dynamic engine should investigate.
    """
    # ── Identity ──────────────────────────────────────────────────────────────
    sha256: str
    package_name: str
    app_name: Optional[str] = None
    analysis_mode: str = "androguard"    # "mobsf" | "androguard"
    manifest_version: str = "1.0"
    generated_at: str = Field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())

    # ── Static Intelligence ───────────────────────────────────────────────────
    stei_score: float = 0.0
    family_classification: str = "Unknown"
    capability_flags: StaticCapabilityFlags = Field(default_factory=StaticCapabilityFlags)
    static_ioc_baseline: StaticIOCBaseline = Field(default_factory=StaticIOCBaseline)

    # ── Dynamic Configuration ─────────────────────────────────────────────────
    goal_priority_config: GoalPriorityConfig = Field(default_factory=GoalPriorityConfig)
    hook_profiles: List[str] = Field(default_factory=list)
    analysis_duration_seconds: int = 60
    max_explorer_actions: int = 50

    # ── Metadata ──────────────────────────────────────────────────────────────
    permissions_count: int = 0
    dangerous_permissions_count: int = 0
    activities_count: int = 0
    services_count: int = 0
    receivers_count: int = 0

    def to_file(self, path: Path) -> None:
        """Serialize manifest to JSON file."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                self.model_dump_json(indent=2),
                encoding="utf-8",
            )
            logger.info(f"[Manifest] Written to {path}")
        except Exception as e:
            logger.error(f"[Manifest] Failed to write manifest: {e}")

    @classmethod
    def from_file(cls, path: Path) -> Optional["InvestigationManifest"]:
        """Load a previously serialized manifest from disk."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(**data)
        except Exception as e:
            logger.error(f"[Manifest] Failed to load manifest from {path}: {e}")
            return None


# ─── Builder ──────────────────────────────────────────────────────────────────

def build_manifest(
    sha256: str,
    package_name: str,
    flags_dict: Dict[str, Any],
    analysis_mode: str = "androguard",
    app_name: Optional[str] = None,
    stei_score: float = 0.0,
    family_classification: str = "Unknown",
    all_permissions: Optional[List[str]] = None,
    dangerous_permissions: Optional[List[Any]] = None,
    activities: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    receivers: Optional[List[str]] = None,
) -> InvestigationManifest:
    """
    Build an InvestigationManifest from the flags_dict produced by static
    analysis normalization.

    This is the sole entry point for creating manifests — all field derivation
    is centralized here to keep upload.py clean.
    """
    # ── Capability flags ──────────────────────────────────────────────────────
    flags = StaticCapabilityFlags(
        has_accessibility_abuse=flags_dict.get("has_accessibility_abuse", False),
        has_sms_read_write=flags_dict.get("has_sms_read_write", False),
        has_system_alert_window=flags_dict.get("has_system_alert_window", False),
        has_device_admin=flags_dict.get("has_device_admin", False),
        has_dynamic_code_loading=flags_dict.get("has_dynamic_code_loading", False),
        has_reflection=flags_dict.get("has_reflection", False),
        has_native_libraries=flags_dict.get("has_native_libraries", False),
        targets_indian_banks=flags_dict.get("targets_indian_banks", False),
        indian_bank_packages=flags_dict.get("indian_bank_packages_found", []),
        obfuscation_score=flags_dict.get("obfuscation_score", 0.0),
    )
    flags.recommended_hook_profiles = flags.derive_hook_profiles()

    # ── IOC baseline ──────────────────────────────────────────────────────────
    combined_urls_ips = flags_dict.get("hardcoded_urls_ips", [])
    urls = [u for u in combined_urls_ips if not u.replace(".", "").replace(":", "").isdigit()]
    ips  = [u for u in combined_urls_ips if u.replace(".", "").replace(":", "").isdigit()]
    ioc_baseline = StaticIOCBaseline(
        hardcoded_urls=urls,
        hardcoded_ips=ips,
        hardcoded_secrets=flags_dict.get("hardcoded_secrets", []),
        suspicious_strings=flags_dict.get("suspicious_strings", []),
    )

    # ── Goal priority ─────────────────────────────────────────────────────────
    goal_config = GoalPriorityConfig.from_flags(flags)

    return InvestigationManifest(
        sha256=sha256,
        package_name=package_name,
        app_name=app_name,
        analysis_mode=analysis_mode,
        stei_score=stei_score,
        family_classification=family_classification,
        capability_flags=flags,
        static_ioc_baseline=ioc_baseline,
        goal_priority_config=goal_config,
        hook_profiles=flags.recommended_hook_profiles,
        permissions_count=len(all_permissions or []),
        dangerous_permissions_count=len(dangerous_permissions or []),
        activities_count=len(activities or []),
        services_count=len(services or []),
        receivers_count=len(receivers or []),
    )
