"""
Sandbox environment configuration.

All values are read dynamically from the process environment so Docker
compose, `.env`, and host shells can switch providers without code changes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class SandboxConfig:
    """Runtime configuration for the sandbox abstraction layer."""

    provider: str = "genymotion"
    adb_host: str = ""
    adb_port: str = "5555"
    device_serial: str = ""
    frida_port: str = "27055"
    frida_bin: str = "sudarshan_agent_srv"
    auto_connect: bool = True
    root_required: bool = True
    # Optional provider-specific overrides
    genymotion_adb: str = ""
    android_sdk_root: str = ""
    preferred_avd: str = ""

    @property
    def tcp_target(self) -> Optional[str]:
        if self.adb_host:
            return f"{self.adb_host}:{self.adb_port}"
        return None


def load_sandbox_config() -> SandboxConfig:
    """Load sandbox config from environment variables."""
    return SandboxConfig(
        provider=os.getenv("SANDBOX_PROVIDER", "genymotion").strip().lower() or "genymotion",
        adb_host=os.getenv("ADB_HOST", "").strip(),
        adb_port=os.getenv("ADB_PORT", "5555").strip() or "5555",
        device_serial=os.getenv("DEVICE_SERIAL", "").strip(),
        frida_port=(
            os.getenv("FRIDA_PORT")
            or os.getenv("SUDARSHAN_FRIDA_PORT")
            or os.getenv("FRIDA_SERVER_PORT")
            or "27055"
        ).strip(),
        frida_bin=os.getenv("SUDARSHAN_FRIDA_BIN", "sudarshan_agent_srv").strip()
        or "sudarshan_agent_srv",
        auto_connect=_bool_env("AUTO_CONNECT", True),
        root_required=_bool_env("ROOT_REQUIRED", True),
        genymotion_adb=os.getenv("GENYMOTION_ADB", "").strip(),
        android_sdk_root=(
            os.getenv("ANDROID_SDK_ROOT")
            or os.getenv("ANDROID_HOME")
            or ""
        ).strip(),
        preferred_avd=os.getenv("SUDARSHAN_AVD", "").strip(),
    )
