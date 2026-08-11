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


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        raw = os.getenv(name)
        if raw is not None and raw.strip() != "":
            return raw.strip()
    return default


@dataclass(frozen=True)
class SandboxConfig:
    """Runtime configuration for the sandbox abstraction layer."""

    # auto | genymotion | android_avd | android_studio | physical
    provider: str = "auto"
    adb_host: str = ""
    adb_port: str = "5555"
    device_serial: str = ""
    frida_port: str = "27055"
    frida_bin: str = "sudarshan_agent_srv"
    frida_version: str = "17.16.4"
    frida_server_dir: str = ""
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

    @property
    def provider_is_auto(self) -> bool:
        return (self.provider or "auto").strip().lower() in ("", "auto")


def load_sandbox_config() -> SandboxConfig:
    """Load sandbox config from environment variables."""
    provider = _first_env(
        "SANDBOX_PROVIDER",
        "ANDROID_SANDBOX_PROVIDER",
        default="auto",
    ).lower() or "auto"

    return SandboxConfig(
        provider=provider,
        adb_host=os.getenv("ADB_HOST", "").strip(),
        adb_port=os.getenv("ADB_PORT", "5555").strip() or "5555",
        device_serial=_first_env("ANDROID_DEVICE_SERIAL", "DEVICE_SERIAL"),
        frida_port=(
            os.getenv("FRIDA_PORT")
            or os.getenv("SUDARSHAN_FRIDA_PORT")
            or os.getenv("FRIDA_SERVER_PORT")
            or "27055"
        ).strip(),
        frida_bin=os.getenv("SUDARSHAN_FRIDA_BIN", "sudarshan_agent_srv").strip()
        or "sudarshan_agent_srv",
        frida_version=_first_env(
            "FRIDA_VERSION", "SUDARSHAN_FRIDA_VERSION", default="17.16.4"
        ),
        frida_server_dir=_first_env("FRIDA_SERVER_DIR", "SUDARSHAN_FRIDA_SERVER_DIR"),
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
