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


# ─── Frida ports ──────────────────────────────────────────────────────────────
#
# Two different numbers that are easy to conflate, so they are named apart:
#
# FRIDA_USB_TRANSPORT_PORT is not configuration. Frida's USB/ADB transport only
# ever talks to 27042 on the guest; that is baked into frida itself and no env
# var moves it.
#
# DEFAULT_FRIDA_SERVER_PORT is the port WE start frida-server on when nothing
# is configured. It deliberately differs from frida's default so a stray
# stock frida-server on the guest cannot be mistaken for ours.
#
# Every module must resolve the server port through frida_server_port() rather
# than repeating a literal. Divergent copies of this default are not a style
# problem: config.py used to answer 27042 while provider.py answered 27055, so
# the server was started on one port and dialled on another - and the failure
# surfaced much later as frida's misleading "need Gadget to attach on jailed
# Android", which sends you looking for a Gadget that was never the problem.
FRIDA_USB_TRANSPORT_PORT: int = 27042
DEFAULT_FRIDA_SERVER_PORT: str = "27055"

# Every name accepted for the server port, in precedence order. One list, so a
# variable honoured by one module cannot be ignored by the next.
FRIDA_PORT_ENV_VARS: tuple = (
    "FRIDA_PORT",
    "SUDARSHAN_FRIDA_PORT",
    "FRIDA_SERVER_PORT",
)


def frida_server_port() -> str:
    """
    The port frida-server listens on, resolved from the environment.

    Single source of truth: starting the server, forwarding to it, dialling it
    and preflighting it all go through here, so they cannot disagree. Falls
    back to DEFAULT_FRIDA_SERVER_PORT, and ignores a non-numeric value rather
    than propagating it into an adb command.
    """
    raw = _first_env(*FRIDA_PORT_ENV_VARS, default=DEFAULT_FRIDA_SERVER_PORT)
    return raw if raw.isdigit() else DEFAULT_FRIDA_SERVER_PORT


def adb_server_host() -> str:
    """
    Host running the ADB server this process talks to, or "" when it is local.

    ``ADB_SERVER_SOCKET=tcp:<host>:<port>`` makes every adb subcommand execute
    on THAT host. ``adb forward`` therefore binds its port in the remote host's
    network namespace, not this one -- so a client of a forwarded port (the
    Frida client, above all) has to dial the same host. Assuming 127.0.0.1 is
    what makes Frida unreachable from inside the containers even though
    ``adb devices`` lists the emulator perfectly.
    """
    raw = (os.getenv("ADB_SERVER_SOCKET") or "").strip()
    if not raw:
        return ""
    value = raw[4:] if raw.lower().startswith("tcp:") else raw
    host = value.rsplit(":", 1)[0] if ":" in value else value
    host = host.strip().strip("[]")
    if host.lower() in ("", "127.0.0.1", "localhost", "::1"):
        return ""
    return host


def adb_server_port() -> int:
    """
    Port of the ADB server this process talks to. 5037 when unset.

    Pairs with adb_server_host(). Libraries that speak the ADB protocol
    directly rather than shelling out to the `adb` binary -- adbutils, and
    uiautomator2 on top of it -- read ADB_SERVER_HOST/ADB_SERVER_PORT and know
    nothing about ADB_SERVER_SOCKET, so the socket form has to be translated
    for them or they silently dial a local server that is not there.
    """
    raw = (os.getenv("ADB_SERVER_SOCKET") or "").strip()
    if not raw:
        return 5037
    value = raw[4:] if raw.lower().startswith("tcp:") else raw
    if ":" not in value:
        return 5037
    port = value.rsplit(":", 1)[1].strip()
    return int(port) if port.isdigit() else 5037


def frida_client_hosts() -> list:
    """
    Ordered, de-duplicated hosts to try when dialling a forwarded Frida port.

    Local loopback first (host runs), then the ADB server host (container runs
    against a host ADB server), then an explicit ADB_HOST.
    """
    hosts = ["127.0.0.1", adb_server_host(), os.getenv("ADB_HOST", "").strip()]
    out: list = []
    for host in hosts:
        if host and host not in out:
            out.append(host)
    return out


@dataclass(frozen=True)
class SandboxConfig:
    """Runtime configuration for the sandbox abstraction layer."""

    # auto | genymotion | android_avd | android_studio | physical
    provider: str = "auto"
    adb_host: str = ""
    adb_port: str = "5555"
    device_serial: str = ""
    frida_port: str = DEFAULT_FRIDA_SERVER_PORT
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
        frida_port=frida_server_port(),
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
