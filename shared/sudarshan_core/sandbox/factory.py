"""Factory for SandboxProvider implementations."""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional, Type

from sudarshan_core.sandbox.android_studio import AndroidStudioProvider
from sudarshan_core.sandbox.auto import AutoDetectProvider, PhysicalDeviceProvider
from sudarshan_core.sandbox.config import SandboxConfig, load_sandbox_config
from sudarshan_core.sandbox.future import (
    CorelliumProvider,
    FutureProvider,
    WaydroidProvider,
)
from sudarshan_core.sandbox.genymotion import GenymotionProvider
from sudarshan_core.sandbox.provider import SandboxProvider

logger = logging.getLogger(__name__)

_PROVIDERS: Dict[str, Type[SandboxProvider]] = {
    "auto": AutoDetectProvider,
    "genymotion": GenymotionProvider,
    "android_avd": AndroidStudioProvider,
    "android_studio": AndroidStudioProvider,
    "androidstudio": AndroidStudioProvider,
    "avd": AndroidStudioProvider,
    "emulator": AndroidStudioProvider,
    "physical": PhysicalDeviceProvider,
    "corellium": CorelliumProvider,
    "waydroid": WaydroidProvider,
    "future": FutureProvider,
}

_lock = threading.Lock()
_cached: Optional[SandboxProvider] = None
_cached_key: Optional[str] = None


def register_provider(name: str, cls: Type[SandboxProvider]) -> None:
    """Register or override a sandbox provider (for tests / plugins)."""
    _PROVIDERS[name.strip().lower()] = cls
    clear_sandbox_provider_cache()


def clear_sandbox_provider_cache() -> None:
    global _cached, _cached_key
    with _lock:
        _cached = None
        _cached_key = None


def get_sandbox_provider(
    config: Optional[SandboxConfig] = None,
    *,
    force_new: bool = False,
) -> SandboxProvider:
    """
    Return the configured SandboxProvider singleton.

    Default provider is auto-detect (`SANDBOX_PROVIDER=auto` /
    `ANDROID_SANDBOX_PROVIDER=auto`).
    """
    global _cached, _cached_key
    cfg = config or load_sandbox_config()
    key = (
        f"{cfg.provider}|{cfg.adb_host}|{cfg.adb_port}|{cfg.device_serial}|"
        f"{cfg.frida_port}|{cfg.auto_connect}|{cfg.root_required}|"
        f"{cfg.frida_version}|{cfg.frida_server_dir}"
    )
    with _lock:
        if not force_new and _cached is not None and _cached_key == key:
            return _cached

        cls = _PROVIDERS.get(cfg.provider)
        if cls is None:
            logger.warning(
                "Unknown SANDBOX_PROVIDER=%r - falling back to auto. Known: %s",
                cfg.provider,
                sorted(set(_PROVIDERS)),
            )
            cls = AutoDetectProvider

        provider = cls(cfg)
        logger.info(
            "[Sandbox] Using provider=%s adb_host=%s adb_port=%s device_serial=%s",
            provider.name,
            cfg.adb_host or "(auto)",
            cfg.adb_port,
            cfg.device_serial or "(auto)",
        )
        _cached = provider
        _cached_key = key
        return provider
