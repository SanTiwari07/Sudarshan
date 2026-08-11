"""
Auto-detecting sandbox provider.

Discovers ADB devices, fingerprints Genymotion / Android AVD / physical,
selects a sandbox deterministically, and delegates provider-specific state
simulation to the matching adapter. Common ADB / root / Frida logic stays on
the base SandboxProvider.
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from sudarshan_core.sandbox.android_studio import AndroidStudioProvider
from sudarshan_core.sandbox.config import SandboxConfig
from sudarshan_core.sandbox.device import (
    PROVIDER_ANDROID_AVD,
    PROVIDER_GENYMOTION,
    PROVIDER_PHYSICAL,
    normalize_provider_name,
    provider_display_name,
)
from sudarshan_core.sandbox.genymotion import GenymotionProvider
from sudarshan_core.sandbox.provider import SandboxProvider
from sudarshan_core.sandbox.types import DeviceInfo

logger = logging.getLogger(__name__)


class PhysicalDeviceProvider(SandboxProvider):
    """ADB-connected physical device (rooted preferred for Frida)."""

    name = "physical"

    def _adb_candidates(self) -> List[str]:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
        sdk = self.config.android_sdk_root
        return [
            c
            for c in [
                os.path.join(sdk, "platform-tools", "adb.exe") if sdk else "",
                os.path.join(sdk, "platform-tools", "adb") if sdk else "",
                os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
                rf"C:\Users\{user}\AppData\Local\Android\Sdk\platform-tools\adb.exe",
                os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
                os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
            ]
            if c
        ]

    def apply_state_profile(self, serial: str, profile: str) -> bool:
        # Physical devices: shell-only simulation (no emu console / Genymotion GPS).
        logger.info("[physical] Applying profile %s on %s", profile, serial)

        def shell(*parts: str) -> bool:
            ok, _ = self.adb("-s", serial, "shell", *parts)
            return ok

        if profile == "wifi_off":
            return shell("svc", "wifi", "disable")
        if profile == "mobile_data_on":
            return shell("svc", "data", "enable")
        if profile == "battery_low":
            return shell("dumpsys", "battery", "set", "level", "15")
        if profile == "charging":
            return shell("dumpsys", "battery", "reset")
        if profile == "dark_mode":
            return shell("cmd", "uimode", "night", "yes")
        if profile == "hindi_locale":
            shell("setprop", "persist.sys.locale", "hi-IN")
            return shell("am", "broadcast", "-a", "android.intent.action.LOCALE_CHANGED")
        if profile in ("gps_active", "sim_present", "banking_apps", "reboot"):
            logger.warning(
                "[physical] Profile %s is limited/unavailable on physical devices",
                profile,
            )
            return False
        logger.warning("[physical] Unknown profile: %s", profile)
        return False

    def reset_state(self, serial: str) -> bool:
        self.adb("-s", serial, "shell", "svc", "wifi", "enable")
        self.adb("-s", serial, "shell", "dumpsys", "battery", "reset")
        self.adb("-s", serial, "shell", "cmd", "uimode", "night", "no")
        return True


class AutoDetectProvider(SandboxProvider):
    """
    Provider-agnostic facade.

    Device discovery fingerprints each online device. After selection, state
    profiles are delegated to Genymotion / AVD / physical adapters. Root and
    Frida remain on the shared base class.
    """

    name = "auto"

    def __init__(self, config: SandboxConfig):
        super().__init__(config)
        self._selected: Optional[DeviceInfo] = None
        self._delegate: Optional[SandboxProvider] = None
        # Concrete adapters for ADB path hints + state profiles
        self._geny = GenymotionProvider(config)
        self._avd = AndroidStudioProvider(config)
        self._phys = PhysicalDeviceProvider(config)

    def _adb_candidates(self) -> List[str]:
        # Prefer Android SDK, then Genymotion tools - either works for both.
        seen = set()
        out: List[str] = []
        for candidate in (
            self._avd._adb_candidates()
            + self._geny._adb_candidates()
            + self._phys._adb_candidates()
        ):
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
        return out

    def _delegate_for(self, provider_id: str) -> SandboxProvider:
        pid = normalize_provider_name(provider_id)
        if pid == PROVIDER_GENYMOTION:
            return self._geny
        if pid == PROVIDER_ANDROID_AVD:
            return self._avd
        if pid == PROVIDER_PHYSICAL:
            return self._phys
        # Unknown → shell-only physical behaviour
        return self._phys

    def select_device(self, preferred_serial: Optional[str] = None) -> DeviceInfo:
        from sudarshan_core.sandbox.device import select_sandbox_device
        from sudarshan_core.sandbox.exceptions import DeviceNotFound
        from sudarshan_core.sandbox.frida_assets import supported_host_abis

        preferred = (preferred_serial or self.config.device_serial or "").strip()
        devices = self.discover_devices()
        cfg_provider = normalize_provider_name(self.config.provider)
        preferred_provider = "" if cfg_provider == "auto" else cfg_provider

        try:
            device = select_sandbox_device(
                devices,
                preferred_serial=preferred,
                preferred_provider=preferred_provider,
                supported_abis=supported_host_abis(),
            )
        except ValueError as exc:
            raise DeviceNotFound(
                str(exc),
                details={"provider": self.name, "adb_host": self.config.adb_host},
            ) from exc

        self._selected = device
        self._delegate = self._delegate_for(device.provider)
        logger.info(
            "[auto] Selected sandbox: %s (%s)",
            provider_display_name(device.provider),
            device.serial,
        )
        os.environ.setdefault("DEVICE_SERIAL", device.serial)
        os.environ.setdefault("ANDROID_DEVICE_SERIAL", device.serial)
        if device.provider == PROVIDER_GENYMOTION and device.ip:
            os.environ.setdefault("ADB_HOST", device.ip)

        return device

    def apply_state_profile(self, serial: str, profile: str) -> bool:
        info = self._selected
        if info is None or info.serial != serial:
            try:
                info = self.get_device_info(serial)
            except Exception:  # noqa: BLE001
                info = DeviceInfo(serial=serial, provider=PROVIDER_PHYSICAL)
        delegate = self._delegate_for(info.provider)
        return delegate.apply_state_profile(serial, profile)

    def reset_state(self, serial: str) -> bool:
        info = self._selected
        if info is None or info.serial != serial:
            try:
                info = self.get_device_info(serial)
            except Exception:  # noqa: BLE001
                info = DeviceInfo(serial=serial, provider=PROVIDER_PHYSICAL)
        delegate = self._delegate_for(info.provider)
        return delegate.reset_state(serial)
