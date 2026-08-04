"""
SUDARSHAN — Device State Simulator
===================================
Simulates real-device conditions (e.g. WiFi, Battery, Location, SMS) via
the active SandboxProvider so multi-stage profiles work on Genymotion
and Android Studio without hardcoding `adb emu`.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class DeviceStateSimulator:
    def __init__(
        self,
        device_serial: str,
        adb_path: str = "adb",
        provider=None,
    ):
        self.device_serial = device_serial
        self.adb_path = adb_path
        self._provider = provider

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        from sudarshan_core.sandbox import get_sandbox_provider
        return get_sandbox_provider()

    def apply_profile(self, profile: str) -> bool:
        """Applies a predefined state profile via the sandbox provider."""
        logger.info(f"[DeviceState] Applying profile: {profile}")
        try:
            return self._get_provider().apply_state_profile(self.device_serial, profile)
        except Exception as e:
            logger.error(f"[DeviceState] Profile {profile!r} failed: {e}")
            return False

    def reset(self) -> bool:
        """Restores the device to a clean, default state."""
        try:
            return self._get_provider().reset_state(self.device_serial)
        except Exception as e:
            logger.error(f"[DeviceState] Reset failed: {e}")
            return False
