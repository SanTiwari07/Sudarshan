"""
Stub providers for future sandbox backends.

These exist so SANDBOX_PROVIDER can be extended (Corellium, Waydroid,
physical rooted devices) without changing the Dynamic Analysis Engine.
"""

from __future__ import annotations

import logging
from typing import List

from sudarshan_core.sandbox.provider import SandboxProvider
from sudarshan_core.sandbox.types import ConnectionResult

logger = logging.getLogger(__name__)


class FutureProvider(SandboxProvider):
    """
    Placeholder for Corellium / Waydroid / physical-device backends.

    Instantiation is allowed so factory registration stays uniform;
    connect() always returns a structured failure until implemented.
    """

    name = "future"

    def __init__(self, config, backend_name: str = "future"):
        super().__init__(config)
        self.name = backend_name

    def _adb_candidates(self) -> List[str]:
        return []

    def apply_state_profile(self, serial: str, profile: str) -> bool:
        logger.warning("[%s] apply_state_profile not implemented", self.name)
        return False

    def reset_state(self, serial: str) -> bool:
        logger.warning("[%s] reset_state not implemented", self.name)
        return False

    def connect(self, preferred_serial=None) -> ConnectionResult:
        return ConnectionResult(
            ok=False,
            error_code="SANDBOX_ERROR",
            error_message=(
                f"Sandbox provider {self.name!r} is registered but not yet "
                "implemented. Use SANDBOX_PROVIDER=genymotion or android_studio."
            ),
            stages=[{"stage": "provider", "ok": False, "detail": self.name}],
        )


class CorelliumProvider(FutureProvider):
    name = "corellium"

    def __init__(self, config):
        super().__init__(config, backend_name="corellium")


class WaydroidProvider(FutureProvider):
    name = "waydroid"

    def __init__(self, config):
        super().__init__(config, backend_name="waydroid")


class PhysicalDeviceProvider(FutureProvider):
    """
    Physical rooted device stub.

    When implemented, this can reuse most of SandboxProvider's ADB/root/Frida
    logic - only device discovery and state simulation differ.
    """

    name = "physical"

    def __init__(self, config):
        super().__init__(config, backend_name="physical")
