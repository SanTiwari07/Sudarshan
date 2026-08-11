"""
Sudarshan Sandbox Abstraction Layer
===================================
Decouples the Dynamic Analysis Engine from a concrete emulator backend.

Providers:
  - AutoDetectProvider   (default) - discovers Genymotion / AVD / physical
  - GenymotionProvider
  - AndroidStudioProvider (android_avd)
  - PhysicalDeviceProvider
  - FutureProvider stubs - Corellium / Waydroid

The DAE must communicate only through SandboxProvider / SandboxDevice.
Analysis logic, risk scoring, Frida hooks, MobSF, and the AI pipeline are
intentionally outside this package.
"""

from sudarshan_core.sandbox.config import SandboxConfig, load_sandbox_config
from sudarshan_core.sandbox.device import (
    detect_provider_from_props,
    format_device_line,
    provider_display_name,
    transport_for_serial,
)
from sudarshan_core.sandbox.exceptions import (
    ADBUnavailable,
    APKInstallFailed,
    AppLaunchFailed,
    DeviceNotFound,
    FridaUnavailable,
    RootUnavailable,
    SandboxError,
    SandboxNotRooted,
    SandboxOffline,
)
from sudarshan_core.sandbox.factory import (
    clear_sandbox_provider_cache,
    get_sandbox_provider,
    register_provider,
)
from sudarshan_core.sandbox.frida_assets import (
    FridaBinarySpec,
    locate_frida_server,
    missing_binary_message,
)
from sudarshan_core.sandbox.provider import SandboxProvider
from sudarshan_core.sandbox.types import (
    ConnectionResult,
    DeviceInfo,
    FridaStatus,
    SandboxDevice,
)

__all__ = [
    "SandboxConfig",
    "load_sandbox_config",
    "SandboxProvider",
    "get_sandbox_provider",
    "register_provider",
    "clear_sandbox_provider_cache",
    "ConnectionResult",
    "DeviceInfo",
    "SandboxDevice",
    "FridaStatus",
    "FridaBinarySpec",
    "locate_frida_server",
    "missing_binary_message",
    "detect_provider_from_props",
    "transport_for_serial",
    "provider_display_name",
    "format_device_line",
    "SandboxError",
    "SandboxOffline",
    "ADBUnavailable",
    "DeviceNotFound",
    "FridaUnavailable",
    "RootUnavailable",
    "SandboxNotRooted",
    "APKInstallFailed",
    "AppLaunchFailed",
]
