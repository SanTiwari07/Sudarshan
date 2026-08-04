"""
Sudarshan Sandbox Abstraction Layer
===================================
Decouples the Dynamic Analysis Engine from a concrete emulator backend.

Providers:
  - GenymotionProvider   (default) — Genymotion Desktop
  - AndroidStudioProvider — Android Studio AVD (optional / legacy)
  - FutureProvider        — Corellium / Waydroid / physical stubs

The DAE must communicate only through SandboxProvider. Analysis logic,
risk scoring, Frida hooks, MobSF, and the AI pipeline are intentionally
outside this package.
"""

from sudarshan_core.sandbox.config import SandboxConfig, load_sandbox_config
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
from sudarshan_core.sandbox.provider import SandboxProvider
from sudarshan_core.sandbox.types import ConnectionResult, DeviceInfo, FridaStatus

__all__ = [
    "SandboxConfig",
    "load_sandbox_config",
    "SandboxProvider",
    "get_sandbox_provider",
    "register_provider",
    "clear_sandbox_provider_cache",
    "ConnectionResult",
    "DeviceInfo",
    "FridaStatus",
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
