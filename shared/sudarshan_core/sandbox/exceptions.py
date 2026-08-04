"""
Sandbox layer exceptions.

Structured, non-fatal error types returned or raised by SandboxProvider
implementations. The Dynamic Analysis Engine maps these to result dicts
and must never crash the analysis pipeline.
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base class for all sandbox abstraction errors."""

    code: str = "SANDBOX_ERROR"

    def __init__(self, message: str = "", *, details: dict | None = None):
        self.message = message or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class SandboxOffline(SandboxError):
    """Sandbox device is offline or unreachable."""

    code = "SANDBOX_OFFLINE"


class ADBUnavailable(SandboxError):
    """ADB binary cannot be found or cannot execute."""

    code = "ADB_UNAVAILABLE"


class DeviceNotFound(SandboxError):
    """No matching device serial found via `adb devices`."""

    code = "DEVICE_NOT_FOUND"


class FridaUnavailable(SandboxError):
    """frida-server is missing, dead, or version-incompatible."""

    code = "FRIDA_UNAVAILABLE"


class RootUnavailable(SandboxError):
    """Device cannot be rooted via `adb root` / whoami."""

    code = "ROOT_UNAVAILABLE"


# Alias required by migration spec
SandboxNotRooted = RootUnavailable


class APKInstallFailed(SandboxError):
    """APK installation onto the sandbox failed."""

    code = "APK_INSTALL_FAILED"


class AppLaunchFailed(SandboxError):
    """Target application failed to launch or stabilize."""

    code = "APP_LAUNCH_FAILED"
