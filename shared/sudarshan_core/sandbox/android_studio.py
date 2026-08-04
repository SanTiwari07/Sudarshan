"""
Android Studio AVD sandbox provider (optional / legacy).

Preserves the previous Android Studio Emulator + `adb emu` console
behaviour so operators can set SANDBOX_PROVIDER=android_studio without
losing multi-stage GPS/battery/SMS simulation.
"""

from __future__ import annotations

import logging
import os
from typing import List

from sudarshan_core.sandbox.provider import SandboxProvider

logger = logging.getLogger(__name__)


class AndroidStudioProvider(SandboxProvider):
    """Sandbox backend for Android Studio AVDs."""

    name = "android_studio"

    def _adb_candidates(self) -> List[str]:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
        sdk = self.config.android_sdk_root
        candidates = [
            os.path.join(sdk, "platform-tools", "adb.exe") if sdk else "",
            os.path.join(sdk, "platform-tools", "adb") if sdk else "",
            os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
            rf"C:\Users\{user}\AppData\Local\Android\Sdk\platform-tools\adb.exe",
            r"C:\Program Files\Android\Android Studio\sdk\platform-tools\adb.exe",
            r"C:\Program Files\Android\android-sdk\platform-tools\adb.exe",
            os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
            os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
        ]
        return [c for c in candidates if c]

    def _emu(self, serial: str, *args: str) -> bool:
        """Send an Android Emulator console command via `adb emu`."""
        ok, out = self.adb("-s", serial, "emu", *args, timeout=5)
        if not ok:
            logger.error("[android_studio] emu command failed: %s", out)
        return ok

    def apply_state_profile(self, serial: str, profile: str) -> bool:
        logger.info("[android_studio] Applying profile %s on %s", profile, serial)

        def shell(*parts: str) -> bool:
            ok, _ = self.adb("-s", serial, "shell", *parts)
            return ok

        if profile == "wifi_off":
            return shell("svc", "wifi", "disable")
        if profile == "mobile_data_on":
            return shell("svc", "data", "enable")
        if profile == "gps_active":
            return self._emu(serial, "geo", "fix", "77.2090", "28.6139")
        if profile == "battery_low":
            self._emu(serial, "battery", "level", "15")
            return self._emu(serial, "battery", "status", "discharging")
        if profile == "charging":
            return self._emu(serial, "battery", "status", "charging")
        if profile == "dark_mode":
            return shell("cmd", "uimode", "night", "yes")
        if profile == "hindi_locale":
            shell("setprop", "persist.sys.locale", "hi-IN")
            return shell("am", "broadcast", "-a", "android.intent.action.LOCALE_CHANGED")
        if profile == "sim_present":
            return self._emu(serial, "sms", "send", "+919876543210", "OTP: 123456")
        if profile == "banking_apps":
            packages = ["com.boi.mobile", "com.sbi.lotusintouch", "com.icici.mobile"]
            for pkg in packages:
                shell("su", "-c", f"mkdir -p /data/data/{pkg}")
            return True
        if profile == "reboot":
            return shell("am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED")

        logger.warning("[android_studio] Unknown profile: %s", profile)
        return False

    def reset_state(self, serial: str) -> bool:
        self.adb("-s", serial, "shell", "svc", "wifi", "enable")
        self._emu(serial, "battery", "level", "100")
        self._emu(serial, "battery", "status", "charging")
        self.adb("-s", serial, "shell", "cmd", "uimode", "night", "no")
        self.adb("-s", serial, "shell", "setprop", "persist.sys.locale", "en-US")
        self.adb(
            "-s",
            serial,
            "shell",
            "am",
            "broadcast",
            "-a",
            "android.intent.action.LOCALE_CHANGED",
        )
        return True
