"""
Genymotion Desktop sandbox provider (default).

Genymotion devices typically appear in `adb devices` as IP:port
(e.g. 192.168.56.101:5555) or as a USB-style serial when using
Genymotion's ADB bridge. Device-state simulation uses shell/dumpsys
APIs because Genymotion does not support Android Studio's `adb emu`
console.
"""

from __future__ import annotations

import logging
import os
from typing import List

from sudarshan_core.sandbox.provider import SandboxProvider

logger = logging.getLogger(__name__)


class GenymotionProvider(SandboxProvider):
    """Sandbox backend for Genymotion Desktop virtual devices."""

    name = "genymotion"

    def _adb_candidates(self) -> List[str]:
        candidates: List[str] = []
        if self.config.genymotion_adb:
            candidates.append(self.config.genymotion_adb)

        # Official Genymotion Desktop tool locations (Windows / macOS / Linux)
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
        candidates.extend(
            [
                r"C:\Program Files\Genymobile\Genymotion\tools\adb.exe",
                r"C:\Program Files (x86)\Genymobile\Genymotion\tools\adb.exe",
                rf"C:\Users\{user}\AppData\Local\Genymobile\Genymotion\tools\adb.exe",
                "/Applications/Genymotion.app/Contents/MacOS/tools/adb",
                "/opt/genymobile/genymotion/tools/adb",
                os.path.expanduser("~/genymotion/tools/adb"),
                # Fall back to Android SDK platform-tools if Genymotion uses system ADB
                os.path.join(
                    self.config.android_sdk_root or "",
                    "platform-tools",
                    "adb.exe" if os.name == "nt" else "adb",
                ),
                os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
                os.path.expanduser("~/Library/Android/sdk/platform-tools/adb"),
                os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
            ]
        )
        return [c for c in candidates if c]

    # ── State profiles (shell / dumpsys — no `adb emu`) ───────────────────────

    def apply_state_profile(self, serial: str, profile: str) -> bool:
        logger.info("[genymotion] Applying profile %s on %s", profile, serial)

        def shell(*parts: str) -> bool:
            ok, _ = self.adb("-s", serial, "shell", *parts)
            return ok

        if profile == "wifi_off":
            return shell("svc", "wifi", "disable")
        if profile == "mobile_data_on":
            return shell("svc", "data", "enable")
        if profile == "gps_active":
            # New Delhi — Genymotion accepts mock location via settings + am
            ok1 = shell("settings", "put", "secure", "mock_location", "1")
            ok2 = shell(
                "am",
                "startservice",
                "-n",
                "com.genymotion.superuser/.gps.GpsService",
                "--ef",
                "latitude",
                "28.6139",
                "--ef",
                "longitude",
                "77.2090",
            )
            # Fallback: setprop used by some Genymotion images
            ok3 = shell("setprop", "persist.genymotion.gps.latitude", "28.6139")
            ok4 = shell("setprop", "persist.genymotion.gps.longitude", "77.2090")
            return ok1 or ok2 or (ok3 and ok4)
        if profile == "battery_low":
            ok1 = shell("dumpsys", "battery", "set", "level", "15")
            ok2 = shell("dumpsys", "battery", "set", "status", "3")  # discharging
            ok3 = shell("dumpsys", "battery", "unplug")
            return ok1 or ok2 or ok3
        if profile == "charging":
            ok1 = shell("dumpsys", "battery", "set", "status", "2")  # charging
            ok2 = shell("dumpsys", "battery", "reset")
            return ok1 or ok2
        if profile == "dark_mode":
            return shell("cmd", "uimode", "night", "yes")
        if profile == "hindi_locale":
            shell("setprop", "persist.sys.locale", "hi-IN")
            return shell("am", "broadcast", "-a", "android.intent.action.LOCALE_CHANGED")
        if profile == "sim_present":
            # Broadcast a received SMS intent (Genymotion has no `adb emu sms`)
            return shell(
                "am",
                "broadcast",
                "-a",
                "android.provider.Telephony.SMS_RECEIVED",
                "--es",
                "sender",
                "+919876543210",
                "--es",
                "body",
                "OTP: 123456",
            )
        if profile == "banking_apps":
            packages = ["com.boi.mobile", "com.sbi.lotusintouch", "com.icici.mobile"]
            for pkg in packages:
                shell("su", "-c", f"mkdir -p /data/data/{pkg}")
            return True
        if profile == "reboot":
            return shell("am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED")

        logger.warning("[genymotion] Unknown profile: %s", profile)
        return False

    def reset_state(self, serial: str) -> bool:
        self.adb("-s", serial, "shell", "svc", "wifi", "enable")
        self.adb("-s", serial, "shell", "dumpsys", "battery", "reset")
        self.adb("-s", serial, "shell", "dumpsys", "battery", "set", "level", "100")
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
