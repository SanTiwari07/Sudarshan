"""
SUDARSHAN — Device State Simulator
===================================
Simulates real-device conditions (e.g. WiFi, Battery, Location, SMS) via ADB
to trigger dormant malware behavior before or during analysis.
"""

import logging
import subprocess
import time
from typing import List

logger = logging.getLogger(__name__)

class DeviceStateSimulator:
    def __init__(self, device_serial: str, adb_path: str = "adb"):
        self.device_serial = device_serial
        self.adb_path = adb_path

    def _adb(self, *args) -> bool:
        cmd = [self.adb_path, "-s", self.device_serial] + list(args)
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=5)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"[DeviceState] ADB command failed: {e}")
            return False

    def _emu(self, *args) -> bool:
        """Sends an 'adb emu' command (only works on Android Studio emulators)."""
        cmd = [self.adb_path, "-s", self.device_serial, "emu"] + list(args)
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=5)
            return res.returncode == 0
        except Exception as e:
            logger.error(f"[DeviceState] Emulator command failed: {e}")
            return False

    def apply_profile(self, profile: str) -> bool:
        """Applies a predefined state profile."""
        logger.info(f"[DeviceState] Applying profile: {profile}")
        
        if profile == "wifi_off":
            return self._adb("shell", "svc", "wifi", "disable")
            
        elif profile == "mobile_data_on":
            return self._adb("shell", "svc", "data", "enable")
            
        elif profile == "gps_active":
            # New Delhi coordinates
            return self._emu("geo", "fix", "77.2090", "28.6139")
            
        elif profile == "battery_low":
            self._emu("battery", "level", "15")
            return self._emu("battery", "status", "discharging")
            
        elif profile == "charging":
            return self._emu("battery", "status", "charging")
            
        elif profile == "dark_mode":
            return self._adb("shell", "cmd", "uimode", "night", "yes")
            
        elif profile == "hindi_locale":
            self._adb("shell", "setprop", "persist.sys.locale", "hi-IN")
            return self._adb("shell", "am", "broadcast", "-a", "android.intent.action.LOCALE_CHANGED")
            
        elif profile == "sim_present":
            # Inject a fake SMS to trigger inbox listeners
            return self._emu("sms", "send", "+919876543210", "OTP: 123456")
            
        elif profile == "banking_apps":
            # Creates dummy packages for banking apps so malware detects them
            # This requires root to create dirs in /data/data/ directly, or we can install a stub APK.
            # We'll simulate it by creating dummy dirs if rooted.
            packages = ["com.boi.mobile", "com.sbi.lotusintouch", "com.icici.mobile"]
            for pkg in packages:
                self._adb("shell", "su", "-c", f"mkdir -p /data/data/{pkg}")
            return True
            
        elif profile == "reboot":
            # Simulates a reboot by force-stopping all apps and broadcasting BOOT_COMPLETED
            self._adb("shell", "am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED")
            return True
            
        else:
            logger.warning(f"[DeviceState] Unknown profile: {profile}")
            return False

    def reset(self) -> bool:
        """Restores the device to a clean, default state."""
        self._adb("shell", "svc", "wifi", "enable")
        self._emu("battery", "level", "100")
        self._emu("battery", "status", "charging")
        self._adb("shell", "cmd", "uimode", "night", "no")
        self._adb("shell", "setprop", "persist.sys.locale", "en-US")
        self._adb("shell", "am", "broadcast", "-a", "android.intent.action.LOCALE_CHANGED")
        return True
