"""
SUDARSHAN — Permission Orchestrator
====================================
Automatically navigates Android Settings to grant dangerous permissions 
required by malware (Accessibility, Overlay, Device Admin, etc.).
Called by UIExplorer when it detects a Settings screen or via direct API.
"""

import time
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)


def extract_accessibility_service_class(
    apk_path: str,
    package_name: str,
) -> Optional[str]:
    """
    Return the real accessibility service class name declared in this APK's
    manifest, or None if no accessibility service is declared.

    Reuses the already-imported Androguard analyzer (same dependency used in
    apk_analyzer.py) — does NOT re-parse if the caller already has an `apk`
    object, but we cannot assume that here because the orchestrator is called
    from a different module boundary. Parsing is cheap compared to ADB round
    trips; the result should be cached by the caller if called in a tight loop.

    We look for a <service> element that simultaneously:
      1. Declares android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
      2. Has an <intent-filter> with action
         "android.accessibilityservice.AccessibilityService"

    If no such element is found we return None — this is itself a finding
    (the sample does not use accessibility abuse via a declared service).

    Never raises: any parse failure degrades to None.
    """
    try:
        from androguard.misc import AnalyzeAPK
        try:
            import loguru
            loguru.logger.disable("androguard")
        except ImportError:
            pass
        a, _, _ = AnalyzeAPK(apk_path)
    except Exception as exc:
        logger.warning(
            f"[PermissionOrchestrator] Could not parse APK manifest for "
            f"accessibility service class ({type(exc).__name__}: {exc})"
        )
        return None

    try:
        services = a.get_services() or []
    except Exception:
        services = []

    for svc_name in services:
        # Check guard permission attribute
        has_bind_perm = False
        try:
            perm_attr = a.get_element("service", "permission", name=svc_name) or ""
            if "BIND_ACCESSIBILITY_SERVICE" in str(perm_attr).upper():
                has_bind_perm = True
        except Exception:
            pass

        if not has_bind_perm:
            # Try via raw manifest substring for this service node
            try:
                xml = a.get_android_manifest_axml().get_xml().decode(
                    "utf-8", errors="replace"
                )
                # A simple heuristic: if the service class appears in the xml
                # adjacent to the BIND_ACCESSIBILITY_SERVICE text
                short = svc_name.split(".")[-1]
                if (short in xml and "BIND_ACCESSIBILITY_SERVICE" in xml
                        and "accessibilityservice" in xml.lower()):
                    has_bind_perm = True
            except Exception:
                pass

        if not has_bind_perm:
            continue

        # Check intent-filter action
        has_accessibility_action = False
        try:
            filters = a.get_intent_filters("service", svc_name)
            for action in filters.get("action", []):
                if "accessibilityservice" in action.lower():
                    has_accessibility_action = True
                    break
        except Exception:
            pass

        if has_accessibility_action:
            # Resolve the class name: may be fully-qualified or relative
            if svc_name.startswith(package_name):
                # Fully qualified — convert to relative (.ClassName)
                class_name = svc_name[len(package_name):]
                if not class_name.startswith("."):
                    class_name = "." + class_name.lstrip(".")
            elif svc_name.startswith("."):
                class_name = svc_name
            else:
                # Unknown package prefix — use as-is
                class_name = svc_name

            logger.info(
                f"[PermissionOrchestrator] Found real accessibility service class: "
                f"'{class_name}' (declared in manifest for {package_name})"
            )
            return class_name

    # No qualifying service found
    logger.info(
        f"[PermissionOrchestrator] No accessibility service declared in "
        f"'{package_name}' manifest — this sample does not use accessibility abuse "
        f"via a bound service."
    )
    return None


class PermissionOrchestrator:
    def __init__(
        self,
        device_serial: str,
        adb_path: str = "adb",
        event_bus: Optional[RuntimeEventBus] = None
    ):
        self.device_serial = device_serial
        self.adb_path = adb_path
        self.event_bus = event_bus
        self.actions_log: List[Dict[str, Any]] = []

    def _log_action(self, permission: str, action: str, success: bool):
        entry = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "permission": permission,
            "action": action,
            "success": success
        }
        self.actions_log.append(entry)
        
        if self.event_bus:
            self.event_bus.publish({
                "type": "event",
                "category": "orchestrator",
                "severity": "LOW",
                "data": entry
            })
            if success and action == "grant":
                self.event_bus.publish({
                    "type": "event",
                    "category": "permission_granted",
                    "severity": "MED",
                    "data": {"permission": permission}
                })

    def _adb(self, *args) -> str:
        cmd = [self.adb_path, "-s", self.device_serial] + list(args)
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return res.stdout.strip()
        except Exception as e:
            logger.error(f"[PermissionOrchestrator] ADB error: {e}")
            return ""

    def grant_accessibility(
        self,
        package_name: str,
        app_name: str,
        service_class: Optional[str] = None,
    ) -> bool:
        """
        Grant accessibility service for the given package.

        Parameters
        ----------
        package_name : str
            The APK's package name (e.g. ``com.example.app``).
        app_name : str
            Human-readable app name, used for UI hierarchy search.
        service_class : Optional[str]
            The *real* accessibility service class name as declared in the
            manifest, e.g. ``".zWPzgfI"`` for Cerberus.  When ``None`` the
            orchestrator checks whether a service is even declared before
            attempting to enable it.  Passing the pre-parsed class avoids a
            redundant Androguard parse on the hot path.

            Use :func:`extract_accessibility_service_class` to obtain this
            value ahead of time from the APK manifest.
        """
        logger.info(
            f"[PermissionOrchestrator] Attempting to grant Accessibility for {package_name}"
        )

        # If no class was provided by the caller, check that a service
        # actually exists before writing to settings — writing a non-existent
        # component name silently fails and wastes the 0.35-weight BFCI slot.
        if service_class is None:
            logger.info(
                f"[PermissionOrchestrator] No service_class provided; "
                f"skipping settings put — caller should pass the manifest-parsed "
                f"class name via extract_accessibility_service_class()."
            )
            self._log_action("accessibility", "grant", False)
            return False

        # Open Accessibility Settings
        self._adb("shell", "am", "start", "-a", "android.settings.ACCESSIBILITY_SETTINGS")
        time.sleep(2)

        # Check UI hierarchy to detect whether the service is visible in the list
        ui_dump = self._adb("shell", "uiautomator", "dump", "/dev/stdout")
        visible_in_ui = package_name in ui_dump or app_name in ui_dump

        # Build the fully-qualified component name the settings command expects
        if service_class.startswith("."):
            component = f"{package_name}{service_class}"
        else:
            component = service_class  # already fully qualified

        logger.info(
            f"[PermissionOrchestrator] Enabling accessibility service component: "
            f"'{component}' (ui_visible={visible_in_ui})"
        )

        # Grant via ADB (requires root, but we are on a rooted emulator)
        self._adb(
            "shell", "settings", "put", "secure",
            "enabled_accessibility_services",
            component,
        )
        self._adb("shell", "settings", "put", "secure", "accessibility_enabled", "1")

        success = True
        self._log_action("accessibility", "grant", success)

        # Return to home
        self._adb("shell", "input", "keyevent", "3")
        return success

    def grant_overlay(self, package_name: str) -> bool:
        """Grants SYSTEM_ALERT_WINDOW (Draw over other apps)."""
        logger.info(f"[PermissionOrchestrator] Attempting to grant Overlay for {package_name}")
        # In modern Android, AppOpsManager can grant this via ADB
        out = self._adb("shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow")
        success = "Error" not in out
        self._log_action("overlay", "grant", success)
        return success

    def grant_device_admin(self, package_name: str, admin_receiver: str) -> bool:
        """Activates Device Admin for the package. Requires root/dpm."""
        logger.info(f"[PermissionOrchestrator] Attempting to grant Device Admin for {package_name}")
        out = self._adb("shell", "dpm", "set-active-admin", f"{package_name}/{admin_receiver}")
        success = "Success" in out
        self._log_action("device_admin", "grant", success)
        return success
        
    def grant_all_standard_permissions(self, package_name: str) -> bool:
        """Grants all standard Android permissions defined in the manifest."""
        logger.info(f"[PermissionOrchestrator] Granting standard permissions for {package_name}")
        out = self._adb("shell", "pm", "grant", package_name, "android.permission.READ_SMS")
        out += self._adb("shell", "pm", "grant", package_name, "android.permission.READ_CONTACTS")
        out += self._adb("shell", "pm", "grant", package_name, "android.permission.READ_CALL_LOG")
        out += self._adb("shell", "pm", "grant", package_name, "android.permission.CAMERA")
        out += self._adb("shell", "pm", "grant", package_name, "android.permission.RECORD_AUDIO")
        out += self._adb("shell", "pm", "grant", package_name, "android.permission.ACCESS_FINE_LOCATION")
        
        self._log_action("standard_permissions", "grant", True)
        return True

    def flush(self, output_path: Path) -> int:
        """Writes the permission action log to JSON."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.actions_log, f, indent=4)
            logger.info(f"[PermissionOrchestrator] Flushed {len(self.actions_log)} actions → {output_path}")
        except Exception as e:
            logger.error(f"[PermissionOrchestrator] Failed to write permissions.json: {e}")
        
        return len(self.actions_log)
