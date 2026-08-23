"""
SUDARSHAN - Permission Orchestrator
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
from sudarshan_core.sandbox import get_sandbox_provider

logger = logging.getLogger(__name__)


def extract_accessibility_service_class(
    apk_path: str,
    package_name: str,
) -> Optional[str]:
    """
    Return the real accessibility service class name declared in this APK's
    manifest, or None if no accessibility service is declared.

    Reuses the already-imported Androguard analyzer (same dependency used in
    apk_analyzer.py) - does NOT re-parse if the caller already has an `apk`
    object, but we cannot assume that here because the orchestrator is called
    from a different module boundary. Parsing is cheap compared to ADB round
    trips; the result should be cached by the caller if called in a tight loop.

    We look for a <service> element that simultaneously:
      1. Declares android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
      2. Has an <intent-filter> with action
         "android.accessibilityservice.AccessibilityService"

    If no such element is found we return None - this is itself a finding
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
                # Fully qualified - convert to relative (.ClassName)
                class_name = svc_name[len(package_name):]
                if not class_name.startswith("."):
                    class_name = "." + class_name.lstrip(".")
            elif svc_name.startswith("."):
                class_name = svc_name
            else:
                # Unknown package prefix - use as-is
                class_name = svc_name

            logger.info(
                f"[PermissionOrchestrator] Found real accessibility service class: "
                f"'{class_name}' (declared in manifest for {package_name})"
            )
            return class_name

    # No qualifying service found
    logger.info(
        f"[PermissionOrchestrator] No accessibility service declared in "
        f"'{package_name}' manifest - this sample does not use accessibility abuse "
        f"via a bound service."
    )
    return None


#: Heading that opens the active-admin section of `dumpsys device_policy`.
_ADMIN_SECTION = "enabled device admins"


def _admin_block_mentions(
    output: str, package_name: str, whole_output: bool = False
) -> bool:
    """
    Whether `package_name` owns a component inside the active-admin section.

    Scoped to that section because the surrounding dump enumerates unrelated
    packages, and matched on the component's package half (``pkg/cls``) rather
    than as a substring, so ``com.example.app`` does not match
    ``com.example.app.other``.
    """
    text = output or ""
    if not text.strip():
        return False

    if whole_output:
        block_lines = text.splitlines()
    else:
        block_lines = []
        inside = False
        heading_indent = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if not inside:
                if _ADMIN_SECTION in line.strip().lower():
                    inside = True
                    heading_indent = indent
                continue
            # The section ends at the next heading at the same depth or
            # shallower. Testing for an *unindented* heading is not enough:
            # `dumpsys device_policy` indents "Registered Package list:" by two
            # spaces, exactly like the admin heading, so a naive check swept the
            # whole package enumeration into the admin block - which is how
            # com.android.chrome came back as an active device admin.
            if indent <= heading_indent:
                break
            block_lines.append(line)
        if not block_lines:
            return False

    for line in block_lines:
        for token in line.replace(",", " ").replace("{", " ").replace("}", " ").split():
            candidate = token.split("/", 1)[0].strip(":")
            if candidate == package_name:
                return True
    return False


def _flatten_component(package_name: str, service_class: str) -> str:
    """
    Android's flattened ComponentName, "package/class".

    `enabled_accessibility_services` is a colon-separated list of these. A bare
    class name in that list is ignored, which is what made the grant a no-op.

    Accepts every shape the manifest and callers produce:

        ".Svc"                  -> "com.pkg/.Svc"
        "com.pkg.Svc"           -> "com.pkg/com.pkg.Svc"
        "com.other.Svc"         -> "com.pkg/com.other.Svc"
        "com.pkg/.Svc"          -> unchanged (already flattened)
    """
    service_class = (service_class or "").strip()
    package_name = (package_name or "").strip()
    if not service_class:
        return ""
    if "/" in service_class:
        return service_class
    if not package_name:
        return service_class
    # A leading dot is already relative-to-package; Android resolves it.
    return f"{package_name}/{service_class}"


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
        """
        Run an ADB command and return its output, or "" if it failed.

        Kept for the existing callers. New code should prefer :meth:`_adb2`,
        which does not conflate "the command failed" with "the command printed
        nothing" - a distinction `grant_overlay` got wrong for exactly this
        reason.
        """
        ok, out = self._adb2(*args)
        return out if ok else ""

    def _adb2(self, *args) -> tuple:
        """Run an ADB command; returns (ok, output)."""
        provider = get_sandbox_provider()
        ok, out = provider.adb("-s", self.device_serial, *args, timeout=10)
        return bool(ok), (out or "")

    # ── Verification helpers (§10) ───────────────────────────────────────────
    #
    # Every grant below is confirmed by re-reading device state. The parsers are
    # imported from action_verifier rather than duplicated: it already models
    # `settings get secure` returning the literal string "null" and the appops
    # "MODE; rejectTime=..." shape, both of which are easy to get wrong twice.

    def accessibility_components(self) -> frozenset:
        """Components currently listed in enabled_accessibility_services."""
        from sudarshan_core.engines.agentic.action_verifier import (
            parse_accessibility_components,
        )

        ok, out = self._adb2(
            "shell", "settings", "get", "secure", "enabled_accessibility_services"
        )
        return parse_accessibility_components(out) if ok else frozenset()

    def verify_accessibility_enabled(self, package_name: str) -> bool:
        """
        Whether an accessibility service belonging to this package is enabled.

        This is the check `grant_accessibility` never performed - it returned a
        hardcoded True, so a run could report accessibility granted when the
        settings write had silently done nothing.
        """
        from sudarshan_core.engines.agentic.action_verifier import (
            accessibility_enabled_for,
        )

        if not accessibility_enabled_for(
            self.accessibility_components(), package_name
        ):
            return False
        # The master switch must also be on; a component listed while
        # accessibility_enabled is 0 does not actually receive events.
        ok, out = self._adb2(
            "shell", "settings", "get", "secure", "accessibility_enabled"
        )
        return ok and (out or "").strip() == "1"

    def verify_overlay_granted(self, package_name: str) -> bool:
        """Whether SYSTEM_ALERT_WINDOW is actually allowed for this package."""
        from sudarshan_core.engines.agentic.action_verifier import parse_appop

        ok, out = self._adb2(
            "shell", "appops", "get", package_name, "SYSTEM_ALERT_WINDOW"
        )
        return ok and parse_appop(out) == "allow"

    def verify_device_admin_active(self, package_name: str) -> bool:
        """
        Whether an active device-admin component belongs to this package.

        Only the "Enabled Device Admins" block of `dumpsys device_policy` is
        read. Searching the whole dump for the package name reports a false
        positive on almost anything: measured on a live emulator,
        `com.android.chrome` appears in an unrelated package list inside that
        dump and was reported as an active device admin.
        """
        if not package_name:
            return False

        ok, out = self._adb2("shell", "dpm", "list-owners")
        if ok and _admin_block_mentions(out, package_name, whole_output=True):
            return True

        ok, out = self._adb2("shell", "dumpsys", "device_policy")
        return ok and _admin_block_mentions(out, package_name)

    def verify_permission_granted(self, package_name: str, permission: str) -> bool:
        """Whether the package actually holds this runtime permission."""
        from sudarshan_core.engines.agentic.action_verifier import (
            parse_granted_permissions,
        )

        ok, out = self._adb2("shell", "dumpsys", "package", package_name)
        return ok and permission in parse_granted_permissions(out)

    # ── Deterministic Settings navigation (§10) ──────────────────────────────

    def open_accessibility_settings(self) -> bool:
        """Bring the Accessibility settings screen to the foreground."""
        ok, _ = self._adb2(
            "shell", "am", "start", "-a", "android.settings.ACCESSIBILITY_SETTINGS"
        )
        if ok:
            time.sleep(2)
        return ok

    def find_accessibility_service(self, package_name: str, app_name: str = "") -> bool:
        """
        Whether the target's accessibility entry is visible in Settings.

        Reported rather than acted on: a service absent from the list usually
        means the manifest declares none, which is itself a finding about the
        sample - not a reason to keep clicking.
        """
        ok, dump = self._adb2("shell", "uiautomator", "dump", "/dev/stdout")
        if not ok:
            return False
        haystack = dump or ""
        return package_name in haystack or bool(app_name and app_name in haystack)

    def return_to_app(self, package_name: str, main_activity: str = "") -> bool:
        """Put the sample back in the foreground after a Settings excursion."""
        if main_activity:
            component = (
                main_activity if "/" in main_activity
                else f"{package_name}/{main_activity}"
            )
            ok, _ = self._adb2("shell", "am", "start", "-n", component)
        else:
            ok, _ = self._adb2(
                "shell", "monkey", "-p", package_name,
                "-c", "android.intent.category.LAUNCHER", "1",
            )
        if ok:
            time.sleep(1.5)
        return ok

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
        # actually exists before writing to settings - writing a non-existent
        # component name silently fails and wastes the 0.35-weight BFCI slot.
        if service_class is None:
            logger.info(
                f"[PermissionOrchestrator] No service_class provided; "
                f"skipping settings put - caller should pass the manifest-parsed "
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

        # Build the FLATTENED COMPONENT the settings key expects: "pkg/cls".
        #
        # This produced a bare class name - ".zWPzgfI" became
        # "com.hmxuxgdngpi.bkqrlzkuwzuj.zWPzgfI" with no "pkg/" prefix - which
        # `enabled_accessibility_services` cannot parse, so the write silently
        # did nothing. It went unnoticed for as long as the method returned a
        # hardcoded True; the first run that actually verified the result
        # reported "grant did not take effect" and exposed it.
        component = _flatten_component(package_name, service_class)

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

        # Ask the device, do not assume.
        #
        # This used to be `success = True`, unconditionally, immediately after
        # the settings write. A write that Android silently ignored - a
        # component name that does not resolve, a service the package does not
        # actually declare - was indistinguishable from one that worked, and
        # the run reported accessibility granted either way. That matters more
        # than most: accessibility is the highest-weight fraud capability the
        # sandbox can enable, so a false positive here misrepresents the whole
        # investigation.
        success = self.verify_accessibility_enabled(package_name)
        self._log_action("accessibility", "grant", success)
        if success:
            logger.info(
                "[PermissionOrchestrator] Accessibility VERIFIED enabled for %s "
                "(component=%s)", package_name, component,
            )
        else:
            logger.warning(
                "[PermissionOrchestrator] Accessibility grant did NOT take "
                "effect for %s - wrote component '%s' but the device does not "
                "report it enabled. The sample most likely declares no such "
                "service.", package_name, component,
            )

        # Return to home
        self._adb("shell", "input", "keyevent", "3")
        return success

    def grant_overlay(self, package_name: str) -> bool:
        """Grants SYSTEM_ALERT_WINDOW (Draw over other apps), then confirms it."""
        logger.info(f"[PermissionOrchestrator] Attempting to grant Overlay for {package_name}")
        # In modern Android, AppOpsManager can grant this via ADB
        self._adb2("shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow")

        # Was: `success = "Error" not in out`, where `out` came from _adb(),
        # which returns "" when the command FAILS. "Error" is not in "", so a
        # failed grant reported success - the check was strictly worse than not
        # checking, because it looked like verification. appops is now read
        # back instead.
        success = self.verify_overlay_granted(package_name)
        self._log_action("overlay", "grant", success)
        if not success:
            logger.warning(
                "[PermissionOrchestrator] Overlay grant did NOT take effect for "
                "%s - appops does not report SYSTEM_ALERT_WINDOW as allowed.",
                package_name,
            )
        return success

    def grant_device_admin(self, package_name: str, admin_receiver: str) -> bool:
        """Activates Device Admin for the package, then confirms it. Requires root/dpm."""
        logger.info(f"[PermissionOrchestrator] Attempting to grant Device Admin for {package_name}")
        ok, out = self._adb2(
            "shell", "dpm", "set-active-admin", f"{package_name}/{admin_receiver}"
        )
        # "Success" in stdout is a reasonable hint, but dpm also prints it in
        # cases where the admin is not subsequently active, so the policy state
        # is the authority.
        success = self.verify_device_admin_active(package_name)
        self._log_action("device_admin", "grant", success)
        if not success:
            logger.warning(
                "[PermissionOrchestrator] Device admin not active for %s after "
                "set-active-admin (dpm said: %s)",
                package_name, (out or "").strip()[:120] or "nothing",
            )
        return success

    def grant_all_standard_permissions(
        self, package_name: str, permissions: Optional[List[str]] = None
    ) -> List[str]:
        """
        Grant runtime permissions and return the ones actually held afterwards.

        Two changes from the original, which granted a fixed list of six and
        returned a bare ``True``:

        * the list is now the caller's - the sample's own declared permissions -
          because granting READ_SMS to an app that never asked for it neither
          helps the investigation nor reflects the sample;
        * the return value is the verified set. A `pm grant` for a permission
          the manifest does not declare exits without granting anything, and
          the old unconditional True recorded those as successes.

        The default list is retained for callers that pass nothing, so existing
        behaviour is preserved apart from now being checked.
        """
        wanted = list(permissions or [
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ])
        logger.info(
            "[PermissionOrchestrator] Granting %d permission(s) for %s",
            len(wanted), package_name,
        )
        for permission in wanted:
            self._adb2("shell", "pm", "grant", package_name, permission)

        from sudarshan_core.engines.agentic.action_verifier import (
            parse_granted_permissions,
        )

        ok, dump = self._adb2("shell", "dumpsys", "package", package_name)
        held = parse_granted_permissions(dump) if ok else frozenset()
        granted = [p for p in wanted if p in held]

        for permission in wanted:
            self._log_action(permission, "grant", permission in held)
        if not ok:
            logger.warning(
                "[PermissionOrchestrator] Could not read permission state for "
                "%s - grants are unverified for this run.", package_name,
            )
        elif len(granted) != len(wanted):
            logger.info(
                "[PermissionOrchestrator] %d of %d permission(s) took effect "
                "for %s; the rest are most likely undeclared.",
                len(granted), len(wanted), package_name,
            )
        return granted

    def flush(self, output_path: Path) -> int:
        """Writes the permission action log to JSON."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.actions_log, f, indent=4)
            logger.info(f"[PermissionOrchestrator] Flushed {len(self.actions_log)} actions → {output_path}")
        except Exception as e:
            logger.error(f"[PermissionOrchestrator] Failed to write permissions.json: {e}")
        
        return len(self.actions_log)
