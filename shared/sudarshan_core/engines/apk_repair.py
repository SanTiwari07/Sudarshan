"""
Sudarshan Forensic APK Derivative Repair & Provenance Engine
============================================================
Preserves original APK binaries in read-only uploads/original/.
When Android OS PackageInstaller rejects an obfuscated malware sample
(e.g., TeaBot/Anubis with ZIP CRC tampering or corrupted AXML string blocks),
this module extracts files via apkInspector header bypass, compiles a clean AXML
manifest with aapt, stores resources.arsc uncompressed, performs 4-byte zipalign,
re-signs with apksigner, and logs a complete forensic provenance metadata record.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_zip_entry_path(target_dir: str, entry_filename: str) -> str:
    """
    Validates that a zip entry path resolves strictly inside target_dir (prevents Zip-Slip).
    Raises ValueError if path traversal is detected.
    """
    target_dir_abs = os.path.abspath(target_dir)
    resolved_path = os.path.abspath(os.path.join(target_dir_abs, entry_filename))
    if not (resolved_path == target_dir_abs or resolved_path.startswith(target_dir_abs + os.sep)):
        raise ValueError(f"Zip-Slip path traversal attack detected: '{entry_filename}' escapes target '{target_dir}'")
    return resolved_path


def sanitize_extracted_directory(target_dir: str) -> None:
    """
    Post-extraction path validation sweep: removes any files/symlinks that resolve
    outside of target_dir.
    """
    target_dir_abs = os.path.abspath(target_dir)
    for root, dirs, files in os.walk(target_dir_abs, topdown=False):
        for name in files + dirs:
            full_path = os.path.abspath(os.path.join(root, name))
            if not (full_path == target_dir_abs or full_path.startswith(target_dir_abs + os.sep)):
                try:
                    if os.path.islink(full_path) or os.path.isfile(full_path):
                        os.remove(full_path)
                    elif os.path.isdir(full_path):
                        shutil.rmtree(full_path, ignore_errors=True)
                except Exception:
                    pass


def extract_activities_from_dex_files(out_dir: str, package_name: str) -> List[str]:
    """
    Extract real Java/Kotlin class names from .dex files in out_dir.
    Filters out framework/library classes and returns candidates under package namespace.
    """
    extracted_classes = []
    ignored_prefixes = (
        "android.", "java.", "javax.", "kotlin.", "kotlinx.",
        "com.google.", "androidx.", "org.json.", "org.apache."
    )
    for root, _, files in os.walk(out_dir):
        for f_name in files:
            if f_name.endswith(".dex"):
                dex_path = os.path.join(root, f_name)
                try:
                    with open(dex_path, "rb") as f_dex:
                        content = f_dex.read()
                    matches = re.findall(b'L([a-zA-Z0-9_$]+(?:/[a-zA-Z0-9_$]+)+);', content)
                    for m in matches:
                        try:
                            class_name = m.decode('ascii', errors='ignore').replace('/', '.')
                            if not any(class_name.startswith(pfx) for pfx in ignored_prefixes):
                                if class_name not in extracted_classes:
                                    extracted_classes.append(class_name)
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(f"[APKRepair] Could not parse {f_name} for DEX classes: {e}")
    return extracted_classes


_PERMISSION_RE = re.compile(
    r'<uses-permission[^>]+android:name="([^"]+)"', re.IGNORECASE
)
# Binary AXML keeps permission names as UTF-16 or UTF-8 strings in the string
# pool even when the structure around them is corrupt, so a regex over the raw
# bytes recovers them when XML parsing cannot.
_PERMISSION_BYTES_RE = re.compile(rb"android\.permission\.[A-Z_0-9]{3,}")


def _extract_declared_permissions(manifest_xml: str, out_dir: str) -> List[str]:
    """
    Recover the permissions the ORIGINAL sample declared.

    Two passes, because the reason we are here is that the manifest is damaged:
      1. the decoded manifest text, if APKTool produced one
      2. a byte-level scan of the raw AndroidManifest.xml string pool

    Returns a de-duplicated, order-stable list. Never raises - an empty list
    means "could not recover", and the caller must NOT substitute a guess.
    """
    found: List[str] = []

    def _add(perm: str) -> None:
        if perm and perm not in found:
            found.append(perm)

    if manifest_xml:
        for perm in _PERMISSION_RE.findall(manifest_xml):
            _add(perm)

    if not found:
        raw_manifest = os.path.join(out_dir, "AndroidManifest.xml")
        try:
            if os.path.exists(raw_manifest):
                with open(raw_manifest, "rb") as fh:
                    blob = fh.read()
                # Strip UTF-16 NULs so both encodings match the same pattern.
                for match in _PERMISSION_BYTES_RE.findall(blob.replace(b"\x00", b"")):
                    _add(match.decode("ascii", errors="ignore"))
        except Exception as exc:
            logger.warning(
                "[APKRepair] Byte-level permission recovery failed (%s: %s)",
                type(exc).__name__, exc,
            )

    logger.info(
        "[APKRepair] Recovered %d declared permission(s) from the original manifest",
        len(found),
    )
    return found


def _debug_keystore_path() -> str:
    return "/tmp/sudarshan_debug.keystore"


def _ensure_debug_keystore() -> bool:
    keystore_path = _debug_keystore_path()
    if os.path.exists(keystore_path):
        return True
    keytool_bin = shutil.which("keytool") or "/usr/bin/keytool"
    if not os.path.exists(keytool_bin):
        return False
    res = subprocess.run(
        [
            keytool_bin, "-genkey", "-noprompt", "-alias", "androiddebugkey",
            "-dname", "CN=Sudarshan, OU=SOC, O=BOI, L=Mumbai, S=MH, C=IN",
            "-keystore", keystore_path, "-storepass", "android",
            "-keypass", "android", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        ],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0 and os.path.exists(keystore_path)


def _apksigner_sign(apk_path: str) -> bool:
    apksigner_bin = shutil.which("apksigner") or "/usr/bin/apksigner"
    if not os.path.exists(apksigner_bin) or not _ensure_debug_keystore():
        return False
    res = subprocess.run(
        [
            apksigner_bin, "sign", "--ks", _debug_keystore_path(), "--ks-pass", "pass:android",
            "--ks-key-alias", "androiddebugkey", "--key-pass", "pass:android",
            apk_path,
        ],
        capture_output=True,
        text=True,
    )
    return res.returncode == 0


def _zipalign_apk(unaligned: str, aligned: str) -> None:
    zipalign_bin = shutil.which("zipalign") or "/usr/bin/zipalign"
    if os.path.exists(zipalign_bin):
        subprocess.run(
            [zipalign_bin, "-v", "-p", "4", unaligned, aligned],
            capture_output=True,
            text=True,
        )
    else:
        shutil.copy2(unaligned, aligned)


def resign_apk_preserving_payload(original_apk_path: str) -> Tuple[bool, str, Dict]:
    """
    Strip broken META-INF signatures and re-sign the original payload unchanged.

    Used when PackageManager rejects INSTALL_PARSE_FAILED_NO_CERTIFICATES but
    classes.dex/resources are intact (common anti-sandbox trick).
    """
    if not os.path.exists(original_apk_path):
        return False, f"Original file not found: {original_apk_path}", {}

    original_sha256 = compute_sha256(original_apk_path)
    base_dir = os.path.dirname(original_apk_path)
    repaired_dir = os.path.join(base_dir, "repaired")
    os.makedirs(repaired_dir, exist_ok=True)
    unaligned = os.path.join(repaired_dir, f"unaligned_resigned_{original_sha256}.apk")
    resigned_apk = os.path.join(repaired_dir, f"resigned_{original_sha256}.apk")

    dex_count = 0
    try:
        with zipfile.ZipFile(original_apk_path, "r") as z_in:
            with zipfile.ZipFile(unaligned, "w") as z_out:
                for member in z_in.infolist():
                    name = member.filename
                    if name.startswith("META-INF/"):
                        continue
                    if name.endswith(".dex"):
                        dex_count += 1
                    data = z_in.read(name)
                    comp = (
                        zipfile.ZIP_STORED
                        if name.endswith((".arsc", ".png", ".jpg", ".jpeg", ".gif"))
                        else zipfile.ZIP_DEFLATED
                    )
                    z_out.writestr(member, data, compress_type=comp)
    except Exception as exc:
        return False, f"Re-sign repackage failed: {exc}", {}

    if dex_count == 0:
        return False, "Re-sign aborted: no classes.dex in original APK", {}

    _zipalign_apk(unaligned, resigned_apk)
    if not _apksigner_sign(resigned_apk):
        return False, "apksigner failed on resigned APK", {}

    try:
        os.remove(unaligned)
    except OSError:
        pass

    resigned_sha = compute_sha256(resigned_apk)
    provenance = {
        "is_repaired_derivative": True,
        "original_sha256": original_sha256,
        "repaired_sha256": resigned_sha,
        "repaired_apk_path": resigned_apk,
        "repair_tool": "zip strip META-INF + apksigner",
        "repair_reason": "INSTALL_PARSE_FAILED_NO_CERTIFICATES (signature block invalid)",
        "modifications_performed": [
            "Removed META-INF signature block from original APK bytes",
            "zipalign + Android debug re-sign (payload unchanged)",
        ],
        "signature_used": "Android Debug Key (RSA-2048)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    logger.info(
        "[APKRepair] Resigned APK ready: %s (%d dex, SHA %s…)",
        resigned_apk,
        dex_count,
        resigned_sha[:12],
    )
    return True, resigned_apk, provenance


def _authoritative_manifest_components(apk_path: str) -> Dict[str, Any]:
    """
    Read the real manifest components before falling back to guesswork.

    A deliberately corrupt AXML defeats the regex scrape further down, but it
    does NOT defeat aapt or androguard - both parse Teabot's manifest correctly.
    Skipping them meant the rebuild invented a launcher from an arbitrary DEX
    class, producing an app that installs and can never start.

    Returns {} when nothing could be parsed, so callers keep their fallbacks.
    """
    out: Dict[str, Any] = {}

    # ── aapt: authoritative for the LAUNCHER activity ────────────────────────
    for tool in ("aapt2", "aapt"):
        exe = shutil.which(tool)
        if not exe:
            continue
        try:
            res = subprocess.run(
                [exe, "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=60,
            )
            for line in res.stdout.splitlines():
                if line.startswith("package: name=") and "package_name" not in out:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        out["package_name"] = parts[1]
                elif line.startswith("launchable-activity: name="):
                    parts = line.split("'")
                    if len(parts) >= 2:
                        out["main_activity"] = parts[1]
            if out.get("main_activity"):
                logger.info(
                    "[APKRepair] %s resolved launcher activity: %s",
                    tool, out["main_activity"],
                )
                break
        except Exception as exc:
            logger.debug("[APKRepair] %s badging failed: %s", tool, exc)

    # ── androguard: full component inventory ─────────────────────────────────
    try:
        try:
            import loguru
            loguru.logger.disable("androguard")
        except ImportError:
            pass
        from androguard.core.apk import APK

        apk = APK(apk_path)
        pkg = apk.get_package()
        if pkg and pkg not in ("Failed", "Unknown", "None"):
            out.setdefault("package_name", pkg)
        if not out.get("main_activity"):
            act = apk.get_main_activity()
            if act:
                out["main_activity"] = act
                logger.info(
                    "[APKRepair] androguard resolved launcher activity: %s", act
                )
        activities = [a for a in (apk.get_activities() or []) if a]
        services = [s for s in (apk.get_services() or []) if s]
        receivers = [r for r in (apk.get_receivers() or []) if r]
        if activities:
            out["activities"] = activities
        if services:
            out["services"] = services
        if receivers:
            out["receivers"] = receivers

        # Which service is the accessibility service, per the manifest itself.
        #
        # get_intent_filters() returns {} on obfuscated manifests like Teabot's -
        # the decoded XML drops the `android:` prefix, so androguard's lookup
        # misses. The declaration is still unambiguous in the raw XML: a service
        # gated by BIND_ACCESSIBILITY_SERVICE, or carrying the accessibility
        # intent action. Matching on those is sample-agnostic; matching on a
        # class name is not.
        accessibility: List[str] = []
        try:
            manifest_xml = apk.get_android_manifest_axml().get_xml().decode(
                "utf-8", "ignore"
            )
        except Exception:
            manifest_xml = ""

        for match in re.finditer(r"<service\b[^>]*>(.*?)</service>|<service\b[^>]*/>",
                                 manifest_xml, re.DOTALL):
            block = match.group(0)
            name_match = re.search(r'(?:android:)?name="([^"]+)"', block)
            if not name_match:
                continue
            srv_name = name_match.group(1)
            declares_a11y = (
                "BIND_ACCESSIBILITY_SERVICE" in block
                or "accessibilityservice" in block.lower()
            )
            if declares_a11y and srv_name not in accessibility:
                accessibility.append(srv_name)

        for srv in services:
            try:
                filters = apk.get_intent_filters("service", srv) or {}
            except Exception:
                filters = {}
            actions = filters.get("action") or []
            if any("accessibilityservice" in str(a).lower() for a in actions):
                if srv not in accessibility:
                    accessibility.append(srv)

        if accessibility:
            out["accessibility_services"] = accessibility
            logger.info(
                "[APKRepair] Manifest declares accessibility service(s): %s",
                accessibility,
            )
    except Exception as exc:
        logger.warning("[APKRepair] androguard component parse failed: %s", exc)

    return out


def _looks_like_activity_class(class_name: str) -> bool:
    """
    Reject DEX candidates that cannot be a launchable Activity.

    The DEX scan yields every class in the binary - interfaces, inner classes,
    JNI helpers - and the old code took element [0] of 6066. These filters do
    not prove a class IS an Activity, they only drop entries that provably are
    not one.
    """
    if not class_name or "." not in class_name:
        return False
    if class_name.startswith("L") and class_name.endswith(";"):
        return False          # unstripped JVM type descriptor
    if "$" in class_name:
        return False          # inner/anonymous class
    if class_name.startswith(("android.", "androidx.", "com.google.android.gms")):
        return False          # framework/support library
    return True


def repair_obfuscated_apk(original_apk_path: str) -> Tuple[bool, str, Dict]:
    """
    Generate an isolated repaired derivative copy for sandbox installation.
    Never mutates original_apk_path in place.
    
    Returns:
        (success: bool, repaired_apk_path_or_error: str, provenance_dict: Dict)
    """
    if not os.path.exists(original_apk_path):
        return False, f"Original file not found: {original_apk_path}", {}

    original_sha256 = compute_sha256(original_apk_path)
    base_dir = os.path.dirname(original_apk_path)
    repaired_dir = os.path.join(base_dir, "repaired")
    metadata_dir = os.path.join(base_dir, "metadata")
    os.makedirs(repaired_dir, exist_ok=True)
    os.makedirs(metadata_dir, exist_ok=True)

    unaligned_apk_path = os.path.join(repaired_dir, f"unaligned_{original_sha256}.apk")
    repaired_apk_path = os.path.join(repaired_dir, f"repaired_{original_sha256}.apk")
    provenance_json_path = os.path.join(metadata_dir, f"{original_sha256}_provenance.json")

    logger.info(f"[APKRepair] Attempting derivative repair for {os.path.basename(original_apk_path)} (SHA: {original_sha256[:12]}...)")

    # Step 1: Extract raw files via apkInspector (bypasses corrupted ZIP CRC headers)
    import tempfile
    out_dir = os.path.join(tempfile.gettempdir(), f"raw_{original_sha256[:8]}")

    shutil.rmtree(out_dir, ignore_errors=True)
    try:
        from apkInspector.extract import extract_all_files_from_central_directory
        from apkInspector.headers import ZipEntry
        with open(original_apk_path, "rb") as f_apk:
            zip_e = ZipEntry.parse(f_apk)
            zdict = zip_e.to_dict()
            extract_all_files_from_central_directory(f_apk, zdict['central_directory'], zdict['local_headers'], out_dir)
            sanitize_extracted_directory(out_dir)
    except Exception as e:
        logger.warning(f"[APKRepair] apkInspector raw extraction warning: {e}")

    os.makedirs(out_dir, exist_ok=True)

    # Fallback to standard zipfile extraction if dex files are missing from out_dir
    dex_files = []
    for root, _, files in os.walk(out_dir):
        for f_name in files:
            if f_name.endswith(".dex"):
                dex_files.append(f_name)
    if not dex_files:
        logger.info("[APKRepair] Dex files missing after apkInspector extraction, attempting standard zipfile fallback...")
        try:
            with zipfile.ZipFile(original_apk_path, "r") as z_in:
                for member in z_in.infolist():
                    if member.filename == "AndroidManifest.xml":
                        continue
                    try:
                        z_in.extract(member, out_dir)
                    except Exception as ex:
                        logger.warning(f"[APKRepair] zipfile member extraction warning ({member.filename}): {ex}")
            sanitize_extracted_directory(out_dir)
        except Exception as e:
            logger.warning(f"[APKRepair] zipfile extraction fallback warning: {e}")

    # Step 2: Parse manifest via apkInspector XML parser or scan DEX binary classes
    manifest_xml = ""
    package_name, main_activity = "com.sudarshan.sandbox", "MainActivity"
    try:
        from apkInspector.axml import parse_apk_for_manifest
        res = parse_apk_for_manifest(original_apk_path)
        if isinstance(res, (list, tuple)) and len(res) > 0:
            manifest_xml = str(res[0])
        elif isinstance(res, str):
            manifest_xml = res
    except Exception as e:
        logger.warning(f"[APKRepair] apkInspector manifest extraction warning: {e}")

    activities = []
    services = []
    receivers = []

    if manifest_xml:
        pkg_match = re.search(r'package="([^"]+)"', manifest_xml)
        if pkg_match:
            package_name = pkg_match.group(1)

        raw_activities = re.findall(r'<activity[^>]+android:name="([^"]+)"', manifest_xml)
        for act in raw_activities:
            if act not in activities and not act.startswith("com.google.android.gms"):
                activities.append(act)

        act_match = re.search(r'<activity[^>]+android:name="([^"]+)"[^>]*>.*?android\.intent\.action\.MAIN', manifest_xml, re.DOTALL)
        if act_match:
            main_activity = act_match.group(1)
        elif activities:
            main_activity = activities[0]

        raw_services = re.findall(r'<service[^>]+android:name="([^"]+)"', manifest_xml)
        for srv in raw_services:
            if srv not in services:
                services.append(srv)

        raw_receivers = re.findall(r'<receiver[^>]+android:name="([^"]+)"', manifest_xml)
        for rcv in raw_receivers:
            if rcv not in receivers:
                receivers.append(rcv)

    # Step 2b: Authoritative manifest read. aapt/androguard parse manifests the
    # regex scrape above cannot - including the deliberately corrupt AXML that
    # sent us down the DEX-guessing path in the first place. These values win.
    authoritative = _authoritative_manifest_components(original_apk_path)
    if authoritative.get("package_name"):
        package_name = authoritative["package_name"]
    if authoritative.get("activities"):
        for act in authoritative["activities"]:
            if act not in activities:
                activities.append(act)
    for srv in authoritative.get("services", []):
        if srv not in services:
            services.append(srv)
    for rcv in authoritative.get("receivers", []):
        if rcv not in receivers:
            receivers.append(rcv)

    authoritative_main = authoritative.get("main_activity")
    if authoritative_main:
        main_activity = authoritative_main
        if main_activity not in activities:
            activities.insert(0, main_activity)

    # Step 3: DEX class scan - last resort only, when no manifest source could
    # name a launcher. Never overrides an authoritative answer.
    if not authoritative_main and (
        not activities or "MainActivity" in main_activity or main_activity == "MainActivity"
    ):
        dex_candidates = extract_activities_from_dex_files(out_dir, package_name)
        plausible = [c for c in dex_candidates if _looks_like_activity_class(c)]
        if plausible:
            logger.warning(
                "[APKRepair] No manifest source named a launcher; falling back to "
                "DEX scan (%d classes, %d plausible). The rebuilt app may not start.",
                len(dex_candidates), len(plausible),
            )
            pkg_classes = [c for c in plausible if c.startswith(package_name)]
            valid_classes = pkg_classes if pkg_classes else plausible
            activities = valid_classes
            main_activity = valid_classes[0]
        elif dex_candidates:
            logger.error(
                "[APKRepair] DEX scan found %d classes but none are plausible "
                "activities - refusing to synthesise a launcher.",
                len(dex_candidates),
            )

    if not activities:
        activities = [main_activity]

    # Exactly one activity may carry MAIN/LAUNCHER. Declaring two makes
    # `cmd package resolve-activity` return the system ResolverActivity (the
    # "which app?" chooser) instead of a component in the package, which reads
    # downstream as "this package has no launcher" and aborts the run.
    if main_activity in activities:
        launcher_activity = main_activity
    else:
        launcher_activity = activities[0] if activities else main_activity

    activity_blocks = []
    for idx, act in enumerate(activities):
        if act == launcher_activity:
            block = f"""        <activity android:name="{act}" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>"""
        else:
            block = f"""        <activity android:name="{act}" android:exported="true"/>"""
        activity_blocks.append(block)

    activity_xml_str = "\n".join(activity_blocks)

    # Which services are accessibility services comes from the parsed manifest.
    # This used to carry a hardcoded Teabot class name, which only ever worked
    # for that one sample and silently mis-declared every other.
    declared_accessibility = set(authoritative.get("accessibility_services", []))

    service_blocks = []
    for srv in services:
        if srv in declared_accessibility or "accessibility" in srv.lower():
            block = f"""        <service android:name="{srv}" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" android:exported="true">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService"/>
            </intent-filter>
        </service>"""
        else:
            block = f"""        <service android:name="{srv}" android:exported="true"/>"""
        service_blocks.append(block)

    service_xml_str = "\n".join(service_blocks)

    receiver_blocks = []
    for rcv in receivers:
        block = f"""        <receiver android:name="{rcv}" android:exported="true"/>"""
        receiver_blocks.append(block)

    receiver_xml_str = "\n".join(receiver_blocks)

    # Step 4: Build the repaired manifest.
    #
    # ─────────────────────────────────────────────────────────────────────────
    # EVIDENTIARY INTEGRITY - read before changing this block.
    #
    # This manifest previously GRANTED a fixed permission set regardless of what
    # the sample declared:
    #
    #     SYSTEM_ALERT_WINDOW · BIND_ACCESSIBILITY_SERVICE
    #     READ_SMS · RECEIVE_SMS · SEND_SMS
    #
    # Those are precisely the five signals the scoring model weights most
    # heavily (CT axis +40/+35/+25; BFCI accessibility 0.35, sms 0.25, overlay
    # 0.20). The repaired derivative is what gets INSTALLED and DYNAMICALLY
    # ANALYSED - so a dynamic finding of "SMS interception observed" could be an
    # observation of a capability WE added, on an artifact the sample never
    # asked for. Combined with android:debuggable="true" and
    # usesCleartextTraffic="true", the runtime behaviour being measured was not
    # the sample's own.
    #
    # The repair now carries over ONLY what the original manifest declared. If a
    # permission cannot be recovered from a corrupted manifest it is not
    # invented; the sample simply runs without it, and the run is honest about
    # what it could not restore.
    # ─────────────────────────────────────────────────────────────────────────
    recovered_permissions = _extract_declared_permissions(manifest_xml, out_dir)

    # INTERNET / ACCESS_NETWORK_STATE are the only additions, and only so the
    # sandbox can observe network behaviour at all. Both are normal-protection
    # permissions granted at install to essentially every app, and NEITHER is
    # scored by any axis - so adding them cannot move a verdict.
    _SANDBOX_REQUIRED = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
    ]
    added_for_sandbox = [p for p in _SANDBOX_REQUIRED if p not in recovered_permissions]
    effective_permissions = list(recovered_permissions) + added_for_sandbox

    permission_xml_str = "\n".join(
        f'    <uses-permission android:name="{p}"/>' for p in effective_permissions
    )

    logger.warning(
        "[APKRepair] Manifest rebuilt with %d permission(s) recovered from the "
        "original%s. Scored capabilities are NOT synthesised.",
        len(recovered_permissions),
        f" plus {added_for_sandbox} for sandbox networking" if added_for_sandbox else "",
    )

    synthetic_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package_name}">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
{permission_xml_str}
    <application android:label="SudarshanRepairedApp" android:usesCleartextTraffic="true">
{activity_xml_str}
{service_xml_str}
{receiver_xml_str}
    </application>
</manifest>"""

    # Step 5: Compile clean AXML binary (aapt primary, apktool fallback)
    aapt_work_dir = f"/tmp/aapt_{original_sha256[:8]}"
    os.makedirs(aapt_work_dir, exist_ok=True)
    manifest_xml_file = os.path.join(aapt_work_dir, "AndroidManifest.xml")
    compiled_apk_file = os.path.join(aapt_work_dir, "compiled.apk")

    with open(manifest_xml_file, "w") as f:
        f.write(synthetic_xml)

    framework_res = "/usr/share/android-framework-res/framework-res.apk"
    aapt_bin = shutil.which("aapt") or "/usr/bin/aapt"
    axml_data = None

    if os.path.exists(aapt_bin) and os.path.exists(framework_res):
        aapt_res = subprocess.run([
            aapt_bin, "package", "-f", "-M", manifest_xml_file,
            "-I", framework_res, "-F", compiled_apk_file
        ], capture_output=True, text=True)
        if aapt_res.returncode == 0 and os.path.exists(compiled_apk_file):
            try:
                with zipfile.ZipFile(compiled_apk_file) as z_comp:
                    axml_data = z_comp.read("AndroidManifest.xml")
            except Exception as e:
                logger.warning(f"[APKRepair] Could not read compiled AXML via aapt: {e}")

    # Fallback to apktool if aapt is unavailable or failed
    if not axml_data:
        apktool_bin = shutil.which("apktool") or "/usr/local/bin/apktool"
        if os.path.exists(apktool_bin):
            apktool_work_dir = f"/tmp/apktool_build_{original_sha256[:8]}"
            shutil.rmtree(apktool_work_dir, ignore_errors=True)
            os.makedirs(apktool_work_dir, exist_ok=True)

            yml_content = """version: 2.10.0
apkFileName: derivative.apk
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: '21'
  targetSdkVersion: '30'
packageInfo:
  forcedPackageId: '127'
"""
            with open(os.path.join(apktool_work_dir, "apktool.yml"), "w") as f:
                f.write(yml_content)
            with open(os.path.join(apktool_work_dir, "AndroidManifest.xml"), "w") as f:
                f.write(synthetic_xml)

            res = subprocess.run([apktool_bin, "b", apktool_work_dir, "-o", compiled_apk_file], capture_output=True, text=True)
            if res.returncode == 0 and os.path.exists(compiled_apk_file):
                try:
                    with zipfile.ZipFile(compiled_apk_file) as z_comp:
                        axml_data = z_comp.read("AndroidManifest.xml")
                    logger.info(f"[APKRepair] Compiled clean AXML via apktool fallback ({len(axml_data)} bytes)")
                except Exception as e:
                    logger.warning(f"[APKRepair] Could not read compiled AXML from apktool: {e}")
            shutil.rmtree(apktool_work_dir, ignore_errors=True)

    if not axml_data:
        return False, f"Failed to compile clean binary AXML for derivative: {package_name}", {}

    # Overwrite AndroidManifest.xml
    with open(os.path.join(out_dir, "AndroidManifest.xml"), "wb") as f_out:
        f_out.write(axml_data)

    # Step 6: Repackage unaligned APK (resources.arsc stored uncompressed!)
    for p in [unaligned_apk_path, repaired_apk_path]:
        if os.path.exists(p):
            try: os.remove(p)
            except Exception: pass

    with zipfile.ZipFile(unaligned_apk_path, "w") as z_out:
        for root, dirs, files in os.walk(out_dir):
            for file in files:
                full_p = os.path.join(root, file)
                rel_p = os.path.relpath(full_p, out_dir)
                comp_type = zipfile.ZIP_STORED if file.endswith(('.arsc', '.png', '.jpg', '.jpeg', '.gif')) else zipfile.ZIP_DEFLATED
                z_out.write(full_p, rel_p, compress_type=comp_type)

    # Step 7: 4-byte zipalign
    zipalign_bin = shutil.which("zipalign") or "/usr/bin/zipalign"
    if os.path.exists(zipalign_bin):
        subprocess.run([zipalign_bin, "-v", "-p", "4", unaligned_apk_path, repaired_apk_path], capture_output=True, text=True)
    else:
        shutil.copy2(unaligned_apk_path, repaired_apk_path)

    signed_ok = _apksigner_sign(repaired_apk_path)

    # Clean up scratch dirs
    shutil.rmtree(aapt_work_dir, ignore_errors=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    if os.path.exists(unaligned_apk_path):
        try: os.remove(unaligned_apk_path)
        except Exception: pass

    repaired_sha256 = compute_sha256(repaired_apk_path)
    provenance = {
        "is_repaired_derivative": True,
        "original_sha256": original_sha256,
        "repaired_sha256": repaired_sha256,
        "package_name": package_name,
        "main_activity": main_activity,
        "activities": activities,
        "repaired_apk_path": repaired_apk_path,
        "repair_tool": "apkInspector v1.2.8 + AAPT Sanitizer",
        "repair_reason": "Corrupt AXML string table / ZIP header tampering (INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION)",
        "permissions_recovered_from_original": recovered_permissions,
        "permissions_added_for_sandbox": added_for_sandbox,
        "modifications_performed": [
            "Extracted raw assets via apkInspector central directory header bypass",
            "Compiled clean AXML binary with AAPT framework resources",
            "Stored resources.arsc uncompressed for Android 11+ compatibility",
            "Aligned zip entries on 4-byte boundaries (zipalign 4)",
            f"Re-signed derivative binary ({'apksigner' if signed_ok else 'debug key fallback'})"
        ],
        "signature_used": "Android Debug Key (RSA-2048)" if signed_ok else "Original",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        with open(provenance_json_path, "w") as f:
            json.dump(provenance, f, indent=2)
    except Exception as e:
        logger.warning(f"[APKRepair] Could not save provenance metadata: {e}")

    logger.info(f"[APKRepair] Repaired derivative artifact ready: {repaired_apk_path} (SHA: {repaired_sha256[:12]}...)")
    return True, repaired_apk_path, provenance
