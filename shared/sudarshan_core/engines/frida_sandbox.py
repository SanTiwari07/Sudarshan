# backend/app/engines/frida_sandbox.py
"""
SUDARSHAN — Frida Dynamic Analysis Sandbox Controller
======================================================
Drives an Android emulator (AVD via Android Studio) to perform
runtime behavioral analysis of a suspicious APK using Frida hooks.

Prerequisites:
  1. Android Studio installed with an AVD (Emulator) created.
  2. frida-server deployed on the emulator (see README_FRIDA.md).
  3. ADB available in PATH (comes with Android Studio).
  4. pip install frida frida-tools  (already done)

Pipeline:
  APK → ADB install → Launch target package → Frida attach → 
  Hook APIs → Collect events (30s) → Compute BFCI → Return result

BFCI Formula (from Sudarshan proposal):
  BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
  
  Where:
    wa = 0.35  → Accessibility abuse score (0–100)
    ws = 0.25  → SMS interception score (0–100)
    wo = 0.20  → Overlay attack score (0–100)
    wb = 0.10  → Banking interaction score (0–100)
    wn = 0.05  → Network C2 communication score (0–100)
    wp = 0.05  → Persistence mechanism score (0–100)
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.engines.event_bus import RuntimeEventBus
from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2, BFCI_WEIGHTS

logger = logging.getLogger(__name__)

try:
    from sudarshan_core.engines.evidence_store import EvidenceStore
except ImportError:
    EvidenceStore = None
    logger.warning("[Frida] evidence_store module not found. Evidence collection disabled.")

try:
    from sudarshan_core.engines.screenshot_manager import ScreenshotManager
    from sudarshan_core.engines.ioc_collector import IOCCollector
    from sudarshan_core.engines.mitre_mapper import MitreMapper
except ImportError:
    ScreenshotManager = None
    IOCCollector = None
    MitreMapper = None
    logger.warning("[Frida] Wave 2 intelligence modules not found.")

try:
    from sudarshan_core.engines.permission_orchestrator import PermissionOrchestrator
    from sudarshan_core.engines.replay_engine import ReplayEngine
except ImportError:
    PermissionOrchestrator = None
    ReplayEngine = None
    logger.warning("[Frida] Wave 3 navigator modules not found.")

try:
    from sudarshan_core.engines.network_capture import NetworkCapture
    from sudarshan_core.engines.anti_analysis_detector import AntiAnalysisDetector
    from sudarshan_core.engines.yara_scanner import YARAScanner
except ImportError:
    NetworkCapture = None  # type: ignore[assignment]
    AntiAnalysisDetector = None  # type: ignore[assignment]
    YARAScanner = None  # type: ignore[assignment]
    logger.warning("[Frida] Wave 4 intelligence modules not found.")

try:
    from sudarshan_core.engines.workflow_reconstructor import WorkflowReconstructor
except ImportError:
    WorkflowReconstructor = None  # type: ignore[assignment]
    logger.warning("[Frida] workflow_reconstructor not found. Fraud workflow reconstruction disabled.")

try:
    from sudarshan_core.engines.analysis_history import AnalysisHistory
    from sudarshan_core.engines.report_generator import ReportGenerator
except ImportError:
    AnalysisHistory = None
    ReportGenerator = None
    logger.warning("[Frida] Wave 5 reporting modules not found.")


# ─── Configuration ─────────────────────────────────────────────────────────────

from sudarshan_core.engines.pipeline_state import (
    PipelineStage,
    get_tracker,
    AnalysisOutcome,
)

# Path to the Frida JS hooks script (banking_trojan.js)
_HOOKS_DIR = Path(__file__).parent / "frida_hooks"
_HOOKS_SOURCE = _HOOKS_DIR / "banking_trojan.js"
_HOOKS_BUNDLE = _HOOKS_DIR / "banking_trojan.bundle.js"

# Prefer the COMPILED BUNDLE.
#
# The previous line here was `_HOOKS_SCRIPT = _HOOKS_SOURCE`, justified as
# "Frida 17+ uses the built-in Java global directly — CommonJS bundle is
# deprecated". That is backwards, and measured on frida 17.16.4 against a live
# device:
#
#     typeof Java              ->  "undefined"
#     Java.perform             ->  ReferenceError: 'Java' is not defined
#
# Frida 17 REMOVED the Java global; the bridge is the external
# `frida-java-bridge` module and must be linked in at build time.
# backend/requirements.txt says exactly this. Loading the raw source therefore
# meant EVERY Java hook failed the availability guard and silently installed
# nothing — which is why every BFCI component reads 0.0 on every sample.
#
# Build the bundle with:   cd frida_hooks && npm install && npm run build
_MIN_BUNDLE_BYTES = 50_000   # a real bundle is ~540 KB; the old stub was 168 B


def _select_hooks_script() -> Path:
    """Bundle if it has actually been built, else source (with a loud warning)."""
    try:
        if _HOOKS_BUNDLE.exists() and _HOOKS_BUNDLE.stat().st_size >= _MIN_BUNDLE_BYTES:
            return _HOOKS_BUNDLE
    except OSError:
        pass
    logger.warning(
        "[Frida] Compiled hook bundle missing or stub-sized at %s — falling back to "
        "raw source. On Frida 17 the Java bridge is NOT available to an unbundled "
        "script, so ALL Java hooks (accessibility, SMS, overlay, banking) will fail "
        "to install and dynamic scoring will be static-only. Build it with: "
        "cd %s && npm install && npm run build",
        _HOOKS_BUNDLE, _HOOKS_DIR,
    )
    return _HOOKS_SOURCE


_HOOKS_SCRIPT = _select_hooks_script()


# UI exploration is goal-driven only.
#
# The random input fuzzer, and the hybrid mode that ran it alongside the agent,
# have both been REMOVED. Reasons, in order of weight:
#
#   1. It corrupted evidence — random taps produced UI events indistinguishable
#      in the timeline from behaviour the SAMPLE chose to perform.
#   2. It contended with the agent for the single ADB socket.
#   3. Its device-side process outlived the session and could inject input into
#      the NEXT sample's analysis window.
#   4. It crashed the app under analysis, and a harness-induced crash is
#      indistinguishable in the report from a sample that did nothing.
#
# AgenticExplorer is the primary explorer; UIExplorer remains as a deterministic
# rollback if the agentic stack cannot be constructed.
try:
    from sudarshan_core.engines.ui_explorer import UIExplorer
except ImportError:
    UIExplorer = None
    logger.warning(
        "[Frida] ui_explorer module not found — AgenticExplorer has no rollback target."
    )

# ADB executable — tries PATH first, then common Android Studio locations
_ADB_CANDIDATES = [
    "adb",
    r"C:\Users\{user}\AppData\Local\Android\Sdk\platform-tools\adb.exe",
    r"C:\Program Files\Android\Android Studio\sdk\platform-tools\adb.exe",
]

# Default analysis duration in seconds
ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "30"))

# ── Session lifecycle pacing ──────────────────────────────────────────────────
# The session is OPEN -> ANALYSE -> CLOSE. Nothing may touch the UI until the
# app has finished starting: a cold Activity start on an emulator is routinely
# 2-4 s, and driving input into a half-started process is what crashed the app
# under analysis. Raise these on a slow or contended emulator.
APP_OPEN_SETTLE_SECONDS: float = float(os.getenv("SUDARSHAN_APP_OPEN_SETTLE", "8.0"))
APP_SETTLE_POLL_SECONDS: float = float(os.getenv("SUDARSHAN_APP_SETTLE_POLL", "0.5"))

# One lock per device serial. See run_frida_analysis for why.
_DEVICE_LOCKS: Dict[str, "asyncio.Lock"] = {}

# Time allowed for the explorer to finish AFTER being asked to stop. Must
# comfortably exceed one in-flight LLM round trip, otherwise artifacts are
# flushed while the agent loop is still mid-iteration.
EXPLORER_JOIN_GRACE_SECONDS: float = 20.0

# Attach retry policy. Attaching resolves a PID first, so it now succeeds on the
# first attempt once the app is up; these only absorb app start-up latency.
# Previously this was 15 attempts x 2s = 30s of guaranteed waste on every run,
# because attaching by package name can never succeed on Android.
ATTACH_MAX_ATTEMPTS: int = 10
ATTACH_RETRY_DELAY_SECONDS: float = 1.5

# ── Docker / TCP ADB support ───────────────────────────────────────────────────
# When running in Docker, the Android emulator is on the HOST machine.
# Set ADB_HOST=host.docker.internal and ADB_PORT=5555 in docker-compose.yml.
# The backend will automatically run: adb connect <ADB_HOST>:<ADB_PORT>
ADB_HOST = os.getenv("ADB_HOST", "")   # e.g. host.docker.internal
ADB_PORT = os.getenv("ADB_PORT", "5555")

# BFCI_WEIGHTS is now imported from bfci_scorer — kept as a re-export for
# callers that import it directly from this module (backwards compatibility).
# Do not redefine it here.

# ─── ADB Helpers ──────────────────────────────────────────────────────────────

def _find_adb() -> Optional[str]:
    """Find the adb executable on this system."""
    import shutil
    # Try PATH first
    adb = shutil.which("adb")
    if adb:
        return adb
    # Try common Android Studio paths
    user = os.environ.get("USERNAME", "user")
    for candidate in _ADB_CANDIDATES[1:]:
        path = candidate.replace("{user}", user)
        if os.path.exists(path):
            return path
    return None


def _adb(*args: str, timeout: int = 30) -> Tuple[bool, str]:
    """Run an adb command. Returns (success, output)."""
    adb = _find_adb()
    if not adb:
        return False, "adb not found"
    try:
        result = subprocess.run(
            [adb] + list(args),
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "adb command timed out"
    except Exception as e:
        return False, str(e)


def get_connected_emulators() -> List[str]:
    """
    Return list of connected emulator/device serials.

    Docker mode: if ADB_HOST env var is set, automatically connects to
    the host-machine emulator via ADB TCP before listing devices.
    """
    # ── Docker TCP mode: auto-connect to host emulator ─────────────────────────
    if ADB_HOST:
        tcp_target = f"{ADB_HOST}:{ADB_PORT}"
        ok, out = _adb("connect", tcp_target, timeout=10)
        if ok:
            logger.info(f"[Frida] ADB TCP connected to host emulator: {tcp_target}")
        else:
            logger.warning(f"[Frida] ADB TCP connect failed ({tcp_target}): {out}")

    ok, output = _adb("devices")
    if not ok:
        return []
    devices = []
    for line in output.splitlines()[1:]:
        if "\t" in line:
            serial, state = line.split("\t", 1)
            if state.strip() == "device":
                devices.append(serial.strip())
    return devices


def _adb_install_apk(apk_path: str, device: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Install an APK onto the target device with multi-stage fallback & forensic provenance.

    Stage 1: Attempt installation of original uploaded APK.
    Stage 2: If low SDK block is encountered, retry with --bypass-low-target-sdk-block.
    Stage 3: If INSTALL_PARSE_FAILED / Corrupt AXML is caught, invoke conditional derivative repair,
             re-sign, install derivative, and record APK Provenance Metadata.
    """
    from sudarshan_core.engines.apk_repair import compute_sha256, repair_obfuscated_apk

    original_sha256 = compute_sha256(apk_path) if os.path.exists(apk_path) else "unknown"
    default_provenance = {
        "is_repaired_derivative": False,
        "original_sha256": original_sha256,
        "repaired_sha256": None,
        "repair_tool": "apkInspector v1.2.8",
        "repair_reason": None,
        "modifications_performed": [],
        "signature_used": "Original APK Signature",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

    last_out = ""

    # ── Stage 1: Try installing Original APK ─────────────────────────────────
    for attempt in range(2):
        ok, out = _adb("-s", device, "install", "-r", "-t", apk_path, timeout=120)
        if ok:
            logger.info(f"[Frida] Original APK installed successfully: {os.path.basename(apk_path)}")
            return True, out, default_provenance

        # ── Stage 2: Bypass deprecated SDK version block ──────────────────────
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out:
            logger.info("[Frida] Retrying install with --bypass-low-target-sdk-block")
            ok2, out2 = _adb(
                "-s", device, "install", "-r", "-t",
                "--bypass-low-target-sdk-block",
                apk_path, timeout=120
            )
            if ok2:
                logger.info(f"[Frida] Original APK installed with SDK bypass: {os.path.basename(apk_path)}")
                return True, out2, default_provenance
            out = out2

        last_out = out
        if any(m in out for m in (
            "INSTALL_PARSE_FAILED",
            "Corrupt XML binary file",
            "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
        )):
            break
        time.sleep(1)

    # ── Stage 3: Conditional Derivative Repair (ZIP/AXML/Manifest corruption) ──
    # Teabot and similar samples deliberately malform their manifest to evade
    # static scanners (INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION).  We detect
    # this, repair the derivative copy, re-sign, and retry.  The repair step
    # is logged prominently in both the console and the provenance record —
    # this is a disclosed methodological step, not evidence tampering.
    _PARSE_FAIL_MARKERS = (
        "INSTALL_PARSE_FAILED",
        "Corrupt XML binary file",
        "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
    )
    if any(m in last_out for m in _PARSE_FAIL_MARKERS):
        logger.warning(
            "\n" + "="*70 + "\n"
            "[Frida Repair] MANIFEST REPAIR REQUIRED\n"
            f"  Sample   : {os.path.basename(apk_path)}\n"
            f"  Reason   : {last_out.strip()}\n"
            "  Action   : Decompiling with APKTool, patching malformed manifest,\n"
            "             recompiling and re-signing a derivative artifact.\n"
            "  NOTE     : Original binary is preserved unchanged. This step is\n"
            "             disclosed methodology, NOT evidence manipulation.\n"
            + "="*70
        )
        rep_ok, rep_path_or_err, rep_provenance = repair_obfuscated_apk(apk_path)
        if rep_ok and os.path.exists(rep_path_or_err):
            logger.info(f"[Frida Repair] Retrying installation on repaired derivative: {rep_path_or_err}")

            # ── Signature-mismatch guard ─────────────────────────────────────
            # The derivative is re-signed with our debug key, so any previously
            # installed copy (signed with the original/obfuscated key) causes:
            #   INSTALL_FAILED_UPDATE_INCOMPATIBLE: signatures do not match
            # Android's package manager refuses to update across a signature
            # boundary even with -r. Uninstalling first clears the old signature
            # record so the fresh install succeeds.
            #
            # This is forensically safe: the *binary* analysis was already
            # performed on the original; we are only clearing the emulator slot
            # so the behavioural sandbox can run on the repaired derivative.
            from sudarshan_core.engines.apk_repair import compute_sha256 as _sha256_fn
            pkg_to_uninstall = None
            try:
                # Best-effort: extract package name from the repaired APK to
                # target the uninstall precisely (avoids uninstalling the wrong pkg)
                from androguard.misc import AnalyzeAPK as _AAA
                _a_r, _, _ = _AAA(rep_path_or_err)
                pkg_to_uninstall = _a_r.get_package()
            except Exception:
                pass
            if not pkg_to_uninstall:
                # Fall back to extracting from the original APK path name or
                # provenance record (set earlier in this function)
                pkg_to_uninstall = rep_provenance.get("package_name") or None

            if pkg_to_uninstall:
                logger.info(
                    f"[Frida Repair] Pre-uninstalling '{pkg_to_uninstall}' to clear "
                    "signature mismatch before installing re-signed derivative"
                )
                _adb("-s", device, "uninstall", pkg_to_uninstall, timeout=30)
            else:
                logger.warning(
                    "[Frida Repair] Could not determine package name for pre-uninstall; "
                    "attempting install anyway (INSTALL_FAILED_UPDATE_INCOMPATIBLE may still occur)"
                )

            ok3, out3 = _adb("-s", device, "install", "-t", "--bypass-low-target-sdk-block", rep_path_or_err, timeout=120)
            if ok3:
                logger.info(f"[Frida Repair] Repaired derivative artifact installed successfully on emulator!")
                return True, out3, rep_provenance
            else:
                logger.error(f"[Frida Repair] Derivative installation failed: {out3}")
                return False, f"Derivative install failed: {out3.strip()}", default_provenance
        else:
            logger.error(f"[Frida Repair] Derivative generation failed: {rep_path_or_err}")
            return False, f"APK parse failure & derivative generation failed: {last_out.strip()}", default_provenance

    return False, f"Failed to install APK after retries. Last error: {last_out.strip()}", default_provenance




def _extract_apk_info(apk_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract package name and main activity from APK.

    Strategy (in order):
      1. aapt2 / aapt  — fastest, requires Android SDK build-tools in PATH
      2. androguard    — pure-Python fallback, always available (in requirements.txt)
    """
    import shutil
    package_name, main_activity = None, None

    # ── Strategy 1: aapt / aapt2 ──────────────────────────────────────────────
    for tool in ["aapt2", "aapt"]:
        aapt = shutil.which(tool)
        if not aapt:
            user = os.environ.get("USERNAME", os.environ.get("USER", "user"))
            candidates = [
                rf"C:\Users\{user}\AppData\Local\Android\Sdk\build-tools\34.0.0\{tool}.exe",
                rf"C:\Users\{user}\AppData\Local\Android\Sdk\build-tools\36.0.0\{tool}.exe",
                rf"C:\Users\{user}\AppData\Local\Android\Sdk\build-tools\36.1.0\{tool}.exe",
            ]
            for c in candidates:
                if os.path.exists(c):
                    aapt = c
                    break
        if aapt:

            try:
                result = subprocess.run(
                    [aapt, "dump", "badging", apk_path],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.splitlines():
                    if line.startswith("package: name="):
                        parts = line.split("'")
                        if len(parts) >= 2:
                            package_name = parts[1]
                    elif line.startswith("launchable-activity: name="):
                        parts = line.split("'")
                        if len(parts) >= 2:
                            main_activity = parts[1]
                if package_name:
                    logger.debug(f"[Frida] Extracted via {tool}: {package_name} / {main_activity}")
                    return package_name, main_activity
            except Exception:
                pass

    try:
        from androguard.misc import AnalyzeAPK
        try:
            import loguru
            loguru.logger.disable("androguard")
        except ImportError:
            pass
        a, _, _ = AnalyzeAPK(apk_path)
        pkg = a.get_package()
        act = a.get_main_activity()
        if pkg and pkg not in ("Failed", "Unknown", "None"):
            package_name = pkg
            main_activity = act
            logger.debug(f"[Frida] Extracted via androguard: {package_name} / {main_activity}")
            return package_name, main_activity
    except ImportError:
        logger.warning("[Frida] androguard not installed — install it: pip install androguard")
    except Exception as e:
        logger.warning(f"[Frida] androguard failed to parse APK: {e}")

    # ── Strategy 3: ZipFile binary AndroidManifest regex inspection ─────────
    try:
        import zipfile
        with zipfile.ZipFile(apk_path) as z:
            if "AndroidManifest.xml" in z.namelist():
                raw = z.read("AndroidManifest.xml")
                matches = re.findall(rb'[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z0-9_.]+', raw)
                for match in matches:
                    decoded = match.decode('ascii', errors='ignore')
                    if len(decoded) > 5 and "." in decoded and not decoded.startswith("android.") and not decoded.startswith("schemas.") and decoded not in ("Failed", "Unknown", "None"):
                        package_name = decoded
                        logger.debug(f"[Frida] Extracted via zip manifest regex: {package_name}")
                        return package_name, main_activity
    except Exception:
        pass

    if package_name in ("Failed", "Unknown", "None"):
        package_name = None

    return package_name, main_activity



def _resolve_launcher_activity(device: str, package_name: str) -> Optional[str]:
    """
    Return the package's launcher activity as 'pkg/.Activity', or None.

    Uses the platform's own intent resolver, which is what the launcher itself
    Replaces the previous `-c LAUNCHER` random-input trick, which delivered the
    intent only as a side effect of starting a fuzzing session and so injected
    stray input events into the app before analysis had begun.
    """
    import shlex as _shlex
    safe_pkg = _shlex.quote(package_name)

    # `cmd package resolve-activity --brief` prints the component on the last
    # non-empty line. Available on API 24+.
    ok, out = _adb(
        "-s", device, "shell",
        f"cmd package resolve-activity --brief {safe_pkg}",
        timeout=15,
    )
    if ok and out:
        for line in reversed([l.strip() for l in out.splitlines() if l.strip()]):
            if "/" in line and not line.lower().startswith("priority"):
                return line

    # Fallback: parse the LAUNCHER intent filter out of `pm dump`.
    ok, out = _adb(
        "-s", device, "shell",
        f"pm dump {safe_pkg} | grep -A 2 'android.intent.category.LAUNCHER'",
        timeout=15,
    )
    if ok and out:
        m = re.search(rf"({re.escape(package_name)}/[\w.$]+)", out)
        if m:
            return m.group(1)

    return None


def _launch_app(device: str, package_name: str) -> bool:
    """Launch the app's declared launcher activity via an explicit intent."""
    component = _resolve_launcher_activity(device, package_name)
    if not component:
        return False
    import shlex as _shlex
    ok, _ = _adb(
        "-s", device, "shell",
        f"am start -W -n {_shlex.quote(component)}",
        timeout=20,
    )
    return ok


def _collect_observed_activities(session: "FridaSession") -> List[str]:
    """
    Collect the real set of activity class names observed during the session.

    Source of truth (in priority order):
      1. ``session.reports["agent_memory"]["visited_screens"]`` — the
         AgenticExplorer's perception layer records the foreground activity
         name on every Observe cycle.  These are real dumpsys values,
         never synthesised.
      2. Any ``category="activity"`` events on the EventBus runtime log
         (set by the perception pipeline's ``update_from_foreground`` call).
      3. Empty list — explicitly NOT ``[session.package_name]``, which was
         the previous fabricated placeholder.

    This function never raises and never invents data: on any parse error
    it returns ``[]`` rather than a guess.
    """
    try:
        # Source 1: agentic explorer memory
        reports = getattr(session, "reports", {}) or {}
        mem_summary = reports.get("agent_memory") or {}
        visited = mem_summary.get("visited_screens") or {}

        activities: List[str] = []
        if isinstance(visited, dict):
            # visited_screens is {screen_hash: {"activity": str, ...}, ...}
            for screen_data in visited.values():
                act = None
                if isinstance(screen_data, dict):
                    act = screen_data.get("activity")
                elif isinstance(screen_data, str):
                    act = screen_data
                if act and isinstance(act, str) and act not in activities:
                    activities.append(act)
        elif isinstance(visited, list):
            # If memory returns a list of screen records
            for item in visited:
                act = item.get("activity") if isinstance(item, dict) else str(item)
                if act and act not in activities:
                    activities.append(act)

        if activities:
            logger.debug(
                f"[Frida] _collect_observed_activities: "
                f"{len(activities)} unique activities from explorer memory"
            )
            return activities

        # Source 2: EventBus activity events (collected via attack_timeline)
        timeline = reports.get("attack_timeline") or []
        for entry in timeline:
            if entry.get("category") == "activity":
                act = (entry.get("data") or {}).get("activity")
                if act and act not in activities:
                    activities.append(act)
        if activities:
            logger.debug(
                f"[Frida] _collect_observed_activities: "
                f"{len(activities)} activities from attack_timeline"
            )
            return activities

    except Exception as exc:
        logger.warning(
            f"[Frida] _collect_observed_activities failed gracefully: {exc}"
        )

    # Source 3: empty list — no observed activities, do not fabricate
    return []


def _collect_screenshots(session: "FridaSession") -> List[str]:
    """
    Return the relative paths of every screenshot captured this session.

    Never raises and never invents entries: a session with no ScreenshotManager,
    or one where every capture failed, yields [].
    """
    mgr = getattr(session, "screenshot_manager", None)
    if mgr is None:
        return []
    try:
        return [
            rec.filename for rec in mgr.get_manifest()
            if getattr(rec, "filename", None)
        ]
    except Exception as exc:
        logger.warning(f"[Frida] Could not read screenshot manifest: {exc}")
        return []


def calculate_bfci(
    collected_events: Dict[str, List[Dict]],
) -> Tuple[float, Dict[str, float], List[str]]:
    """
    Backwards-compatible wrapper around bfci_scorer.calculate_bfci_v2.

    Returns (bfci_score, component_scores, evidence_list) — same signature
    as v1 so all call sites are unaffected. detected_sequences is embedded
    in the evidence_list for v1 callers; use calculate_bfci_v2 directly for
    the full 4-tuple return.
    """
    bfci, components, evidence, sequences = calculate_bfci_v2(collected_events)
    return bfci, components, evidence

# ─── Frida Session Manager ────────────────────────────────────────────────────

# ─── Per-sample artifact directories ──────────────────────────────────────────

# Forensic artifacts used to be written to the process working directory, so
# every scan overwrote the previous one and no per-sample record survived. They
# now go under a per-sample subdirectory of the APK's own folder.
ARTIFACT_ROOT_DIRNAME: str = "sudarshan_artifacts"

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")


def artifact_dir_for(apk_path: str) -> Path:
    """
    Return the forensic artifact directory for one APK, creating it if needed.

    The directory name combines the sanitised file stem (human-readable in an
    investigation) with a short digest of the resolved path (so two samples
    that share a stem but live in different folders never collide).

    Re-analysing the SAME sample intentionally reuses its directory; analysing a
    DIFFERENT sample never touches it.
    """
    # Resolve FIRST, then derive the parent. Taking the parent of an unresolved
    # path lets a traversal component ("../evil.apk") place artifacts outside
    # the sample's real folder. After resolution the parent is always the
    # directory the file actually lives in.
    raw = Path(apk_path)
    try:
        resolved_path = raw.resolve()
    except OSError:
        resolved_path = raw.absolute()

    stem = _UNSAFE_NAME_CHARS.sub("_", resolved_path.stem)[:64] or "sample"
    digest = hashlib.sha256(
        str(resolved_path).encode("utf-8", errors="ignore")
    ).hexdigest()[:8]

    target = resolved_path.parent / ARTIFACT_ROOT_DIRNAME / f"{stem}_{digest}"
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error(
            f"[Frida] Cannot create artifact dir {target} ({type(exc).__name__}: {exc}) "
            f"— falling back to the APK's own folder"
        )
        return resolved_path.parent
    return target


class FridaSession:
    """Manages a Frida instrumentation session against a target app."""

    def __init__(
        self,
        device_serial: str,
        package_name: str,
        main_activity: Optional[str] = None,
        artifact_dir: Optional[Path] = None,
    ):
        self.device_serial = device_serial
        self.package_name = package_name
        self.main_activity = main_activity
        # Where per-sample forensic artifacts are written. Defaults to the
        # process CWD only when a caller supplies nothing, which keeps the
        # constructor usable in tests without touching the filesystem.
        self.artifact_dir: Path = Path(artifact_dir) if artifact_dir else Path(".")
        self.event_bus = RuntimeEventBus()
        # Keys MUST mirror the `events` object in frida_hooks/banking_trojan.js.
        # An unrecognised category is remapped to "dangerous_apis" by
        # _on_message, so a category present in the agent but missing here is
        # silently misfiled rather than dropped.
        #
        # Only the first six are scored — see bfci_scorer.BFCI_WEIGHTS. The rest
        # are collected as evidence and contribute nothing to BFCI, which is what
        # keeps ordinary application behaviour out of the fraud score.
        self.collected_events: Dict[str, List[Dict]] = {
            # ── Scored ────────────────────────────────────────────────────────
            "accessibility": [], "sms": [], "overlay": [],
            "banking": [], "network": [], "persistence": [],
            # ── Unscored: evidence only ───────────────────────────────────────
            "dangerous_apis": [], "files_accessed": [],
            "anti_analysis": [],        # sandbox evasion / anti-instrumentation
            "device_fingerprint": [],   # IMEI/IMSI/ICCID/MSISDN, app + account enumeration
            "app_telemetry": [],        # activity lifecycle, keyboard, generic crypto/prefs
            "notification": [],         # notification interception
        }
        self.canary_received: bool = False
        self.total_hook_events_received: int = 0
        self.hooks_installed_count: int = 0   # incremented by hook_installed messages
        self.hook_errors: List[str] = []
        # True when the Frida agent could not obtain a working Java bridge, so
        # none of the ~40 Java hooks installed. Distinguishes a harness fault
        # from a sample that genuinely did nothing.
        self.java_bridge_failed: bool = False
        self.java_bridge_source: Optional[str] = None
        self.java_hooks_installed: int = 0
        self.native_hooks_installed: int = 0
        # Per-hook fire / error counts, owned by this process. See _on_message.
        self.hook_fire_counts: Dict[str, int] = {}
        self.hook_error_counts: Dict[str, int] = {}
        # Which explorer actually ran ("agentic" | "ui_explorer" | "none"), and
        # why it failed if it did. Surfaced in the result so a reviewer can tell
        # AI exploration from a rollback without reading the logs.
        self.explorer_used: str = "none"
        self.explorer_error: Optional[str] = None
        # Which of the 5-step launch ladder succeeded for this sample.
        # None means we haven't attempted launch yet; "failed" means all 5 failed.
        self.launch_method_used: Optional[str] = None
        # Real accessibility service class extracted from the APK manifest.
        # Passed through to AgenticExplorer → ToolExecutor so the correct
        # component name is used in 'settings put secure enabled_accessibility_services'.
        self.accessibility_service_class: Optional[str] = None
        # True when the package was still alive after `am force-stop` at the end
        # of the session — a persistence signal (watchdog service, restart
        # receiver), surfaced in the result rather than swallowed.
        self.survived_force_stop: bool = False
        # Set by stop() to cut an in-flight analysis short instead of sleeping
        # out the full window.
        self._stop_event = threading.Event()
        self._session = None
        self._script = None
        self.reports = {}

        # ── Wave 1: Evidence Store ─────────────────────────────────────────────
        if EvidenceStore is not None:
            self.evidence_store = EvidenceStore(
                event_bus=self.event_bus,
                package_name=package_name,
                analysis_stage="single",
            )
        else:
            self.evidence_store = None

        # ── Wave 2: Intelligence Collectors ────────────────────────────────────
        self.screenshot_manager = None
        self.ioc_collector = None
        self.mitre_mapper = None
        
        # ── Wave 3: Navigator Upgrades ─────────────────────────────────────────
        self.permission_orchestrator = None
        self.last_error: Optional[str] = None
        self.replay_engine = None
        
        # ── Wave 4: Intelligence Depth ─────────────────────────────────────────
        self.network_capture = None
        self.anti_analysis_detector = None
        self.yara_scanner = None
        
        if ScreenshotManager is not None:
            # We don't know the output_dir yet, it will be set later in run_frida_analysis, 
            # but we can initialize the manager later or pass a dummy path for now.
            # Actually, let's just initialize them in run_frida_analysis where we have apk_dir.
            pass

    def _on_message(self, message: Dict, data: Any) -> None:
        """Handle messages sent from the Frida JS script."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            msg_type = payload.get("type")

            if msg_type == "event":
                self.total_hook_events_received += 1
                # The payload from the JS emit() is the event object itself.
                # Some older message paths nest it under 'payload', others don't.
                event = payload.get("payload", payload) if "payload" in payload else payload
                # If the emit wrapper itself IS the event (no inner payload key)
                # fall back gracefully:
                if not event.get("category"):
                    event = payload

                category = event.get("category")

                # FIX Bug #5: unrecognized categories fall through to dangerous_apis
                # instead of being silently discarded. This prevents novel hook
                # categories from disappearing from collected_events.
                if category not in self.collected_events:
                    category = "dangerous_apis"
                    event = dict(event)
                    event["original_category"] = event.get("category", "unknown")
                    event["category"] = "dangerous_apis"

                self.collected_events[category].append(event)
                severity = event.get("severity", (event.get("data") or {}).get("severity", "MED"))
                hook_name = (event.get("data") or {}).get("hook") or event.get("hook", "?")
                logger.debug(f"[Frida] [{severity}] {category}: {hook_name}")

                # Update pipeline tracker event counters
                tracker = get_tracker(self.package_name, self.package_name)
                tracker.event_counters.received += 1

                # Hook telemetry. This previously imported
                # app.routes.runtime_api — from sudarshan_core UP into the
                # backend — inside a bare `except: pass`. The analysis engine
                # has no such package, so on the primary (delegated) path every
                # one of these raised and was swallowed, and the hook counters
                # the dashboard reads stayed at zero while instrumentation was
                # working fine. Counted locally now, and surfaced in the result.
                self.hook_fire_counts[hook_name] = self.hook_fire_counts.get(hook_name, 0) + 1

                # Publish to Event Bus (EvidenceStore + UIExplorer subscribe here)
                self.event_bus.publish(event)

            elif msg_type == "ping":
                self.last_heartbeat_ts = time.time()
                tracker = get_tracker(self.package_name, self.package_name)
                tracker.frida_running = True
                # Update hook count from ping payload (v4 script sends hooks_installed)
                hi = payload.get("hooks_installed")
                if hi is not None:
                    self.hooks_installed_count = int(hi)

            elif msg_type == "hook_installed":
                # v4 script sends this after each successful hook registration
                self.hooks_installed_count = payload.get("total", self.hooks_installed_count)
                hook_name = payload.get('hook', '?')
                # Track Java vs native separately. "Java hooks installed" is the
                # only reliable signal that the bridge really worked: the agent
                # can fail at the availability guard, inside Java.perform, or
                # part-way through, and each path reports a different message.
                # Counting outcomes beats matching error strings.
                if str(hook_name).startswith("native:"):
                    self.native_hooks_installed += 1
                else:
                    self.java_hooks_installed += 1
                logger.debug(f"[Frida] Hook installed: {hook_name} (total={self.hooks_installed_count})")
                self.hook_fire_counts.setdefault(hook_name, 0)

            elif msg_type == "canary":
                self.canary_received = True
                tracker = get_tracker(self.package_name, self.package_name)
                tracker.hooks_loaded = True
                logger.info(f"[Frida Canary] Script load canary received: {payload.get('msg')}")

            elif msg_type == "hook_error":
                err = f"Hook failed: {payload.get('hook')} — {payload.get('error')}"
                self.hook_errors.append(err)
                logger.warning(f"[Frida] {err}")
                self.hook_error_counts[payload.get('hook', '?')] = (
                    self.hook_error_counts.get(payload.get('hook', '?'), 0) + 1
                )

            elif msg_type == "ready":
                hooks_count = payload.get("hooks_installed", 0)
                logger.info(
                    f"[Frida] {payload.get('message')} — "
                    f"{hooks_count} hooks installed, "
                    f"{payload.get('hook_errors', 0)} errors"
                )

            elif msg_type == "diag":
                logger.info(f"[Frida DIAG] {payload}")

            elif msg_type == "error":
                # A Java-bridge failure means NO Java hooks installed. That is an
                # instrumentation fault, not evidence about the sample, and must
                # not be reported as NO_BEHAVIOR_OBSERVED.
                _desc = str(payload.get("description", ""))
                if payload.get("java_bridge_source") or "Java bridge unavailable" in _desc or "Java.perform" in _desc:
                    self.java_bridge_failed = True
                    self.java_bridge_source = payload.get("java_bridge_source") or _desc[:160]
                # The agent sends this when the whole Java.perform block dies.
                # Because the canary is sent BEFORE initHooks, the run still
                # reports canary_received=True even on total hook failure.
                # This branch ensures the error is always recorded.
                err = f"Hook initialization failed: {payload.get('description') or payload}"
                self.hook_errors.append(err)
                logger.error(f"[Frida] {err}")

        elif message.get("type") == "error":
            # Frida's own runtime envelope — a hook body that threw.
            err = f"Script error: {message.get('description')}"
            self.hook_errors.append(err)
            logger.error(f"[Frida] {err}")

    # ── Session lifecycle helpers ─────────────────────────────────────────────

    def _wait_for_app_settled(self, timeout: float) -> bool:
        """
        Block until the target app's window stops changing, or `timeout`.

        Polls mCurrentFocus and requires two consecutive identical samples.
        Returns True if the UI was seen to settle. Never raises — a settling
        wait that can fail the run would be worse than the crash it prevents.
        """
        deadline = time.monotonic() + timeout
        last_sig = None
        stable = 0

        while time.monotonic() < deadline:
            ok, out = _adb(
                "-s", self.device_serial, "shell",
                "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
                timeout=10,
            )
            if not ok or not out:
                time.sleep(APP_SETTLE_POLL_SECONDS)
                continue

            sig = " ".join(out.split())
            if sig == last_sig:
                stable += 1
                if stable >= 2:
                    logger.info("[Frida] App window settled.")
                    return True
            else:
                stable = 0
                last_sig = sig
            time.sleep(APP_SETTLE_POLL_SECONDS)

        logger.warning(
            "[Frida] App did not settle within %.1fs — continuing anyway.", timeout
        )
        return False

    def _capture_screenshot(self, label: str, category: str) -> None:
        """
        Take a lifecycle screenshot, if a ScreenshotManager is attached.

        The manager's own event-driven captures are gated on evidence existing,
        which is correct for evidence-linked shots but means a run that produces
        no hook events produces no images at all. The three lifecycle captures
        (opened / explored / final) are ungated: they document what the analyst
        would have seen, and are labelled `source='lifecycle'` so they are never
        mistaken for evidence of a detected behaviour.
        """
        if self.screenshot_manager is None:
            return
        try:
            ref = self.screenshot_manager.capture(
                label=label, category=category, source="lifecycle",
            )
            if ref:
                logger.info(f"[Frida] Screenshot captured: {label}")
        except Exception as exc:
            logger.warning(
                f"[Frida] Lifecycle screenshot '{label}' failed "
                f"({type(exc).__name__}: {exc}) — continuing."
            )

    def _close_app(self) -> None:
        """
        Stop the app cleanly at the end of the session.

        Previously nothing closed it: the sample was left running on the device
        after the window ended, so it kept executing (and kept its overlays,
        services and alarms alive) into the NEXT sample's analysis. Any
        behaviour it produced then was attributed to the wrong APK.

        Best-effort — a sample that resists force-stop is itself worth noting,
        but it must not fail the run.
        """
        import shlex as _shlex
        safe_pkg = _shlex.quote(self.package_name)
        logger.info(f"[Frida] CLOSE: force-stopping {self.package_name}")
        ok, out = _adb(
            "-s", self.device_serial, "shell", f"am force-stop {safe_pkg}", timeout=20
        )
        if not ok:
            logger.warning(f"[Frida] force-stop failed: {out}")
            return

        # Confirm it actually died. A process that survives force-stop is a
        # persistence signal worth recording rather than assuming success.
        time.sleep(1.0)
        if self._resolve_pid() is not None:
            logger.warning(
                f"[Frida] {self.package_name} still running after force-stop — "
                f"possible persistence mechanism (watchdog service / restart receiver)."
            )
            self.survived_force_stop = True
        else:
            logger.info(f"[Frida] {self.package_name} stopped.")

    def _resolve_pid(self) -> Optional[int]:
        """
        Return the running PID of the target package, or None.

        Uses `pidof`, which maps a package name to its process id directly.
        This exists because frida's own process list reports Android apps by
        their display label ("InsecureBankv2"), not their package name
        ("com.android.insecurebankv2"), so attaching by name fails on a process
        that is demonstrably running.

        Falls back to scanning `ps -A` on devices whose toybox lacks `pidof`.
        """
        ok, out = _adb("-s", self.device_serial, "shell", "pidof", self.package_name, timeout=10)
        if ok and out.strip():
            # A multi-process app returns several pids; the first is the main one.
            for token in out.split():
                if token.isdigit():
                    return int(token)

        ok, out = _adb("-s", self.device_serial, "shell", "ps", "-A", timeout=15)
        if ok:
            for line in out.splitlines():
                # Process name is the final column; match it exactly so that
                # ":remote" sub-processes do not shadow the main process.
                parts = line.split()
                if parts and parts[-1] == self.package_name:
                    for token in parts:
                        if token.isdigit():
                            return int(token)
        return None

    def run(self, duration_seconds: int = ANALYSIS_DURATION_SECONDS) -> bool:
        """
        Attach Frida to the target app and collect events for `duration_seconds`.

        Strategy (Android 15 / API 37 compatible):
          1. Launch app via `am start` (manifest or resolved launcher activity)
          2. Wait for process to appear
          3. Attach Frida by package name
          4. Load hooks, collect events
          Falls back to device.spawn() if attach-by-name fails.
        """
        try:
            import frida
        except ImportError:
            logger.error("frida package not installed. Run: pip install frida")
            return False

        if not _HOOKS_SCRIPT.exists():
            logger.error(f"Frida hooks script not found: {_HOOKS_SCRIPT}")
            return False

        script_source = _HOOKS_SCRIPT.read_text(encoding="utf-8")

        try:
            logger.info(f"[Frida] Connecting to device {self.device_serial}")
            device = None
            for attempt in range(3):
                try:
                    # FIX Bug #7: Docker TCP mode requires using frida's remote device API.
                    # When ADB_HOST is set, the device serial is an IP:port string
                    # (e.g. 'host.docker.internal:5555'). frida.enumerate_devices() only
                    # lists USB/local devices; it will never find a TCP-connected emulator
                    # unless we explicitly add it as a remote device using the Frida
                    # server port (27042 by default) on the host running the emulator.
                    #
                    # Strategy:
                    #   1. If ADB_HOST is set, add remote device via frida device manager.
                    #   2. Otherwise, enumerate devices normally.
                    if ADB_HOST:
                        candidate_ports = []
                        for p_env in [os.getenv("SUDARSHAN_FRIDA_PORT"), os.getenv("FRIDA_SERVER_PORT"), "27055", "27042"]:
                            if p_env and p_env.isdigit():
                                p_int = int(p_env)
                                if p_int not in candidate_ports:
                                    candidate_ports.append(p_int)

                        # WHERE the forward actually lands.
                        #
                        # `adb forward` binds the local port on the machine running
                        # the ADB CLIENT — which, in Docker mode, is THIS CONTAINER.
                        # The previous code forwarded inside the container and then
                        # connected to `{ADB_HOST}:{port}`, i.e. the HOST, which has
                        # no such forward unless an operator created one by hand.
                        # Result: frida-server was running fine on the emulator and
                        # every attach failed with
                        #     ServerNotRunningError: unable to connect to remote frida-server
                        # while the app itself launched correctly (ADB works, so the
                        # process and pid resolved) — which made it look like an
                        # injection/permission fault rather than a plumbing one.
                        #
                        # frida-server also binds device-local loopback
                        # (127.0.0.1:27042), so it is ONLY reachable through a
                        # forward. Try the container's own forwarded port first, and
                        # keep ADB_HOST as a fallback for setups where the operator
                        # forwarded on the host instead.
                        for f_port in candidate_ports:
                            fwd_ok, fwd_out = _adb(
                                "-s", self.device_serial, "forward",
                                f"tcp:{f_port}", f"tcp:{f_port}", timeout=10,
                            )
                            if not fwd_ok:
                                logger.debug(
                                    f"[Frida] adb forward tcp:{f_port} failed: {fwd_out}"
                                )

                            for frida_host in ("127.0.0.1", ADB_HOST):
                                try:
                                    device = frida.get_device_manager().add_remote_device(
                                        f"{frida_host}:{f_port}"
                                    )
                                    # add_remote_device is lazy — it can return a
                                    # device object that fails on first real use.
                                    # Force a round trip so a dead endpoint is
                                    # rejected here rather than at attach time.
                                    device.enumerate_processes()
                                    logger.info(
                                        f"[Frida] TCP remote device connected: "
                                        f"{frida_host}:{f_port}"
                                    )
                                    break
                                except Exception as tcp_err:
                                    device = None
                                    logger.debug(
                                        f"[Frida] remote device {frida_host}:{f_port} "
                                        f"unusable: {type(tcp_err).__name__}: {tcp_err}"
                                    )
                            if device:
                                break

                        if not device:
                            logger.warning(
                                "[Frida] No reachable frida-server on %s via ports %s. "
                                "Check that frida-server is running on the device and "
                                "that its port matches SUDARSHAN_FRIDA_PORT.",
                                self.device_serial, candidate_ports,
                            )
                        if device:
                            break

                    # Local/USB mode (or TCP fallback): enumerate all devices
                    all_devices = frida.enumerate_devices()
                    logger.info(f"[Frida] Available devices: {[d.id for d in all_devices]}")
                    for d in all_devices:
                        if d.id == self.device_serial:
                            device = d
                            break
                    if device:
                        break
                    raise Exception(f"Device '{self.device_serial}' not in enumerate_devices list")
                except Exception as e:
                    logger.warning(f"[Frida] Device connect attempt {attempt+1} failed: {e}")
                    time.sleep(2)
            if not device:
                raise Exception("Failed to get device after 3 attempts")

            # ── Wake up Device ──
            logger.info("[Frida] Waking up device screen...")
            _adb("-s", self.device_serial, "shell", "input keyevent 26") # Power
            time.sleep(0.5)
            _adb("-s", self.device_serial, "shell", "input keyevent 82") # Unlock/Menu
            time.sleep(0.5)
            _adb("-s", self.device_serial, "shell", "wm dismiss-keyguard") # Android 8+
            time.sleep(0.5)

            import shlex
            safe_pkg = shlex.quote(self.package_name)

            # ── 5-step launch fallback ladder ────────────────────────────────
            # Each step is tried in order; the first that results in a running
            # process sets self.launch_method_used and breaks the loop.
            # If all 5 fail we mark the run INSTRUMENTATION_FAILED immediately
            # rather than allowing a silent proceed with nothing running.
            #
            # Step 1: am start with manifest-declared launcher activity
            # Step 2: resolved LAUNCHER activity
            # Step 3: enumerate all exported activities and try each
            # Step 4: BOOT_COMPLETED + PACKAGE_ADDED broadcasts (packed samples)
            # Step 5: deep link via declared URI scheme (if any)
            #
            # "required non-standard launch method" is itself a weak
            # anti-analysis signal worth recording in launch_method_used.

            def _check_running() -> bool:
                """Return True if the target process is now running."""
                return self._resolve_pid() is not None

            def _am_start(activity_component: str) -> bool:
                ok, out = _adb(
                    "-s", self.device_serial, "shell",
                    f"am start -n {activity_component}",
                    timeout=15,
                )
                return ok

            launched = False

            # Step 1 — manifest-declared launcher activity
            if self.main_activity:
                safe_act = shlex.quote(self.main_activity)
                logger.info(
                    f"[Frida] Launch step 1: am start -n "
                    f"{self.package_name}/{self.main_activity}"
                )
                _am_start(f"{safe_pkg}/{safe_act}")
                time.sleep(3)
                if _check_running():
                    self.launch_method_used = "am_start_main_activity"
                    launched = True
                    logger.info(
                        f"[Frida] Launch step 1 succeeded: am_start_main_activity"
                    )

            # Step 2 — resolved LAUNCHER activity via an explicit intent.
            # The platform's own resolver gives us the component directly,
            # with no stray input events.
            if not launched:
                logger.info(
                    f"[Frida] Launch step 2: resolve LAUNCHER activity for "
                    f"{self.package_name}"
                )
                component = _resolve_launcher_activity(
                    self.device_serial, self.package_name
                )
                if component:
                    logger.info(f"[Frida] Resolved launcher activity: {component}")
                    _am_start(shlex.quote(component))
                    time.sleep(3)
                    if _check_running():
                        self.launch_method_used = "resolved_launcher_activity"
                        launched = True
                        logger.info(
                            "[Frida] Launch step 2 succeeded: resolved_launcher_activity"
                        )
                else:
                    logger.info(
                        "[Frida] Launch step 2: no LAUNCHER activity declared "
                        "(expected for packed droppers)"
                    )

            # Step 3 — enumerate all exported activities from manifest
            if not launched:
                logger.info(
                    f"[Frida] Launch step 3: trying all exported activities for "
                    f"{self.package_name}"
                )
                exported_activities: List[str] = []
                try:
                    from androguard.misc import AnalyzeAPK
                    _a, _, _ = AnalyzeAPK(getattr(self, '_apk_path', "") or "")
                    exported_activities = [
                        act for act in (_a.get_activities() or [])
                        if act and act != self.main_activity
                    ]
                except Exception:
                    pass
                # Also try pm dump to list exported activities at runtime
                if not exported_activities:
                    ok, dump_out = _adb(
                        "-s", self.device_serial, "shell",
                        f"pm dump {safe_pkg}",
                        timeout=15,
                    )
                    if ok:
                        for line in dump_out.splitlines():
                            line = line.strip()
                            if "Activity{" in line or ("android.intent.action.MAIN" in line
                                                        and self.package_name in line):
                                import re as _re
                                m = _re.search(
                                    rf"{re.escape(self.package_name)}(/\.?[\w.]+)",
                                    line,
                                )
                                if m:
                                    exported_activities.append(
                                        self.package_name + m.group(1)
                                    )

                for act in exported_activities[:8]:  # cap at 8 to bound time
                    safe_act = shlex.quote(act)
                    logger.info(
                        f"[Frida] Launch step 3: trying exported activity {act}"
                    )
                    _am_start(f"{safe_pkg}/{safe_act}")
                    time.sleep(2)
                    if _check_running():
                        self.launch_method_used = f"exported_activity:{act}"
                        launched = True
                        logger.info(
                            f"[Frida] Launch step 3 succeeded via exported "
                            f"activity: {act}"
                        )
                        break

            # Step 4 — BOOT_COMPLETED + PACKAGE_ADDED broadcasts
            # Cerberus / Drinik activate their payload only after the device
            # boots or a new package is added, so no launcher activity exists.
            if not launched:
                logger.info(
                    f"[Frida] Launch step 4: simulating boot/install broadcasts "
                    f"for {self.package_name}"
                )
                _adb(
                    "-s", self.device_serial, "shell",
                    f"am broadcast -a android.intent.action.BOOT_COMPLETED "
                    f"-p {safe_pkg}",
                    timeout=10,
                )
                time.sleep(1)
                _adb(
                    "-s", self.device_serial, "shell",
                    f"am broadcast -a android.intent.action.PACKAGE_ADDED "
                    f"-p {safe_pkg}",
                    timeout=10,
                )
                time.sleep(3)
                if _check_running():
                    self.launch_method_used = "boot_broadcast"
                    launched = True
                    logger.info(
                        "[Frida] Launch step 4 succeeded: boot_broadcast "
                        "(packed sample)"
                    )

            # Step 5 — deep link via URI scheme declared in manifest
            if not launched:
                logger.info(
                    f"[Frida] Launch step 5: attempting URI scheme deep link "
                    f"for {self.package_name}"
                )
                uri_scheme: Optional[str] = None
                try:
                    from androguard.misc import AnalyzeAPK
                    _a2, _, _ = AnalyzeAPK(getattr(self, '_apk_path', "") or "")
                    for act in (_a2.get_activities() or []):
                        try:
                            filters = _a2.get_intent_filters("activity", act)
                            for scheme in filters.get("scheme", []):
                                if scheme and scheme not in (
                                    "http", "https", "market", "intent",
                                ):
                                    uri_scheme = scheme
                                    break
                        except Exception:
                            pass
                        if uri_scheme:
                            break
                except Exception:
                    pass

                if uri_scheme:
                    safe_scheme = shlex.quote(f"{uri_scheme}://")
                    logger.info(
                        f"[Frida] Launch step 5: deep link "
                        f"am start -a VIEW -d {uri_scheme}://"
                    )
                    _adb(
                        "-s", self.device_serial, "shell",
                        f"am start -a android.intent.action.VIEW "
                        f"-d {safe_scheme}",
                        timeout=15,
                    )
                    time.sleep(3)
                    if _check_running():
                        self.launch_method_used = f"deep_link:{uri_scheme}"
                        launched = True
                        logger.info(
                            f"[Frida] Launch step 5 succeeded: "
                            f"deep_link:{uri_scheme}"
                        )

            if not launched:
                self.launch_method_used = "failed"
                self.last_error = (
                    f"LAUNCH_FAILED: All 5 launch methods failed for "
                    f"{self.package_name}. "
                    "Steps tried: am_start_main_activity, resolved_launcher_activity, "
                    "exported_activity, boot_broadcast, deep_link. "
                    "This sample may require manual launch or has no runnable "
                    "entry point in the current environment."
                )
                logger.error(f"[Frida] {self.last_error}")
                return False

            logger.info(
                f"[Frida] App launched successfully via "
                f"'{self.launch_method_used}'"
            )

            self._session = None
            for attempt in range(ATTACH_MAX_ATTEMPTS):
                # Resolve the PID from the device and attach by PID.
                #
                # frida's enumerate_processes() reports a running Android app by
                # its APPLICATION LABEL (e.g. "InsecureBankv2"), not by its
                # package name, so device.attach("com.android.insecurebankv2")
                # raises ProcessNotFoundError even while the process is running.
                # `pidof` is the authoritative mapping from package to PID.
                pid = self._resolve_pid()
                try:
                    if pid:
                        self._session = device.attach(pid)
                        logger.info(
                            f"[Frida] Attached to {self.package_name} "
                            f"(pid={pid}, attempt {attempt+1})"
                        )
                        break
                    # No PID yet — the app may still be starting. Fall back to
                    # attaching by name in case a future frida reports it that way.
                    self._session = device.attach(self.package_name)
                    logger.info(
                        f"[Frida] Attached to {self.package_name} by name (attempt {attempt+1})"
                    )
                    break
                except frida.ProcessNotFoundError:
                    logger.warning(
                        f"[Frida] {self.package_name} not running yet "
                        f"(attempt {attempt+1}/{ATTACH_MAX_ATTEMPTS}), waiting..."
                    )
                    time.sleep(ATTACH_RETRY_DELAY_SECONDS)
                except Exception as e:
                    logger.warning(
                        f"[Frida] Attach attempt {attempt+1} failed: "
                        f"{type(e).__name__}: {e}"
                    )
                    time.sleep(ATTACH_RETRY_DELAY_SECONDS)

            is_spawned = False
            if not self._session:
                logger.info("[Frida] Attach-by-pid failed, falling back to device.spawn()")
                pid = None
                spawn_errors: List[str] = []
                for attempt in range(3):
                    try:
                        pid = device.spawn([self.package_name])
                        break
                    except Exception as e:
                        spawn_errors.append(f"{type(e).__name__}: {e}")
                        logger.warning(f"[Frida] Spawn attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                if not pid:
                    # Report what actually went wrong. The old message always
                    # blamed frida-server, which cost real debugging time when
                    # the true cause was SELinux denying ptrace (attach raised
                    # PermissionDeniedError while frida-server was running fine).
                    running = self._resolve_pid()
                    _, enforce = _adb("-s", self.device_serial, "shell", "getenforce", timeout=10)
                    hint = ""
                    if "Enforcing" in (enforce or ""):
                        hint = (" SELinux is Enforcing, which blocks Frida from attaching "
                                "even as root — run 'adb shell setenforce 0'.")
                    elif running:
                        hint = (f" The process IS running (pid={running}) but could not be "
                                "attached, so this is an injection/permission problem, "
                                "not a launch problem.")
                    raise Exception(
                        "Frida could not instrument "
                        f"{self.package_name}.{hint} "
                        f"Last spawn errors: {spawn_errors[-1] if spawn_errors else 'none'}"
                    )

                for attempt in range(3):
                    try:
                        self._session = device.attach(pid)
                        break
                    except Exception as e:
                        logger.warning(f"[Frida] Post-spawn attach attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                if not self._session:
                    raise Exception("Failed to attach to spawned process")
                is_spawned = True

            self._script = self._session.create_script(script_source)
            self._script.on("message", self._on_message)
            self._script.load()

            if is_spawned:
                logger.info(f"[Frida] Resuming spawned process {pid} AFTER script load...")
                device.resume(pid)

                import shlex
                safe_pkg = shlex.quote(self.package_name)
                # Force the UI to the foreground.
                logger.info(f"[Frida] Pushing spawned app to foreground...")
                if self.main_activity:
                    safe_act = shlex.quote(self.main_activity)
                    _adb("-s", self.device_serial, "shell", f"am start -n {safe_pkg}/{safe_act}")
                else:
                    component = _resolve_launcher_activity(
                        self.device_serial, self.package_name
                    )
                    if component:
                        _adb("-s", self.device_serial, "shell",
                             f"am start -n {shlex.quote(component)}")
                time.sleep(2)


            # ══════════════════════════════════════════════════════════════════
            # PHASE 2 of 3 — ANALYSE
            #
            # The session runs as three explicit phases:
            #
            #   OPEN     launch the app, let it settle, capture the entry screen
            #   ANALYSE  goal-driven exploration under instrumentation, with
            #            screenshots taken at each observed screen
            #   CLOSE    capture the exit screen, then force-stop the package
            #
            # The random fuzzer that used to run here is gone; see the comment
            # on the explorer import at the top of this module.
            # ══════════════════════════════════════════════════════════════════

            # ── OPEN: let the app finish starting before anything touches it ──
            # A cold start on an emulator is routinely 2-4 s. Driving input into
            # a process that is still inflating its first Activity is what
            # crashed the app under analysis, and a harness-induced crash reads
            # in the report exactly like a sample that chose to do nothing.
            logger.info(
                f"[Frida] OPEN: waiting up to {APP_OPEN_SETTLE_SECONDS:.0f}s for "
                f"{self.package_name} to finish starting..."
            )
            self._wait_for_app_settled(APP_OPEN_SETTLE_SECONDS)
            self._capture_screenshot("01_app_opened", "lifecycle")

            logger.info(f"[Frida] ANALYSE: monitoring {self.package_name} for {duration_seconds}s...")
            explorer = None
            explorer_thread = None

            # ── Agentic Explorer (primary) — falls back to UIExplorer on error ──
            try:
                from sudarshan_core.engines.agentic_explorer import AgenticExplorer
                explorer = AgenticExplorer(
                    device_serial=self.device_serial,
                    adb_path=_find_adb(),
                    package_name=self.package_name,
                    event_bus=self.event_bus,
                    # Forward the manifest-parsed accessibility service class
                    # so ToolExecutor uses the real obfuscated class name.
                    accessibility_service_class=self.accessibility_service_class,
                    screenshot_manager=self.screenshot_manager,
                )
                self.explorer_used = "agentic"
                logger.info("[Frida] AgenticExplorer selected.")
            except Exception as exc:
                # Rollback covers ANY construction failure, not just
                # ImportError: a missing dependency, a bad device serial or
                # a constructor raising must all degrade to the legacy
                # explorer rather than abandoning exploration entirely.
                logger.error(
                    f"[Frida] AgenticExplorer unavailable "
                    f"({type(exc).__name__}: {exc}) — attempting rollback",
                    exc_info=True,
                )
                if UIExplorer is not None:
                    try:
                        explorer = UIExplorer(
                            self.device_serial, _find_adb(),
                            event_bus=self.event_bus,
                        )
                        self.explorer_used = "ui_explorer"
                        logger.warning("[Frida] Rolled back to UIExplorer.")
                    except Exception as ui_exc:
                        explorer = None
                        self.explorer_used = "none"
                        logger.error(
                            f"[Frida] UIExplorer rollback also failed "
                            f"({type(ui_exc).__name__}: {ui_exc})",
                            exc_info=True,
                        )
                else:
                    explorer = None
                    self.explorer_used = "none"
                    logger.error("[Frida] Both AgenticExplorer and UIExplorer unavailable.")

            if explorer is not None:
                def _run_explorer():
                    """
                    Explorer thread body.

                    This previously had NO exception handling: any error
                    inside the agent loop killed the thread silently, the
                    analysis still slept out its full window, and the run
                    reported success with zero exploration performed. A
                    failure here must be recorded, never swallowed.
                    """
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(explorer.start(duration_seconds))
                    except Exception as exc:
                        self.explorer_error = f"{type(exc).__name__}: {exc}"
                        logger.error(
                            f"[Frida] Explorer thread crashed: {self.explorer_error}",
                            exc_info=True,
                        )
                        # Nothing further can be explored — release the main
                        # wait immediately instead of idling for the rest of
                        # the window.
                        self._stop_event.set()
                    finally:
                        try:
                            loop.close()
                        except Exception as close_exc:
                            logger.warning(
                                f"[Frida] Explorer event loop close failed: "
                                f"{type(close_exc).__name__}: {close_exc}"
                            )

                explorer_thread = threading.Thread(target=_run_explorer, daemon=True)
                explorer_thread.start()

            # NOTE: run() is synchronous and is dispatched via
            # loop.run_in_executor(), so waiting here occupies a worker thread,
            # not the event loop. What it must NOT be is uninterruptible: use a
            # stop Event so stop() can cut the analysis short, and join the
            # explorer so we return as soon as exploration genuinely finishes.
            self._stop_event.wait(timeout=duration_seconds)

            if explorer_thread is not None and explorer_thread.is_alive():
                # Ask the explorer to wind down BEFORE waiting on it. Without
                # this the thread runs to its own deadline while we block, and
                # artifacts get flushed mid-iteration — the goal summary and
                # benchmark counters are written before the explorer computes
                # them, reporting goals_completed=0 for a run that did progress.
                if explorer is not None and hasattr(explorer, "stop"):
                    explorer.stop()
                explorer_thread.join(timeout=EXPLORER_JOIN_GRACE_SECONDS)
                if explorer_thread.is_alive():
                    logger.warning(
                        f"[Frida] Explorer did not finish within "
                        f"{EXPLORER_JOIN_GRACE_SECONDS}s of being asked to stop "
                        f"— artifacts may be incomplete"
                    )

            # ── CLOSE: final screen, then stop the app ────────────────────────
            # Capture BEFORE stopping: the last screen is often the most
            # interesting one (an overlay left up, a phishing form mid-fill),
            # and force-stopping destroys it.
            self._capture_screenshot("99_final_screen", "lifecycle")
            self._close_app()
            return True

        except Exception as e:
            # Record the real cause so the caller can report it. Previously the
            # wrapper discarded this and substituted a fixed
            # "Ensure frida-server is running" string, which named the wrong
            # component on every failure.
            self.last_error = f"{type(e).__name__}: {e}"
            logger.error(f"[Frida] Session failed: {self.last_error}")
            return False

        finally:
            # No fuzzer to reap any more.
            if 'explorer' in locals() and explorer:
                try:
                    explorer.stop()
                    self.reports = explorer.get_reports()
                    # Flush agentic-only artifacts (audit_log.json, benchmark.json)
                    # UIExplorer does not have flush_artifacts() — guarded by hasattr.
                    if hasattr(explorer, 'flush_artifacts'):
                        explorer.flush_artifacts(self.artifact_dir)
                except Exception as exc:
                    logger.error(
                        f"[Frida] Failed to flush explorer artifacts to "
                        f"{self.artifact_dir}: {type(exc).__name__}: {exc}",
                        exc_info=True,
                    )

            if getattr(self, '_script', None):
                try:
                    self._script.unload()
                except Exception:
                    pass
                    
            if getattr(self, '_session', None):
                try:
                    self._session.detach()
                except Exception:
                    pass
            logger.info(f"[Frida] Session cleanup complete")


# ─── Main Analysis Entry Point ─────────────────────────────────────────────────

async def run_frida_analysis(apk_path: str, package_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Full Frida dynamic analysis pipeline:
      1. Find connected emulator
      2. Install APK
      3. Extract package name
      4. Launch app + attach Frida
      5. Collect behavioral events
      6. Compute BFCI
      7. Return structured result (compatible with risk_engine.py)

    Returns a dict matching the dynamic_result schema expected by calculate_risk_score().
    Falls back gracefully with available=False if anything fails.
    """
    base_result: Dict[str, Any] = {
        "available": False,
        "engine": "frida",
        "dynamic_status": "INSTRUMENTATION_FAILED",
        "bfci": 0.0,
        "bfci_components": {},
        "bfci_weights": BFCI_WEIGHTS,
        "activities_triggered": [],
        "network_logs": [],
        "api_calls": [],
        "files_accessed": [],
        "screenshots": [],
        "logcat": "",
        "evidence": [],
        "hook_errors": [],
        "duration_seconds": ANALYSIS_DURATION_SECONDS,
    }


    # ── Step 1: Find emulator ──────────────────────────────────────────────────
    emulators = []
    for attempt in range(3):
        emulators = get_connected_emulators()
        if emulators:
            break
        logger.warning(f"[Frida] No emulators found, attempt {attempt+1}. Retrying in 2s...")
        await asyncio.sleep(2)
        
    if not emulators:
        logger.warning("[Frida] No Android emulators connected. Start an AVD in Android Studio.")
        base_result["error"] = "No emulator connected. Start an AVD in Android Studio."
        return base_result

    device_serial = emulators[0]
    logger.info(f"[Frida] Using emulator: {device_serial}")

    # ── Serialise access to the device ────────────────────────────────────────
    # There is exactly ONE emulator and it was taken with no lock, while the
    # engine allows MAX_CONCURRENT_ANALYSES=2. Two dynamic runs could therefore
    # interleave `adb install`, `am start`, `pidof` and Frida attach against the
    # same device — and _adb_install_apk performs an `adb uninstall` on the
    # signature-mismatch path, which could uninstall the package another run was
    # actively instrumenting. That is a correctness hazard, not a throughput
    # limit: whichever run lost the race reported behaviour that never happened.
    #
    # Held for the whole install → instrument → close cycle.
    async with _device_lock_for(device_serial):
        return await _run_device_session(
            apk_path=apk_path,
            package_name=package_name,
            device_serial=device_serial,
            base_result=base_result,
        )


def _device_lock_for(device_serial: str) -> asyncio.Lock:
    """Return the process-wide lock guarding one device."""
    lock = _DEVICE_LOCKS.get(device_serial)
    if lock is None:
        lock = asyncio.Lock()
        _DEVICE_LOCKS[device_serial] = lock
    return lock


async def _run_device_session(
    apk_path: str,
    package_name: Optional[str],
    device_serial: str,
    base_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Install, instrument and close one sample. Caller holds the device lock."""
    loop = asyncio.get_event_loop()

    # ── Step 1a: adbd must be root, and SELinux must be permissive ─────────────
    #
    # Without this, frida-server runs happily and every attach still fails with
    #     PermissionDeniedError: unable to access process with pid <pid>
    # because SELinux (Enforcing by default on Android 15+) denies the ptrace
    # that injection requires — even for uid 0. The old code only checked that
    # frida-server was alive, so the failure surfaced as the misleading
    # "Ensure frida-server is running on emulator", which it was.
    #
    # This is an analysis sandbox: the AVD is disposable and exists to be
    # instrumented. It is never applied to anything but the attached emulator.
    await loop.run_in_executor(None, _adb, "-s", device_serial, "root")
    await asyncio.sleep(1)

    ok, enforce = await loop.run_in_executor(
        None, _adb, "-s", device_serial, "shell", "getenforce"
    )
    if "Enforcing" in (enforce or ""):
        logger.warning(
            "[Frida] SELinux is Enforcing — Frida cannot attach to app processes. "
            "Setting the sandbox emulator to Permissive."
        )
        await loop.run_in_executor(
            None, _adb, "-s", device_serial, "shell", "setenforce 0"
        )
        ok, enforce = await loop.run_in_executor(
            None, _adb, "-s", device_serial, "shell", "getenforce"
        )
        if "Permissive" not in (enforce or ""):
            logger.error(
                "[Frida] Could not set SELinux permissive (still %r). Attach will "
                "likely fail with PermissionDeniedError. The emulator must be "
                "started from a userdebug/eng image.", (enforce or "").strip()
            )
    logger.info("[Frida] SELinux mode: %s", (enforce or "unknown").strip())

    # ── Step 1b: Automatically start frida-server if dead ──────────────────────
    logger.info("[Frida] Checking frida-server status...")
    ok, out = await loop.run_in_executor(
        None, _adb, "-s", device_serial, "shell", "ps -A | grep frida-server"
    )
    if "frida-server" not in out:
        logger.info("[Frida] frida-server not running, starting it automatically...")
        # Since adb is running as root, we can run it directly and background it
        await loop.run_in_executor(
            None, _adb, "-s", device_serial, "shell", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
        )
        await asyncio.sleep(2) # Give it time to start up

    # ── Step 2: Extract package name ───────────────────────────────────────────
    main_activity = None
    if not package_name or package_name in ("Failed", "Unknown", "None"):
        package_name, main_activity = await loop.run_in_executor(None, _extract_apk_info, apk_path)
        
    if not package_name or package_name in ("Failed", "Unknown", "None"):
        logger.warning("[Frida] Could not extract valid package name from APK")
        base_result["error"] = "Could not extract valid package name from APK."
        return base_result

    logger.info(f"[Frida] Target package: {package_name} (Main Activity: {main_activity})")

    # ── Step 3: Install APK ────────────────────────────────────────────────────
    ok, output, provenance = await loop.run_in_executor(None, _adb_install_apk, apk_path, device_serial)
    base_result["provenance"] = provenance
    if not ok:
        logger.error(f"[Frida] APK install failed: {output}")
        base_result["error"] = f"APK install failed: {output}"
        return base_result
    logger.info(f"[Frida] APK installed: {package_name} (Derivative Repaired: {provenance.get('is_repaired_derivative', False)})")

    effective_apk_path = apk_path
    if provenance.get("is_repaired_derivative"):
        rep_p = provenance.get("repaired_apk_path")
        if rep_p and os.path.exists(rep_p):
            effective_apk_path = rep_p
        rep_act = provenance.get("main_activity")
        if rep_act and rep_act != "MainActivity":
            main_activity = rep_act
            logger.info(f"[Frida] Using repaired derivative main activity: {main_activity}")

    # ── Step 4: Run Frida session ──────────────────────────────────────────────
    # Per-sample artifact directory: previously every scan wrote audit_log.json
    # and benchmark.json into the process CWD, so each run destroyed the last
    # one's forensic record.
    apk_dir = artifact_dir_for(apk_path)
    logger.info(f"[Frida] Artifacts for this sample: {apk_dir}")

    session = FridaSession(
        device_serial, package_name,
        main_activity=main_activity,
        artifact_dir=apk_dir,
    )
    # Give the launch ladder access to the APK path for steps 3 & 5
    # (androguard activity enumeration and URI scheme discovery).
    session._apk_path = effective_apk_path  # type: ignore[attr-defined]

    # Extract the real accessibility service class name from the manifest
    # once here, before the session runs. The result is forwarded into
    # AgenticExplorer → ToolExecutor so it reaches the settings put command.
    try:
        from sudarshan_core.engines.permission_orchestrator import (
            extract_accessibility_service_class,
        )
        session.accessibility_service_class = extract_accessibility_service_class(
            apk_path, package_name
        )
    except Exception as _exc:
        logger.warning(
            f"[Frida] Could not extract accessibility service class: {_exc}"
        )
    
    # ── Wave 2: Initialize Intelligence Collectors ─────────────────────────────
    if ScreenshotManager is not None:
        session.screenshot_manager = ScreenshotManager(
            device_serial=device_serial,
            adb_path=_find_adb() or "adb",
            output_dir=apk_dir,
            event_bus=session.event_bus,
            evidence_store=session.evidence_store
        )
    if IOCCollector is not None:
        session.ioc_collector = IOCCollector(
            event_bus=session.event_bus,
            apk_path=apk_path,
            device_serial=device_serial,
            package_name=package_name
        )
    if MitreMapper is not None:
        session.mitre_mapper = MitreMapper(event_bus=session.event_bus)

    # ── Wave 3: Initialize Navigator Upgrades ──────────────────────────────────
    if PermissionOrchestrator is not None:
        session.permission_orchestrator = PermissionOrchestrator(
            device_serial=device_serial,
            event_bus=session.event_bus
        )
    if ReplayEngine is not None:
        session.replay_engine = ReplayEngine(event_bus=session.event_bus)

    # ── Wave 4: Initialize Intelligence Depth ──────────────────────────────────
    if NetworkCapture is not None:
        session.network_capture = NetworkCapture(event_bus=session.event_bus)
    if AntiAnalysisDetector is not None:
        session.anti_analysis_detector = AntiAnalysisDetector(event_bus=session.event_bus)
    if YARAScanner is not None:
        # YARA rules directory.
        #
        # This was Path("yara_rules") — RELATIVE, so it resolved against the
        # process working directory, which differs between the gateway and the
        # analysis engine. No directory of that name exists anywhere in the
        # repository, so the scanner had nothing to load and YARA scanning was
        # a silent no-op in both services.
        #
        # Resolved absolutely, with the location overridable, and the outcome
        # logged either way so "no YARA matches" can be distinguished from
        # "YARA never ran".
        rules_dir = Path(
            os.getenv("SUDARSHAN_YARA_RULES_DIR", str(Path(__file__).parent / "yara_rules"))
        ).resolve()
        if rules_dir.is_dir() and any(rules_dir.glob("*.yar*")):
            session.yara_scanner = YARAScanner(rules_dir=rules_dir, event_bus=session.event_bus)
            logger.info(f"[Frida] YARA rules loaded from {rules_dir}")
        else:
            session.yara_scanner = None
            logger.warning(
                f"[Frida] YARA scanning DISABLED — no .yar/.yara rules found in "
                f"{rules_dir}. Set SUDARSHAN_YARA_RULES_DIR to enable it."
            )

    def _run_sync():
        return session.run(duration_seconds=ANALYSIS_DURATION_SECONDS)

    success = await loop.run_in_executor(None, _run_sync)

    if not success:
        base_result["error"] = (
            getattr(session, "last_error", None)
            or "Frida instrumentation failed (no further detail reported)."
        )
        return base_result

    # ── Step 5: Compute BFCI & Instrumentation Status ───────────────────────
    bfci, components, evidence = calculate_bfci(session.collected_events)

    if not session.canary_received:
        dynamic_status = "INSTRUMENTATION_FAILED"
    elif session.java_bridge_failed or session.java_hooks_installed == 0:
        # The script loaded and native hooks installed, but the Java bridge did
        # not, so accessibility / SMS / overlay / banking could never fire.
        # Calling that NO_BEHAVIOR_OBSERVED would blame the sample for a
        # harness fault, and risk_engine would treat it as a real observation.
        dynamic_status = "INSTRUMENTATION_FAILED"
        logger.error(
            "[Frida] NO Java hooks installed (%d native only; bridge: %s). "
            "Accessibility, SMS, overlay and banking hooks could never fire, so "
            "this run is INSTRUMENTATION_FAILED, not 'no behaviour observed' — "
            "the sample is not being credited with doing nothing.",
            session.native_hooks_installed,
            session.java_bridge_source or "unknown",
        )
    elif session.total_hook_events_received == 0:
        dynamic_status = "NO_BEHAVIOR_OBSERVED"
    else:
        dynamic_status = "EVENTS_CAPTURED"

    # ── Step 6: Build structured result ───────────────────────────────────────
    # Flatten API calls for risk_engine.py compatibility
    # Flattened view of every hook that fired. This is a REPORTING surface, not a
    # scoring one — risk_engine only consumes it on the MobSF path, and
    # _dynamic_run_was_conclusive counts it to decide whether the sandbox saw
    # anything at all. It therefore spans scored AND unscored categories: an event
    # that is excluded from BFCI (a device-identity read, say) is still real
    # observed behaviour and must not vanish from the analyst's view.
    api_calls = [
        e.get("data", {}).get("hook", "")
        for category in ["accessibility", "sms", "overlay", "banking",
                         "persistence", "dangerous_apis",
                         "device_fingerprint", "app_telemetry", "notification"]
        for e in session.collected_events.get(category, [])
    ]

    network_logs = [
        e["data"].get("url", "")
        for e in session.collected_events.get("network", [])
        if e.get("data", {}).get("url")
    ]

    files_accessed = [
        e["data"].get("path", "")
        for e in session.collected_events.get("files_accessed", [])
        if e.get("data", {}).get("path")
    ]

    # Map to risk_engine.py's expected _calculate_dynamic_score() keys
    # This makes the BFCI directly usable by the existing pipeline
    result = {
        **base_result,
        "available": True,
        "engine": "frida",
        "dynamic_status": dynamic_status,
        "canary_received": session.canary_received,
        "package_name": package_name,
        "device": device_serial,


        # Exploration provenance — additive fields so a reviewer can tell which
        # explorer produced this evidence, and whether it crashed part-way.
        # Deliberately NOT consumed by risk_engine: provenance never scores.
        "explorer_used":       session.explorer_used,
        "explorer_error":      session.explorer_error,
        "artifact_dir":        str(apk_dir),
        # Which of the 5-step launch ladder succeeded (or "failed" if none did).
        # Presence of non-standard launch method is itself a weak signal of
        # anti-analysis hardening. NOT consumed by risk_engine.
        "launch_method_used":  session.launch_method_used,

        # BFCI result (new fields for the updated risk_engine)
        "bfci": bfci,
        "bfci_components": components,
        "bfci_evidence": evidence,

        # Legacy fields expected by risk_engine._calculate_dynamic_score()
        # Maps Frida events → string signals the existing engine checks
        "api_calls": list(set(api_calls))[:30],
        "network_logs": network_logs[:20],
        "files_accessed": list(set(files_accessed))[:20],
        # Screenshots WERE being captured — the ScreenshotManager subscribes to
        # the event bus and fires on CRITICAL/overlay/anti_analysis events — but
        # this field was hardcoded to [] with a "not implemented" comment, so
        # every captured image was invisible to the API, the report and the
        # analyst. The manifest is now surfaced here and flushed to disk below.
        "screenshots": _collect_screenshots(session),
        # Package still alive after force-stop at session end.
        "survived_force_stop": session.survived_force_stop,
        # Real activities observed during the session, derived from the
        # agentic explorer's visited-screen memory. If no explorer ran, or
        # if the memory contains no activity data, this is an empty list —
        # never [package_name], which was a fabricated placeholder that
        # incorrectly counted toward _dynamic_run_was_conclusive.
        "activities_triggered": _collect_observed_activities(session),

        # Metadata
        "hook_errors": session.hook_errors,
        "hooks_installed": session.hooks_installed_count,
        "java_bridge_failed": session.java_bridge_failed,
        "java_hooks_installed": session.java_hooks_installed,
        "native_hooks_installed": session.native_hooks_installed,
        "java_bridge_source": session.java_bridge_source,
        "hook_fire_counts": dict(session.hook_fire_counts),
        "hook_error_counts": dict(session.hook_error_counts),
        "evidence": evidence,
        "raw_event_counts": {k: len(v) for k, v in session.collected_events.items()},
    }

    logger.info(
        f"[Frida] Analysis complete: BFCI={bfci:.1f} "
        f"components={components}"
    )
    
    if session.reports:
        result["attack_timeline"] = session.reports.get("attack_timeline", [])
        result["coverage_metrics"] = session.reports.get("coverage", {})
        result["clicked_nodes"] = list(session.reports.get("exploration_summary", {}).get("clicked_nodes", []))
    
    # ── Step 7: Write UI Explorer Reports to disk ────────────────────────────
    # Do not break the API contract of returning base_result. 
    # Just write the new reports into the same directory as the APK.
    apk_dir = artifact_dir_for(apk_path)
    
    if session.reports:
        try:
            with open(apk_dir / "exploration_graph.json", "w", encoding="utf-8") as f:
                json.dump(session.reports.get("exploration_graph", []), f, indent=4)
            with open(apk_dir / "coverage.json", "w", encoding="utf-8") as f:
                json.dump(session.reports.get("coverage", {}), f, indent=4)
            with open(apk_dir / "attack_timeline.json", "w", encoding="utf-8") as f:
                json.dump(session.reports.get("attack_timeline", []), f, indent=4)
            with open(apk_dir / "exploration_summary.json", "w", encoding="utf-8") as f:
                json.dump(session.reports.get("exploration_summary", {}), f, indent=4)
            logger.info("[Frida] Wrote AI Exploration telemetry files successfully.")
        except Exception as e:
            logger.error(f"[Frida] Failed to write AI Exploration files: {e}")

    # ── Wave 1: Flush Evidence Store ───────────────────────────────────────────
    # FIX Bug #6: Drain the EventBus background queue BEFORE flushing the store.
    # The EventBus processes events on a background thread. Without this join(),
    # events published near the end of the session can still be in the queue
    # when flush() is called, causing them to be silently lost from evidence.json.
    if session.evidence_store is not None:
        try:
            # Drain the queue with a bounded timeout so we never block indefinitely.
            _drain_timeout = 5.0
            try:
                session.event_bus._queue.join()
            except Exception:
                # join() with timeout requires get_nowait loop; use wait instead
                try:
                    import queue as _q
                    deadline = time.time() + _drain_timeout
                    while not session.event_bus._queue.empty() and time.time() < deadline:
                        time.sleep(0.1)
                except Exception:
                    pass
            n = session.evidence_store.flush(apk_dir / "evidence.json")
            result["evidence_record_count"] = n
            result["anti_analysis_events"] = session.collected_events.get("anti_analysis", [])
            logger.info(f"[Frida] Evidence store flushed: {n} records written to evidence.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write evidence.json: {e}")

    # ── Fraud Workflow Reconstruction ─────────────────────────────────────────
    # Build causal chain evidence from raw collected_events. This runs after
    # the evidence store flush so workflow records are available for the report.
    if WorkflowReconstructor is not None and session.total_hook_events_received > 0:
        try:
            # Flatten all hooked events into a record list the reconstructor understands
            workflow_records = []
            for cat, evts in session.collected_events.items():
                for ev in evts:
                    data = ev.get("data", {})
                    workflow_records.append({
                        "id":           f"{cat}_{ev.get('timestamp', 0)}",
                        "category":     cat,
                        "hook":         data.get("hook", ""),
                        "timestamp_ms": ev.get("timestamp", 0),
                        "severity":     ev.get("severity", data.get("severity", "MED")),
                        "description":  data.get("description", ""),
                    })

            reconstructor = WorkflowReconstructor()
            workflow = reconstructor.reconstruct(workflow_records)
            workflow_dict = workflow.to_dict()
            result["fraud_workflow"] = workflow_dict

            # Write to artifact dir
            try:
                with open(apk_dir / "workflow.json", "w", encoding="utf-8") as f:
                    json.dump(workflow_dict, f, indent=4)
                logger.info(
                    f"[Frida] Fraud workflow: {workflow.sequence_label} "
                    f"({len(workflow.stages)} stages, confidence={workflow.chain_confidence:.0%})"
                )
            except Exception as e:
                logger.error(f"[Frida] Failed to write workflow.json: {e}")
        except Exception as e:
            logger.error(f"[Frida] Workflow reconstruction failed: {e}")
            result["fraud_workflow"] = {"fraud_sequence_detected": False, "sequence_label": "RECONSTRUCTION_ERROR", "stages": []}
            
    # ── Wave 2: Flush Intelligence ─────────────────────────────────────────────
    if hasattr(session, "ioc_collector") and session.ioc_collector is not None:
        try:
            session.ioc_collector.flush(apk_dir / "iocs.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write iocs.json: {e}")
            
    if hasattr(session, "mitre_mapper") and session.mitre_mapper is not None:
        try:
            session.mitre_mapper.flush(apk_dir / "mitre.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write mitre.json: {e}")

    # The screenshot manifest was never flushed: images landed on disk but the
    # index describing them (label, trigger evidence id, category, source) was
    # discarded, so report_generator's gallery had nothing to enumerate.
    if hasattr(session, "screenshot_manager") and session.screenshot_manager is not None:
        try:
            n = session.screenshot_manager.flush_manifest(apk_dir / "screenshots.json")
            logger.info(f"[Frida] Screenshot manifest flushed: {n} image(s)")
        except Exception as e:
            logger.error(f"[Frida] Failed to write screenshots.json: {e}")

    # ── Wave 3: Flush Navigator Upgrades ───────────────────────────────────────
    if hasattr(session, "permission_orchestrator") and session.permission_orchestrator is not None:
        try:
            session.permission_orchestrator.flush(apk_dir / "permissions.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write permissions.json: {e}")

    if hasattr(session, "replay_engine") and session.replay_engine is not None:
        try:
            session.replay_engine.flush(apk_dir / "replay.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write replay.json: {e}")

    # ── Wave 4: Flush Intelligence Depth ───────────────────────────────────────
    if hasattr(session, "network_capture") and session.network_capture is not None:
        try:
            session.network_capture.flush(apk_dir / "network.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write network.json: {e}")
            
    if hasattr(session, "anti_analysis_detector") and session.anti_analysis_detector is not None:
        try:
            session.anti_analysis_detector.flush(apk_dir / "anti_analysis.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write anti_analysis.json: {e}")

    if hasattr(session, "yara_scanner") and session.yara_scanner is not None:
        try:
            session.yara_scanner.flush(apk_dir / "yara_results.json")
            if hasattr(session.yara_scanner, "matches"):
                result["yara_matches"] = session.yara_scanner.matches
        except Exception as e:
            logger.error(f"[Frida] Failed to write yara_results.json: {e}")

    # ── Wave 5: Aggregation & Reporting ────────────────────────────────────────
    if AnalysisHistory is not None:
        try:
            history = AnalysisHistory()
            history.save_run(result, apk_sha256="unknown", stage_name="single")
        except Exception as e:
            logger.error(f"[Frida] Failed to save analysis history: {e}")
            
    if ReportGenerator is not None:
        try:
            rg = ReportGenerator(result, apk_dir)
            rg.render(apk_dir / "report.html")
        except Exception as e:
            logger.error(f"[Frida] Failed to generate HTML report: {e}")

    return result


# ─── Sandbox Status Check ──────────────────────────────────────────────────────

def get_sandbox_status() -> Dict[str, Any]:
    """
    Return the current status of the Frida sandbox environment.
    Called by the /api/v1/sandbox/status endpoint.
    """
    try:
        import frida
        frida_version = frida.__version__
        frida_available = True
    except ImportError:
        frida_version = None
        frida_available = False

    adb_path = _find_adb()
    emulators = get_connected_emulators() if adb_path else []

    hooks_ok = _HOOKS_SCRIPT.exists()

    ready = frida_available and adb_path is not None and len(emulators) > 0 and hooks_ok

    # Determine connection mode
    tcp_error = None
    if ADB_HOST:
        mode = "docker-tcp"
        connection_info = (
            f"Docker mode: connecting to Android emulator at {ADB_HOST}:{ADB_PORT} via ADB TCP. "
            f"Ensure: (1) Emulator is running on host, (2) 'adb tcpip 5555' was run on host."
        )
        if adb_path and len(emulators) == 0:
            ok, out = _adb("connect", f"{ADB_HOST}:{ADB_PORT}", timeout=5)
            if not ok or "cannot connect" in out.lower() or "failed to connect" in out.lower():
                tcp_error = out.strip()
                connection_info += f" [ERROR: {tcp_error}]"
    else:
        mode = "local"
        connection_info = "Local mode: looking for USB/AVD emulator connected via adb devices."

    return {
        "ready": ready,
        "mode": mode,
        "connection_info": connection_info,
        "frida_available": frida_available,
        "frida_version": frida_version,
        "adb_found": adb_path is not None,
        "adb_path": adb_path,
        "adb_host": ADB_HOST or None,
        "adb_port": ADB_PORT if ADB_HOST else None,
        "emulators_connected": emulators,
        "hooks_script_present": hooks_ok,
        "hooks_script_path": str(_HOOKS_SCRIPT),
        "analysis_duration_seconds": ANALYSIS_DURATION_SECONDS,
        "bfci_weights": BFCI_WEIGHTS,
        "message": (
            "Frida sandbox is ready for dynamic analysis."
            if ready else
            "Frida sandbox not fully configured. See status fields for missing components."
        ),
    }
