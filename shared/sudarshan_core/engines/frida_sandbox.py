# backend/app/engines/frida_sandbox.py
"""
SUDARSHAN - Frida Dynamic Analysis Sandbox Controller
======================================================
Drives an Android sandbox (via SandboxProvider) to perform runtime
behavioral analysis of a suspicious APK using Frida hooks.

The emulator backend is abstracted: Genymotion Desktop is the default
provider; Android Studio AVD remains optional via SANDBOX_PROVIDER.
This module talks only to SandboxProvider for device/ADB/root/Frida
lifecycle - analysis logic (install, launch, hooks, explorer) is unchanged.

Prerequisites:
  1. Sandbox running (Genymotion Desktop by default, or Android Studio AVD).
  2. frida-server deployed on the device (see README_FRIDA.md / HOW_TO_RUN.md).
  3. ADB available in PATH (or provider-specific tools path).
  4. pip install frida frida-tools  (already done)

Pipeline:
  APK → SandboxProvider.connect → ADB install → Launch → Frida attach →
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
import dataclasses
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

from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus
from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2, BFCI_WEIGHTS
from sudarshan_core.engines.dae_pipeline import DAEPipelineTracker, DAEStage
from sudarshan_core.engines.apk_repair import compute_sha256

logger = logging.getLogger(__name__)


def log_pipeline_lifecycle(stage: int, label: str, detail: str = "") -> None:
    """Observable lifecycle marker for dynamic pipeline debugging (stages 1–12)."""
    suffix = f" — {detail}" if detail else ""
    logger.info("[Pipeline %02d] %s%s", stage, label, suffix)

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

from enum import Enum

class DynamicAnalysisStatus(str, Enum):
    FRIDA_ATTACH_FAILED = "FRIDA_ATTACH_FAILED"
    PID_NOT_FOUND = "PID_NOT_FOUND"
    INSTRUMENTATION_FAILED = "INSTRUMENTATION_FAILED"
    RUNTIME_COMPLETED_NO_EVENTS = "RUNTIME_COMPLETED_NO_EVENTS"
    INCONCLUSIVE = "INCONCLUSIVE"
    EVENTS_CAPTURED = "EVENTS_CAPTURED"
    NO_UI_RENDERED = "NO_UI_RENDERED"

# Path to the Frida JS hooks script (banking_trojan.js)
_HOOKS_DIR = Path(__file__).parent / "frida_hooks"
_HOOKS_SOURCE = _HOOKS_DIR / "banking_trojan.js"
_HOOKS_BUNDLE = _HOOKS_DIR / "banking_trojan.bundle.js"

# Prefer the COMPILED BUNDLE.
#
# The previous line here was `_HOOKS_SCRIPT = _HOOKS_SOURCE`, justified as
# "Frida 17+ uses the built-in Java global directly - CommonJS bundle is
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
# nothing - which is why every BFCI component reads 0.0 on every sample.
#
# Build the bundle with:   cd frida_hooks && npm install && npm run build
_MIN_BUNDLE_BYTES = 50_000   # a real bundle is ~540 KB; the old stub was 168 B


def _select_hooks_script() -> Path:
    """
    Return the compiled bundle. There is no usable fallback.

    banking_trojan.js is an ES module - it `import`s frida-java-bridge, which is
    the only way the bundler will keep the dependency (a dynamic require inside
    a try/catch got tree-shaken out, producing a bundle that loaded but had no
    Java bridge at all). So the raw source is NOT a valid classic script:
    handing it to create_script raises a SyntaxError.

    Falling back to it would therefore turn "hooks are missing" into "the whole
    session dies with a confusing parse error". Returning the bundle path even
    when absent produces a clear "hooks script not found" from run(), which is
    the honest failure.
    """
    try:
        if _HOOKS_BUNDLE.exists() and _HOOKS_BUNDLE.stat().st_size >= _MIN_BUNDLE_BYTES:
            return _HOOKS_BUNDLE
    except OSError:
        pass
    logger.error(
        "[Frida] Compiled hook bundle missing or stub-sized at %s. Dynamic "
        "analysis CANNOT run without it - the raw source is an ES module and is "
        "not loadable as a Frida script. Build it with:  cd %s && npm install "
        "&& npm run build",
        _HOOKS_BUNDLE, _HOOKS_DIR,
    )
    return _HOOKS_BUNDLE


_HOOKS_SCRIPT = _select_hooks_script()


# UI exploration is goal-driven only.
#
# The random input fuzzer, and the hybrid mode that ran it alongside the agent,
# have both been REMOVED. Reasons, in order of weight:
#
#   1. It corrupted evidence - random taps produced UI events indistinguishable
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
        "[Frida] ui_explorer module not found - AgenticExplorer has no rollback target."
    )

# Default analysis duration in seconds.
# 30 s was too tight for droppers: the second stage lands after the first-run
# delay, so the capture window closed before any weighted behaviour occurred and
# BFCI read 0.0 for samples that are demonstrably active. Overridable per run.
ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "90"))

# ── Session lifecycle pacing ──────────────────────────────────────────────────
# The session is OPEN -> ANALYSE -> CLOSE. Nothing may touch the UI until the
# app has finished starting: a cold Activity start on an emulator is routinely
# 2-4 s, and driving input into a half-started process is what crashed the app
# under analysis. Raise these on a slow or contended emulator.
APP_OPEN_SETTLE_SECONDS: float = float(os.getenv("SUDARSHAN_APP_OPEN_SETTLE", "8.0"))
APP_SETTLE_POLL_SECONDS: float = float(os.getenv("SUDARSHAN_APP_SETTLE_POLL", "0.5"))

# ── Launch stability constants ─────────────────────────────────────────────────
# Total time budget given to each launch step to produce a stable process.
# A cold emulator start can take 4-8 s; 12 s gives comfortable headroom.
LAUNCH_STABLE_SECONDS: float = float(os.getenv("SUDARSHAN_LAUNCH_STABLE", "12.0"))
# PID must be continuously present for this long before we declare it stable.
# Five seconds is enough to survive transient splash-screen sub-processes while
# still detecting a crasher that dies in < 1 s.
LAUNCH_PID_STABLE_MIN_SECONDS: float = float(os.getenv("SUDARSHAN_PID_STABLE_MIN", "5.0"))
# After a stable PID appears, how long to wait for the package to actually own a
# window. A stable PID alone is not a launch: a Teabot run held a PID for the
# full session while first_activity/first_window stayed null, so no UI-driven
# hook ever fired and the remaining launch strategies were never tried.
LAUNCH_UI_RENDER_SECONDS: float = float(os.getenv("SUDARSHAN_LAUNCH_UI_RENDER", "6.0"))
# Polling interval for the PID stability loop.
LAUNCH_PID_POLL_SECONDS: float = 0.25

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

# ── Docker / TCP ADB support (via SandboxProvider config) ──────────────────────
# When running in Docker, ADB_HOST is the Genymotion VM endpoint visible from
# the container, obtained from `adb devices -l`, not the Docker host alias.
# SANDBOX_PROVIDER selects Genymotion (default) or android_studio.
# DEVICE_SERIAL pins a device when multiple are online.
def _sandbox_env():
    from sudarshan_core.sandbox import load_sandbox_config
    return load_sandbox_config()


# Module-level mirrors kept for backwards-compatible imports / status APIs.
# Re-read on each call site that needs freshness via _sandbox_env().
ADB_HOST = os.getenv("ADB_HOST", "")   # e.g. Genymotion VM IP or host.docker.internal for AVD

# The only guest port frida's USB/ADB transport will talk to. Running
# frida-server anywhere else forces that transport into jailed mode, where
# attach() cannot work - see the transport selection in start_session().
# Re-exported from sandbox.config so there is exactly one definition; the name
# stays here for backwards-compatible imports.
from sudarshan_core.sandbox.config import (  # noqa: E402
    FRIDA_USB_TRANSPORT_PORT,
    frida_server_port,
)
ADB_PORT = os.getenv("ADB_PORT", "5555")
DEVICE_SERIAL = os.getenv("ANDROID_DEVICE_SERIAL") or os.getenv("DEVICE_SERIAL", "")
SANDBOX_PROVIDER_NAME = (
    os.getenv("ANDROID_SANDBOX_PROVIDER")
    or os.getenv("SANDBOX_PROVIDER")
    or "auto"
)

# BFCI_WEIGHTS is now imported from bfci_scorer - kept as a re-export for
# callers that import it directly from this module (backwards compatibility).
# Do not redefine it here.


# ─── Crash Report & Launch Timeline ───────────────────────────────────────────

@dataclasses.dataclass
class CrashReport:
    """
    Structured crash evidence collected when the target process dies before
    becoming stable. Fields map 1-to-1 to Requirement 7.

    Never fabricated: every string field is either a real logcat line, a
    tombstone fragment, or an explicit None when the datum was not found.
    """
    # What crashed
    exception_type: Optional[str] = None
    exception_message: Optional[str] = None
    java_stacktrace: Optional[str] = None
    native_stacktrace: Optional[str] = None
    # Timing
    process_lifetime_ms: Optional[float] = None
    launch_duration_ms: Optional[float] = None
    # Identity
    launcher_activity: Optional[str] = None
    package_name: Optional[str] = None
    # APK provenance
    repair_status: Optional[str] = None    # "original" | "repaired" | "unknown"
    resign_status: Optional[str] = None    # "original_signature" | "debug_resigned"
    apk_checksum: Optional[str] = None
    # Environment
    emulator_serial: Optional[str] = None
    android_version: Optional[str] = None
    abi: Optional[str] = None
    page_size: Optional[str] = None
    # Diagnosis
    selinux_denials: List[str] = dataclasses.field(default_factory=list)
    logcat_errors: List[str] = dataclasses.field(default_factory=list)
    tombstone_path: Optional[str] = None
    tombstone_excerpt: Optional[str] = None
    recommendation: Optional[str] = None
    # Root cause flags (auto-filled by _assess_crash_cause)
    is_apk_repair_issue: bool = False
    is_resign_issue: bool = False
    is_emulator_compat_issue: bool = False
    is_launch_logic_issue: bool = False
    is_manifest_issue: bool = False
    is_instrumentation_issue: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# A mapping from milestone label → wall-clock timestamp (time.monotonic()).
# None means the milestone was not reached.
LaunchTimeline = Dict[str, Optional[float]]


def _make_launch_timeline() -> LaunchTimeline:
    """Return a zeroed-out timeline; caller fills in values as events occur."""
    return {
        "apk_install":     None,
        "launch_intent":   None,
        "first_pid":       None,
        "first_activity":  None,
        "first_window":    None,
        "first_ui_dump":   None,
        "frida_attach":    None,
        "canary_received": None,
        "explorer_start":  None,
        "first_hook_event": None,
    }


def _timeline_to_seconds(tl: LaunchTimeline) -> Dict[str, Optional[float]]:
    """
    Convert monotonic timestamps to seconds-since-apk-install offsets so the
    report is human-readable. Timestamps before apk_install (shouldn't happen)
    are kept as absolute monotonic values.
    """
    base = tl.get("apk_install")
    out: Dict[str, Optional[float]] = {}
    for k, v in tl.items():
        if v is None:
            out[k] = None
        elif base is not None:
            out[k] = round(v - base, 3)
        else:
            out[k] = round(v, 3)
    return out

# ─── ADB Helpers (delegated to SandboxProvider) ───────────────────────────────

def _get_provider():
    """Return the configured SandboxProvider (cached)."""
    from sudarshan_core.sandbox import get_sandbox_provider
    return get_sandbox_provider()


def _find_adb() -> Optional[str]:
    """Find the adb executable via the active SandboxProvider."""
    return _get_provider().find_adb()


def _adb(*args: str, timeout: int = 30) -> Tuple[bool, str]:
    """Run an adb command. Returns (success, output)."""
    return _get_provider().adb(*args, timeout=timeout)


def _device_api_level(device: str) -> int:
    ok, out = _adb("-s", device, "shell", "getprop", "ro.build.version.sdk", timeout=10)
    if not ok:
        return 0
    try:
        return int(out.strip())
    except ValueError:
        return 0


def _supports_low_sdk_bypass(device: str) -> bool:
    """``--bypass-low-target-sdk-block`` exists only on Android 14+ (API 34)."""
    return _device_api_level(device) >= 34


# Genymotion / older API levels reject adb incremental installs; always disable.
_ADB_INSTALL_FLAGS = ("install", "--no-incremental", "-r", "-t", "-g")

_CERT_FAIL_MARKERS = (
    "INSTALL_PARSE_FAILED_NO_CERTIFICATES",
    "NO_CERTIFICATES",
    "Failed collecting certificates",
    "APK content size did not verify",
)

_MANIFEST_REPAIR_MARKERS = (
    "Corrupt XML binary file",
    "INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION",
    "INSTALL_PARSE_FAILED_BAD_MANIFEST",
)


def get_connected_emulators() -> List[str]:
    """
    Return list of connected sandbox device serials.

    Delegates to SandboxProvider.list_devices() which:
      - auto-connects via ADB_HOST:ADB_PORT when AUTO_CONNECT=true
      - parses `adb devices` for state=device
    """
    devices = _get_provider().list_devices()
    return [d.serial for d in devices]


def _adb_install_apk(apk_path: str, device: str) -> Tuple[bool, str, Dict[str, Any]]:
    """Install an APK onto the target device with multi-stage fallback & forensic provenance.

    Stage 1: Attempt installation of original uploaded APK.
    Stage 2: If low SDK block is encountered, retry with --bypass-low-target-sdk-block.
    Stage 3: If INSTALL_PARSE_FAILED / Corrupt AXML is caught, invoke conditional derivative repair,
             re-sign, install derivative, and record APK Provenance Metadata.
    """
    from sudarshan_core.engines.apk_repair import (
        compute_sha256,
        repair_obfuscated_apk,
        resign_apk_preserving_payload,
    )

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
        ok, out = _adb("-s", device, *_ADB_INSTALL_FLAGS, apk_path, timeout=120)
        if ok:
            logger.info(f"[Frida] Original APK installed successfully: {os.path.basename(apk_path)}")
            return True, out, default_provenance

        # ── Stage 2: Bypass deprecated SDK version block (Android 14+ only) ─
        if (
            "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out
            and _supports_low_sdk_bypass(device)
        ):
            logger.info("[Frida] Retrying install with --bypass-low-target-sdk-block")
            ok2, out2 = _adb(
                "-s", device, "install", "--no-incremental", "-r", "-t", "-g",
                "--bypass-low-target-sdk-block",
                apk_path, timeout=120
            )
            if ok2:
                logger.info(f"[Frida] Original APK installed with SDK bypass: {os.path.basename(apk_path)}")
                return True, out2, default_provenance
            out = out2

        last_out = out
        if any(m in out for m in _MANIFEST_REPAIR_MARKERS):
            break
        if any(m in out for m in _CERT_FAIL_MARKERS):
            break
        time.sleep(1)

    # ── Stage 2b: Re-sign when signature block is invalid (payload intact) ───
    if any(m in last_out for m in _CERT_FAIL_MARKERS):
        logger.info("[Frida] Invalid APK signatures - re-signing original payload for sandbox install")
        res_ok, res_path, res_prov = resign_apk_preserving_payload(apk_path)
        if res_ok and os.path.exists(res_path):
            pkg_to_uninstall = None
            try:
                from androguard.misc import AnalyzeAPK as _AAA
                _a_r, _, _ = _AAA(res_path)
                pkg_to_uninstall = _a_r.get_package()
            except Exception:
                pass
            if pkg_to_uninstall:
                _adb("-s", device, "uninstall", pkg_to_uninstall, timeout=30)
            ok_res, out_res = _adb("-s", device, *_ADB_INSTALL_FLAGS, res_path, timeout=120)
            if ok_res:
                logger.info("[Frida] Resigned APK installed successfully")
                return True, out_res, res_prov
            last_out = out_res
            logger.warning("[Frida] Resigned APK install failed: %s", out_res.strip()[:500])

    # ── Stage 3: Conditional Derivative Repair (ZIP/AXML/Manifest corruption) ──
    # Teabot and similar samples deliberately malform their manifest to evade
    # static scanners (INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION).  We detect
    # this, repair the derivative copy, re-sign, and retry.  The repair step
    # is logged prominently in both the console and the provenance record - # this is a disclosed methodological step, not evidence tampering.
    _PARSE_FAIL_MARKERS = _MANIFEST_REPAIR_MARKERS
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

            ok3, out3 = _adb(
                "-s", device, *_ADB_INSTALL_FLAGS,
                rep_path_or_err, timeout=120
            )
            if (
                not ok3
                and _supports_low_sdk_bypass(device)
                and "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out3
            ):
                ok3, out3 = _adb(
                    "-s", device, "install", "--no-incremental", "-r", "-t", "-g",
                    "--bypass-low-target-sdk-block",
                    rep_path_or_err, timeout=120
                )
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




def _find_aapt_executable(tool: str) -> Optional[str]:
    """Locate ``aapt`` / ``aapt2`` on PATH or under the Android SDK build-tools."""
    import shutil

    aapt = shutil.which(tool)
    if aapt:
        return aapt
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    candidates: List[str] = []

    # Every SDK root worth searching: the configured one first, then the
    # per-platform default install locations. The defaults matter because
    # Android Studio does not export ANDROID_HOME on a fresh install, so a
    # machine with a perfectly good SDK looks toolless without them.
    roots: List[str] = []
    if sdk_root:
        roots.append(sdk_root)
    home = os.path.expanduser("~")
    roots.extend([
        os.path.join(home, "AppData", "Local", "Android", "Sdk"),   # Windows
        os.path.join(home, "Library", "Android", "sdk"),            # macOS
        os.path.join(home, "Android", "Sdk"),                       # Linux
    ])

    # Enumerate whatever versions are actually installed, newest first, rather
    # than naming specific ones. Pinned version numbers rot: the list here used
    # to be 36.1.0/36.0.0/34.0.0, so a machine with only 35.x installed fell
    # through to "tool not found" despite having the tool.
    for root in roots:
        bt = os.path.join(root, "build-tools")
        if not os.path.isdir(bt):
            continue
        try:
            versions = sorted(os.listdir(bt), reverse=True)
        except OSError:
            continue
        for ver in versions:
            candidates.append(os.path.join(bt, ver, f"{tool}.exe"))
            candidates.append(os.path.join(bt, ver, tool))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def _extract_apk_info(apk_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract package name and main activity from APK.

    Strategy (in order):
      1. aapt2 / aapt - fastest, requires Android SDK build-tools in PATH
      2. androguard - pure-Python fallback, always available (in requirements.txt)
    """
    import shutil
    package_name, main_activity = None, None

    # ── Strategy 1: aapt / aapt2 ──────────────────────────────────────────────
    for tool in ["aapt2", "aapt"]:
        aapt = _find_aapt_executable(tool)
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
        logger.warning("[Frida] androguard not installed - install it: pip install androguard")
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


def _format_activity_component(package_name: str, activity: str) -> str:
    """Build an ``am start -n`` component string."""
    act = (activity or "").strip()
    if not act:
        return ""
    if act.startswith("."):
        return f"{package_name}/{act}"
    if "/" in act:
        return act
    if act.startswith(package_name):
        return f"{package_name}/{act}"
    return f"{package_name}/{act}"


def _read_dumpsys_activities(device: str) -> str:
    ok, out = _adb("-s", device, "shell", "dumpsys", "activity", "activities", timeout=20)
    return out or ""


def _get_foreground_component(device: str) -> str:
    """Return '<package>/<activity>' for the resumed window, or 'unknown'."""
    try:
        from sudarshan_core.engines.agentic.perception import parse_foreground_activity

        comp = parse_foreground_activity(_read_dumpsys_activities(device))
        if comp != "unknown":
            return comp
    except Exception as exc:
        logger.debug("[Frida] parse_foreground_activity failed: %s", exc)

    ok, out = _adb(
        "-s",
        device,
        "shell",
        "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
        timeout=15,
    )
    if ok and out:
        match = re.search(r"([\w.]+/[\w.$]+)", out)
        if match:
            return match.group(1)
    return "unknown"


def _foreground_package(device: str) -> str:
    comp = _get_foreground_component(device)
    if "/" in comp:
        return comp.split("/", 1)[0]
    return ""


def _launch_failure_is_process_crash(reason: str) -> bool:
    """True only when a PID existed and died - not when launch intent never started."""
    r = (reason or "").lower()
    if "never appeared" in r or "launch failed" in r:
        return False
    if "exited after" in r or "appeared but only survived" in r:
        return True
    if "unstable" in r and "pid" in r:
        return True
    return False


def _dismiss_permission_review_screen(device: str) -> bool:
    """
    Android 11+ shows ReviewPermissionsActivity for legacy targetSdk apps even
    when permissions were pre-granted via ``pm grant``. The target app process
  does not appear in ``pidof`` until the user taps CONTINUE.
    """
    ok, out = _adb("-s", device, "shell", "dumpsys", "activity", "activities", timeout=20)
    if not ok or "ReviewPermissionsActivity" not in (out or ""):
        return False

    ok_dump, _ = _adb(
        "-s", device, "shell",
        "uiautomator dump /data/local/tmp/sudarshan_perm_ui.xml",
        timeout=25,
    )
    if ok_dump:
        ok_cat, xml = _adb(
            "-s", device, "shell",
            "cat /data/local/tmp/sudarshan_perm_ui.xml",
            timeout=15,
        )
        if ok_cat and xml:
            m = re.search(
                r'resource-id="com\.android\.permissioncontroller:id/continue_button"'
                r'[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                xml,
            )
            if m:
                x1, y1, x2, y2 = (int(m.group(i)) for i in range(1, 5))
                tx, ty = (x1 + x2) // 2, (y1 + y2) // 2
                _adb("-s", device, "shell", f"input tap {tx} {ty}", timeout=10)
                logger.info(
                    "[Frida] Dismissed ReviewPermissionsActivity (continue at %d,%d)",
                    tx, ty,
                )
                time.sleep(0.75)
                return True

    logger.info("[Frida] ReviewPermissionsActivity visible - using fallback CONTINUE tap")
    _adb("-s", device, "shell", "input tap 507 1127", timeout=10)
    time.sleep(0.75)
    return True


def _grant_declared_runtime_permissions(device: str, apk_path: str, package_name: str) -> int:
    """
  Pre-grant install-time runtime permissions via ``pm grant`` so cold-start
  does not block on ReviewPermissionsActivity (which leaves pidof empty).
    """
    import shlex as _shlex
    import shutil

    perms: List[str] = []
    for tool in ("aapt2", "aapt"):
        aapt = _find_aapt_executable(tool)
        if not aapt:
            continue
        try:
            result = subprocess.run(
                [aapt, "dump", "permissions", apk_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            for line in (result.stdout or "").splitlines():
                line = line.strip()
                if line.startswith("uses-permission:") and "name=" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        perms.append(parts[1])
            if perms:
                break
        except Exception:
            continue

    granted = 0
    safe_pkg = _shlex.quote(package_name)
    for perm in perms:
        if not perm.startswith("android.permission."):
            continue
        ok, out = _adb(
            "-s", device, "shell", f"pm grant {safe_pkg} {perm}", timeout=10,
        )
        if ok or "granted" in (out or "").lower():
            granted += 1
        else:
            logger.debug("[Frida] pm grant skipped for %s: %s", perm, out)
    if granted:
        logger.info(
            "[Frida] Pre-granted %d declared permission(s) for %s before launch",
            granted, package_name,
        )
    return granted


def _launch_main_launcher_intent(device: str, package_name: str) -> bool:
    """
    Strategy 2: launch via resolved LAUNCHER component.

    ``am start -p`` with implicit MAIN/LAUNCHER fails on API 30+ with
    'unable to resolve Intent' (verified on InsecureBankv2 / Genymotion 11).
    """
    component = _resolve_launcher_activity(device, package_name)
    if not component:
        return False
    import shlex as _shlex
    ok, out = _adb(
        "-s", device, "shell",
        f"am start -W -n {_shlex.quote(component)}",
        timeout=20,
    )
    if not ok and out:
        logger.warning("[Frida] main launcher start: %s", out[:200])
    return ok


def _launch_via_monkey(device: str, package_name: str) -> bool:
    """Strategy 4: Monkey launcher (single event, category LAUNCHER)."""
    import shlex as _shlex
    safe_pkg = _shlex.quote(package_name)
    ok, _ = _adb(
        "-s", device, "shell",
        f"monkey -p {safe_pkg} -c android.intent.category.LAUNCHER 1",
        timeout=25,
    )
    return ok


def _verify_package_installed(device: str, package_name: str, retries: int = 5) -> bool:
    """Confirm APK path is registered with PackageManager."""
    import shlex as _shlex
    safe_pkg = _shlex.quote(package_name)
    for attempt in range(retries):
        ok, out = _adb("-s", device, "shell", f"pm path {safe_pkg}", timeout=15)
        if ok and package_name in (out or "") and "package:" in (out or ""):
            return True
        time.sleep(0.5 * (attempt + 1))
    return False


def _force_stop_package(device: str, package_name: str) -> None:
    import shlex as _shlex
    safe_pkg = _shlex.quote(package_name)
    _adb("-s", device, "shell", f"am force-stop {safe_pkg}", timeout=15)
    time.sleep(0.5)


# ─── Launch State Machine Helpers ─────────────────────────────────────────────

def _poll_pid_until_stable(
    device: str,
    package_name: str,
    *,
    total_timeout: float = LAUNCH_STABLE_SECONDS,
    stable_min: float = LAUNCH_PID_STABLE_MIN_SECONDS,
    poll_interval: float = LAUNCH_PID_POLL_SECONDS,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Poll ``pidof <package>`` every *poll_interval* seconds until the process
    has been continuously present for *stable_min* seconds, or until
    *total_timeout* is exhausted.

    Returns:
        (stable, pid, reason)
        stable  – True when the PID was present for *stable_min* seconds.
        pid     – The last seen PID, or None if the process never appeared.
        reason  – Human-readable explanation of the outcome.

    This is the ONLY place in the codebase that decides whether a process is
    ready for Frida attachment. Never attach before this returns True.

    The function intentionally does NOT call time.sleep(3) and then assume
    success. The previous approach caused every crash to be invisible: the app
    started, sleep returned, _check_running() found a PID (the process had
    not yet crashed), and Frida attached to a dying process.
    """
    deadline = time.monotonic() + total_timeout
    stable_since: Optional[float] = None
    last_pid: Optional[int] = None
    last_review_dismiss = 0.0

    logger.info(
        "[Frida] Stability monitor: waiting up to %.0fs for %s "
        "(requires %.0fs of continuous PID presence, polling every %.0fms)",
        total_timeout, package_name, stable_min, poll_interval * 1000,
    )

    while time.monotonic() < deadline:
        ok, out = _adb("-s", device, "shell", "pidof", package_name, timeout=10)
        pid: Optional[int] = None
        if ok and out.strip():
            for token in out.split():
                if token.isdigit():
                    pid = int(token)
                    break

        now = time.monotonic()

        if pid is not None:
            last_pid = pid
            if stable_since is None:
                stable_since = now
                logger.debug(
                    "[Frida] PID %d appeared for %s at t=%.1fs",
                    pid, package_name, now,
                )
            elif (now - stable_since) >= stable_min:
                logger.info(
                    "[Frida] PID %d stable for %.1fs (>= %.0fs required) - "
                    "process confirmed alive for %s",
                    pid, now - stable_since, stable_min, package_name,
                )
                return True, pid, f"PID {pid} stable for {now - stable_since:.1f}s"
        else:
            if stable_since is not None:
                # PID was alive but disappeared - the app crashed.
                lived_for = now - stable_since
                msg = (
                    f"Process {package_name} (last PID={last_pid}) "
                    f"exited after {lived_for:.1f}s - app crashed before becoming stable"
                )
                logger.error("[Frida] %s", msg)
                return False, last_pid, msg
            # PID not yet seen - permission review UI blocks process visibility.
            if last_pid is None and (now - last_review_dismiss) >= 1.5:
                if _dismiss_permission_review_screen(device):
                    last_review_dismiss = now
                    continue

        time.sleep(poll_interval)

    # Exhausted timeout.
    if last_pid is None:
        reason = (
            f"{package_name} never appeared in the process list within "
            f"{total_timeout:.0f}s - launch failed or package name mismatch"
        )
    else:
        # PID appeared but never stable for long enough.
        lived = (time.monotonic() - (stable_since or time.monotonic()))
        reason = (
            f"{package_name} (PID={last_pid}) appeared but only survived "
            f"{lived:.1f}s (required {stable_min:.0f}s) - app is unstable"
        )
    logger.error("[Frida] Stability timeout: %s", reason)
    return False, last_pid, reason


def _poll_until_package_owns_window(
    device: str,
    package_name: str,
    *,
    total_timeout: float = LAUNCH_UI_RENDER_SECONDS,
    poll_interval: float = 0.5,
) -> bool:
    """
    Wait for *package_name* to own the foreground window.

    A stable PID proves the process exists; it does not prove the app launched.
    Android will happily keep a process alive that never inflates an Activity -
    an ANR at start, a dropper stub that finishes onCreate and returns, or a
    launcher intent that resolved to nothing. In that state every UI-driven hook
    (accessibility, overlay, credential capture) is unreachable, so the run
    yields no behaviour and the sample looks dormant.

    Returns True as soon as dumpsys reports the package in the focused window.
    """
    deadline = time.monotonic() + total_timeout
    while time.monotonic() < deadline:
        ok, out = _adb(
            "-s", device, "shell",
            "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
            timeout=10,
        )
        if ok and out and package_name in out:
            return True
        time.sleep(poll_interval)
    return False


def _collect_crash_diagnostics(
    device: str,
    package_name: str,
    artifact_dir: Path,
    *,
    provenance: Optional[Dict[str, Any]] = None,
    launcher_activity: Optional[str] = None,
    process_lifetime_ms: Optional[float] = None,
    launch_duration_ms: Optional[float] = None,
    apk_checksum: Optional[str] = None,
) -> CrashReport:
    """
    Collect all available crash evidence from the device and return a
    populated CrashReport.

    Gathers (in order):
      - Full logcat buffer filtered to error/fatal lines
      - AndroidRuntime FATAL EXCEPTION including Java stacktrace
      - Native crashes (libc, signal faults)
      - UnsatisfiedLinkError, VerifyError, ClassNotFoundException, etc.
      - PackageManager errors
      - ART verifier errors
      - SELinux denials (avc: denied)
      - Native tombstones (/data/tombstones/)
      - Device environment (Android version, ABI, page size)

    All fields default to None/[] when the datum cannot be obtained - nothing
    is fabricated.
    """
    report = CrashReport(
        package_name=package_name,
        launcher_activity=launcher_activity,
        process_lifetime_ms=process_lifetime_ms,
        launch_duration_ms=launch_duration_ms,
        apk_checksum=apk_checksum,
        emulator_serial=device,
    )

    if provenance:
        report.repair_status = "repaired" if provenance.get("is_repaired_derivative") else "original"
        report.resign_status = provenance.get("signature_used", "unknown")
        if not apk_checksum:
            report.apk_checksum = provenance.get("original_sha256")

    # ── Device environment ────────────────────────────────────────────────────
    try:
        _, ver = _adb("-s", device, "shell", "getprop ro.build.version.release", timeout=10)
        report.android_version = ver.strip() or None
    except Exception:
        pass
    try:
        _, abi = _adb("-s", device, "shell", "getprop ro.product.cpu.abi", timeout=10)
        report.abi = abi.strip() or None
    except Exception:
        pass
    try:
        _, pgsz = _adb("-s", device, "shell", "getconf PAGESIZE", timeout=10)
        report.page_size = pgsz.strip() or None
    except Exception:
        pass

    # ── Logcat ────────────────────────────────────────────────────────────────
    # Filters of interest (Requirement 3)
    _CRASH_FILTERS = (
        "AndroidRuntime", "FATAL EXCEPTION", "E/libc",
        "UnsatisfiedLinkError", "VerifyError", "ClassNotFoundException",
        "ActivityNotFoundException", "SecurityException",
        "ResourcesNotFoundException", "PackageManager", "ART",
        "avc: denied", "INSTALL_", "Fatal signal",
    )
    try:
        ok, logcat_raw = _adb(
            "-s", device, "logcat", "-d", "-v", "time",
            "-b", "crash,main,system",
            timeout=30,
        )
        if ok and logcat_raw:
            # Write full logcat to disk
            logcat_path = artifact_dir / "crash_logcat.txt"
            try:
                logcat_path.write_text(logcat_raw, encoding="utf-8", errors="replace")
                logger.info("[CrashDiag] Full logcat written: %s", logcat_path)
            except OSError as e:
                logger.warning("[CrashDiag] Could not write logcat: %s", e)

            # Extract relevant lines
            error_lines: List[str] = []
            in_java_trace = False
            java_trace_lines: List[str] = []
            for line in logcat_raw.splitlines():
                if any(f in line for f in _CRASH_FILTERS):
                    error_lines.append(line)
                # Capture Java stacktrace block
                if "FATAL EXCEPTION" in line and package_name in line:
                    in_java_trace = True
                if in_java_trace:
                    java_trace_lines.append(line)
                    # Stop at the next non-indented log line after we've started
                    if len(java_trace_lines) > 1 and not line.startswith(" ") and not line.startswith("\t") and "at " not in line and "Caused by:" not in line:
                        in_java_trace = False

            report.logcat_errors = error_lines[:100]  # cap at 100 lines

            # Parse exception type & message from FATAL EXCEPTION block
            for line in error_lines:
                if "FATAL EXCEPTION" in line:
                    # Extract the exception on the next "E/AndroidRuntime: " line
                    pass
                # Pattern: E/AndroidRuntime:  java.lang.SomeException: message
                m = re.search(
                    r"AndroidRuntime[^\s]*\s+([A-Za-z][\w.]+Exception[^\n]*)",
                    line,
                )
                if m and not report.exception_type:
                    exc_str = m.group(1).strip()
                    if ":" in exc_str:
                        parts = exc_str.split(":", 1)
                        report.exception_type = parts[0].strip()
                        report.exception_message = parts[1].strip()
                    else:
                        report.exception_type = exc_str

            if java_trace_lines:
                report.java_stacktrace = "\n".join(java_trace_lines[:80])

            # SELinux denials
            report.selinux_denials = [
                ln for ln in error_lines if "avc: denied" in ln
            ][:20]

            # Native crash signal
            for line in error_lines:
                if "Fatal signal" in line or "E/libc" in line:
                    if not report.native_stacktrace:
                        report.native_stacktrace = line.strip()

    except Exception as exc:
        logger.warning("[CrashDiag] logcat collection failed: %s", exc)

    # ── Tombstones ────────────────────────────────────────────────────────────
    try:
        ok, ts_list = _adb(
            "-s", device, "shell",
            "ls -t /data/tombstones/ 2>/dev/null | head -1",
            timeout=10,
        )
        if ok and ts_list.strip():
            latest = ts_list.strip().split()[0]
            ts_path = f"/data/tombstones/{latest}"
            report.tombstone_path = ts_path
            ok2, ts_content = _adb(
                "-s", device, "shell", f"cat {ts_path}", timeout=15
            )
            if ok2 and ts_content:
                report.tombstone_excerpt = ts_content[:4000]
                # Also write to disk
                tb_disk = artifact_dir / f"tombstone_{latest}"
                try:
                    tb_disk.write_text(ts_content, encoding="utf-8", errors="replace")
                    logger.info("[CrashDiag] Tombstone written: %s", tb_disk)
                except OSError:
                    pass
                # Supplement native stacktrace from tombstone
                if not report.native_stacktrace:
                    for line in ts_content.splitlines():
                        if "backtrace:" in line.lower() or "#0" in line:
                            report.native_stacktrace = ts_content[:2000]
                            break
    except Exception as exc:
        logger.warning("[CrashDiag] Tombstone collection failed: %s", exc)

    # ── Auto-classify root cause ──────────────────────────────────────────────
    _assess_crash_cause(report, provenance)

    # ── Generate recommendation ───────────────────────────────────────────────
    if not report.recommendation:
        report.recommendation = _generate_crash_recommendation(report)

    # ── Write crash_report.json ───────────────────────────────────────────────
    try:
        rpt_path = artifact_dir / "crash_report.json"
        rpt_path.write_text(
            json.dumps(report.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("[CrashDiag] crash_report.json written: %s", rpt_path)
    except OSError as e:
        logger.warning("[CrashDiag] Could not write crash_report.json: %s", e)

    return report


def _assess_crash_cause(report: CrashReport, provenance: Optional[Dict[str, Any]]) -> None:
    """
    Auto-classify the crash into root-cause categories based on the logcat
    errors and provenance metadata. Mutates *report* in-place.
    """
    errors_text = " ".join(report.logcat_errors)

    # APK repair introduced it?
    if provenance and provenance.get("is_repaired_derivative"):
        if any(k in errors_text for k in ("VerifyError", "BytecodeVerifier", "VerifyClass")):
            report.is_apk_repair_issue = True
        if "ClassNotFoundException" in errors_text:
            report.is_apk_repair_issue = True

    # Re-signing introduced it?
    if provenance and provenance.get("signature_used") in ("debug", "debug_resigned"):
        if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in errors_text:
            report.is_resign_issue = True
        if "SecurityException" in errors_text and "signature" in errors_text.lower():
            report.is_resign_issue = True

    # Emulator ABI/compatibility?
    if report.native_stacktrace or report.tombstone_excerpt:
        native_text = (report.native_stacktrace or "") + (report.tombstone_excerpt or "")
        if "UnsatisfiedLinkError" in (errors_text + native_text):
            report.is_emulator_compat_issue = True
        if "Fatal signal 4" in native_text or "SIGILL" in native_text:
            # Illegal instruction = wrong ABI
            report.is_emulator_compat_issue = True

    # Manifest corruption?
    if any(k in errors_text for k in (
        "ActivityNotFoundException", "INSTALL_PARSE_FAILED",
        "Corrupt XML", "ResourcesNotFoundException",
    )):
        report.is_manifest_issue = True

    # Instrumentation artefact?
    if any(k in errors_text for k in ("avc: denied", "ptrace")):
        report.is_instrumentation_issue = True

    # Pure launch logic?
    if not any([
        report.is_apk_repair_issue, report.is_resign_issue,
        report.is_emulator_compat_issue, report.is_manifest_issue,
        report.is_instrumentation_issue,
    ]):
        if report.exception_type or report.java_stacktrace:
            # Exception present but no recognised cause → likely app code crash
            report.is_launch_logic_issue = True


def _generate_crash_recommendation(report: CrashReport) -> str:
    """Return a one-sentence actionable recommendation given a classified CrashReport."""
    if report.is_instrumentation_issue:
        return (
            "SELinux denial detected - run 'adb shell setenforce 0' on the "
            "emulator to allow Frida to ptrace the target process."
        )
    if report.is_emulator_compat_issue:
        return (
            f"Native crash or UnsatisfiedLinkError on ABI={report.abi}. "
            "Use an x86_64 emulator image for APKs targeting x86/x86_64; "
            "for arm-only samples, enable ARM translation (houdini/ndk translation layer)."
        )
    if report.is_apk_repair_issue:
        return (
            "The repaired derivative fails bytecode verification - the repair "
            "step damaged a dex file. Try running the analysis on the original "
            "APK directly (set SKIP_REPAIR=1) or report the repair failure."
        )
    if report.is_resign_issue:
        return (
            "Signature mismatch after re-signing. Uninstall any previously "
            "installed version with 'adb uninstall <pkg>' before installing "
            "the re-signed derivative."
        )
    if report.is_manifest_issue:
        return (
            "ActivityNotFoundException or manifest parse failure. The declared "
            "launcher activity does not exist in the APK - inspect the manifest "
            "with 'aapt dump badging' and verify the component name."
        )
    if report.is_launch_logic_issue and report.exception_type:
        return (
            f"{report.exception_type} in application onCreate. This is an "
            "in-app crash, not a harness issue. The app may require specific "
            "device state (SIM card, network, device model check) to initialise."
        )
    return (
        "Application crashed before becoming stable. Inspect crash_logcat.txt "
        "in the artifact directory for the full error context."
    )


def _verify_launch_readiness(
    device: str,
    package_name: str,
    stable_pid: int,
    artifact_dir: Path,
    *,
    launcher_activity: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Run six checks that confirm the app is genuinely ready for Frida attachment.

    Must only be called AFTER _poll_pid_until_stable() returns True.

    Checks (stops on first failure):
      1. Package exists in PackageManager
      2. Launcher activity resolves
      3. PID still alive (hasn't died between stability check and this gate)
      4. PID is the same one we found stable (no restart)
      5. UI hierarchy can be dumped
      6. Foreground window belongs to our package

    Returns (True, "ok") on full pass, or (False, "reason") on first failure.
    """
    import shlex as _shlex
    safe_pkg = _shlex.quote(package_name)

    # Check 1: Package exists
    ok, out = _adb("-s", device, "shell", f"pm list packages | grep -F {safe_pkg}", timeout=15)
    if not ok or package_name not in out:
        return False, f"Check 1 FAIL: package '{package_name}' not found in pm list packages"
    logger.debug("[LaunchGate] Check 1 PASS: package present in PackageManager")

    # Check 2: Launcher activity resolves
    component = _resolve_launcher_activity(device, package_name)
    if not component:
        # Not a hard failure - some samples have no LAUNCHER intent but are
        # runnable via broadcast (Cerberus-style). Log a warning, continue.
        logger.warning(
            "[LaunchGate] Check 2 WARN: no LAUNCHER activity for %s - "
            "packed/dropper sample; continuing without activity validation",
            package_name,
        )
    else:
        if launcher_activity and package_name not in component:
            return False, (
                f"Check 2 FAIL: resolved component '{component}' does not belong "
                f"to package '{package_name}'"
            )
        logger.debug("[LaunchGate] Check 2 PASS: launcher activity resolves to %s", component)

    # Check 3: PID still alive
    ok, out = _adb("-s", device, "shell", "pidof", package_name, timeout=10)
    current_pid: Optional[int] = None
    if ok and out.strip():
        for token in out.split():
            if token.isdigit():
                current_pid = int(token)
                break
    if current_pid is None:
        return False, (
            f"Check 3 FAIL: PID {stable_pid} for '{package_name}' disappeared "
            "between stability confirmation and readiness gate - app crashed"
        )
    logger.debug("[LaunchGate] Check 3 PASS: PID %d still alive", current_pid)

    # Check 4: Same PID (no silent restart)
    if current_pid != stable_pid:
        logger.warning(
            "[LaunchGate] Check 4 WARN: PID changed from %d to %d - "
            "process restarted; proceeding with new PID",
            stable_pid, current_pid,
        )
    else:
        logger.debug("[LaunchGate] Check 4 PASS: PID unchanged (%d)", current_pid)

    # Check 5: UI hierarchy can be dumped
    ok, dump_out = _adb(
        "-s", device, "shell",
        "uiautomator dump /dev/null 2>&1 && echo UI_DUMP_OK",
        timeout=20,
    )
    if not ok or "UI_DUMP_OK" not in dump_out:
        return False, (
            f"Check 5 FAIL: uiautomator dump failed - UI is not ready. "
            f"Output: {dump_out[:200]}"
        )
    logger.debug("[LaunchGate] Check 5 PASS: uiautomator dump succeeded")

    # Check 6: Foreground window belongs to our package
    ok, win_out = _adb(
        "-s", device, "shell",
        "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
        timeout=15,
    )
    if ok and win_out and package_name not in win_out:
        # Not necessarily fatal - some apps start in the background then bring
        # a window forward; log and continue rather than aborting.
        logger.warning(
            "[LaunchGate] Check 6 WARN: foreground window does not mention %s "
            "(found: %s) - app may be launching in the background",
            package_name, win_out.strip()[:120],
        )
    else:
        logger.debug("[LaunchGate] Check 6 PASS: foreground window is %s", package_name)

    return True, "ok"


def _collect_observed_activities(session: "FridaSession") -> List[str]:
    """
    Collect the real set of activity class names observed during the session.

    Source of truth (in priority order):
      1. ``session.reports["agent_memory"]["visited_screens"]`` - the
         AgenticExplorer's perception layer records the foreground activity
         name on every Observe cycle.  These are real dumpsys values,
         never synthesised.
      2. Any ``category="activity"`` events on the EventBus runtime log
         (set by the perception pipeline's ``update_from_foreground`` call).
      3. Empty list - explicitly NOT ``[session.package_name]``, which was
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

    # Source 3: empty list - no observed activities, do not fabricate
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

    Returns (bfci_score, component_scores, evidence_list) - same signature
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
            f" - falling back to the APK's own folder"
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
        case_id: str = "",
    ):
        self.device_serial = device_serial
        self.package_name = package_name
        self.main_activity = main_activity
        # Where per-sample forensic artifacts are written. Defaults to the
        # process CWD only when a caller supplies nothing, which keeps the
        # constructor usable in tests without touching the filesystem.
        self.artifact_dir: Path = Path(artifact_dir) if artifact_dir else Path(".")
        self.dae = DAEPipelineTracker(package_name=package_name)
        self.event_bus = RuntimeEventBus()
        # Keys MUST mirror the `events` object in frida_hooks/banking_trojan.js.
        # An unrecognised category is remapped to "dangerous_apis" by
        # _on_message, so a category present in the agent but missing here is
        # silently misfiled rather than dropped.
        #
        # Only the first six are scored - see bfci_scorer.BFCI_WEIGHTS. The rest
        # are collected as evidence and contribute nothing to BFCI, which is what
        # keeps ordinary application behaviour out of the fraud score.
        self.collected_events: Dict[str, List[Dict]] = {
            # ── Scored ────────────────────────────────────────────────────────
            "accessibility": [], "sms": [], "overlay": [],
            "banking": [], "network": [], "persistence": [],
            # ── Unscored: evidence only ───────────────────────────────────────
            "dangerous_apis": [], "files_accessed": [],
            "anti_analysis": [],        # sandbox evasion / anti-instrumentation
            "smoke": [],                # baseline runtime smoke-test events
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
        self.last_ui_hierarchy_xml: str = ""
        self.explorer_used: str = "none"
        self.explorer_error: Optional[str] = None
        # Which of the 5-step launch ladder succeeded for this sample.
        # None means we haven't attempted launch yet; "failed" means all 5 failed.
        self.launch_method_used: Optional[str] = None
        # Real accessibility service class extracted from the APK manifest.
        # Passed through to AgenticExplorer → ToolExecutor so the correct
        # component name is used in 'settings put secure enabled_accessibility_services'.
        self.accessibility_service_class: Optional[str] = None

        # Set when every launch strategy produced a process but none produced a
        # foreground window. Downstream this becomes dynamic_status
        # NO_UI_RENDERED so a UI-less run is never scored as observed behaviour.
        self.ui_render_failed: bool = False
        # True when the package was still alive after `am force-stop` at the end
        # of the session - a persistence signal (watchdog service, restart
        # receiver), surfaced in the result rather than swallowed.
        self.survived_force_stop: bool = False
        # True when lifecycle screenshots were taken while another package owned
        # the foreground (typically the launcher home screen).
        self.foreground_mismatch: bool = False
        # Set by stop() to cut an in-flight analysis short instead of sleeping
        # out the full window.
        self._stop_event = threading.Event()
        self._session = None
        self._script = None
        self.reports = {}

        # ── Launch timeline (Requirement 6) ───────────────────────────────────
        # Records wall-clock timestamps (time.monotonic()) for each launch
        # milestone. None means the milestone was not reached this session.
        # Converted to seconds-since-install offsets before being written to
        # launch_timeline.json so the report is human-readable.
        self.launch_timeline: LaunchTimeline = _make_launch_timeline()

        # ── Crash report (Requirement 7) ──────────────────────────────────────
        # Set to a CrashReport instance when the app crashes before becoming
        # stable. None means the app launched successfully (or we haven't tried
        # yet). This is NEVER a fabricated placeholder.
        self.crash_report: Optional[CrashReport] = None

        # PID that was confirmed stable by _poll_pid_until_stable(). Used by
        # _verify_launch_readiness() to detect silent restarts.
        self._stable_pid: Optional[int] = None

        # ── Wave 1: Evidence Store ─────────────────────────────────────────────
        if EvidenceStore is not None:
            self.evidence_store = EvidenceStore(
                event_bus=self.event_bus,
                package_name=package_name,
                analysis_stage="single",
                case_id=case_id,
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
                # app.routes.runtime_api - from sudarshan_core UP into the
                # backend - inside a bare `except: pass`. The analysis engine
                # has no such package, so on the primary (delegated) path every
                # one of these raised and was swallowed, and the hook counters
                # the dashboard reads stayed at zero while instrumentation was
                # working fine. Counted locally now, and surfaced in the result.
                self.hook_fire_counts[hook_name] = self.hook_fire_counts.get(hook_name, 0) + 1

                # Stamp first_hook_event milestone (Requirement 6)
                if self.launch_timeline.get("first_hook_event") is None:
                    self.launch_timeline["first_hook_event"] = time.monotonic()

                # Publish to Event Bus (EvidenceStore, NetworkCapture, BehaviorGraph,
                # ThreatCorrelatorListener). The agent tags hook payloads with
                # event_type=FRIDA_HOOK; subscribers expect FRIDA_EVENT / NETWORK_EVENT.
                bus_event = dict(event)
                bus_event["event_type"] = EventType.FRIDA_EVENT
                bus_event["type"] = EventType.FRIDA_EVENT
                self.event_bus.publish(bus_event)
                log_pipeline_lifecycle(
                    10,
                    "RuntimeEvent emitted",
                    f"category={category} hook={hook_name}",
                )

                if category == "network":
                    net_data = event.get("data") or {}
                    url = net_data.get("url") or net_data.get("ioc")
                    if url:
                        ts_raw = event.get("timestamp", 0) or 0
                        ts_sec = (
                            ts_raw / 1000.0
                            if ts_raw > 1e12
                            else (ts_raw if ts_raw else time.time())
                        )
                        self.event_bus.publish(
                            RuntimeEvent(
                                event_type=EventType.NETWORK_EVENT,
                                timestamp=ts_sec,
                                payload={**net_data, "url": url},
                                category="network",
                                severity=str(severity),
                            )
                        )

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
                self.dae.transition(DAEStage.VERIFY_HOOKS, "canary received")
                # Stamp canary_received timeline milestone (Requirement 6)
                if self.launch_timeline.get("canary_received") is None:
                    self.launch_timeline["canary_received"] = time.monotonic()
                tracker = get_tracker(self.package_name, self.package_name)
                tracker.hooks_loaded = True
                logger.info(f"[Frida Canary] Script load canary received: {payload.get('msg')}")


            elif msg_type == "hook_error":
                err = f"Hook failed: {payload.get('hook')} - {payload.get('error')}"
                self.hook_errors.append(err)
                logger.warning(f"[Frida] {err}")
                self.hook_error_counts[payload.get('hook', '?')] = (
                    self.hook_error_counts.get(payload.get('hook', '?'), 0) + 1
                )

            elif msg_type == "ready":
                hooks_count = payload.get("hooks_installed", 0)
                logger.info(
                    f"[Frida] {payload.get('message')} - "
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
                if payload.get("java_bridge_failed") or payload.get("java_bridge_source") or "Java bridge unavailable" in _desc or "Java.perform" in _desc or "self-test failed" in _desc:
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
            # Frida's own runtime envelope - a hook body that threw.
            err = f"Script error: {message.get('description')}"
            self.hook_errors.append(err)
            logger.error(f"[Frida] {err}")

    # ── Session lifecycle helpers ─────────────────────────────────────────────

    def _bring_target_to_foreground(self) -> bool:
        """Issue am start for the target package and return whether adb succeeded."""
        import shlex as _shlex

        launched = False
        if self.main_activity:
            component = _format_activity_component(self.package_name, self.main_activity)
            if component:
                ok, _ = _adb(
                    "-s",
                    self.device_serial,
                    "shell",
                    f"am start -W -n {_shlex.quote(component)}",
                    timeout=20,
                )
                launched = ok
        if not launched:
            launched = _launch_app(self.device_serial, self.package_name)
        if not launched:
            launched = _launch_main_launcher_intent(self.device_serial, self.package_name)
        time.sleep(1.0)
        return launched

    def _ensure_target_foreground(self, attempts: int = 4) -> bool:
        for attempt in range(attempts):
            pkg = _foreground_package(self.device_serial)
            if pkg == self.package_name:
                return True
            logger.warning(
                "[Frida] Foreground is %r (want %s) - bringing target forward "
                "(attempt %d/%d)",
                pkg or "unknown",
                self.package_name,
                attempt + 1,
                attempts,
            )
            self._bring_target_to_foreground()
        return _foreground_package(self.device_serial) == self.package_name

    def _wait_for_app_settled(self, timeout: float) -> bool:
        """
        Block until the target app's window stops changing, or `timeout`.

        Polls mCurrentFocus and requires two consecutive identical samples
        while the target package owns the foreground window.
        Returns True if the UI was seen to settle. Never raises - a settling
        wait that can fail the run would be worse than the crash it prevents.
        """
        deadline = time.monotonic() + timeout
        last_sig = None
        stable = 0

        while time.monotonic() < deadline:
            if _foreground_package(self.device_serial) != self.package_name:
                self._bring_target_to_foreground()
                stable = 0
                last_sig = None
                time.sleep(APP_SETTLE_POLL_SECONDS)
                continue

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
            "[Frida] App did not settle within %.1fs - continuing anyway.", timeout
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
            self._ensure_target_foreground(3)
            activity = _get_foreground_component(self.device_serial)
            fg_pkg = _foreground_package(self.device_serial)
            if fg_pkg and fg_pkg != self.package_name:
                self.foreground_mismatch = True
                logger.warning(
                    "[Frida] Screenshot '%s' taken while foreground is %s, not %s",
                    label,
                    fg_pkg,
                    self.package_name,
                )
            ref = self.screenshot_manager.capture(
                label=label, category=category, source="lifecycle",
                reason="LIFECYCLE", force=True, activity=activity,
            )
            if ref:
                logger.info(f"[Frida] Screenshot captured: {label}")
        except Exception as exc:
            logger.warning(
                f"[Frida] Lifecycle screenshot '{label}' failed "
                f"({type(exc).__name__}: {exc}) - continuing."
            )

    def _close_app(self) -> None:
        """
        Stop the app cleanly at the end of the session.

        Previously nothing closed it: the sample was left running on the device
        after the window ended, so it kept executing (and kept its overlays,
        services and alarms alive) into the NEXT sample's analysis. Any
        behaviour it produced then was attributed to the wrong APK.

        Best-effort - a sample that resists force-stop is itself worth noting,
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
                f"[Frida] {self.package_name} still running after force-stop - "
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
            try:
                from sudarshan_core.sandbox import get_sandbox_provider
                provider = get_sandbox_provider()
                provider.ensure_frida(self.device_serial, restart_if_needed=True)
                time.sleep(1.0)
            except Exception as st_err:
                logger.warning(f"[Frida] Sandbox provider ensure_frida check: {st_err}")

            # Transport order is load-bearing.
            #
            # Frida's USB/ADB transport only ever talks to port 27042 on the
            # guest. We run frida-server on FRIDA_PORT (27055 by default). When
            # those differ the USB transport does NOT fail - it silently
            # degrades to "jailed" mode, answering enumerate_processes() and
            # query_system_parameters() over plain adb. The device therefore
            # looks perfectly healthy right up until attach(), which dies with
            # ServerNotRunningError, and spawn(), which then demands a Gadget
            # ("need Gadget to attach on jailed Android"). That Gadget message
            # is a symptom, never the cure.
            #
            # So when the configured port is not frida's default, dial the real
            # server over TCP first and treat USB as the fallback.
            # Configured port first, then frida's fixed USB port as a last
            # resort. Built from frida_server_port() rather than re-reading the
            # environment here: this list used to consult only two of the three
            # accepted variable names, so setting FRIDA_PORT alone started the
            # server on a port that was never dialled.
            candidate_ports: List[int] = []
            for p_env in (frida_server_port(), str(FRIDA_USB_TRANSPORT_PORT)):
                if p_env and str(p_env).isdigit() and int(p_env) not in candidate_ports:
                    candidate_ports.append(int(p_env))

            def _connect_usb() -> Optional[Any]:
                try:
                    all_devices = frida.enumerate_devices()
                    logger.info(f"[Frida] Available devices: {[d.id for d in all_devices]}")
                except Exception as enum_err:
                    logger.debug(f"[Frida] enumerate_devices failed: {enum_err}")
                    return None
                for d in all_devices:
                    if d.id == self.device_serial:
                        logger.info("[Frida] Using USB/ADB transport")
                        return d
                return None

            def _connect_tcp() -> Optional[Any]:
                from sudarshan_core.sandbox.config import frida_client_hosts

                for f_port in candidate_ports:
                    # `adb forward` runs wherever the ADB SERVER runs. With
                    # ADB_SERVER_SOCKET set (the container default) that is the
                    # host, so the forwarded port is bound on the host - dialling
                    # this container's 127.0.0.1 would never connect.
                    _adb(
                        "-s", self.device_serial, "forward",
                        f"tcp:{f_port}", f"tcp:{f_port}", timeout=10,
                    )
                    for frida_host in frida_client_hosts():
                        try:
                            dev_remote = frida.get_device_manager().add_remote_device(
                                f"{frida_host}:{f_port}"
                            )
                            dev_remote.enumerate_processes()
                            logger.info(
                                f"[Frida] TCP remote device connected: {frida_host}:{f_port}"
                            )
                            return dev_remote
                        except Exception:
                            continue
                return None

            configured_port = candidate_ports[0] if candidate_ports else FRIDA_USB_TRANSPORT_PORT
            if configured_port == FRIDA_USB_TRANSPORT_PORT:
                connectors = (_connect_usb, _connect_tcp)
            else:
                logger.info(
                    f"[Frida] frida-server port {configured_port} != USB transport port "
                    f"{FRIDA_USB_TRANSPORT_PORT} - preferring TCP transport"
                )
                connectors = (_connect_tcp, _connect_usb)

            device = None
            for attempt in range(3):
                try:
                    for connect in connectors:
                        device = connect()
                        if device:
                            break

                    if device:
                        break
                    raise Exception(f"Device '{self.device_serial}' not found")
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
            self.dae.transition(DAEStage.RESOLVE_ACTIVITY, "launch ladder")
            self.dae.transition(DAEStage.LAUNCHING, "issuing launch intents")

            # ── 5-step launch fallback ladder ─────────────────────────────────
            # Each step is tried in order.  After issuing am start, the step
            # does NOT use time.sleep(3) + a one-shot pidof check.  Instead it
            # calls _poll_pid_until_stable(), which polls every 250 ms and
            # requires the PID to be continuously present for LAUNCH_PID_STABLE_MIN_SECONDS
            # (default 5 s) before declaring success.
            #
            # If the process appears and then disappears (crash), the stability
            # monitor returns False immediately and we run crash diagnostics and
            # abort - Frida is NEVER attached to a dying process.
            #
            # Step 1: am start -W with manifest-declared launcher activity
            # Step 2: resolved LAUNCHER activity via cmd package resolve-activity
            # Step 3: enumerate all exported activities and try each
            # Step 4: BOOT_COMPLETED + PACKAGE_ADDED broadcasts (packed samples)
            # Step 5: deep link via declared URI scheme (if any)
            #
            # Monkey is NEVER used.  "Required non-standard launch method" is
            # itself a weak anti-analysis signal worth recording.

            _launch_intent_ts = time.monotonic()  # first intent issued
            _launch_start_ts  = _launch_intent_ts

            # A stable PID that never owns a window is only accepted once every
            # strategy has been tried. Held here so the run still proceeds
            # (headless malware is real) instead of being abandoned.
            _ui_less_pid: Optional[int] = None
            _ui_less_step: Optional[str] = None
            # Only demand a window from packages that actually declare UI.
            _launcher_activity_expected = bool(self.main_activity)

            def _am_start_w(activity_component: str) -> bool:
                """Issue am start -W for an explicit component. Returns adb success."""
                ok, _ = _adb(
                    "-s", self.device_serial, "shell",
                    f"am start -W -n {activity_component}",
                    timeout=20,
                )
                return ok

            def _try_launch_step(
                step_label: str,
                launch_fn: "callable",
            ) -> bool:
                """
                Issue a launch attempt, then call _poll_pid_until_stable().

                Returns True if the process became stable, False if it crashed or
                never appeared. On crash, populates self.crash_report and
                self.last_error so the caller can stop immediately.
                """
                nonlocal _launch_intent_ts
                _launch_intent_ts = time.monotonic()
                self.launch_timeline["launch_intent"] = _launch_intent_ts

                launch_fn()

                stable, pid, reason = _poll_pid_until_stable(
                    self.device_serial, self.package_name,
                )
                if stable and pid is not None:
                    # Record first_pid milestone on first successful PID
                    if self.launch_timeline.get("first_pid") is None:
                        self.launch_timeline["first_pid"] = time.monotonic()
                    self._stable_pid = pid
                    self.launch_method_used = step_label
                    logger.info(
                        "[Frida] Launch step '%s' produced stable PID %d",
                        step_label, pid,
                    )

                    # A PID without a window is not a launch. Keep it as a
                    # fallback, but let the ladder try the remaining strategies -
                    # a resolved-launcher or monkey start often renders where a
                    # bare intent did not.
                    if _launcher_activity_expected:
                        if _poll_until_package_owns_window(
                            self.device_serial, self.package_name,
                        ):
                            return True
                        logger.warning(
                            "[Frida] Launch step '%s' produced PID %d but %s never "
                            "owned the foreground window within %.0fs - trying the "
                            "next launch strategy",
                            step_label, pid, self.package_name,
                            LAUNCH_UI_RENDER_SECONDS,
                        )
                        nonlocal _ui_less_pid, _ui_less_step
                        if _ui_less_pid is None:
                            _ui_less_pid, _ui_less_step = pid, step_label
                        return False
                    return True

                # Process crashed or never appeared.
                logger.error(
                    "[Frida] Launch step '%s' failed: %s - collecting crash diagnostics",
                    step_label, reason,
                )
                self._last_launch_reason = reason  # type: ignore[attr-defined]
                if _launch_failure_is_process_crash(reason):
                    _art_dir = getattr(self, "artifact_dir", Path("."))
                    _prov    = getattr(self, "_provenance", None)
                    _apk_cks = getattr(self, "_apk_checksum", None)
                    _lifetime_ms: Optional[float] = None
                    if self.launch_timeline.get("first_pid") is not None:
                        _lifetime_ms = (time.monotonic() - self.launch_timeline["first_pid"]) * 1000
                    self.crash_report = _collect_crash_diagnostics(
                        self.device_serial,
                        self.package_name,
                        _art_dir,
                        provenance=_prov,
                        launcher_activity=self.main_activity,
                        process_lifetime_ms=_lifetime_ms,
                        launch_duration_ms=(time.monotonic() - _launch_start_ts) * 1000,
                        apk_checksum=_apk_cks,
                    )
                    self.last_error = (
                        f"CRASH_BEFORE_STABLE: {reason}. "
                        f"exception_type={self.crash_report.exception_type}, "
                        f"recommendation={self.crash_report.recommendation}"
                    )
                else:
                    logger.warning(
                        "[Frida] Launch step '%s' did not start process (not a crash) - "
                        "trying next launch strategy",
                        step_label,
                    )
                    self.crash_report = None
                return False

            launched = False
            _crash_on_step: Optional[str] = None

            # Step 1 - manifest-declared launcher activity (am start -W)
            if self.main_activity:
                component = _format_activity_component(
                    self.package_name, self.main_activity,
                )
                logger.info(
                    "[Frida] Launch step 1: am start -W -n %s",
                    component,
                )
                if _try_launch_step(
                    "am_start_main_activity",
                    lambda c=component: _am_start_w(shlex.quote(c)),
                ):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "step1_am_start_main_activity"

            # Step 1b - MAIN + LAUNCHER implicit intent (PackageManager resolver)
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 1b: MAIN/LAUNCHER intent for %s",
                    self.package_name,
                )
                if _try_launch_step(
                    "main_launcher_intent",
                    lambda: _launch_main_launcher_intent(
                        self.device_serial, self.package_name
                    ),
                ):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "step1b_main_launcher_intent"

            # Step 2 - resolved LAUNCHER activity via cmd package resolve-activity
            # Never falls back to Monkey. Uses the platform resolver directly.
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 2: resolve LAUNCHER activity for %s",
                    self.package_name,
                )
                component = _resolve_launcher_activity(
                    self.device_serial, self.package_name
                )
                if component:
                    logger.info("[Frida] Resolved launcher activity: %s", component)
                    if _try_launch_step(
                        "resolved_launcher_activity",
                        lambda comp=component: _am_start_w(shlex.quote(comp)),
                    ):
                        launched = True
                    elif self.crash_report is not None:
                        _crash_on_step = "step2_resolved_launcher"
                else:
                    logger.info(
                        "[Frida] Launch step 2: no LAUNCHER activity declared "
                        "(expected for packed droppers)"
                    )

            # Step 3 - enumerate all exported activities from manifest/pm dump
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 3: trying all exported activities for %s",
                    self.package_name,
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
                if not exported_activities:
                    ok, dump_out = _adb(
                        "-s", self.device_serial, "shell",
                        f"pm dump {safe_pkg}",
                        timeout=15,
                    )
                    if ok:
                        for line in dump_out.splitlines():
                            line = line.strip()
                            if "Activity{" in line or (
                                "android.intent.action.MAIN" in line
                                and self.package_name in line
                            ):
                                import re as _re
                                m = _re.search(
                                    rf"{re.escape(self.package_name)}(/\.?[\w.]+)",
                                    line,
                                )
                                if m:
                                    exported_activities.append(
                                        self.package_name + m.group(1)
                                    )

                for act in exported_activities[:8]:
                    safe_act_3 = shlex.quote(act)
                    logger.info(
                        "[Frida] Launch step 3: trying exported activity %s", act
                    )
                    if _try_launch_step(
                        f"exported_activity:{act}",
                        lambda c=f"{safe_pkg}/{safe_act_3}": _am_start_w(c),
                    ):
                        launched = True
                        break
                    elif self.crash_report is not None:
                        _crash_on_step = f"step3_exported_activity:{act}"
                        break

            # Step 4 - BOOT_COMPLETED + PACKAGE_ADDED broadcasts
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 4: simulating boot/install broadcasts for %s",
                    self.package_name,
                )
                def _broadcast_launch():
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
                if _try_launch_step("boot_broadcast", _broadcast_launch):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "step4_boot_broadcast"

            # Step 5 - deep link via URI scheme declared in manifest
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 5: attempting URI scheme deep link for %s",
                    self.package_name,
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
                        "[Frida] Launch step 5: am start VIEW -d %s://", uri_scheme,
                    )
                    def _deep_link_launch(ss=safe_scheme):
                        _adb(
                            "-s", self.device_serial, "shell",
                            f"am start -a android.intent.action.VIEW -d {ss}",
                            timeout=15,
                        )
                    if _try_launch_step(f"deep_link:{uri_scheme}", _deep_link_launch):
                        launched = True
                    elif self.crash_report is not None:
                        _crash_on_step = f"step5_deep_link:{uri_scheme}"

            # Step 6 - force-stop then retry resolved launcher (cold start)
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 6: force-stop + resolved launcher for %s",
                    self.package_name,
                )
                self.dae.metrics["launch_retries"] = (
                    int(self.dae.metrics.get("launch_retries", 0)) + 1
                )

                def _force_stop_and_launch():
                    _force_stop_package(self.device_serial, self.package_name)
                    component = _resolve_launcher_activity(
                        self.device_serial, self.package_name
                    )
                    if component:
                        import shlex as _shlex
                        _am_start_w(_shlex.quote(component))
                    else:
                        _launch_main_launcher_intent(
                            self.device_serial, self.package_name
                        )

                if _try_launch_step("force_stop_retry", _force_stop_and_launch):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "step6_force_stop_retry"

            # Step 7 - Monkey launcher
            if not launched and _crash_on_step is None:
                logger.info(
                    "[Frida] Launch step 7: monkey LAUNCHER for %s",
                    self.package_name,
                )
                if _try_launch_step(
                    "monkey_launcher",
                    lambda: _launch_via_monkey(
                        self.device_serial, self.package_name
                    ),
                ):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "step7_monkey_launcher"

            # ── Fallback: a process without a window is still a process ───────
            # Every strategy ran and none produced UI. Rather than abandon the
            # run, attach to the stable PID we did get and record that no UI ever
            # rendered, so the risk engine can mark the dynamic axis inconclusive
            # (NO_UI_RENDERED) instead of scoring the silence as benign.
            if not launched and _crash_on_step is None and _ui_less_pid is not None:
                self._stable_pid = _ui_less_pid
                self.launch_method_used = _ui_less_step or "ui_less_pid"
                self.ui_render_failed = True
                launched = True
                logger.warning(
                    "[Frida] No launch strategy rendered UI for %s - proceeding with "
                    "PID %d from '%s'. Behavioural coverage will be limited and the "
                    "dynamic axis will be reported inconclusive.",
                    self.package_name, _ui_less_pid, self.launch_method_used,
                )

            # ── Gate: did any step succeed? ───────────────────────────────────
            if not launched:
                if _crash_on_step:
                    # App launched but crashed before becoming stable.
                    # crash_report already populated and written to disk.
                    self.launch_method_used = "failed"
                    logger.error(
                        "[Frida] Application crashed during %s - "
                        "NOT attaching Frida. See crash_report.json for details.",
                        _crash_on_step,
                    )
                else:
                    self.launch_method_used = "failed"
                    self.last_error = (
                        f"LAUNCH_FAILED: All 5 launch methods failed for "
                        f"{self.package_name}. "
                        "Steps tried: am_start_main_activity, main_launcher_intent, "
                        "resolved_launcher_activity, "
                        "exported_activity, boot_broadcast, deep_link, "
                        "force_stop_retry, monkey_launcher. "
                        "This sample may require manual launch or has no runnable "
                        "entry point in the current environment."
                    )
                    logger.error("[Frida] %s", self.last_error)
                return False

            logger.info(
                "[Frida] App launched and stable via '%s' (PID=%s)",
                self.launch_method_used, self._stable_pid,
            )

            # ── Pre-Frida Readiness Gate ──────────────────────────────────────
            # Six checks that confirm the app is genuinely ready for attachment.
            # If any check fails we stop here - never attach to a dying process.
            _art_dir_gate = getattr(self, "artifact_dir", Path("."))
            gate_ok, gate_reason = _verify_launch_readiness(
                self.device_serial,
                self.package_name,
                self._stable_pid or 0,
                _art_dir_gate,
                launcher_activity=self.main_activity,
            )
            if not gate_ok:
                self.launch_method_used = "failed"
                self.last_error = f"READINESS_GATE_FAIL: {gate_reason}"
                logger.error("[Frida] %s", self.last_error)
                # Collect crash diagnostics - the gate may have caught a crash
                # that the stability monitor missed (race between stable check
                # and readiness check).
                if self.crash_report is None:
                    _prov_g   = getattr(self, "_provenance", None)
                    _apk_cks_g = getattr(self, "_apk_checksum", None)
                    self.crash_report = _collect_crash_diagnostics(
                        self.device_serial,
                        self.package_name,
                        _art_dir_gate,
                        provenance=_prov_g,
                        launcher_activity=self.main_activity,
                        apk_checksum=_apk_cks_g,
                    )
                return False

            # Record first_activity and first_window milestones
            _ok_w, _win = _adb(
                "-s", self.device_serial, "shell",
                "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
                timeout=15,
            )
            if _win and self.package_name in _win:
                self.launch_timeline["first_activity"]  = time.monotonic()
                self.launch_timeline["first_window"]    = time.monotonic()

            # Record first_ui_dump milestone
            _ok_u, _ = _adb(
                "-s", self.device_serial, "shell",
                "uiautomator dump /dev/null 2>&1",
                timeout=15,
            )
            if _ok_u:
                self.launch_timeline["first_ui_dump"] = time.monotonic()

            # ── Attach Frida ──────────────────────────────────────────────────
            # At this point:
            #   * _poll_pid_until_stable() confirmed PID was alive for ≥5 s
            #   * _verify_launch_readiness() confirmed all 6 checks passed
            # We attach by the stable PID - no polling retry needed.
            self.launch_timeline["frida_attach"] = time.monotonic()
            self.dae.transition(DAEStage.ATTACH_FRIDA, "attaching to stable PID")

            self._session = None
            for attempt in range(ATTACH_MAX_ATTEMPTS):
                # Use the stable PID first; fall back to a fresh pidof only if
                # the session attach raises (rare - the process is verified alive).
                pid = self._stable_pid or self._resolve_pid()
                try:
                    if pid:
                        self._session = device.attach(pid)
                        logger.info(
                            "[Frida] Attached to %s (pid=%d, attempt %d)",
                            self.package_name, pid, attempt + 1,
                        )
                        break
                    # No PID - should not happen after gate passed; try by name
                    # as a last resort (rare frida enumeration quirk).
                    self._session = device.attach(self.package_name)
                    logger.info(
                        "[Frida] Attached to %s by name (attempt %d)",
                        self.package_name, attempt + 1,
                    )
                    break
                except frida.ProcessNotFoundError:
                    logger.warning(
                        "[Frida] %s not found at attempt %d/%d - "
                        "process may have crashed after readiness gate",
                        self.package_name, attempt + 1, ATTACH_MAX_ATTEMPTS,
                    )
                    time.sleep(ATTACH_RETRY_DELAY_SECONDS)
                except Exception as e:
                    logger.warning(
                        "[Frida] Attach attempt %d failed: %s: %s",
                        attempt + 1, type(e).__name__, e,
                    )
                    time.sleep(ATTACH_RETRY_DELAY_SECONDS)

            is_spawned = False
            if not self._session:
                logger.info("[Frida] Attach-by-pid failed, falling back to device.spawn()")
                pid = None
                spawn_errors: List[str] = []
                for attempt in range(3):
                    try:
                        pid = device.spawn(self.package_name)
                        break
                    except Exception as e:
                        spawn_errors.append(f"{type(e).__name__}: {e}")
                        logger.warning(f"[Frida] Spawn attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                if not pid:
                    running = self._resolve_pid()
                    _, enforce = _adb("-s", self.device_serial, "shell", "getenforce", timeout=10)
                    hint = ""
                    if "Enforcing" in (enforce or ""):
                        hint = (" SELinux is Enforcing, which blocks Frida from attaching "
                                "even as root - run 'adb shell setenforce 0'.")
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

            logger.info(
                f"[Frida] App launched successfully via "
                f"'{self.launch_method_used}'"
            )


            # ══════════════════════════════════════════════════════════════════
            # PHASE 2 of 3 - ANALYSE
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
            self.dae.transition(DAEStage.CAPTURE_RUNTIME, "exploration window")
            explorer = None
            explorer_thread = None

            # ── Agentic Explorer (primary) - falls back to UIExplorer on error ──
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
                self.dae.transition(DAEStage.START_EXPLORER, "AgenticExplorer")
            except Exception as exc:
                # Rollback covers ANY construction failure, not just
                # ImportError: a missing dependency, a bad device serial or
                # a constructor raising must all degrade to the legacy
                # explorer rather than abandoning exploration entirely.
                logger.error(
                    f"[Frida] AgenticExplorer unavailable "
                    f"({type(exc).__name__}: {exc}) - attempting rollback",
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
                        # Nothing further can be explored - release the main
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
                # artifacts get flushed mid-iteration - the goal summary and
                # benchmark counters are written before the explorer computes
                # them, reporting goals_completed=0 for a run that did progress.
                if explorer is not None and hasattr(explorer, "stop"):
                    explorer.stop()
                explorer_thread.join(timeout=EXPLORER_JOIN_GRACE_SECONDS)
                if explorer_thread.is_alive():
                    logger.warning(
                        f"[Frida] Explorer did not finish within "
                        f"{EXPLORER_JOIN_GRACE_SECONDS}s of being asked to stop "
                        f" - artifacts may be incomplete"
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
                    ui_xml = getattr(explorer, "last_ui_hierarchy_xml", "") or ""
                    if ui_xml:
                        self.last_ui_hierarchy_xml = ui_xml
                    # Flush agentic-only artifacts (audit_log.json, benchmark.json)
                    # UIExplorer does not have flush_artifacts() - guarded by hasattr.
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
        "sha256": compute_sha256(apk_path) if os.path.isfile(apk_path) else "",
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


    # ── Step 1: Connect sandbox via SandboxProvider ────────────────────────────
    # Device detection, ADB, root, and Frida verification are owned by the
    # sandbox abstraction. Analysis logic below is unchanged.
    provider = _get_provider()
    connection = None
    device_serial = None

    for attempt in range(3):
        connection = provider.connect()
        if connection.ok and connection.device:
            device_serial = connection.device.serial
            break
        logger.warning(
            "[Frida] Sandbox connect attempt %s failed: %s (%s). Retrying in 2s...",
            attempt + 1,
            connection.error_code if connection else "unknown",
            connection.error_message if connection else "no result",
        )
        await asyncio.sleep(2)

    if not device_serial or not connection or not connection.ok:
        err_code = (connection.error_code if connection else "SANDBOX_OFFLINE") or "SANDBOX_OFFLINE"
        err_msg = (
            (connection.error_message if connection else None)
            or (
                "No sandbox device connected. Start Genymotion Desktop "
                "(or set SANDBOX_PROVIDER=android_studio and start an AVD)."
            )
        )
        log_pipeline_lifecycle(1, "emulator ready", f"FAIL {err_code}")
        logger.warning("[Frida] %s: %s", err_code, err_msg)
        base_result["error"] = err_msg
        base_result["error_code"] = err_code
        if connection:
            base_result["sandbox_connection"] = connection.to_dict()
        return base_result

    logger.info(
        "[Frida] Using sandbox provider=%s serial=%s android=%s abi=%s "
        "root=%s frida=%s connect_ms=%.1f",
        provider.name,
        device_serial,
        connection.device.android_version if connection.device else "?",
        connection.device.abi if connection.device else "?",
        connection.device.rooted if connection.device else "?",
        connection.device.frida_running if connection.device else "?",
        connection.connection_time_ms,
    )
    base_result["sandbox_connection"] = connection.to_dict()
    base_result["sandbox_provider"] = provider.name
    log_pipeline_lifecycle(1, "emulator ready", f"serial={device_serial}")
    log_pipeline_lifecycle(4, "Frida device connected", provider.name)

    # ── Serialise access to the device ────────────────────────────────────────
    # There is exactly ONE emulator and it was taken with no lock, while the
    # engine allows MAX_CONCURRENT_ANALYSES=2. Two dynamic runs could therefore
    # interleave `adb install`, `am start`, `pidof` and Frida attach against the
    # same device - and _adb_install_apk performs an `adb uninstall` on the
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


def _build_root_cause_analysis(
    session: "FridaSession",
    provenance: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Assemble a root_cause_analysis dict from session state and crash report.
    This answers the diagnostic questions from Requirement 10.
    """
    cr = session.crash_report
    if cr is None:
        return {
            "why_crashing": None,
            "subsystem": None,
            "is_apk_repair": False,
            "is_resigning": False,
            "is_emulator_compat": False,
            "is_launch_logic": False,
            "is_manifest": False,
            "is_instrumentation": False,
            "fix_applied": "Session completed successfully - no crash detected.",
        }

    why = None
    if cr.exception_type:
        why = f"{cr.exception_type}: {cr.exception_message or '(no message)'}"
    elif cr.native_stacktrace:
        why = f"Native crash: {cr.native_stacktrace[:200]}"
    elif cr.selinux_denials:
        why = f"SELinux denial: {cr.selinux_denials[0][:200]}"
    elif cr.logcat_errors:
        why = cr.logcat_errors[0][:200]
    else:
        why = session.last_error or "Unknown crash cause"

    subsystem = "unknown"
    if cr.is_instrumentation_issue:   subsystem = "instrumentation"
    elif cr.is_emulator_compat_issue: subsystem = "emulator_abi"
    elif cr.is_apk_repair_issue:      subsystem = "apk_repair"
    elif cr.is_resign_issue:          subsystem = "resigning"
    elif cr.is_manifest_issue:        subsystem = "manifest"
    elif cr.is_launch_logic_issue:    subsystem = "app_code"

    fix_applied = cr.recommendation or "See crash_report.json and crash_logcat.txt in the artifact directory."

    return {
        "why_crashing":       why,
        "subsystem":          subsystem,
        "is_apk_repair":      cr.is_apk_repair_issue,
        "is_resigning":       cr.is_resign_issue,
        "is_emulator_compat": cr.is_emulator_compat_issue,
        "is_launch_logic":    cr.is_launch_logic_issue,
        "is_manifest":        cr.is_manifest_issue,
        "is_instrumentation": cr.is_instrumentation_issue,
        "process_lifetime_ms": cr.process_lifetime_ms,
        "fix_applied":        fix_applied,
    }


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
    # that injection requires - even for uid 0. The old code only checked that
    # frida-server was alive, so the failure surfaced as the misleading
    # "Ensure frida-server is running on emulator", which it was.
    #
    # This is an analysis sandbox: the AVD is disposable and exists to be
    # instrumented. It is never applied to anything but the attached emulator.
    await loop.run_in_executor(None, _adb, "-s", device_serial, "root")
    # Wait for ADB daemon to reconnect if adbd restarted
    for _ in range(10):
        await asyncio.sleep(0.5)
        ok_who, who = await loop.run_in_executor(None, _adb, "-s", device_serial, "shell", "whoami")
        if ok_who and ("root" in (who or "") or "shell" in (who or "")):
            break

    ok, enforce = await loop.run_in_executor(
        None, _adb, "-s", device_serial, "shell", "getenforce"
    )
    if "Enforcing" in (enforce or ""):
        logger.warning(
            "[Frida] SELinux is Enforcing - Frida cannot attach to app processes. "
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
    # Frida lifecycle is owned by SandboxProvider.connect(). Do not duplicate
    # it here with a hard-coded legacy `/data/local/tmp/frida-server` probe:
    # Genymotion deployments may run a deliberately named agent binary and a
    # non-default port. The provider validates the configured agent before this
    # session starts; FridaSession then performs the authoritative attach/canary.
    logger.info("[Frida] Configured Frida agent verified by SandboxProvider.")

    # ── Step 2: Extract package name ───────────────────────────────────────────
    main_activity = None
    if not package_name or package_name in ("Failed", "Unknown", "None"):
        package_name, main_activity = await loop.run_in_executor(None, _extract_apk_info, apk_path)
        
    if not package_name or package_name in ("Failed", "Unknown", "None"):
        logger.warning("[Frida] Could not extract valid package name from APK")
        base_result["error"] = "Could not extract valid package name from APK."
        return base_result

    if not main_activity:
        _pn, _ma = await loop.run_in_executor(None, _extract_apk_info, apk_path)
        if _ma:
            main_activity = _ma
        if not package_name and _pn:
            package_name = _pn

    logger.info(f"[Frida] Target package: {package_name} (Main Activity: {main_activity})")

    apk_dir = artifact_dir_for(apk_path)
    logger.info(f"[Frida] Artifacts for this sample: {apk_dir}")

    content_sha256 = base_result.get("sha256") or compute_sha256(apk_path)
    base_result["sha256"] = content_sha256

    session = FridaSession(
        device_serial, package_name,
        main_activity=main_activity,
        artifact_dir=apk_dir,
        case_id=content_sha256,
    )

    # ── Step 3: Install APK ────────────────────────────────────────────────────
    log_pipeline_lifecycle(2, "APK installed", "starting adb install")
    _install_start = time.monotonic()
    session.dae.transition(DAEStage.INSTALLING, "adb install")
    ok, output, provenance = await loop.run_in_executor(None, _adb_install_apk, apk_path, device_serial)
    base_result["provenance"] = provenance
    if not ok:
        logger.error(f"[Frida] APK install failed: {output}")
        session.dae.fail(f"APK install failed: {output}")
        base_result["error"] = f"APK install failed: {output}"
        base_result["dae_pipeline"] = session.dae.to_dict()
        return base_result
    log_pipeline_lifecycle(2, "APK installed", package_name)
    session.dae.transition(DAEStage.VERIFY_INSTALL, "pm path verification")
    if not await loop.run_in_executor(
        None, _verify_package_installed, device_serial, package_name
    ):
        logger.warning(
            "[Frida] Install reported success but pm path missing - reinstalling once"
        )
        session.dae.metrics["launch_retries"] = (
            int(session.dae.metrics.get("launch_retries", 0)) + 1
        )
        ok, output, provenance = await loop.run_in_executor(
            None, _adb_install_apk, apk_path, device_serial
        )
        base_result["provenance"] = provenance
        if not ok:
            session.dae.fail(f"Reinstall failed: {output}")
            base_result["error"] = f"APK reinstall failed: {output}"
            base_result["dae_pipeline"] = session.dae.to_dict()
            return base_result
    logger.info(f"[Frida] APK installed: {package_name} (Derivative Repaired: {provenance.get('is_repaired_derivative', False)})")
    _install_ts = time.monotonic()  # install completed

    effective_apk_path = apk_path
    if provenance.get("is_repaired_derivative"):
        rep_p = provenance.get("repaired_apk_path")
        if rep_p and os.path.exists(rep_p):
            effective_apk_path = rep_p

        # The manifest-derived launcher wins. This used to overwrite it
        # unconditionally, so a rebuild that guessed its launcher from an
        # arbitrary DEX class replaced the correct activity with one that cannot
        # start - the app then installed and never rendered a window.
        #
        # The repaired APK is what is actually installed, so its activity is
        # still used when the real launcher is not declared in the rebuild.
        rep_act = provenance.get("main_activity")
        rep_acts = provenance.get("activities") or []
        if main_activity and (not rep_acts or main_activity in rep_acts):
            logger.info(
                "[Frida] Keeping manifest launcher activity: %s "
                "(repaired derivative declares it)", main_activity,
            )
        elif rep_act and rep_act != "MainActivity":
            logger.warning(
                "[Frida] Manifest launcher %r is not declared by the repaired "
                "derivative - falling back to its activity: %s",
                main_activity, rep_act,
            )
            main_activity = rep_act

    # Post-install gate: can the platform actually resolve a launcher? A
    # rebuilt manifest can name a class that is not an Activity, which installs
    # cleanly and then cannot be started by any means.
    resolved_component = await loop.run_in_executor(
        None, _resolve_launcher_activity, device_serial, package_name,
    )
    # A component outside the package means the platform could not pick a
    # launcher for it - typically ResolverActivity, the disambiguation chooser,
    # which appears when a manifest declares zero or several LAUNCHER entries.
    if resolved_component and package_name in resolved_component:
        logger.info("[Frida] Launcher resolves post-install: %s", resolved_component)
    else:
        if resolved_component:
            logger.error(
                "[Frida] Launcher for %s resolves to %s, which is outside the "
                "package - the manifest declares no single LAUNCHER activity.",
                package_name, resolved_component,
            )
        base_result["launcher_unresolved"] = True
        logger.error(
            "[Frida] No launcher activity resolves for %s after install%s. The "
            "app cannot be started from the launcher; UI-driven hooks will not "
            "fire and the dynamic axis will be reported inconclusive.",
            package_name,
            " (repaired derivative)" if provenance.get("is_repaired_derivative") else "",
        )

    await loop.run_in_executor(
        None,
        _grant_declared_runtime_permissions,
        device_serial,
        effective_apk_path,
        package_name,
    )

    if not main_activity:
        comp = await loop.run_in_executor(
            None, _resolve_launcher_activity, device_serial, package_name,
        )
        if comp and "/" in comp:
            main_activity = comp.split("/", 1)[1]
            session.main_activity = main_activity
            logger.info("[Frida] Resolved main activity from launcher: %s", main_activity)

    if main_activity:
        session.main_activity = main_activity

    # ── Step 4: Run Frida session ──────────────────────────────────────────────
    # Give the launch ladder access to the APK path for steps 3 & 5
    # (androguard activity enumeration and URI scheme discovery).
    session._apk_path = effective_apk_path  # type: ignore[attr-defined]

    # Stamp the apk_install milestone now that we have the session object.
    # (install completed before session was constructed; use _install_ts)
    session.launch_timeline["apk_install"] = _install_ts

    # Forward provenance + checksum so crash diagnostics inside run() can use them.
    session._provenance   = provenance           # type: ignore[attr-defined]
    session._apk_checksum = provenance.get("original_sha256")  # type: ignore[attr-defined]


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
            evidence_store=session.evidence_store,
            package_name=package_name,
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
    try:
        from sudarshan_core.services.threat_correlator import ThreatCorrelatorListener

        session._threat_listener = ThreatCorrelatorListener(
            event_bus=session.event_bus,
            package_name=package_name,
        )
    except Exception as _tc_exc:
        logger.warning("[Frida] ThreatCorrelatorListener not started: %s", _tc_exc)
    if AntiAnalysisDetector is not None:
        session.anti_analysis_detector = AntiAnalysisDetector(event_bus=session.event_bus)
    if YARAScanner is not None:
        # YARA rules directory.
        #
        # This was Path("yara_rules") - RELATIVE, so it resolved against the
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
                f"[Frida] YARA scanning DISABLED - no .yar/.yara rules found in "
                f"{rules_dir}. Set SUDARSHAN_YARA_RULES_DIR to enable it."
            )

    def _run_sync():
        return session.run(duration_seconds=ANALYSIS_DURATION_SECONDS)

    success = await loop.run_in_executor(None, _run_sync)

    if not success:
        err_msg = (
            getattr(session, "last_error", None)
            or "Frida instrumentation failed (no further detail reported)."
        )
        base_result["error"] = err_msg
        # Attach crash report and timeline to the failure result so the API
        # consumer gets diagnostics even when the session never ran.
        if session.crash_report is not None:
            base_result["crash_report"] = session.crash_report.to_dict()
        base_result["launch_timeline"] = _timeline_to_seconds(session.launch_timeline)
        base_result["launch_method_used"] = session.launch_method_used
        # Write launch_timeline.json even on failure
        try:
            tl_path = apk_dir / "launch_timeline.json"
            tl_path.write_text(
                json.dumps(base_result["launch_timeline"], indent=2),
                encoding="utf-8",
            )
            logger.info("[Frida] launch_timeline.json written (failure path): %s", tl_path)
        except OSError:
            pass
        return base_result


    # ── Step 5: Compute BFCI & Instrumentation Status ───────────────────────
    bfci, components, evidence = calculate_bfci(session.collected_events)

    if not session.canary_received:
        dynamic_status = DynamicAnalysisStatus.INSTRUMENTATION_FAILED.value
    elif session.java_bridge_failed or session.java_hooks_installed == 0:
        # The script loaded and native hooks installed, but the Java bridge did
        # not, so accessibility / SMS / overlay / banking could never fire.
        # Calling that NO_BEHAVIOR_OBSERVED would blame the sample for a
        # harness fault, and risk_engine would treat it as a real observation.
        dynamic_status = DynamicAnalysisStatus.INSTRUMENTATION_FAILED.value
        logger.error(
            "[Frida] NO Java hooks installed (%d native only; bridge: %s). "
            "Accessibility, SMS, overlay and banking hooks could never fire, so "
            "this run is INSTRUMENTATION_FAILED, not 'no behaviour observed' - "
            "the sample is not being credited with doing nothing.",
            session.native_hooks_installed,
            session.java_bridge_source or "unknown",
        )
    elif getattr(session, "ui_render_failed", False):
        # The process ran but never owned a window, so no UI-driven hook could
        # fire. Blaming the sample for that silence would score a launch failure
        # as benign behaviour.
        dynamic_status = DynamicAnalysisStatus.NO_UI_RENDERED.value
    elif session.total_hook_events_received == 0:
        dynamic_status = DynamicAnalysisStatus.RUNTIME_COMPLETED_NO_EVENTS.value
    else:
        dynamic_status = DynamicAnalysisStatus.EVENTS_CAPTURED.value

    # ── Step 6: Build structured result ───────────────────────────────────────
    # Flatten API calls for risk_engine.py compatibility
    # Flattened view of every hook that fired. This is a REPORTING surface, not a
    # scoring one - risk_engine only consumes it on the MobSF path, and
    # _dynamic_run_was_conclusive counts it to decide whether the sandbox saw
    # anything at all. It therefore spans scored AND unscored categories: an event
    # that is excluded from BFCI (a device-identity read, say) is still real
    # observed behaviour and must not vanish from the analyst's view.
    api_calls = [
        e.get("data", {}).get("hook", "") or e.get("hook", "")
        for category in ["accessibility", "sms", "overlay", "banking",
                         "persistence", "dangerous_apis", "smoke",
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

        # Exploration provenance - additive fields so a reviewer can tell which
        # explorer produced this evidence, and whether it crashed part-way.
        # Deliberately NOT consumed by risk_engine: provenance never scores.
        "explorer_used":       session.explorer_used,
        "explorer_error":      session.explorer_error,
        "artifact_dir":        str(apk_dir),
        "dae_pipeline":        session.dae.to_dict(),
        # Which of the 5-step launch ladder succeeded (or "failed" if none did).
        # Presence of non-standard launch method is itself a weak signal of
        # anti-analysis hardening. NOT consumed by risk_engine.
        "launch_method_used":  session.launch_method_used,
        "foreground_mismatch": session.foreground_mismatch,

        # Launch diagnostics (Requirement 6) - timestamps for all 10 milestones.
        # Offsets are seconds since apk_install (None = milestone not reached).
        "launch_timeline": _timeline_to_seconds(session.launch_timeline),

        # Crash report (Requirement 7) - None when app launched successfully.
        "crash_report": session.crash_report.to_dict() if session.crash_report else None,

        # Root cause analysis (Requirement 10)
        "root_cause_analysis": _build_root_cause_analysis(session, provenance),

        # BFCI result (new fields for the updated risk_engine)
        "bfci": bfci,
        "bfci_components": components,
        "bfci_evidence": evidence,

        # Legacy fields expected by risk_engine._calculate_dynamic_score()
        # Maps Frida events → string signals the existing engine checks
        "api_calls": list(set(api_calls))[:30],
        "network_logs": network_logs[:20],
        "files_accessed": list(set(files_accessed))[:20],
        # Screenshots WERE being captured - the ScreenshotManager subscribes to
        # the event bus and fires on CRITICAL/overlay/anti_analysis events - but
        # this field was hardcoded to [] with a "not implemented" comment, so
        # every captured image was invisible to the API, the report and the
        # analyst. The manifest is now surfaced here and flushed to disk below.
        "screenshots": _collect_screenshots(session),
        "frida_events": {
            cat: list(events)[:50]
            for cat, events in session.collected_events.items()
        },
        "ui_hierarchy_xml": session.last_ui_hierarchy_xml or None,
        # Package still alive after force-stop at session end.
        "survived_force_stop": session.survived_force_stop,
        # Real activities observed during the session, derived from the
        # agentic explorer's visited-screen memory. If no explorer ran, or
        # if the memory contains no activity data, this is an empty list - # never [package_name], which was a fabricated placeholder that
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

    # Write launch_timeline.json to artifact dir (success path)
    try:
        tl_path = apk_dir / "launch_timeline.json"
        tl_path.write_text(
            json.dumps(result["launch_timeline"], indent=2),
            encoding="utf-8",
        )
        logger.info("[Frida] launch_timeline.json written: %s", tl_path)
    except OSError:
        pass

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
            session.event_bus.drain(8.0)
            if session.screenshot_manager is not None:
                session.screenshot_manager.wait_pending(30.0)
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
            session.dae.transition(DAEStage.COLLECT_EVIDENCE, "flushing evidence store")
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
            session.dae.transition(DAEStage.BUILD_WORKFLOW, "workflow reconstruction")
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
            session.screenshot_manager.wait_pending(30.0)
            n = session.screenshot_manager.flush_manifest()
            # Legacy alias used by older report tooling
            session.screenshot_manager.flush_manifest(apk_dir / "screenshots.json")
            session.dae.update_metrics(
                **session.screenshot_manager.get_telemetry()
            )
            logger.info(f"[Frida] Screenshot manifest flushed: {n} image(s)")
        except Exception as e:
            logger.error(f"[Frida] Failed to write screenshot manifest: {e}")

    try:
        from sudarshan_core.visual_evidence.linker import write_visual_evidence_artifact
        from sudarshan_core.visual_evidence.static_sources import merge_static_flags

        static_flags = merge_static_flags(
            apk_dir,
            {
                "has_accessibility_abuse": bool(result.get("has_accessibility_abuse")),
                "has_system_alert_window": bool(result.get("has_system_alert_window")),
                "has_sms_read_write": bool(result.get("has_sms_read_write")),
                "targets_indian_banks": bool(result.get("targets_indian_banks")),
            },
        )
        write_visual_evidence_artifact(
            apk_dir,
            analysis_id=str(result.get("sha256") or package_name or ""),
            package_name=str(package_name or ""),
            static_flags=static_flags,
            vide_result=result.get("vide") if isinstance(result.get("vide"), dict) else {},
            session_metadata={"explorer_used": result.get("explorer_used")},
        )
    except Exception as e:
        logger.error(f"[Frida] Failed to write visual_evidence.json: {e}")

    session.dae.transition(DAEStage.GENERATE_REPORT, "artifact flush complete")

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
            result["network_flows"] = list(session.network_capture.flows)
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

    session.dae.transition(DAEStage.COMPLETE, "dynamic session finished")

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

    try:
        hooks_ok = (
            _HOOKS_BUNDLE.exists()
            and _HOOKS_BUNDLE.stat().st_size >= _MIN_BUNDLE_BYTES
        )
    except OSError:
        hooks_ok = False

    ready = frida_available and adb_path is not None and len(emulators) > 0 and hooks_ok

    # Determine connection mode from sandbox config
    cfg = _sandbox_env()
    tcp_error = None
    if cfg.adb_host:
        mode = "docker-tcp"
        connection_info = (
            f"Docker mode: connecting to {cfg.provider} sandbox at "
            f"{cfg.adb_host}:{cfg.adb_port} via ADB TCP. "
            f"Ensure: (1) Sandbox is running on host, (2) 'adb tcpip {cfg.adb_port}' "
            f"was run on host (or Genymotion ADB is reachable)."
        )
        if adb_path and len(emulators) == 0:
            ok, out = _adb("connect", f"{cfg.adb_host}:{cfg.adb_port}", timeout=5)
            if not ok or "cannot connect" in out.lower() or "failed to connect" in out.lower():
                tcp_error = out.strip()
                connection_info += f" [ERROR: {tcp_error}]"
    else:
        mode = "local"
        connection_info = (
            f"Local mode ({cfg.provider}): looking for devices via `adb devices`. "
            f"Set DEVICE_SERIAL if multiple devices are online."
        )

    return {
        "ready": ready,
        "mode": mode,
        "sandbox_provider": cfg.provider,
        "device_serial_configured": cfg.device_serial or None,
        "connection_info": connection_info,
        "frida_available": frida_available,
        "frida_version": frida_version,
        "adb_found": adb_path is not None,
        "adb_path": adb_path,
        "adb_host": cfg.adb_host or None,
        "adb_port": cfg.adb_port if cfg.adb_host else None,
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
