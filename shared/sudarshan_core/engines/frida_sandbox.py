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
import queue
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.engines.event_bus import EventType, RuntimeEvent, RuntimeEventBus
from sudarshan_core.engines.bfci_scorer import calculate_bfci_v2, BFCI_WEIGHTS
from sudarshan_core.engines.dae_pipeline import DAEPipelineTracker, DAEStage
from sudarshan_core.engines.apk_repair import compute_sha256
from sudarshan_core.engines.dynamic_budget import (
    DYNAMIC_MAX_WALL_TIME_SECONDS,
    TIMEOUT_REASON,
    DynamicDeadline,
    clear_active_deadline,
    get_active_deadline,
    set_active_deadline,
)
from sudarshan_core.engines.runtime_event import normalize_collected_events
from sudarshan_core.engines.dynamic_coverage import (
    DynamicCoverageStatus,
    build_dynamic_coverage,
)
from sudarshan_core.engines.runtime_lifecycle import (
    RuntimeLifecycleTracker,
    get_active_tracker,
    record_lifecycle_event,
    set_active_tracker,
)

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
    # Hooks installed correctly, the process ran, and nothing the SAMPLE did was
    # observed - because the agent arrived after the app had already started.
    # Distinct from RUNTIME_COMPLETED_NO_EVENTS, which claims the sample was
    # quiet. A real run reported EVENTS_CAPTURED with 77 hooks installed and one
    # hook fire that was the harness spoofing its own Build fields, and the
    # report then read as though the sample had been observed doing nothing.
    INSTRUMENTED_TOO_LATE = "INSTRUMENTED_TOO_LATE"

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
# How long the sample is exercised, in seconds.
#
# Raised from 90s once the investigation plan began driving the run. Measured on
# Cerberus: 22 actions in 92s, so ~4.2s per action with the LLM planner. An
# fullest trojan plan is 14 stages, which at 4 actions per stage needs 56
# actions, i.e. ~235s - a 90s window truncated the walk at stage 3 and the
# sample's accessibility stage was never reached.
#
# The cost is real: every dynamic run is now ~5 minutes rather than ~90s.
#
# ── Reduced to 150s once the planner stopped being on the critical path ──────
#
# The 300s figure was sized against "~4.2s per action". That number no longer
# described reality: measured on Anubis, Gemini alone took 7.9s, 13.8s, 15.1s
# and 11.2s on consecutive iterations - ~12s each - because the planner was
# consulted BEFORE the exploration graph, every iteration, and its answer was
# then discarded whenever the graph had a tap or a type to offer. Twenty calls
# consumed roughly 240s of the 300s window and bought 20 actions.
#
# With the planner consulted only when it can change the outcome (see
# _planner_could_change_outcome in agentic_explorer), the per-iteration cost is
# dominated by perception and execution again, and the window no longer has to
# be padded to absorb model latency.
#
# 240s is the measured floor for a DROPPER: Anubis does not install its
# payload until t+86s, and a window that closes before the payload is
# instrumented produces no fraud-bucket events at all - measured directly,
# 120s gave axes_excluded=[dynamic] while ~180s+ gave axes_excluded=[] with
# both packages instrumented. Shorter windows suit single-stage samples;
# this default has to cover the two-stage case. Earlier note kept below.
# The old operational constraint this engine is actually used under:
# a whole scan - static, launch, exploration and teardown - inside 3-4 minutes.
# Raise it with FRIDA_ANALYSIS_DURATION when a sample genuinely needs a longer
# walk; nothing here assumes the default.
ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "130"))

# ── Adaptive exploration window ───────────────────────────────────────────────
# ANALYSIS_DURATION_SECONDS above is the STARTING budget, not a fixed one. It is
# the same number for every sample, and it is wrong in both directions: an app
# that is mid-login at t=299 is cut off with the interesting part unobserved,
# and an app that reached a dead end at t=40 keeps the emulator for another four
# minutes producing nothing.
#
# The explorer owns the decision (see agentic.adaptive_budget) and extends its
# own deadline while it is still learning something. This side of the lifecycle
# has to allow that: the wait below used to time out at exactly
# duration_seconds and then force explorer.stop(), so an extension granted by
# the explorer would have been overruled here and the adaptive budget would have
# changed nothing.
#
# So the wait is bounded by the HARD MAXIMUM rather than the starting budget,
# and released early by the explorer thread the moment it genuinely finishes.
# The run is still bounded - by MAX_EXPLORATION_BUDGET_SECONDS, which no amount
# of progress can move.
try:
    from sudarshan_core.engines.agentic.adaptive_budget import (
        ADAPTIVE_EXPLORATION_ENABLED,
        MAX_EXPLORATION_BUDGET_SECONDS,
    )
except Exception:  # pragma: no cover - keep the sandbox importable
    ADAPTIVE_EXPLORATION_ENABLED = False
    MAX_EXPLORATION_BUDGET_SECONDS = ANALYSIS_DURATION_SECONDS

# ── Session lifecycle pacing ──────────────────────────────────────────────────
# The session is OPEN -> ANALYSE -> CLOSE. Nothing may touch the UI until the
# app has finished starting: a cold Activity start on an emulator is routinely
# 2-4 s, and driving input into a half-started process is what crashed the app
# under analysis. Raise these on a slow or contended emulator.
APP_OPEN_SETTLE_SECONDS: float = float(os.getenv("SUDARSHAN_APP_OPEN_SETTLE", "8.0"))
APP_SETTLE_POLL_SECONDS: float = float(os.getenv("SUDARSHAN_APP_SETTLE_POLL", "0.5"))

# ── Autonomous anti-evasion ───────────────────────────────────────────────────
# The time-warp / persona sequence runs at the end of exploration, while the
# process is still alive and the hooks are still installed. That timing is the
# whole point: run it after the session and the counters it compares belong to a
# process that no longer exists, so the only reachable verdict is "not
# observed". Costs ~15s of a 300s run; set SUDARSHAN_ANTI_EVASION=0 to skip it.
ANTI_EVASION_ENABLED: bool = os.getenv("SUDARSHAN_ANTI_EVASION", "1").strip().lower() not in (
    "0", "false", "no", "off",
)
ANTI_EVASION_OBSERVE_SECONDS: float = float(
    os.getenv("SUDARSHAN_ANTI_EVASION_OBSERVE", "8.0")
)

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

# ── Spawn-gated instrumentation ───────────────────────────────────────────────
#
# The launch ladder below starts the app with `am start` and attaches AFTER the
# process is stable. Measured on a real run (dynamic_result.json, InsecureBankv2
# handing off to com.tjmonh.android): the process was alive at t+50s and Frida
# attached at t+86s. Thirty-six seconds of Application.attachBaseContext,
# Application.onCreate, DEX loading, service registration and the C2 first
# beacon executed with no hooks installed. The run finished with 77 hooks
# installed and exactly one hook fire - `Build.<static fields>`, which is the
# HARNESS spoofing its own emulator fields. Every fraud bucket read 0.
#
# Nothing about that is a tuning problem. Attaching to a running process cannot
# observe what the process already did, so whether a run captures anything
# depends on whether the sample happens to act again after the attach - which is
# why dynamic analysis "worked sometimes".
#
# So: spawn the process SUSPENDED, load the agent, and only then resume. Frida's
# own guidance is explicit that resume() must follow script.load() or early
# entry points cannot be hooked.
SPAWN_FIRST: bool = (os.getenv("SUDARSHAN_SPAWN_FIRST", "1").strip().lower()
                     not in {"0", "false", "no", "off"})
# device.spawn() on Android hangs when the forked zygote never reaches
# setArgV0() (frida/frida#3758, #2005). Bounded, and the ladder stays a real
# fallback rather than a formality.
SPAWN_TIMEOUT_SECONDS: float = float(os.getenv("SUDARSHAN_SPAWN_TIMEOUT", "30.0"))
SPAWN_MAX_ATTEMPTS: int = int(os.getenv("SUDARSHAN_SPAWN_ATTEMPTS", "3"))
# Device-wide spawn gating: every process the SAMPLE starts is caught suspended
# and instrumented before it runs a single instruction. This is what covers the
# dropper case - the payload package previously ran entirely uninstrumented
# because _detect_companion() only ran three times, all before exploration
# began, and a hand-off during exploration was never seen.
SPAWN_GATING: bool = (os.getenv("SUDARSHAN_SPAWN_GATING", "1").strip().lower()
                      not in {"0", "false", "no", "off"})
# How long after the process appears the agent may still be considered "early".
# Beyond this, a run that observed nothing from the sample is reported as
# INSTRUMENTED_TOO_LATE rather than as the sample having been quiet - see
# DynamicAnalysisStatus.INSTRUMENTED_TOO_LATE. Spawn-gated runs attach before
# the process executes anything and never reach this test.
INSTRUMENTATION_LATENCY_BUDGET_SECONDS: float = float(
    os.getenv("SUDARSHAN_INSTRUMENTATION_LATENCY_BUDGET", "5.0")
)
# How long the device's third-party package list stays fresh. Short enough that
# a payload the sample installs mid-run is seen, long enough that the gating
# handler never holds a suspended process waiting on adb. See _is_third_party.
_THIRD_PARTY_TTL_SECONDS: float = 3.0
# How long teardown waits for queued gated spawns to be instrumented and
# resumed. Each queued item is a process sitting suspended, so this is a
# drain deadline, not a politeness timeout.
SPAWN_WORKER_DRAIN_SECONDS: float = 20.0
# How long any single frida teardown call may take before it is abandoned.
# frida's Python API has no timeout of its own: unload() and detach() wait for
# a reply from an agent that, during teardown after a transport failure, is
# usually already gone. See the cleanup block in FridaSession.run.
FRIDA_TEARDOWN_TIMEOUT_SECONDS: float = float(
    os.getenv("SUDARSHAN_FRIDA_TEARDOWN_TIMEOUT", "10.0")
)

# How many times to relaunch after a crash that is OURS rather than the app's.
# See _crash_is_instrumentation_race: an ART JIT thread that SIGSEGVs while
# hooks are being installed into methods it is concurrently compiling is a race,
# and the same sample launches cleanly on a retry.
MAX_INSTRUMENTATION_RACE_RETRIES: int = int(
    os.getenv("SUDARSHAN_MAX_INSTRUMENTATION_RACE_RETRIES", "2")
)
# Let the process table and ART settle before trying again. Retrying instantly
# tends to reproduce the same race.
INSTRUMENTATION_RACE_BACKOFF_SECONDS: float = float(
    os.getenv("SUDARSHAN_INSTRUMENTATION_RACE_BACKOFF", "3.0")
)

#: Frames that identify ART's JIT compiler. A SIGSEGV on one of these threads,
#: with no Java exception, is the compiler tripping over instrumented methods -
#: not the sample crashing.
_ART_JIT_CRASH_MARKERS: Tuple[str, ...] = (
    "art::jit::",
    "JitCompile",
    "OptimizingCompiler",
    "HBasicBlockBuilder",
    "HGraphBuilder",
    "Jit thread pool",
    # ART's heap/GC daemon. Measured on Anubis under spawn-gated
    # instrumentation: "Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault
    # addr 0x0 in tid 8152 (HeapTaskDaemon)". Same phenomenon as the JIT thread
    # - an ART daemon tripping over methods being instrumented underneath it -
    # and it appears for the same reason: hooks now go in during startup, when
    # these daemons are busiest.
    "HeapTaskDaemon",
    "ReferenceQueueD",
)


def _crash_is_instrumentation_race(report: Optional["CrashReport"]) -> bool:
    """
    Whether this crash was caused by instrumenting the app rather than by the app.

    True only for a NATIVE crash inside ART's JIT compiler with no Java
    exception attached. A sample that throws is a sample that crashed, and must
    still stop the launch ladder on the first attempt - retrying it would spend
    the analysis window relaunching an app that cannot run.
    """
    if report is None:
        return False
    # A Java stacktrace means the app itself failed. Not ours, not retryable.
    if getattr(report, "exception_type", None) or getattr(report, "java_stacktrace", None):
        return False
    native = getattr(report, "native_stacktrace", None) or ""
    if not native:
        return False
    return any(marker in native for marker in _ART_JIT_CRASH_MARKERS)

# One lock per device serial. See run_frida_analysis for why.
_DEVICE_LOCKS: Dict[str, "asyncio.Lock"] = {}

# Time allowed for the explorer to finish AFTER being asked to stop. Must
# comfortably exceed one in-flight LLM round trip, otherwise artifacts are
# flushed while the agent loop is still mid-iteration.
EXPLORER_JOIN_GRACE_SECONDS: float = 20.0

# ── Global-deadline reserves ──────────────────────────────────────────────────
#
# Wall clock held back from the ONE 30-minute dynamic deadline so the run can
# always finish what it started. Finalisation is not exploration: draining the
# event bus, flushing the evidence store, reconstructing the workflow and
# computing BFCI are how the collected evidence becomes a result, and a run that
# spends its last second on one more tap has traded that evidence for nothing.
#
# Measured on the reference emulator: explorer join grace 20s, screenshot
# manager drain up to 30s, event-bus drain 8s, evidence flush and workflow
# reconstruction a few seconds - so 90s covers the tail with margin.
DYNAMIC_FINALISATION_RESERVE_SECONDS: float = float(
    os.getenv("SUDARSHAN_DYNAMIC_FINALISATION_RESERVE", "90")
)

#: What the anti-evasion sequence (time warp + persona seeding + re-observation)
#: costs. Consulted before it starts, so it is skipped and REPORTED rather than
#: run past the deadline.
ANTI_EVASION_COST_SECONDS: float = float(
    os.getenv("SUDARSHAN_ANTI_EVASION_COST_SECONDS", "60")
)

# How often the analysis window looks for a payload that was dropped and
# launched after the primary attach. A dropper's second stage does not exist at
# attach time, so the one-shot sweep there cannot see it; this is what catches
# it. Short enough that the payload is hooked within a few actions of appearing,
# long enough that the extra `pidof` costs nothing measurable against a
# multi-minute window. Override for a slow sandbox.
_COMPANION_SWEEP_INTERVAL_SECONDS: float = float(
    os.getenv("SUDARSHAN_COMPANION_SWEEP_SECONDS", "5")
)

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


#: The one agent constant the host is allowed to set, and the exact token it is
#: written as in the compiled bundle. Kept to a single BOOLEAN on purpose: this
#: is a string substitution into a script that runs inside the sample's process,
#: so the only safe value space is one that cannot express anything but true or
#: false. Nothing app-controlled reaches it - the value comes from an operator
#: environment variable and is re-rendered from a Python bool, never
#: interpolated.
_AGENT_DEOPT_TOKEN = "var DEOPT_BOOT_IMAGE_FORCED = false;"


def _apply_agent_config(script_source: str) -> str:
    """
    Render host-side agent configuration into the compiled bundle.

    Only `SUDARSHAN_DEOPT_BOOT_IMAGE` is honoured, and only as a boolean. See
    the agent's own comment for why boot-image deoptimization is off by default
    on API 34+: it stalls the device past Android's ANR watchdog, so the system
    kills the walk before the sample has rendered anything to observe.
    """
    raw = (os.getenv("SUDARSHAN_DEOPT_BOOT_IMAGE") or "").strip().lower()
    forced = raw in {"1", "true", "yes", "on"}
    if not forced:
        return script_source
    if _AGENT_DEOPT_TOKEN not in script_source:
        logger.warning(
            "[Frida] SUDARSHAN_DEOPT_BOOT_IMAGE is set but the agent bundle has "
            "no configuration slot - rebuild banking_trojan.bundle.js"
        )
        return script_source
    logger.info(
        "[Frida] Boot-image deoptimization FORCED on by "
        "SUDARSHAN_DEOPT_BOOT_IMAGE - expect a multi-second device stall after "
        "attach, and ANR dialogs over the sample on API 34+"
    )
    return script_source.replace(
        _AGENT_DEOPT_TOKEN, "var DEOPT_BOOT_IMAGE_FORCED = true;", 1,
    )


def _timeline_to_seconds(tl: LaunchTimeline) -> Dict[str, Optional[float]]:
    """
    Convert monotonic timestamps to seconds-since-apk-install offsets so the
    report is human-readable. Timestamps before apk_install (shouldn't happen)
    are kept as absolute monotonic values.

    Non-numeric entries are passed through untouched rather than subtracted.
    The timeline is typed ``Dict[str, Optional[float]]``, but it is a plain
    dict that several code paths write to, and one of them stored a package
    NAME in it (``first_window_package``) on the launch-hand-off path. This
    function then raised ``TypeError: unsupported operand type(s) for -: 'str'
    and 'float'`` - after a complete, successful dynamic run - which surfaced
    as a 500 from the analysis engine, a fail-closed 503 at the gateway, and a
    case whose report said dynamic analysis was never performed.

    A malformed telemetry ENTRY must never destroy the telemetry, so the loop
    is total: anything that cannot be expressed as an offset survives as
    itself. `base` is likewise only used when it is numeric.
    """
    base = tl.get("apk_install")
    if not isinstance(base, (int, float)) or isinstance(base, bool):
        base = None
    out: Dict[str, Optional[float]] = {}
    for k, v in tl.items():
        if v is None:
            out[k] = None
        elif isinstance(v, bool) or not isinstance(v, (int, float)):
            # Metadata rather than a milestone (e.g. the package that owned
            # the first window). Keep it - it is real evidence - but do not
            # pretend it is a duration.
            out[k] = v
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


def _process_sched_state(device: str, pid: int) -> str:
    """
    The kernel wait-channel for a pid, or "" - `do_freezer_trap` when frozen.

    Used only to explain an instrumentation failure. Cheap, best-effort, and
    never allowed to raise into the caller's error path.
    """
    try:
        ok, out = _adb(
            "-s", device, "shell", f"ps -A -o PID,S,WCHAN | grep -w {pid}",
            timeout=8,
        )
        return (out or "").strip().splitlines()[0].strip() if ok and out else ""
    except Exception:                               # noqa: BLE001
        return ""


def _channel_dump_hierarchy(device: str) -> str:
    """
    The UI hierarchy via the persistent uiautomator2 channel, or "".

    THE SHELL `uiautomator dump` AND THE u2 CHANNEL ARE MUTUALLY EXCLUSIVE.
    Android permits exactly one registered UiAutomation at a time. Once
    DeviceChannel connects, its on-device agent (`com.wetest.uia2.Main`, started
    from /data/local/tmp/u2.jar) holds that registration for the whole session,
    and every subsequent `adb shell uiautomator dump` dies with

        java.lang.IllegalStateException: UiAutomationService ... already registered!

    which surfaces as SIGKILL (rc=137) and an empty dump. Measured live on
    emulator-5554 (Android 17 / API 37): with the agent up, `uiautomator dump`
    returns rc=137 and writes no file; kill the agent and the same command
    returns rc=0 with a 4466-byte hierarchy.

    That mattered far beyond the dumps themselves. `_dismiss_blocking_system_dialog`
    finds its button by parsing this hierarchy, so an empty dump meant
    DeprecatedTargetSdkVersionDialog - which Android raises on the first launch
    of every legacy-targetSdk sample, i.e. most banking trojans - could never be
    dismissed. It logged "offers no button this harness is willing to press",
    stayed on top of the target, and the explorer spent its whole budget on
    whatever was behind it. Observed on Anubis (com.tjmonh.android, payload
    com.hsjjsjs.android): the eChallan form was never reached at all.

    Channel first, shell second, matching perception._dump_ui_xml.
    """
    try:
        from sudarshan_core.sandbox.device_channel import get_channel

        xml = get_channel(device).dump_hierarchy()
        return xml or ""
    except Exception as exc:                    # noqa: BLE001
        logger.debug("[Frida] channel dump_hierarchy unavailable: %s", exc)
        return ""


def _dump_ui_xml(device: str) -> str:
    """
    Read the current UI hierarchy, or "" if it cannot be read.

    Used by the lifecycle captures - the two frames an analyst always sees, the
    opened app and the final screen - and, more importantly, by
    `_dismiss_blocking_system_dialog`, which cannot find a button to press
    without it.

    Prefers the persistent channel: it is one call over an already-open
    connection instead of two shell round trips, and while that channel is
    connected the shell path CANNOT WORK AT ALL (see
    `_channel_dump_hierarchy`). Best-effort throughout: an unreadable hierarchy
    costs a sentence, never the screenshot.
    """
    xml = _channel_dump_hierarchy(device)
    if xml:
        return xml

    remote = "/data/local/tmp/sudarshan_lifecycle_ui.xml"
    ok, _ = _adb("-s", device, "shell", f"uiautomator dump {remote}", timeout=25)
    if not ok:
        return ""
    ok_cat, xml = _adb("-s", device, "shell", f"cat {remote}", timeout=15)
    _adb("-s", device, "shell", f"rm -f {remote}", timeout=5)
    if not ok_cat or not xml:
        return ""
    match = re.search(r"(<\?xml.*)", xml, re.DOTALL)
    return match.group(1) if match else ""


def _ui_dump_ok(device: str) -> bool:
    """
    Whether the UI hierarchy can be read at all - the "UI is ready" probe.

    Same mutual-exclusion problem as `_dump_ui_xml`: probing with a bare shell
    `uiautomator dump` reports "UI is not ready" for the entire run once the u2
    channel is connected, because the command is killed rather than because the
    UI is unready. The launch gate then fails a healthy app.
    """
    if _channel_dump_hierarchy(device):
        return True
    ok, out = _adb(
        "-s", device, "shell",
        "uiautomator dump /dev/null 2>&1 && echo UI_DUMP_OK",
        timeout=20,
    )
    return bool(ok and "UI_DUMP_OK" in (out or ""))


# ─── Blocking system dialogs ─────────────────────────────────────────────────
#
# A modal system dialog owns the focused window and sits ON TOP of the target,
# and `am start` cannot get behind it: re-issuing the launch intent leaves the
# dialog exactly where it was. The harness could not even see the problem,
# because `_foreground_package()` regexes the first `package/activity` pair out
# of dumpsys, and a system dialog contributes no such pair - so it read the
# launcher from `mFocusedApp` and concluded the app had simply not come forward.
#
# The one that matters in practice is DeprecatedTargetSdkVersionDialog ("This
# app was built for an older version of Android"). Android raises it on the
# FIRST launch after install for any sample whose targetSdk is far enough
# behind the device - which is every launch the sandbox performs, and most
# banking-trojan samples, which are years old. Measured on this emulator
# (Android 17 / API 37) with Cerberus (targetSdk 27): uninstall, reinstall,
# launch -> mCurrentFocus=DeprecatedTargetSdkVersionDialog, every time.
#
# The consequence was the whole dynamic axis. The app never reached the
# foreground, the explorer spent its action budget on the launcher behind the
# dialog, no hooks fired, BFCI came out 0.0, and the risk engine excluded the
# dynamic axis with NO_BEHAVIOR_OBSERVED - the exclusion that then floors the
# verdict to Inconclusive and prints no score at all.
#
# `am compat disable 171986851 <pkg>` (DEPRECATED_TARGET_SDK_VERSION) is the
# documented suppression and does NOT work here: API 37 reports the change as
# unknown, and A/B tested across a fresh install the dialog appears with the
# override applied exactly as without it. Dismissing the dialog is what works.
_BLOCKING_DIALOG_WINDOWS = (
    "DeprecatedTargetSdkVersionDialog",   # built for an older version of Android
    "UnsupportedDisplaySizeDialog",       # may not display properly on this screen
    "UnsupportedCompileSdkDialog",
    "AppErrorDialog",                     # "<app> keeps stopping"
    "BaseErrorDialog",
    "AppNotRespondingDialog",             # ANR - "<app> isn't responding"
    "AppWarnings",
)

# Ordered by preference. A blocking dialog usually offers one button that
# proceeds and one that ends the run; picking by LABEL rather than by button
# index is what keeps an ANR from being answered with "Close app", which would
# kill the process mid-analysis. Nothing outside this list is ever tapped -
# the dialog is left alone and reported rather than answered by guesswork.
_DIALOG_DISMISS_LABELS = (
    "wait",            # ANR: keep the process alive
    "ok",              # deprecated-target-sdk, unsupported display size
    "got it",
    "continue",
    "continue anyway",
    "open anyway",
    "close",           # crash dialogs: nothing left to keep alive
    "close app",
)

_UI_NODE_RE = re.compile(r"<node\b[^>]*>")


def _focused_window_name(device: str) -> str:
    """The raw mCurrentFocus window description, or "" if it cannot be read."""
    ok, out = _adb(
        "-s", device, "shell",
        "dumpsys window | grep -E 'mCurrentFocus'",
        timeout=15,
    )
    return out.strip() if ok and out else ""


def _blocking_dialog_in_focus(device: str) -> str:
    """
    Name of the blocking system dialog owning the focused window, else "".

    Matched on the window description rather than on the owning package: these
    dialogs are drawn by the system (package `android`), so a package check
    cannot tell them apart from any other system surface.
    """
    focus = _focused_window_name(device)
    if not focus:
        return ""
    for name in _BLOCKING_DIALOG_WINDOWS:
        if name in focus:
            return name
    return ""


def _dialog_dismiss_target(ui_xml: str) -> Optional[Tuple[int, int, str]]:
    """
    Centre point and label of the button that dismisses the dialog, or None.

    Only buttons whose label is in `_DIALOG_DISMISS_LABELS` are considered, and
    they are considered in that list's order, so "Wait" wins over "Close app"
    on an ANR no matter which one the dialog lists first.
    """
    if not ui_xml:
        return None

    candidates: Dict[str, Tuple[int, int]] = {}
    for match in _UI_NODE_RE.finditer(ui_xml):
        node = match.group(0)
        if 'clickable="true"' not in node:
            continue
        text_m = re.search(r'text="([^"]*)"', node)
        bounds_m = re.search(r'bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', node)
        if not text_m or not bounds_m:
            continue
        label = text_m.group(1).strip()
        if not label:
            continue
        x1, y1, x2, y2 = (int(g) for g in bounds_m.groups())
        candidates.setdefault(label.lower(), ((x1 + x2) // 2, (y1 + y2) // 2))

    for wanted in _DIALOG_DISMISS_LABELS:
        if wanted in candidates:
            x, y = candidates[wanted]
            return x, y, wanted
    return None


def _dismiss_blocking_system_dialog(device: str) -> Optional[Dict[str, str]]:
    """
    Dismiss a modal system dialog covering the target, if one is up.

    Returns a record of what was dismissed, or None when there was no blocking
    dialog (the overwhelmingly common case) or when it could not be answered
    safely. Never raises: a dialog that cannot be dismissed must degrade the
    run, not end it.
    """
    try:
        dialog = _blocking_dialog_in_focus(device)
        if not dialog:
            return None

        # The window is in focus a moment before its buttons are laid out, so a
        # dump taken the instant the dialog appears returns the frame without
        # them. Observed on the first attempt of a live run: "offers no button"
        # on the first pass, dismissed cleanly on the next. Retry here rather
        # than leaning on the caller's retry loop - by the time control returns
        # there, several seconds of the exploration budget have been spent
        # driving whatever is behind the dialog.
        target = None
        for _ in range(3):
            target = _dialog_dismiss_target(_dump_ui_xml(device))
            if target is not None:
                break
            time.sleep(0.8)

        if target is None:
            logger.warning(
                "[Frida] %s is blocking the target and offers no button this "
                "harness is willing to press - leaving it alone.", dialog,
            )
            return None

        x, y, label = target
        ok, _ = _adb("-s", device, "shell", f"input tap {x} {y}", timeout=15)
        if not ok:
            logger.warning("[Frida] Tap to dismiss %s failed.", dialog)
            return None

        time.sleep(1.0)
        still_up = _blocking_dialog_in_focus(device)
        if still_up == dialog:
            logger.warning("[Frida] %s survived the '%s' tap.", dialog, label)
            return None

        logger.info("[Frida] Dismissed blocking system dialog %s via '%s'.", dialog, label)
        return {"dialog": dialog, "button": label}
    except Exception as exc:                                        # noqa: BLE001
        logger.warning(
            "[Frida] Blocking-dialog check failed (%s: %s) - continuing.",
            type(exc).__name__, exc,
        )
        return None


def _foreground_package(device: str) -> str:
    comp = _get_foreground_component(device)
    if "/" in comp:
        return comp.split("/", 1)[0]
    return ""


#: `am start` output that means the component can never start, however long we
#: wait for it.
#:
#: Android answers immediately and definitively here - "Activity class {...}
#: does not exist" - and the ladder was ignoring that answer and then waiting
#: the full stability timeout for a process that could not appear.
#:
#: Measured on a packed sample whose manifest declares a launcher class the APK
#: does not contain (a common packer artifact, and the same reason frida.spawn
#: reports "unable to find a front-door activity"): three ladder steps each
#: burned 12s waiting on a component Android had already rejected, delaying the
#: Frida attach by ~36s. The sample had self-terminated by the time the agent
#: landed, and the run reported INSTRUMENTED_TOO_LATE - which was true, and
#: avoidable.
_ACTIVITY_REJECTED_MARKERS = (
    "does not exist",
    "error type 3",
    "unable to resolve intent",
    "no activities found to run",
    "permission denial",
    "activity not started, unable to resolve",
)


def _activity_start_was_rejected(output: str) -> str:
    """
    The reason `am start` refused, or "" when it did not refuse.

    Only DEFINITIVE refusals count. A start that succeeds and whose process
    then dies is a crash, and must keep its full diagnostic path - this is
    strictly about not waiting for something Android said would never happen.
    """
    text = (output or "").strip().lower()
    if not text:
        return ""
    for marker in _ACTIVITY_REJECTED_MARKERS:
        if marker in text:
            return marker
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

    # Channel first - the shell dump is dead while the u2 agent is connected,
    # which meant CONTINUE was never found and legacy-targetSdk samples stalled
    # on ReviewPermissionsActivity without ever starting their process.
    xml = _channel_dump_hierarchy(device)
    ok_dump = bool(xml)
    if not ok_dump:
        ok_dump, _ = _adb(
            "-s", device, "shell",
            "uiautomator dump /data/local/tmp/sudarshan_perm_ui.xml",
            timeout=25,
        )
    if ok_dump:
        ok_cat = True
        if not xml:
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


#: Whether declared runtime permissions are granted before the app is launched.
#:
#: Default ON, and deliberately so. It exists because a legacy-targetSdk app
#: cold-starts into ReviewPermissionsActivity, which leaves `pidof` empty and
#: breaks the launch ladder - turning it off wholesale trades a permission
#: dialog for a failed run.
#:
#: But it has a cost that was invisible until the permission investigator went
#: in: granting everything up front means Android never shows a runtime
#: permission dialog, so the investigation cannot observe *which* permissions
#: the sample actually asks for, and the dialog that the report is supposed to
#: screenshot never appears. What the app requests is a behaviour; what the
#: manifest declares is only an intention.
#:
#: Set SUDARSHAN_PREGRANT_PERMISSIONS=0 to observe the real request flow.
#: Changing it changes what the sandbox sees, and therefore BFCI inputs, so the
#: default is left alone until both modes have been measured on the corpus.
PREGRANT_PERMISSIONS: bool = os.getenv(
    "SUDARSHAN_PREGRANT_PERMISSIONS", "1"
).strip().lower() not in ("0", "false", "no")


def _declared_runtime_permissions(apk_path: str) -> List[str]:
    """Permission names the manifest declares, read with aapt."""
    perms: List[str] = []
    for tool in ("aapt2", "aapt"):
        aapt = _find_aapt_executable(tool)
        if not aapt:
            continue
        try:
            result = subprocess.run(
                [aapt, "dump", "permissions", apk_path],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
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
    return perms


def _grant_declared_runtime_permissions(
    device: str, apk_path: str, package_name: str
) -> List[str]:
    """
    Pre-grant declared runtime permissions via ``pm grant`` so cold-start does
    not block on ReviewPermissionsActivity (which leaves pidof empty).

    Returns the permissions that were actually granted, not a count: the
    investigation needs to know *which* capabilities the sample holds without
    ever having asked for them, and a bare integer cannot say that. Callers
    record these as GRANTED_WITHOUT_REQUEST - a finding about the harness
    rather than about the sample.

    Honours :data:`PREGRANT_PERMISSIONS`; returns [] when disabled.
    """
    import shlex as _shlex
    import shutil

    if not PREGRANT_PERMISSIONS:
        logger.info(
            "[Frida] Pre-granting disabled (SUDARSHAN_PREGRANT_PERMISSIONS=0) - "
            "the sample must request permissions at runtime, and the launch "
            "ladder may hit ReviewPermissionsActivity on a legacy-targetSdk app."
        )
        return []

    perms = _declared_runtime_permissions(apk_path)

    granted: List[str] = []
    safe_pkg = _shlex.quote(package_name)
    for perm in perms:
        if not perm.startswith("android.permission."):
            continue
        ok, out = _adb(
            "-s", device, "shell", f"pm grant {safe_pkg} {perm}", timeout=10,
        )
        if ok or "granted" in (out or "").lower():
            granted.append(perm)
        else:
            logger.debug("[Frida] pm grant skipped for %s: %s", perm, out)
    if granted:
        logger.info(
            "[Frida] Pre-granted %d declared permission(s) for %s before launch "
            "- no runtime permission dialog will be shown for these",
            len(granted), package_name,
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
    accept_handoff: Optional["callable"] = None,
) -> Tuple[bool, str]:
    """
    Wait for *package_name*, or a package it handed off to, to own the window.

    A stable PID proves the process exists; it does not prove the app launched.
    Android will happily keep a process alive that never inflates an Activity -
    an ANR at start, a dropper stub that finishes onCreate and returns, or a
    launcher intent that resolved to nothing. In that state every UI-driven hook
    (accessibility, overlay, credential capture) is unreachable, so the run
    yields no behaviour and the sample looks dormant.

    `accept_handoff` is called with the current dumpsys text and returns the
    package the sample handed the journey to, or None. It exists because a
    LOADER is a launch that succeeded: the target starts, immediately starts a
    second package that draws the UI, and stays alive behind it. Judging that
    on "did the TARGET own the window" reports a perfectly good launch as a
    failure, and the caller then walks its entire ladder of launch strategies -
    six attempts, ~12-19s each - re-launching an app that was already running
    and on screen. That burned ~90s of a 300s analysis window before
    exploration began, on every loader-style sample.

    Returns (rendered, package_that_owns_the_window). The second element is ""
    when nothing rendered, and names the companion on a hand-off so the caller
    can record which package drew the screen.
    """
    deadline = time.monotonic() + total_timeout
    while time.monotonic() < deadline:
        ok, out = _adb(
            "-s", device, "shell",
            "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
            timeout=10,
        )
        if ok and out and package_name in out:
            return True, package_name
        if ok and out and accept_handoff is not None:
            try:
                companion = accept_handoff(out)
            except Exception as exc:                       # noqa: BLE001
                # A hand-off probe that fails must not fail the launch gate;
                # fall through and keep waiting for the target itself.
                logger.debug("[Frida] hand-off probe failed: %s", exc)
                companion = None
            if companion:
                return True, companion
        time.sleep(poll_interval)
    return False, ""


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

            # ── Parse the exception, but only OUR exception ──────────────────
            #
            # This used to scan every error line in the buffer for any
            # "AndroidRuntime ... Exception", with no check that the crash
            # belonged to the sample. logcat is device-wide, so whatever
            # happened to be failing in the background became the sample's
            # cause of death - and the `if "FATAL EXCEPTION" in line: pass`
            # above it did nothing at all.
            #
            # Measured: two unrelated samples (com.sina.weibo and
            # com.tjmonh.android) both reported the identical
            # "java.lang.RuntimeException: Bad file descriptor" with no Java
            # stacktrace. That is one background exception being copied onto
            # two crash reports.
            #
            # It is not only a wrong label. _crash_is_instrumentation_race()
            # returns False as soon as exception_type is set - "a sample that
            # throws is a sample that crashed" - so a borrowed exception
            # silently disables the ART/JIT race retry that would have
            # relaunched a sample we broke ourselves.
            #
            # Android prints the block as:
            #     E/AndroidRuntime(1234): FATAL EXCEPTION: main
            #     E/AndroidRuntime(1234): Process: com.foo, PID: 1234
            #     E/AndroidRuntime(1234): java.lang.RuntimeException: ...
            # so the exception is claimed only after a Process: line naming the
            # target, within the same block.
            _in_fatal_block = False
            _block_is_ours = False
            for line in error_lines:
                if "FATAL EXCEPTION" in line:
                    _in_fatal_block = True
                    _block_is_ours = False
                    continue
                if not _in_fatal_block:
                    continue
                if "Process:" in line:
                    _block_is_ours = package_name in line
                    continue
                m = re.search(r"([A-Za-z][\w.]*Exception[^\n]*)", line)
                if m and _block_is_ours and not report.exception_type:
                    exc_str = m.group(1).strip()
                    if ":" in exc_str:
                        parts = exc_str.split(":", 1)
                        report.exception_type = parts[0].strip()
                        report.exception_message = parts[1].strip()
                    else:
                        report.exception_type = exc_str
                    _in_fatal_block = False
                elif m:
                    # An exception line for somebody else's block. Leave the
                    # report's cause unset rather than borrowing it.
                    _in_fatal_block = False

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

    # Check 5: UI hierarchy can be dumped.
    # Goes through _ui_dump_ok rather than a bare shell `uiautomator dump`: once
    # the u2 channel is connected the shell command is killed on every call, and
    # this gate would fail a perfectly healthy app for the whole run.
    if not _ui_dump_ok(device):
        return False, (
            "Check 5 FAIL: UI hierarchy could not be read via the device "
            "channel or `uiautomator dump` - UI is not ready."
        )
    logger.debug("[LaunchGate] Check 5 PASS: UI hierarchy readable")

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


def _collect_screenshots(session: "FridaSession") -> List[Dict[str, Any]]:
    """
    Return the full manifest record of every screenshot captured this session.

    Returns enriched dicts (not bare filenames) so report renderers can read
    description/capture_trigger/title without re-reading manifest.json.

    Never raises and never invents entries: a session with no ScreenshotManager,
    or one where every capture failed, yields [].
    """
    mgr = getattr(session, "screenshot_manager", None)
    if mgr is None:
        return []
    try:
        return [
            dataclasses.asdict(rec) for rec in mgr.get_manifest()
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
        static_findings: Optional[Dict[str, Any]] = None,
    ):
        self.device_serial = device_serial
        self.package_name = package_name
        self.main_activity = main_activity
        # What static analysis already learned about this sample: declared
        # permissions, app label, static flags.
        #
        # Before this existed the dynamic engine ran blind. AgenticExplorer has
        # always accepted `static_findings` and PerceptionPipeline has always
        # forwarded it into every Observation - but nothing upstream ever
        # supplied it, so it was `{}` on every real run. The engine could not
        # compare declared permissions against what the app requested at
        # runtime because it was never told what was declared.
        #
        # Optional on purpose: dynamic analysis must still run for callers that
        # have no static pass (validation harnesses, recovery re-runs). An empty
        # dict reproduces the previous behaviour exactly.
        self.static_findings: Dict[str, Any] = dict(static_findings or {})
        # Permissions granted by the harness before launch, so the explorer can
        # tell capability the sample asked for from capability we handed it.
        self.pregranted_permissions: List[str] = []
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
            # Code execution and payload deployment: shell exec, dynamic DEX
            # loading, writing an APK. Split out of dangerous_apis, which also
            # held PathClassLoader (every app loads its own APK through it) and
            # System.loadLibrary (any app with native code) - weighting that
            # mixed bucket would have inflated every verdict equally.
            "code_execution": [],
            # ── Unscored: evidence only ───────────────────────────────────────
            "dangerous_apis": [], "files_accessed": [],
            "anti_analysis": [],        # evasion attempted BY THE SAMPLE
            # Actions the HARNESS performed on the device (Build-field spoofing,
            # and anything else we do to conceal the sandbox). Held apart from
            # anti_analysis because scoring treats an evasion event as evidence
            # about the sample: filing our own countermeasure there excluded the
            # dynamic axis on five trojans and scored them Safe. Unregistered
            # categories fall through to dangerous_apis, so this bucket has to
            # exist for the split to hold.
            "harness_action": [],
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
        #: Per-screen view hierarchies from the explorer, for VIDE.
        self.state_ui_hierarchies: list = []
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
        # ── Companion packages (launch hand-off) ─────────────────────────────
        #
        # A loader renders nothing itself: it starts, launches a SECOND package
        # to draw the user-facing journey, and idles. Measured on an e-challan
        # sample - `START cmp=<other>/.MainActivity from uid <sample>` 211ms
        # after its own MainActivity - where the four-field form the victim
        # sees belongs entirely to the other package.
        #
        # Two things broke because nothing here knew about that:
        #   · Frida attached to the target PID only, so every hook lived in the
        #     idle loader and the process doing the work was uninstrumented.
        #     Runtime evidence was empty for a reason that had nothing to do
        #     with the sample's behaviour.
        #   · the first_activity/first_window milestones were stamped only when
        #     the foreground window mentioned the TARGET package, so an app that
        #     had plainly rendered a form was recorded as never rendering UI,
        #     and risk_engine excluded the dynamic axis as NO_UI_RENDERED.
        #
        # Both are answered from one detection, here, because attach happens
        # after the hand-off has already completed.
        self.companion_packages: List[str] = []
        #: Third-party packages present before the sample ran. Anything that
        #: appears later and has a process was dropped BY the sample.
        self._preexisting_packages: set = set()
        #: The package that actually owned the first window, when that was NOT
        #: the target. Kept here rather than in `launch_timeline`, which is a
        #: map of monotonic floats - putting a package name in it crashed
        #: `_timeline_to_seconds` and threw away the whole run.
        self.first_window_package: str = ""
        self._companion_sessions: Dict[str, Any] = {}
        self._companion_scripts: Dict[str, Any] = {}
        #: The device's third-party package set, re-read on a short TTL. Held
        #: as a SET rather than per-package answers so that a payload installed
        #: mid-run is discovered - see _is_third_party. None means never read.
        self._third_party_packages: Optional[set] = None
        self._third_party_fetched_at: float = 0.0
        # True when the package was still alive after `am force-stop` at the end
        # of the session - a persistence signal (watchdog service, restart
        # receiver), surfaced in the result rather than swallowed.
        self.survived_force_stop: bool = False
        # Before/after result of the autonomous anti-evasion sequence, run at
        # the end of exploration while the hooks are still live. None when the
        # sequence was disabled or could not run - never an empty result, which
        # would read as "measured, and nothing happened".
        self.anti_evasion_result: Optional[Dict[str, Any]] = None
        #: Set when the anti-evasion sequence was skipped rather than
        #: run, so the report can say "not attempted, and why" instead
        #: of leaving an empty result that reads as "attempted, nothing
        #: moved".
        self.anti_evasion_skipped_reason: str = ""
        #: Canonical behaviours observed this run, {behaviour: count},
        #: from the post-run reconciliation. The semantic counterpart
        #: to raw_event_counts: 50 `code_execution` events say nothing
        #: about WHICH code execution was seen.
        self.behavior_summary: Dict[str, int] = {}
        self.normalized_event_count: int = 0
        #: Raw output of the most recent launch command. Retained because
        #: `adb` exits zero even when Android refuses to start a
        #: component, so the exit code cannot tell a launch from a
        #: rejection - see _activity_start_was_rejected.
        self._last_launch_output: str = ""
        # True when lifecycle screenshots were taken while another package owned
        # the foreground (typically the launcher home screen).
        self.foreground_mismatch: bool = False
        # Modal system dialogs this run had to clear out of the way, in order.
        # Surfaced on the result so an analyst reading a thin dynamic section
        # can tell "the sandbox was blocked and said so" from "the sample did
        # nothing", and so a recurring blocker is visible rather than inferred.
        self.system_dialogs_dismissed: List[Dict[str, str]] = []
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

        # ── Spawn gating ──────────────────────────────────────────────────────
        # True when the agent was loaded into a SUSPENDED process, i.e. before
        # the app executed anything. False means we fell back to the `am start`
        # ladder and attached to an already-running process, which cannot
        # observe startup behaviour - so this flag is the difference between
        # "the sample did nothing" and "we arrived too late to see it".
        self.spawn_gated: bool = False
        self.spawn_fallback_reason: str = ""
        # True when device.spawn() actually confirmed the launch, so the process
        # is OURS and suspended. False on the recovery path, where frida timed
        # out confirming a launch it had in fact performed - the app is running
        # and must NOT be resumed, only attached to.
        self.spawn_confirmed: bool = True
        # The connected frida Device, held so teardown can disable spawn gating
        # from the `finally` block where the local would be unbound.
        self._device: Any = None
        # True when device-wide spawn gating is active, so any process the
        # sample starts is caught suspended and instrumented.
        self._spawn_gating_enabled: bool = False
        # Gated spawns handed off frida's callback thread. Unbounded: dropping
        # an item would leave a process suspended forever. See _on_spawn_added.
        self._spawn_queue: "queue.Queue" = queue.Queue()
        self._spawn_worker_thread: Optional[threading.Thread] = None

        # ── Wave 1: Evidence Store ─────────────────────────────────────────────
        # The case this session belongs to - the content sha256 on a real run,
        # which is also the id the investigation UI keys its panels on. It was
        # previously forwarded to the evidence store and then forgotten, so
        # nothing else in the session could say which case it was analysing.
        self.case_id: str = case_id

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

    # ── Companion packages (launch hand-off) ─────────────────────────────────

    def _is_third_party(self, package: str) -> bool:
        """
        Whether `package` was installed onto this device rather than shipped
        with the image.

        Asked of the device instead of matched against a denylist, because a
        denylist of "packages that are not payloads" cannot be written - the
        payload's package name is unknown and frequently random. The launcher,
        Settings and Chrome are system packages on every image we run, so this
        one question excludes them all without naming any.

        A failed query answers False: an unreadable device narrows what we are
        willing to instrument rather than widening it.

        The whole third-party SET is cached with a short TTL, rather than one
        yes/no per package. Two reasons, both load-bearing:

          * A negative used to be cached forever. `pm list packages -3` is
            asked once per package name, so a payload the sample INSTALLS
            mid-run - the dropper case this engine exists to catch - was
            answered False before it existed and never re-asked. It could then
            never be instrumented, no matter how many times it was seen.
          * Under spawn gating this runs on frida's callback thread while the
            spawned process is SUSPENDED, and every unseen package name cost a
            full adb round trip. Device-wide gating means that is every system
            process the device starts. Membership in a cached set is free; the
            set is refreshed at most once per _THIRD_PARTY_TTL_SECONDS, which
            is short enough to see a freshly installed payload and long enough
            that no process is held suspended waiting for adb.
        """
        now = time.monotonic()
        if (
            self._third_party_packages is None
            or (now - self._third_party_fetched_at) > _THIRD_PARTY_TTL_SECONDS
        ):
            ok, out = _adb(
                "-s", self.device_serial, "shell", "pm list packages -3", timeout=20,
            )
            if ok:
                self._third_party_packages = {
                    line.split(":", 1)[1].strip()
                    for line in (out or "").splitlines()
                    if line.strip().startswith("package:")
                }
                self._third_party_fetched_at = now
            elif self._third_party_packages is None:
                # Never successfully read. Answer False without caching, so the
                # next question re-asks rather than freezing an unread device
                # into "nothing here is third party".
                return False
        return package in (self._third_party_packages or set())

    def _foreground_package(self, window_dump: Optional[str] = None) -> str:
        """
        The package owning the foreground window, or "" if unreadable.

        `window_dump` of None means "read it yourself"; an empty STRING means
        the caller already read it and got nothing. The two are different facts
        - "not asked" versus "asked and the device said nothing" - and
        collapsing them would turn a failed adb call into a fresh query whose
        answer describes a later moment than the one being judged.
        """
        dump = window_dump
        if dump is None:
            _ok, dump = _adb(
                "-s", self.device_serial, "shell",
                "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'",
                timeout=15,
            )
        if not dump:
            return ""
        match = re.search(r"([A-Za-z][\w.]+)/[\w.$]+", dump)
        return match.group(1) if match else ""

    def _detect_companion(self, window_dump: Optional[str] = None) -> Optional[str]:
        """
        A package the SAMPLE launched to render its own journey, if there is one.

        Three conditions, each removing a specific way this could go wrong:

        1. The foreground is not the target and not a system surface. A
           launcher or a Settings screen is not a payload.
        2. It is a third-party package - installed onto the device, like the
           sample itself.
        3. The sample's own process is still alive behind it. A sample that
           died and left something else on screen did not hand off to it.

        Deliberately NOT conditioned on any name, label or hash: the loader and
        its payload are unknown packages, and the whole point is to recognise
        the RELATIONSHIP from what the device reports.
        """
        foreground = self._foreground_package(window_dump)
        if not foreground or foreground == self.package_name:
            return None
        if foreground in self.companion_packages:
            return foreground
        # Imported here rather than at module scope: screenshot_policy owns
        # these sets, and this module is imported by tooling that must not pull
        # the agentic package in.
        from sudarshan_core.engines.agentic.screenshot_policy import (
            INSTALLER_PACKAGES,
            LAUNCHER_PACKAGES,
            SETTINGS_PACKAGES,
            SYSTEM_UI_PACKAGES,
            VPN_DIALOG_PACKAGES,
        )

        if foreground in LAUNCHER_PACKAGES or foreground in SYSTEM_UI_PACKAGES:
            return None
        if foreground in INSTALLER_PACKAGES or foreground in SETTINGS_PACKAGES:
            return None
        if foreground in VPN_DIALOG_PACKAGES:
            return None
        if not self._is_third_party(foreground):
            return None
        if not self._resolve_pid():
            logger.info(
                "[Frida] HANDOFF rejected: %s is in front but %s is no longer "
                "running, so the sample did not hand off to it",
                foreground, self.package_name,
            )
            return None
        return foreground

    def _companion_message_handler(self, package: str):
        """
        Route a companion's hook events into the same collection as the target's.

        The source package is stamped onto every event so the report can say
        WHICH process a behaviour came from. Evidence from a payload is still
        evidence about this investigation, but attributing it to the loader
        would be a fabrication.
        """
        def _handler(message: Dict, data: Any) -> None:
            try:
                if message.get("type") == "send":
                    payload = message.get("payload")
                    if isinstance(payload, dict):
                        event = payload.get("payload")
                        target = event if isinstance(event, dict) else payload
                        target.setdefault("source_package", package)
                        target.setdefault("companion_of", self.package_name)
            except Exception:
                # Provenance is a nicety; losing it must never lose the event.
                pass
            self._on_message(message, data)
        return _handler

    @staticmethod
    def _unfreeze_guest_for_instrumentation(device_serial: str) -> None:
        """
        Turn off Android's cached-app freezer for the duration of the run.

        A dropper's payload spends most of the walk in the background - the
        explorer is off in the package installer, the permission controller or
        Settings - and Android freezes cached processes. A frozen process does
        not schedule, so Frida's injection handshake cannot complete and
        `device.attach(pid)` fails with `TransportError: timeout was reached`.
        The process that does the fraud is exactly the one most likely to be
        frozen, because it is exactly the one not in the foreground.

        Same category of change as `setenforce 0`: it makes the guest
        observable. The guest is already treated as fully compromised after
        every session, so relaxing it costs nothing that was not already spent.

        Best-effort - a device that will not accept the setting still runs.
        """
        for cmd in (
            "settings put global cached_apps_freezer disabled",
            "device_config put activity_manager_native_boot use_freezer false",
        ):
            ok, out = _adb("-s", device_serial, "shell", cmd, timeout=10)
            if not ok:
                logger.debug("[Frida] Freezer disable step failed (%s): %s", cmd, out)
        logger.info(
            "[Frida] Cached-app freezer disabled for this run - a backgrounded "
            "payload stays schedulable, so it can still be instrumented."
        )

    def _await_analysis_window(
        self, device: Any, script_source: str, wait_timeout: float,
    ) -> None:
        """
        Hold the analysis window open, instrumenting payloads as they appear.

        Companion instrumentation used to happen ONCE, immediately after the
        primary attach. That is the wrong moment for a dropper: the payload does
        not exist yet. Anubis (com.tjmonh.android, "RTO eChallan") ships a stub
        loader whose only screen is "New Update Available / Install"; the payload
        com.hsjjsjs.android is written and launched MINUTES into the walk, once
        the explorer has driven Install -> package installer -> Update. By then
        the one-shot sweep had long finished, so the process that actually
        renders the credential form and does the fraud was never hooked.

        Measured consequence: the explorer reached the four-field Challan
        Details form and completed it, the run recorded 19 screens and 17 button
        clicks - and BFCI came out 0.0 with activities_triggered empty, because
        every hook lived in the loader idling behind the payload. The only
        categories that ever fired were `smoke` and `app_telemetry`, neither of
        which carries BFCI weight.

        Waiting in slices instead of one long `wait()` keeps the stop-event
        semantics identical - `wait` still returns as soon as stop() is called -
        while giving the sweep somewhere to run.
        """
        deadline = time.monotonic() + wait_timeout
        while time.monotonic() < deadline:
            slice_s = min(_COMPANION_SWEEP_INTERVAL_SECONDS, deadline - time.monotonic())
            if slice_s <= 0:
                break
            if self._stop_event.wait(timeout=slice_s):
                return                                    # stop() was called
            try:
                self._sweep_for_new_companions(device, script_source)
            except Exception as exc:                      # noqa: BLE001
                # A sweep that raises must never end the analysis window.
                logger.debug("[Frida] Companion sweep error: %s", exc)
            try:
                # Answer a modal system dialog that appeared mid-walk.
                #
                # The launch-time dismissal cannot cover this: the dialog that
                # matters most here is AppNotRespondingDialog, and it arrives
                # DURING exploration, not before it. Measured on the Anubis
                # payload, whose WebView blocks on a C2 that no longer answers:
                # "Application Not Responding: com.hsjjsjs.android" was raised
                # repeatedly through the run and left standing. While it is up
                # the app is not driveable AND its main thread sits in
                # futex_wait_queue, so `device.attach(pid)` times out too - one
                # unanswered dialog costs both the exploration and the
                # instrumentation.
                #
                # "Wait" is first in _DIALOG_DISMISS_LABELS precisely so an ANR
                # is answered by keeping the process alive rather than by
                # "Close app", which would end the run being analysed.
                dismissed = _dismiss_blocking_system_dialog(self.device_serial)
                if dismissed:
                    logger.info(
                        "[Frida] MID_RUN_DIALOG_DISMISSED %s - the walk and the "
                        "hooks can both proceed", dismissed,
                    )
            except Exception as exc:                      # noqa: BLE001
                logger.debug("[Frida] Mid-run dialog dismissal error: %s", exc)

    def snapshot_preexisting_packages(self) -> None:
        """Record the third-party packages present before the sample ran."""
        ok, out = _adb(
            "-s", self.device_serial, "shell", "pm list packages -3", timeout=20,
        )
        if not ok or not out:
            logger.debug("[Frida] Could not snapshot pre-existing packages")
            return
        self._preexisting_packages = {
            line.strip().replace("package:", "")
            for line in out.splitlines() if line.strip()
        }

    def _dropped_packages_running(self) -> List[str]:
        """
        Packages installed by the sample during this run that have live processes.

        This is what finds a payload the sandbox has no other way to name.
        `_detect_companion` cannot: it requires the companion to be in the
        FOREGROUND, and during a walk the foreground is usually the package
        installer, the permission controller or Settings - so the payload is
        invisible to it for most of the run, which is precisely when it needs
        instrumenting.
        """
        if not self._preexisting_packages:
            return []
        ok, out = _adb(
            "-s", self.device_serial, "shell", "pm list packages -3", timeout=20,
        )
        if not ok or not out:
            return []
        now = {
            line.strip().replace("package:", "")
            for line in out.splitlines() if line.strip()
        }
        dropped = now - self._preexisting_packages - {self.package_name}
        if not dropped:
            return []
        live: List[str] = []
        for pkg in dropped:
            ok_p, out_p = _adb(
                "-s", self.device_serial, "shell", "pidof", pkg, timeout=8,
            )
            if ok_p and any(t.isdigit() for t in (out_p or "").split()):
                live.append(pkg)
        return live

    def _sweep_for_new_companions(self, device: Any, script_source: str) -> None:
        """
        Attach the agent to any payload that has appeared since the last pass.

        Three sources, because a dropper can surface any of these ways round:
          * `_detect_companion()` - the package currently drawing the foreground,
            which is how a launch hand-off shows up;
          * `companion_packages` - anything the hand-off detector has already
            adopted but the sandbox has not yet hooked;
          * `_dropped_packages_running()` - anything the SAMPLE installed during
            this run that now has a process. This is the one that catches a
            payload while the explorer is away in the installer or Settings,
            which is where it spends most of a dropper walk.
        """
        candidates: List[str] = []
        try:
            detected = self._detect_companion()
        except Exception:                                 # noqa: BLE001
            detected = None
        if detected:
            candidates.append(detected)
        candidates.extend(self.companion_packages)
        try:
            candidates.extend(self._dropped_packages_running())
        except Exception as exc:                          # noqa: BLE001
            logger.debug("[Frida] dropped-package scan failed: %s", exc)

        for pkg in candidates:
            if not pkg or pkg == self.package_name:
                continue
            if pkg in self._companion_sessions:
                continue
            if self._attach_companion(device, pkg, script_source):
                logger.info(
                    "[Frida] LATE_COMPANION_INSTRUMENTED %s - dropped during the "
                    "run and hooked mid-window; its behaviour is now observable",
                    pkg,
                )

    def _attach_companion(self, device: Any, package: str, script_source: str) -> bool:
        """
        Instrument a companion package with the same agent as the target.

        Failure is logged and returns False rather than raising: a run that
        cannot instrument the payload is a WORSE run, but it is still a run,
        and the target's own session must survive the attempt.
        """
        if package in self._companion_sessions:
            return True
        ok, out = _adb("-s", self.device_serial, "shell", "pidof", package, timeout=10)
        pid = next(
            (int(t) for t in (out or "").split() if t.isdigit()), None,
        ) if ok else None
        if pid is None:
            logger.warning(
                "[Frida] Companion %s has no running process - not instrumented",
                package,
            )
            return False
        try:
            session = device.attach(pid)
            script = session.create_script(script_source)
            script.on("message", self._companion_message_handler(package))
            script.load()
        except Exception as exc:                      # noqa: BLE001
            # Record WHY, not just that it failed. `TransportError: timeout was
            # reached` has two very different causes that the message cannot
            # distinguish: a process Android has frozen (cached-app freezer -
            # scheduler state `do_freezer_trap`, injection handshake never runs)
            # and a frida-server saturated by the explorer's own traffic. The
            # scheduler state tells them apart, and without it a run that failed
            # to instrument the payload leaves nothing to diagnose from.
            state = _process_sched_state(self.device_serial, pid)
            logger.warning(
                "[Frida] Could not instrument companion %s (pid=%d, sched=%s): "
                "%s: %s - the payload's behaviour will NOT be observed, so "
                "silence from it is absence of observation, not absence of "
                "behaviour.",
                package, pid, state or "unknown", type(exc).__name__, exc,
            )
            return False

        self._companion_sessions[package] = session
        self._companion_scripts[package] = script
        if package not in self.companion_packages:
            self.companion_packages.append(package)
        logger.info(
            "[Frida] COMPANION_INSTRUMENTED parent=%s companion=%s pid=%d - "
            "the package rendering the journey is now hooked",
            self.package_name, package, pid,
        )
        if self.event_bus:
            try:
                self.event_bus.publish({
                    "type": "event",
                    "category": "multi_stage",
                    "severity": "MEDIUM",
                    "data": {
                        # Named for what was observed - a foreground hand-off
                        # while the sample stayed alive - not for an API we did
                        # not hook.
                        "hook": "activity.launch_handoff",
                        "description": (
                            f"{self.package_name} launched {package}, which "
                            f"renders the user-facing journey; {package} has "
                            f"been instrumented as part of this investigation"
                        ),
                        "package": self.package_name,
                        "child_package": package,
                    },
                })
            except Exception:
                pass
        return True

    # ── Host-driven WebView drain ────────────────────────────────────────────

    def _webview_instrumentation_summary(self) -> Dict[str, int]:
        """
        How many WebViews each agent is injecting into.

        Read so the report can distinguish "the page made no requests" from
        "there was no page to watch" - opposite claims that a bare zero renders
        identically. Never drives the drain: an rpc call arrives on a thread
        that is not attached to the VM, and Java.choose from there hangs rather
        than failing. The drain is triggered inside the agent, on the UI thread,
        by the victim's own touches.
        """
        summary: Dict[str, int] = {}
        scripts = [(self.package_name, getattr(self, "_script", None))]
        scripts += list(getattr(self, "_companion_scripts", {}).items())
        for label, script in scripts:
            if script is None:
                continue
            try:
                exports = getattr(script, "exports_sync", None) or script.exports
                summary[label] = int(exports.webview_count())
            except Exception as exc:                  # noqa: BLE001
                logger.debug("[Frida] webview_count unavailable for %s: %s", label, exc)
        return summary

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

    def _clear_blocking_dialog(self) -> bool:
        """
        Dismiss a modal system dialog covering the target, and record that we did.

        Recorded as `harness_action`, never as `anti_analysis`: this is something
        the HARNESS did to the device, and the scoring path reads an
        anti_analysis event as proof the SAMPLE evaded - which would exclude the
        dynamic axis and floor the verdict, the exact outcome this method exists
        to prevent. Same reasoning as the Build-field spoofing event.
        """
        record = _dismiss_blocking_system_dialog(self.device_serial)
        if not record:
            return False

        self.system_dialogs_dismissed.append(record)
        now_ms = int(time.time() * 1000)
        self.collected_events["harness_action"].append({
            "event_id": f"ev_{now_ms}_dialog{len(self.system_dialogs_dismissed)}",
            "timestamp": now_ms,
            "package": self.package_name,
            "process": self.package_name,
            "event_type": "HARNESS_ACTION",
            "category": "harness_action",
            "severity": "INFO",
            "method": "sandbox.system_dialog_dismissed",
            "hook": "sandbox.system_dialog_dismissed",
            "class": "android.app.AlertDialog",
            "class_name": "android.app.AlertDialog",
            "source": "harness",
            "actor": "harness",
            "arguments": [],
            "return_value": None,
            "stack_trace": [],
            "evidence": (
                f"SANDBOX ACTION: the system dialog {record['dialog']} was "
                f"covering the target and blocking every launch intent; the "
                f"harness dismissed it via '{record['button']}' so the "
                f"application could be exercised (performed by the harness, "
                f"not by the application)."
            ),
            "data": {
                "hook": "sandbox.system_dialog_dismissed",
                "actor": "harness",
                "severity": "INFO",
                "dialog": record["dialog"],
                "button": record["button"],
            },
        })
        return True

    def _ensure_target_foreground(self, attempts: int = 4) -> bool:
        for attempt in range(attempts):
            pkg = _foreground_package(self.device_serial)
            if pkg == self.package_name:
                return True

            # Before re-issuing the launch intent, check whether anything can
            # get through at all. A modal system dialog sits above the target
            # and swallows the launch: `am start` returns success, the activity
            # is resumed behind the dialog, and the foreground never changes -
            # so without this the loop burns all its attempts and every one of
            # them is a no-op. Dismissing first is what makes the retry mean
            # something.
            if self._clear_blocking_dialog():
                if _foreground_package(self.device_serial) == self.package_name:
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
                # Same reason as in _ensure_target_foreground: a dialog on top
                # makes the relaunch a no-op, so this loop would otherwise spin
                # until `timeout` and then report "did not settle".
                self._clear_blocking_dialog()
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

    def _describe_lifecycle_screen(self, activity: str) -> Optional[Any]:
        """
        Read the screen behind a lifecycle frame, or None if it cannot be read.

        Best-effort in every step: a failed dump, an unparsable hierarchy or a
        classifier that cannot name the screen each degrade the sentence rather
        than costing the screenshot.
        """
        try:
            ui_xml = _dump_ui_xml(self.device_serial)
            from sudarshan_core.engines.agentic.ui_observation import (
                _widgets_from_xml,
                describe_screen,
            )
            widgets = _widgets_from_xml(ui_xml) if ui_xml else []
            screen_type = ""
            if widgets:
                from sudarshan_core.engines.agentic.screen_classifier import (
                    classify_screen,
                )
                screen_type = classify_screen(
                    activity, widgets, ui_xml, self.package_name,
                ).screen_type
            return describe_screen(
                activity=activity,
                ui_xml=ui_xml,
                screen_type=screen_type,
            )
        except Exception as exc:
            logger.debug("[Frida] Lifecycle screen description failed: %s", exc)
            return None

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
            # The hierarchy behind the frame, so the manifest can say what the
            # screen SHOWS rather than only that a lifecycle capture happened.
            #
            # The classification is resolved HERE and handed over as a finished
            # observation rather than passed to capture() as `semantic_type`.
            # That parameter also feeds the ScreenshotPolicy's ownership
            # resolution, and a lifecycle frame must be captured on the strength
            # of being a lifecycle frame - not become suppressible because the
            # classifier read the final screen as a launcher.
            observation = self._describe_lifecycle_screen(activity)
            ref = self.screenshot_manager.capture(
                label=label, category=category, source="lifecycle",
                reason="LIFECYCLE", force=True, activity=activity,
                screen_observation=observation,
            )
            if ref:
                logger.info(f"[Frida] Screenshot captured: {label}")
        except Exception as exc:
            logger.warning(
                f"[Frida] Lifecycle screenshot '{label}' failed "
                f"({type(exc).__name__}: {exc}) - continuing."
            )

    def _hook_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Per-session hook counts for the anti-evasion delta.

        Read straight off this session's own ``collected_events`` rather than
        any process-wide buffer, so the counts belong to *this* sample and
        nothing else running on the host can contribute to the delta.

        ``attached`` is False unless the Java bridge really came up. Hooks that
        were never installed cannot fire, and reporting their absence as "zero
        SMS reads" would turn an instrumentation failure into a finding about
        the sample.
        """
        attached = bool(
            self.canary_received
            and self.java_hooks_installed > 0
            and not self.java_bridge_failed
        )
        return {
            "attached": attached,
            "source": f"live Frida session ({self.hooks_installed_count} hooks installed)",
            "counts": {cat: len(events) for cat, events in self.collected_events.items()},
        }

    def _run_anti_evasion_sequence(self) -> None:
        """
        Time-warp and persona-seed the device, and measure what changed.

        Runs at the end of exploration and before the app is closed, which is
        the only window where the measurement is meaningful: the process is
        alive, the hooks are installed and counting, and anything the sample
        does in reaction lands in this session's own event buckets.

        Never raises. A sandbox control failing is a degraded run, not a failed
        analysis, and the sample's telemetry so far is still worth reporting.
        """
        from sudarshan_core.engines.anti_evasion import AntiEvasionOrchestrator

        logger.info(
            "[Frida] ANTI-EVASION: time warp + synthetic persona on %s",
            self.device_serial,
        )
        try:
            orchestrator = AntiEvasionOrchestrator(
                self.device_serial,
                self.package_name,
                telemetry_probe=self._hook_telemetry_snapshot,
            )
            result = orchestrator.run_sequence(
                observation_seconds=ANTI_EVASION_OBSERVE_SECONDS,
                session_id=self.case_id or self.package_name,
                restore=True,
            )
            self.anti_evasion_result = result.to_dict()
            logger.info(
                "[Frida] ANTI-EVASION: %s (%s)",
                result.verdict,
                ", ".join(result.triggered_keys) or "no threat-class delta",
            )
            # The screen after the sequence is evidence in its own right: a
            # dormancy-broken sample often has an overlay up by now, and the
            # final lifecycle screenshot is taken after the app is closed.
            self._capture_screenshot("90_after_anti_evasion", "lifecycle")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[Frida] ANTI-EVASION: sequence failed (%s: %s) - continuing",
                type(exc).__name__,
                exc,
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

    # ── Spawn-gated instrumentation ──────────────────────────────────────────

    def _on_spawn_added(self, spawn: Any) -> None:
        """
        frida `spawn-added` signal handler. MUST NOT call back into frida.

        This runs on frida's own callback thread. frida-python's `_invoke`
        dispatches every API call onto frida's main context and then waits for
        the reply - so calling `device.attach()` from here waits for a context
        that is currently executing THIS function. It deadlocks, permanently,
        and it takes any other thread in a frida call down with it.

        Observed exactly that: two threads parked forever in
        `frida/__init__.py:210 _invoke -> Event.wait()`, one from this handler
        and one from the launch ladder's own attach, with the run producing no
        further output while uvicorn kept serving health checks.

        So the handler does one non-frida thing - hand the spawn to a worker -
        and returns. The queue is unbounded on purpose: a dropped item would be
        a process left suspended, and resuming it from here is precisely what
        is not allowed.
        """
        self._spawn_queue.put(
            (getattr(spawn, "pid", None), getattr(spawn, "identifier", "") or "")
        )

    def _spawn_worker(self, device: Any, script_source: str) -> None:
        """Drain gated spawns off frida's callback thread, where blocking is safe."""
        while True:
            item = self._spawn_queue.get()
            if item is None:               # shutdown sentinel
                self._spawn_queue.task_done()
                return
            pid, identifier = item
            try:
                self._instrument_gated_spawn(device, pid, identifier, script_source)
            except Exception as exc:       # noqa: BLE001
                logger.error(
                    "[Frida] Spawn worker failed on %s (pid=%s): %s",
                    identifier or "?", pid, exc,
                )
            finally:
                self._spawn_queue.task_done()

    def _instrument_gated_spawn(
        self, device: Any, pid: Optional[int], identifier: str, script_source: str,
    ) -> None:
        """
        Handle one gated spawn: instrument it if it is the sample's, resume it.

        Called ONLY from _spawn_worker, never from the frida callback thread -
        every frida call below would deadlock there. See _on_spawn_added.

        Resume is unconditional and runs in a `finally`. A gated spawn that is
        never resumed stays suspended forever, and because gating is device-wide
        that would freeze system processes and take the emulator down with it -
        turning a missed hook into a dead sandbox.
        """
        try:
            if pid is None:
                return
            # Only the sample's own processes are worth the attach cost. Asked
            # of the device (pm list packages -3) rather than matched against a
            # denylist, for the reason _is_third_party documents: the payload's
            # package name is unknown and usually random.
            if not identifier or not self._is_third_party(identifier):
                return
            if identifier in self._companion_sessions:
                return
            # The target's own primary session is created by _spawn_gated_launch
            # and owns self._script. Loading a second agent into the same
            # process would double every event it reports.
            if identifier == self.package_name and self._session is not None:
                return
            session = device.attach(pid)
            script = session.create_script(script_source)
            if identifier == self.package_name:
                script.on("message", self._on_message)
            else:
                script.on("message", self._companion_message_handler(identifier))
            script.load()
            self._companion_sessions[identifier] = session
            self._companion_scripts[identifier] = script
            if identifier not in self.companion_packages:
                self.companion_packages.append(identifier)
            logger.info(
                "[Frida] SPAWN_GATED_INSTRUMENTED %s (pid=%s) - hooks are in "
                "place before the process executes its first instruction",
                identifier, pid,
            )
            if self.event_bus:
                try:
                    self.event_bus.publish({
                        "type": "event",
                        "category": "multi_stage",
                        "severity": "MEDIUM",
                        "data": {
                            "hook": "process.spawn_gated",
                            "description": (
                                f"{self.package_name} started process "
                                f"{identifier}, which was caught suspended and "
                                f"instrumented before it ran"
                            ),
                            "package": self.package_name,
                            "child_package": identifier,
                        },
                    })
                except Exception:
                    pass
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Could not instrument gated spawn %s (pid=%s): %s: %s - "
                "resuming it uninstrumented; its behaviour will NOT be observed.",
                identifier or "?", pid, type(exc).__name__, exc,
            )
        finally:
            if pid is not None:
                try:
                    device.resume(pid)
                except Exception as exc:               # noqa: BLE001
                    logger.error(
                        "[Frida] FAILED to resume gated spawn pid=%s (%s): %s - "
                        "the process is stuck suspended.",
                        pid, identifier or "?", exc,
                    )

    def _enable_spawn_gating(self, device: Any, script_source: str) -> bool:
        """
        Catch every process the sample starts, instrument it, then resume it.

        This is the fix for droppers. `_detect_companion()` is called three
        times, all of them before exploration starts, so a hand-off that happens
        mid-run - which is the normal case, the payload launches after the
        victim taps something - was never instrumented. A real run shows exactly
        that: clicking "New Update Available" moved the foreground to
        com.tjmonh.android, and nothing ever attached to it.

        Gating removes the race instead of narrowing it: there is no window in
        which a new process can run uninstrumented.

        Returns False (and leaves the run to the companion-polling path) when
        the device does not support gating, rather than failing the session.
        """
        if not SPAWN_GATING:
            logger.info("[Frida] Spawn gating disabled by SUDARSHAN_SPAWN_GATING")
            return False
        try:
            # Worker first: the handler starts queueing the moment gating is on,
            # and a queued spawn stays SUSPENDED until something drains it.
            self._spawn_worker_thread = threading.Thread(
                target=self._spawn_worker,
                args=(device, script_source),
                name="frida-spawn-worker",
                daemon=True,
            )
            self._spawn_worker_thread.start()
            device.on("spawn-added", self._on_spawn_added)
            device.enable_spawn_gating()
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Spawn gating unavailable (%s: %s) - falling back to "
                "foreground-polling companion detection, which cannot see a "
                "process that starts and exits between polls.",
                type(exc).__name__, exc,
            )
            return False
        self._spawn_gating_enabled = True
        logger.info(
            "[Frida] Spawn gating ENABLED - every process this sample starts "
            "will be instrumented before it runs"
        )
        return True

    def _disable_gating_for_fallback(self, device: Any, reason: str) -> None:
        """
        Turn gating off before handing back to the `am start` launch ladder.

        Every exit from _spawn_gated_launch that returns False says the same
        thing: instrumenting this sample at its entry point did not work. The
        ladder's whole value in that case is that it attaches LATE - but with
        gating still enabled the ladder's own `am start` is caught at spawn and
        instrumented just as early, so the sample meets the identical condition
        and dies the identical way.

        Measured on com.android.s4protect: spawn() failed with "unable to find
        a front-door activity", the ladder took over, and step 3's `am start`
        was then caught by the gate -

            SPAWN_GATED_INSTRUMENTED com.android.s4protect (pid=13060)
            Process ... exited after 0.6s - app crashed before becoming stable

        - java.lang.RuntimeException in Application.onCreate. The run ended
        INSTRUMENTATION_FAILED with no dynamic evidence at all, on a fallback
        that had never actually fallen back.

        Idempotent, so every failure path can call it without checking first.
        """
        if not self._spawn_gating_enabled:
            return
        try:
            device.disable_spawn_gating()
            self._spawn_gating_enabled = False
            logger.info(
                "[Frida] Spawn gating disabled for the ladder fallback (%s) - "
                "%s will now be instrumented after it starts, not before.",
                reason, self.package_name,
            )
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Could not disable spawn gating before fallback: %s - "
                "the relaunch may fail the same way.", exc,
            )

    def _spawn_gated_launch(self, device: Any, script_source: str) -> bool:
        """
        PRIMARY launch path: start the app suspended, hook it, then resume.

        Order is load-bearing and is the whole point of this function:

            spawn(pkg)      process created, suspended at its entry point
            attach(pid)
            script.load()   hooks installed - nothing has executed yet
            resume(pid)     the app's first instruction runs INSIDE the hooks

        Returns True when the process is instrumented and running. On any
        failure returns False, having force-stopped whatever it started, and the
        caller falls through to the `am start` launch ladder unchanged - so a
        sample that cannot be spawned (packed loaders, samples with no launchable
        entry point) behaves exactly as it did before.
        """
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout

        # A live process would make spawn() fail or, worse, succeed against a
        # second instance while the explorer drives the first.
        _force_stop_package(self.device_serial, self.package_name)

        self.launch_timeline["launch_intent"] = time.monotonic()

        pid: Optional[int] = None
        spawn_errors: List[str] = []
        # NOT a `with` block. ThreadPoolExecutor.__exit__ calls
        # shutdown(wait=True), which blocks until the submitted call returns -
        # so wrapping this in `with` made the timeout decorative: a spawn that
        # hung still hung, and the observed 67s came from frida's own internal
        # timeout rather than from ours. The pool is deliberately leaked on
        # timeout (daemon-ish, one idle thread) because the alternative is
        # blocking on the very call we are trying to bound.
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="frida-spawn")
        try:
            for attempt in range(SPAWN_MAX_ATTEMPTS):
                try:
                    pid = pool.submit(device.spawn, self.package_name).result(
                        timeout=SPAWN_TIMEOUT_SECONDS
                    )
                    break
                except _FTimeout:
                    spawn_errors.append(
                        f"spawn timed out after {SPAWN_TIMEOUT_SECONDS:.0f}s"
                    )
                    logger.warning(
                        "[Frida] Spawn attempt %d/%d exceeded our %.0fs bound",
                        attempt + 1, SPAWN_MAX_ATTEMPTS, SPAWN_TIMEOUT_SECONDS,
                    )
                    # The worker thread is still inside frida's spawn. Retrying
                    # would queue behind it on this single-worker pool and buy
                    # nothing, so stop here and let the recovery below run.
                    break
                except Exception as exc:               # noqa: BLE001
                    spawn_errors.append(f"{type(exc).__name__}: {exc}")
                    logger.warning(
                        "[Frida] Spawn attempt %d/%d failed: %s: %s",
                        attempt + 1, SPAWN_MAX_ATTEMPTS, type(exc).__name__, exc,
                    )
                    if "timed out" in str(exc).lower():
                        # frida's own timeout. Same reasoning as above, and the
                        # app has usually launched anyway - see below.
                        break
                    time.sleep(2)
        finally:
            pool.shutdown(wait=False)

        if not pid:
            # ── Recover the launch frida could not confirm ────────────────────
            #
            # "unexpectedly timed out while waiting for app to launch" is a
            # long-standing Android issue in frida (frida#3743, #2005, #1737,
            # #2653, #3679; frida-core#157, #376): the app DOES launch, frida
            # just fails to confirm it within its own window. The documented
            # workaround in every one of those reports is to attach to the
            # process that is now running.
            #
            # So look before falling back. Attaching to a process that started
            # a second ago still observes almost everything; grinding the whole
            # eight-step ladder first would cost ~100s and attach far later, to
            # the same process.
            recovered = self._resolve_pid()
            if recovered:
                logger.warning(
                    "[Frida] spawn() did not confirm the launch (%s), but %s IS "
                    "running as pid %d - attaching to it immediately rather "
                    "than restarting it through the ladder.",
                    spawn_errors[-1] if spawn_errors else "no error reported",
                    self.package_name, recovered,
                )
                pid = recovered
                self.spawn_confirmed = False
            else:
                logger.warning(
                    "[Frida] Could not spawn %s (%s) - falling back to the am "
                    "start launch ladder. Hooks will be installed AFTER the app "
                    "has started, so startup behaviour will not be observed.",
                    self.package_name,
                    spawn_errors[-1] if spawn_errors else "no error reported",
                )
                self.spawn_gated = False
                self.spawn_fallback_reason = (
                    spawn_errors[-1] if spawn_errors else "spawn returned no pid"
                )
                self._disable_gating_for_fallback(device, "spawn failed")
                return False

        self.launch_timeline["first_pid"] = time.monotonic()

        try:
            self._session = device.attach(pid)
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Attach to spawned pid %d failed (%s: %s) - killing it "
                "and falling back to the launch ladder.",
                pid, type(exc).__name__, exc,
            )
            try:
                device.kill(pid)
            except Exception:
                pass
            self._session = None
            self.spawn_gated = False
            self.spawn_fallback_reason = f"attach failed: {type(exc).__name__}"
            self._disable_gating_for_fallback(device, "attach failed")
            return False

        self.launch_timeline["frida_attach"] = time.monotonic()
        self.dae.transition(DAEStage.ATTACH_FRIDA, "attaching to spawned (suspended) process")

        try:
            self._script = self._session.create_script(script_source)
            self._script.on("message", self._on_message)
            self._script.load()
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Agent load into spawned %s failed (%s: %s) - killing "
                "and falling back to the launch ladder.",
                self.package_name, type(exc).__name__, exc,
            )
            try:
                device.kill(pid)
            except Exception:
                pass
            self._session = None
            self._script = None
            self.spawn_gated = False
            self.spawn_fallback_reason = f"script load failed: {type(exc).__name__}"
            self._disable_gating_for_fallback(device, "agent load failed")
            return False

        # Hooks are in. Nothing has executed. Resume.
        #
        # Only a process WE suspended needs resuming. On the recovery path the
        # app was launched by frida but never confirmed, so it is already
        # running: resume() would fail there, and treating that failure as fatal
        # would throw away a perfectly good early attach.
        if self.spawn_confirmed:
            try:
                device.resume(pid)
            except Exception as exc:                   # noqa: BLE001
                logger.error(
                    "[Frida] Failed to resume spawned %s (pid=%d): %s - the "
                    "process is suspended and cannot be analysed.",
                    self.package_name, pid, exc,
                )
                self.spawn_gated = False
                self.spawn_fallback_reason = f"resume failed: {type(exc).__name__}"
                self._disable_gating_for_fallback(device, "resume failed")
                return False

        self._stable_pid = pid
        if self.spawn_confirmed:
            self.launch_method_used = "spawn_gated"
            self.spawn_gated = True
            logger.info(
                "[Frida] SPAWN_GATED launch of %s (pid=%d): agent loaded BEFORE "
                "the first instruction ran - Application.onCreate and everything "
                "after it is instrumented",
                self.package_name, pid,
            )
        else:
            # Early, but not pre-first-instruction. spawn_gated stays False so
            # the report never claims more than we did, and so
            # INSTRUMENTED_TOO_LATE still applies if this attach was in fact
            # too late to see anything.
            self.launch_method_used = "spawn_recovered_attach"
            self.spawn_gated = False
            self.spawn_fallback_reason = (
                "spawn did not confirm; attached to the running process instead"
            )
            logger.info(
                "[Frida] Attached to %s (pid=%d) moments after frida launched "
                "it. Earlier than the ladder by ~100s, but the very first "
                "instructions were not observed.",
                self.package_name, pid,
            )

        # A spawned process starts with no window. `am start` brings the
        # launcher activity forward so the explorer has something to drive;
        # the process itself is already ours and is not restarted by this.
        component = (
            _format_activity_component(self.package_name, self.main_activity)
            if self.main_activity
            else _resolve_launcher_activity(self.device_serial, self.package_name)
        )
        if component:
            import shlex as _shlex
            _adb(
                "-s", self.device_serial, "shell",
                f"am start -n {_shlex.quote(component)}", timeout=20,
            )
        else:
            _launch_main_launcher_intent(self.device_serial, self.package_name)

        # The process must survive the resume. A sample that dies here has
        # crashed under instrumentation, and that is worth knowing precisely -
        # but it is still a launch failure, so hand back to the ladder.
        stable, live_pid, reason = _poll_pid_until_stable(
            self.device_serial, self.package_name,
        )
        if not stable:
            logger.warning(
                "[Frida] Spawned %s did not stay alive after resume (%s) - "
                "falling back to the launch ladder.",
                self.package_name, reason,
            )
            self._disable_gating_for_fallback(device, 'died after resume')
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None
            self._script = None
            self._stable_pid = None
            self.launch_method_used = None
            self.spawn_gated = False
            self.spawn_fallback_reason = f"died after resume: {reason}"
            return False

        if live_pid and live_pid != pid:
            # The app restarted itself out from under the spawn (some loaders
            # do this deliberately). Our session is attached to a process that
            # no longer matters, so the ladder path is the honest answer.
            logger.warning(
                "[Frida] %s restarted after resume (pid %d -> %d) - the spawned "
                "process is not the one running; falling back to the ladder.",
                self.package_name, pid, live_pid,
            )
            self._disable_gating_for_fallback(device, 'process restarted')
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None
            self._script = None
            self._stable_pid = None
            self.launch_method_used = None
            self.spawn_gated = False
            self.spawn_fallback_reason = f"process restarted ({pid} -> {live_pid})"
            return False

        return True

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

        script_source = _apply_agent_config(_HOOKS_SCRIPT.read_text(encoding="utf-8"))

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
            # Held on the session so teardown can reach it. The cleanup block
            # runs in a `finally` that is also entered when the connect above
            # raises, where the local `device` would be unbound.
            self._device = device

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
                """
                Issue am start -W for an explicit component. Returns adb success.

                The OUTPUT is retained on the session, not discarded: `adb`
                exits zero even when Android refuses the component, so the exit
                code alone cannot distinguish "started" from "Activity class
                does not exist". _try_launch_step reads it to avoid waiting a
                full stability timeout for a process Android has already said
                will never appear.
                """
                ok, out = _adb(
                    "-s", self.device_serial, "shell",
                    f"am start -W -n {activity_component}",
                    timeout=20,
                )
                self._last_launch_output = out or ""
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

                self._last_launch_output = ""
                launch_fn()

                # Android already answered. Waiting the full stability timeout
                # for a component it has refused to start delays the Frida
                # attach by that timeout per dead step, and on a packed sample
                # whose declared launcher is absent from the APK that is every
                # step in the early ladder. The sample gets on with whatever it
                # was going to do while we wait for a process that cannot exist.
                _rejected = _activity_start_was_rejected(
                    getattr(self, "_last_launch_output", "")
                )
                if _rejected:
                    logger.info(
                        "[Frida] Launch step '%s' was refused by Android (%s) - "
                        "skipping the stability wait and trying the next "
                        "strategy immediately",
                        step_label, _rejected,
                    )
                    self._last_launch_reason = f"activity_rejected:{_rejected}"
                    return False

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
                        _rendered, _owner = _poll_until_package_owns_window(
                            self.device_serial, self.package_name,
                            accept_handoff=self._detect_companion,
                        )
                        if _rendered:
                            if _owner and _owner != self.package_name:
                                # The launch worked; the sample just is not the
                                # thing drawing. Record it and stop laddering.
                                if _owner not in self.companion_packages:
                                    self.companion_packages.append(_owner)
                                self.first_window_package = _owner
                                logger.info(
                                    "[Frida] Launch step '%s' produced stable PID %d "
                                    "and a LAUNCH HAND-OFF: %s is drawing while %s "
                                    "stays alive behind it - accepting as launched",
                                    step_label, pid, _owner, self.package_name,
                                )
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
                        elif pid == _ui_less_pid:
                            # ── Stop laddering against a process we already have ──
                            #
                            # The remaining steps all issue another `am start`
                            # against a package that is ALREADY running as this
                            # exact pid. The platform will not create a second
                            # process, and an intent that did not raise a window
                            # the first time will not raise one the fourth, so
                            # every further step costs ~13s (5s stability + 6s
                            # window wait + adb) to re-measure an unchanged fact.
                            #
                            # Measured on Anubis: steps 1, 1b, 2 and 3 each
                            # reported "produced stable PID 3727 but never owned
                            # the foreground window", burning ~90s before the
                            # ui-less fallback below accepted pid 3727 anyway.
                            #
                            # A dropper whose launcher activity finishes itself
                            # is exhibiting BEHAVIOUR, not failing to launch.
                            # Accept the process now and let the run proceed;
                            # ui_render_failed still records that nothing was
                            # drawn, so the dynamic axis is reported honestly.
                            # Deliberately NOT setting ui_render_failed here.
                            #
                            # It was set on this path, and it is sticky: it
                            # forces dynamic_status to NO_UI_RENDERED, which
                            # excludes the dynamic axis no matter what the
                            # exploration goes on to find. But this shortcut
                            # fires ~25s in, and a DROPPER has not finished
                            # installing its payload by then - the window that
                            # eventually appears belongs to the payload, and the
                            # post-ladder companion check below is what sees it.
                            # Declaring "no UI rendered" before that check has
                            # run reports a conclusion we have not reached.
                            #
                            # If no window ever appears, first_activity and
                            # first_window stay null and risk_engine's own
                            # _ui_never_rendered reaches the same verdict from
                            # the evidence instead of from a guess.
                            logger.warning(
                                "[Frida] '%s' produced the SAME pid %d as '%s' "
                                "with no window yet. Further launch strategies "
                                "cannot change a running process - accepting it "
                                "now and letting the companion check decide "
                                "whether anything rendered.",
                                step_label, pid, _ui_less_step,
                            )
                            return True
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

            # ── Step 0 (PRIMARY): spawn-gated launch ──────────────────────────
            #
            # Everything below this block is the fallback. The ladder attaches
            # to an already-running process, which structurally cannot observe
            # Application.onCreate, DEX loading or the first C2 beacon - see the
            # measurement in the SPAWN_FIRST comment at the top of this module.
            #
            # Every ladder step is guarded on `not launched`, so a successful
            # spawn skips all of them without restructuring the ladder.
            if SPAWN_FIRST:
                # Gating first: enabling it before the target starts means any
                # process the sample forks during its own startup is caught too.
                self._enable_spawn_gating(device, script_source)
                logger.info(
                    "[Frida] Launch step 0: spawn-gated launch of %s "
                    "(suspend -> hook -> resume)", self.package_name,
                )
                if self._spawn_gated_launch(device, script_source):
                    launched = True
                else:
                    # _spawn_gated_launch cleans up after itself; the ladder
                    # starts from a force-stopped package either way.
                    self.dae.transition(
                        DAEStage.RESOLVE_ACTIVITY,
                        f"spawn fallback: {self.spawn_fallback_reason}",
                    )

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
            #
            # Skipped when an earlier step already produced a running process
            # that simply never showed a window. This step force-stops the
            # package first, so running it against a live headless process
            # destroys the only observation target we have.
            #
            # Measured on Anubis: steps 1-6 each reported the SAME stable PID
            # (12966) with no foreground window - the app runs headless, which
            # is the behaviour, not a launch failure. force_stop_retry then
            # killed it, the restart crashed at 10.8s, _crash_on_step was set,
            # and the ui-less fallback below is gated on _crash_on_step being
            # None - so a viable process was discarded and the run reported
            # INSTRUMENTATION_FAILED with zero hooks fired.
            #
            # The ladder exists to OBTAIN an attachable process. Once we have
            # one, escalating can only lose it.
            if not launched and _crash_on_step is None and _ui_less_pid is None:
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
            # A crash on a LATER, more aggressive step does not invalidate a
            # process an EARLIER step already established - provided that
            # process is still alive. Requiring _crash_on_step to be None threw
            # away a live headless process because a subsequent escalation
            # broke a different one. Liveness is re-checked here rather than
            # assumed: if the escalation really did kill it, the crash is the
            # honest answer and we fall through to the gate below.
            if not launched and _ui_less_pid is not None:
                _still_alive = self._resolve_pid() == _ui_less_pid
                if _still_alive:
                    self._stable_pid = _ui_less_pid
                    self.launch_method_used = _ui_less_step or "ui_less_pid"
                    self.ui_render_failed = True
                    launched = True
                    if _crash_on_step:
                        logger.warning(
                            "[Frida] '%s' crashed, but PID %d from '%s' is still "
                            "running - attaching to it rather than abandoning the "
                            "run.", _crash_on_step, _ui_less_pid,
                            _ui_less_step or "ui_less_pid",
                        )
                    logger.warning(
                        "[Frida] No launch strategy rendered UI for %s - proceeding with "
                        "PID %d from '%s'. Behavioural coverage will be limited and the "
                        "dynamic axis will be reported inconclusive.",
                        self.package_name, _ui_less_pid, self.launch_method_used,
                    )
                else:
                    logger.warning(
                        "[Frida] PID %d from '%s' is no longer running; cannot use it "
                        "as a fallback.", _ui_less_pid, _ui_less_step or "ui_less_pid",
                    )

            # ── Retry a crash that is ours, not the app's ─────────────────────
            #
            # `_crash_on_step` deliberately short-circuits the rest of the
            # ladder: an app that dies on every launch should not be started
            # eight times. But not every crash is the app's fault.
            #
            # Measured on the e-challan payload, API 37: an intermittent SIGSEGV
            # in ART's JIT compiler thread -
            #     art::HBasicBlockBuilder::Build()
            #     art::OptimizingCompiler::JitCompile(...)
            #     "Jit thread pool"
            # - which is the JIT racing the hooks being installed into methods
            # it is concurrently compiling. The same sample launches cleanly
            # without instrumentation, and survives the identical agent on a
            # repeat attempt; it is a race, not a defect. Left unhandled it
            # ended the whole dynamic run and the case reported no runtime
            # evidence at all.
            #
            # Only this signature is retried. A Java exception is the app's own
            # crash and still stops the ladder immediately, which is what keeps
            # a genuinely broken sample from burning the budget.
            def _relaunch_after_race():
                component = _resolve_launcher_activity(
                    self.device_serial, self.package_name
                ) or self.main_activity
                if component:
                    import shlex as _shlex
                    _am_start_w(_shlex.quote(component))
                else:
                    _launch_main_launcher_intent(
                        self.device_serial, self.package_name
                    )

            _race_retries = 0
            while (
                not launched
                and _crash_on_step
                and _race_retries < MAX_INSTRUMENTATION_RACE_RETRIES
                and _crash_is_instrumentation_race(self.crash_report)
            ):
                _race_retries += 1
                logger.warning(
                    "[Frida] Crash during %s looks like an ART/JIT race with "
                    "instrumentation, not an app defect - retrying launch (%d/%d)",
                    _crash_on_step, _race_retries,
                    MAX_INSTRUMENTATION_RACE_RETRIES,
                )
                self.dae.metrics["instrumentation_race_retries"] = _race_retries
                _force_stop_package(self.device_serial, self.package_name)
                time.sleep(INSTRUMENTATION_RACE_BACKOFF_SECONDS)
                self.crash_report = None
                self.last_error = ""
                _crash_on_step = None
                if _try_launch_step("instrumentation_race_retry", _relaunch_after_race):
                    launched = True
                elif self.crash_report is not None:
                    _crash_on_step = "instrumentation_race_retry"

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
            # ── A live process is worth more than a clean gate ────────────────
            #
            # The gate exists to stop us attaching to a DYING process. When
            # _poll_pid_until_stable has just confirmed the pid alive for
            # LAUNCH_PID_STABLE_MIN_SECONDS and it is still alive now, that
            # purpose is already served, and failing the run instead throws away
            # the only chance to observe the sample.
            #
            # Measured: a run aborted here with first_activity, first_window,
            # first_ui_dump and frida_attach all null - Frida never attached,
            # the explorer never started, and the case reported 0 runtime
            # evidence records. The process was alive the whole time. The
            # sample was a dropper whose own launcher activity finishes
            # immediately, which is behaviour, not a launch failure.
            if not gate_ok and self._stable_pid and self._resolve_pid() == self._stable_pid:
                logger.warning(
                    "[Frida] Readiness gate reported '%s', but pid %d is alive "
                    "and was confirmed stable - attaching anyway. A headless or "
                    "dropper process is still worth instrumenting; the run "
                    "records that no window rendered rather than abandoning it.",
                    gate_reason, self._stable_pid,
                )
                gate_ok = True
            if not gate_ok and self.spawn_gated:
                # The gate exists to stop us attaching to a dying process. On
                # the spawn-gated path we are ALREADY attached, to a process
                # that _poll_pid_until_stable confirmed alive after resume.
                # Detaching an instrumented, running sample to report a launch
                # failure would throw away the only run that observes startup
                # behaviour - the exact outcome this whole path exists to fix.
                logger.warning(
                    "[Frida] Readiness gate reported '%s' on a spawn-gated "
                    "session - continuing, since the process is already "
                    "instrumented and alive.", gate_reason,
                )
                gate_ok = True
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
            # A hand-off is detected ONCE, here, and answers two questions that
            # used to be decided separately and inconsistently: which processes
            # to instrument, and whether the app rendered anything.
            _companion = self._detect_companion(_win if _ok_w else None)
            if _companion and _companion not in self.companion_packages:
                self.companion_packages.append(_companion)
                logger.info(
                    "[Frida] LAUNCH_HANDOFF parent=%s companion=%s - the "
                    "foreground belongs to a third-party package the sample "
                    "launched while it is still running",
                    self.package_name, _companion,
                )
            # "Did this app render a screen?" must be answered about the app as
            # the USER experiences it. A loader whose payload is drawing a form
            # has rendered a screen; recording otherwise made risk_engine
            # exclude the dynamic axis as NO_UI_RENDERED for an app that was
            # visibly on screen, and the report then said "the app never
            # rendered a screen in the sandbox" underneath a screenshot of its
            # form.
            if _win and (self.package_name in _win or _companion):
                self.launch_timeline["first_activity"]  = time.monotonic()
                self.launch_timeline["first_window"]    = time.monotonic()
                if _companion:
                    self.first_window_package = _companion

            # Record first_ui_dump milestone. Channel-first for the same reason
            # as the launch gate: the shell probe cannot succeed once the u2
            # agent holds UiAutomation, so this milestone was never recorded.
            if _ui_dump_ok(self.device_serial):
                self.launch_timeline["first_ui_dump"] = time.monotonic()

            # ── Attach Frida ──────────────────────────────────────────────────
            # Only reached when the spawn-gated path did NOT run (SPAWN_FIRST
            # off, or spawn/attach/resume failed and the ladder launched the
            # app instead). When it did run, self._session is already attached
            # to a process that was instrumented while suspended, and
            # re-attaching here would both double-load the agent and overwrite
            # the frida_attach timestamp that proves the hooks were early.
            #
            # On this fallback path, at this point:
            #   * _poll_pid_until_stable() confirmed PID was alive for ≥5 s
            #   * _verify_launch_readiness() confirmed all 6 checks passed
            # We attach by the stable PID - no polling retry needed.
            if self._session is None:
                self.launch_timeline["frida_attach"] = time.monotonic()
                self.dae.transition(DAEStage.ATTACH_FRIDA, "attaching to stable PID")

            for attempt in range(0 if self._session is not None else ATTACH_MAX_ATTEMPTS):
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

            # Already loaded, while the process was suspended, by
            # _spawn_gated_launch. Loading it again would install every hook
            # twice and double-count every event the sample produces.
            if self._script is None:
                self._script = self._session.create_script(script_source)
                self._script.on("message", self._on_message)
                self._script.load()

            # ── Instrument the package that actually draws the journey ────────
            # The target's own session stays primary and is never replaced. A
            # companion gets the SAME agent script, so accessibility, SMS,
            # overlay, network and banking hooks are present in the process
            # doing the work rather than only in the loader that idles behind
            # it. Re-detected here as well as before attach because a slow
            # hand-off may only have completed during the attach retries.
            for _pkg in list(self.companion_packages):
                self._attach_companion(device, _pkg, script_source)
            _late = self._detect_companion()
            if _late and _late not in self._companion_sessions:
                self._attach_companion(device, _late, script_source)


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
            # Last sweep before exploration begins. A hand-off that waits on a
            # splash screen or a network round-trip only lands once the app has
            # settled, and instrumenting it here still precedes every action the
            # victim takes - which is where the behaviour worth observing is.
            _settled_companion = self._detect_companion()
            if _settled_companion and _settled_companion not in self._companion_sessions:
                if _settled_companion not in self.companion_packages:
                    self.companion_packages.append(_settled_companion)
                self._attach_companion(device, _settled_companion, script_source)
                if self.launch_timeline.get("first_activity") is None:
                    self.launch_timeline["first_activity"] = time.monotonic()
                    self.launch_timeline["first_window"] = time.monotonic()
                    self.first_window_package = _settled_companion
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
                    # Needed to put the app back in the foreground after a crash
                    # or after a tap hands the foreground to another app.
                    main_activity=self.main_activity,
                    # The static->dynamic bridge. AgenticExplorer has always
                    # accepted this and PerceptionPipeline has always forwarded
                    # it into every Observation, but this call site never
                    # supplied it - so the explorer ran with `{}` and could not
                    # know which permissions the manifest declared.
                    static_findings=self.static_findings,
                    # Capability the harness handed the sample before it ran, so
                    # the investigation does not mistake it for something the
                    # app requested.
                    pregranted_permissions=self.pregranted_permissions,
                )
                # Hand the explorer what the sandbox already established. The
                # hand-off completes milliseconds after launch, so by the time
                # the explorer starts its own "before any victim action" test
                # may no longer be the right question - and it should not have
                # to rediscover a fact the sandbox needed first anyway.
                for _companion in self.companion_packages:
                    explorer.adopt_companion_package(
                        _companion,
                        evidence=(
                            "detected by the sandbox at attach time: foreground "
                            f"belonged to {_companion} while {self.package_name} "
                            "was still running"
                        ),
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
                        # Release the main wait as soon as exploration really
                        # finishes, however it finished. Without this the wait
                        # below always runs to its full timeout, so raising
                        # that timeout to the adaptive maximum would make every
                        # short run wait for the maximum instead of the walk's
                        # actual duration.
                        self._stop_event.set()
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
            # Bounded by the hard maximum when an adaptive explorer is driving,
            # and released early by _run_explorer's finally the moment the walk
            # ends. A run with no explorer (or with adaptation switched off)
            # keeps exactly the old fixed window.
            wait_timeout = duration_seconds
            if explorer_thread is not None and ADAPTIVE_EXPLORATION_ENABLED:
                wait_timeout = max(duration_seconds, MAX_EXPLORATION_BUDGET_SECONDS)
                logger.info(
                    f"[Frida] ANALYSE: adaptive window - starting budget "
                    f"{duration_seconds}s, hard maximum {wait_timeout}s"
                )
            # The global 30-minute deadline outranks the adaptive ceiling, and
            # a reserve is kept back so teardown, evidence flush, workflow
            # reconstruction and BFCI can still run. Waiting the whole budget
            # and then having nothing left to finalise with would throw away
            # exactly the evidence the wait was spent collecting (§P11).
            _deadline = get_active_deadline()
            if _deadline is not None:
                _usable = max(
                    0.0,
                    _deadline.remaining() - DYNAMIC_FINALISATION_RESERVE_SECONDS,
                )
                if _usable < wait_timeout:
                    logger.info(
                        "[DYNAMIC][BUDGET] analysis window clamped %.0fs -> "
                        "%.0fs by the global deadline (remaining %.0fs, "
                        "finalisation reserve %.0fs)",
                        wait_timeout, _usable, _deadline.remaining(),
                        DYNAMIC_FINALISATION_RESERVE_SECONDS,
                    )
                    wait_timeout = _usable
            # Sliced wait, so a payload dropped mid-run still gets hooked.
            # See _await_analysis_window for why the one-shot sweep after attach
            # is too early for a dropper.
            self._await_analysis_window(device, script_source, wait_timeout)

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

            # ── ANTI-EVASION: defeat dormancy, then measure the reaction ──────
            # After exploration (the sample has had its chance under normal
            # conditions) and before the app is closed (the hooks must still be
            # live for the delta to mean anything).
            # Gated on the global deadline as well as the stop event. This
            # sequence used to consult no clock at all, so it ran in full after
            # a window that had already used its whole budget - which is one of
            # the ways the dynamic lifecycle overran the number it advertised.
            _deadline = get_active_deadline()
            _anti_evasion_affordable = _deadline is None or _deadline.allows(
                ANTI_EVASION_COST_SECONDS, stage="anti_evasion",
            )
            if ANTI_EVASION_ENABLED and not self._stop_event.is_set():
                if _anti_evasion_affordable:
                    self._run_anti_evasion_sequence()
                else:
                    logger.warning(
                        "[DYNAMIC][TIMEOUT] Skipping the anti-evasion sequence: "
                        "%.0fs remain of the %.0fs analysis budget, and it "
                        "needs ~%.0fs. Recorded as a limitation rather than "
                        "run past the deadline.",
                        _deadline.remaining() if _deadline else 0.0,
                        _deadline.total_seconds if _deadline else 0.0,
                        ANTI_EVASION_COST_SECONDS,
                    )
                    self.anti_evasion_skipped_reason = TIMEOUT_REASON

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
                    # ── Reconcile the goal graph against EVERY collected event ──
                    #
                    # The tracker was only ever fed events the explorer happened
                    # to drain from the bus during its walk, so anything that
                    # fired before the walk started, after it stopped, or from a
                    # background thread it never observed was invisible to the
                    # goal graph - while being counted perfectly well everywhere
                    # else.
                    #
                    # Measured on Drinik: the session collected 49
                    # `code_execution` events and BFCI scored 10.0 from them,
                    # yet the goal graph reported 0 successful and 0 partial
                    # goals, with stage 10 (Dynamic Code Loading) NOT_REACHED.
                    # The evidence existed; the graph simply never saw it.
                    #
                    # This is a reconciliation, not a second source of truth:
                    # update_from_frida_events is idempotent per goal (a goal
                    # already COMPLETED is skipped, and duplicate evidence
                    # cannot un-complete one), so replaying the full set can
                    # only ever ADD confirmations the walk missed.
                    try:
                        # Normalize once, classify into canonical behaviours,
                        # then evaluate EVERY goal against the complete set.
                        # Confirmation is by behaviour, never by raw hook name,
                        # so a hook the agent renames breaks one table entry in
                        # behavior_taxonomy instead of silently disabling a
                        # stage - which is the defect the red goal-hook contract
                        # tests have been reporting since they were written.
                        normalized = normalize_collected_events(self.collected_events)
                        summary = explorer.goals.reconcile(normalized=normalized)
                        self.behavior_summary = summary.get("behaviors_observed", {})
                        self.normalized_event_count = summary.get("events_considered", 0)
                        if summary.get("goals_changed"):
                            logger.info(
                                "[Frida] Goal graph reconciled against %d collected "
                                "event(s) -> behaviours %s; %d goal(s) changed: %s",
                                summary.get("events_considered", 0),
                                summary.get("behaviors_observed", {}),
                                len(summary["goals_changed"]),
                                ", ".join(summary["goals_changed"]),
                            )
                        else:
                            logger.info(
                                "[Frida] Goal graph reconciled against %d collected "
                                "event(s); behaviours observed: %s",
                                summary.get("events_considered", 0),
                                summary.get("behaviors_observed", {}) or "none",
                            )
                        # Re-settle: reconciliation can move a goal out of
                        # NOT_REACHED, and a finished run must not publish
                        # IN_PROGRESS. finalize() is idempotent.
                        explorer.goals.finalize(reason="post_run_reconciliation")
                    except Exception as exc:            # noqa: BLE001
                        logger.warning(
                            "[Frida] Goal reconciliation skipped: %s", exc,
                            exc_info=True,
                        )
                    self.reports = explorer.get_reports()
                    ui_xml = getattr(explorer, "last_ui_hierarchy_xml", "") or ""
                    if ui_xml:
                        self.last_ui_hierarchy_xml = ui_xml
                    # One hierarchy per distinct in-app screen. VIDE judges a
                    # clone on view structure, and the login form is the one
                    # screen a clone and its target necessarily share - the
                    # screens behind it are where the difference shows.
                    self.state_ui_hierarchies = list(
                        (self.reports or {}).get("ui_hierarchies") or []
                    )
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

            # Spawn gating is device-wide, so it must be turned off before the
            # session ends. Left enabled, the next process ANY app on the device
            # starts is caught suspended with no handler left to resume it, and
            # the emulator wedges - which would make this fix look like a worse
            # bug than the one it replaces.
            # Order matters. Gating off FIRST so nothing new is queued, then let
            # the worker drain what is already queued - each of those is a
            # process sitting suspended and only the worker may resume it -
            # then stop the worker.
            _dev = getattr(self, "_device", None)
            if _dev is not None and getattr(self, "_spawn_gating_enabled", False):
                # Bounded for the same reason as the unload/detach calls below:
                # this is a frida call, and after a transport failure it can
                # block indefinitely rather than raise.
                from concurrent.futures import ThreadPoolExecutor as _TPE
                from concurrent.futures import TimeoutError as _TE0

                _p = _TPE(max_workers=1, thread_name_prefix="frida-ungate")
                try:
                    _p.submit(_dev.disable_spawn_gating).result(
                        timeout=FRIDA_TEARDOWN_TIMEOUT_SECONDS
                    )
                    self._spawn_gating_enabled = False
                    logger.info("[Frida] Spawn gating disabled")
                except _TE0:
                    logger.error(
                        "[Frida] disable_spawn_gating did not return within "
                        "%.0fs - abandoning it. New processes on %s may hang "
                        "suspended until frida-server is restarted.",
                        FRIDA_TEARDOWN_TIMEOUT_SECONDS, self.device_serial,
                    )
                except Exception as exc:               # noqa: BLE001
                    logger.error(
                        "[Frida] Could not disable spawn gating: %s - new "
                        "processes on %s may hang suspended until frida-server "
                        "is restarted.", exc, self.device_serial,
                    )
                finally:
                    _p.shutdown(wait=False)
            if getattr(self, "_spawn_worker_thread", None) is not None:
                self._spawn_queue.put(None)            # shutdown sentinel
                self._spawn_worker_thread.join(timeout=SPAWN_WORKER_DRAIN_SECONDS)
                if self._spawn_worker_thread.is_alive():
                    logger.warning(
                        "[Frida] Spawn worker did not drain within %.0fs - some "
                        "gated processes may still be suspended.",
                        SPAWN_WORKER_DRAIN_SECONDS,
                    )
                self._spawn_worker_thread = None

            # ── Teardown must be bounded ──────────────────────────────────────
            #
            # Every call below goes to frida, and frida's Python API has no
            # timeout: unload() and detach() wait for a reply from an agent
            # that, on the path that brings us here, may already be gone.
            #
            # Measured on Hook (com.half.powder): the session died with
            # "TransportError: timeout was reached" and the run then produced
            # no further output for over ten minutes - teardown blocked on a
            # transport that no longer existed, and because the device lock is
            # held for the whole session, every queued sample behind it stopped
            # too. One dead transport wedged the entire corpus run.
            #
            # try/except cannot help: a hang is not an exception. Each call is
            # given its own bounded attempt and abandoned if it overruns; the
            # worker thread is left to its fate rather than joined, because
            # joining it is the very thing that blocks.
            def _bounded(label: str, fn) -> None:
                from concurrent.futures import ThreadPoolExecutor
                from concurrent.futures import TimeoutError as _TE

                pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="frida-teardown")
                try:
                    pool.submit(fn).result(timeout=FRIDA_TEARDOWN_TIMEOUT_SECONDS)
                except _TE:
                    logger.warning(
                        "[Frida] %s did not return within %.0fs - abandoning it. "
                        "The transport is most likely already dead; the run's "
                        "evidence is unaffected.",
                        label, FRIDA_TEARDOWN_TIMEOUT_SECONDS,
                    )
                except Exception:                      # noqa: BLE001
                    pass
                finally:
                    pool.shutdown(wait=False)

            # Companions first: they were attached last, and a failure to tear
            # one down must not prevent the target's own session from closing.
            for _pkg, _cs in list(getattr(self, "_companion_scripts", {}).items()):
                _bounded(f"companion script unload ({_pkg})", _cs.unload)
            for _pkg, _cse in list(getattr(self, "_companion_sessions", {}).items()):
                _bounded(f"companion detach ({_pkg})", _cse.detach)

            if getattr(self, '_script', None):
                _bounded("script unload", self._script.unload)

            if getattr(self, '_session', None):
                _bounded("session detach", self._session.detach)
            logger.info(f"[Frida] Session cleanup complete")


# ─── Main Analysis Entry Point ─────────────────────────────────────────────────

async def run_frida_analysis(
    apk_path: str,
    package_name: Optional[str] = None,
    *,
    static_findings: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
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

    static_findings
        What the static pass already established - at minimum
        ``{"permissions": [...], "app_label": str, "flags": {...}}``. Keyword-only
        and optional: every existing caller keeps working unchanged, and a run
        without it behaves exactly as before. Supplying it is what lets the
        dynamic side compare declared permissions against what the app actually
        requests at runtime.
    """
    # ── The ONE deadline for this dynamic analysis ────────────────────────────
    #
    # Armed here, at the top of the dynamic lifecycle, and read by every child:
    # the explorer's adaptive window, the per-goal slice, the action ladder, the
    # planner's call timeout, the anti-evasion sequence and the analysis wait.
    # None of them keeps a clock of its own, which is what stops the five
    # previously-independent timeouts from adding up (§P25).
    #
    # Measured from NOW, not from the start of any individual stage - install,
    # launch, attach, exploration, anti-evasion and teardown all spend from the
    # same 30 minutes.
    deadline = DynamicDeadline()
    set_active_deadline(deadline)
    deadline.log_state("dynamic_analysis_start")

    content_sha256 = compute_sha256(apk_path) if os.path.isfile(apk_path) else ""
    lifecycle = RuntimeLifecycleTracker(case_id=content_sha256)
    lifecycle.mark_requested()
    set_active_tracker(lifecycle)
    record_lifecycle_event(
        "runtime_controller_started",
        "STARTING",
        "frida_sandbox",
        "run_frida_analysis invoked",
    )

    base_result: Dict[str, Any] = {
        "available": False,
        "runtime_requested": True,
        "runtime_attempted": False,
        "engine": "frida",
        "dynamic_status": "NOT_STARTED",
        "sha256": content_sha256,
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
        base_result["dynamic_status"] = "EMULATOR_UNAVAILABLE"
        if connection:
            base_result["sandbox_connection"] = connection.to_dict()
        lifecycle.emulator_status = "FAILED"
        lifecycle.dynamic_status = "EMULATOR_UNAVAILABLE"
        lifecycle.dashboard_inclusion_status = "FAILED"
        lifecycle.record(
            "emulator_selected",
            "FAILED",
            "sandbox_provider",
            err_msg,
            error=err_code,
        )
        # CASE F: no sandbox. The dynamic axis does not exist for this case and
        # is EXCLUDED from scoring rather than scored as zero - a run that never
        # happened must not read as a run that found nothing (§P16).
        base_result["dynamic_coverage"] = build_dynamic_coverage(
            None,
            sandbox_available=False,
            instrumentation_ok=False,
            budget_seconds=deadline.total_seconds,
            elapsed_seconds=deadline.elapsed(),
        )
        lifecycle.attach_to_result(base_result)
        apk_dir = artifact_dir_for(apk_path)
        lifecycle.write_json(apk_dir)
        set_active_tracker(None)
        clear_active_deadline()
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
    lifecycle.emulator_status = "READY"
    lifecycle.record(
        "emulator_ready",
        "READY",
        "sandbox_provider",
        f"serial={device_serial}",
    )
    base_result["runtime_attempted"] = True

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
    #
    # The deadline is cleared in `finally` so it cannot leak into the next
    # analysis in this process: a stale deadline would make the following run
    # believe its budget was already spent and finalise immediately.
    try:
        async with _device_lock_for(device_serial):
            return await _run_device_session(
                apk_path=apk_path,
                package_name=package_name,
                device_serial=device_serial,
                base_result=base_result,
                static_findings=static_findings,
            )
    finally:
        deadline.log_state("dynamic_analysis_end")
        clear_active_deadline()


#: Buckets that hold events about the HARNESS, not about the sample. A run
#: whose only events live here observed nothing, however many events it counts.
#: `harness_action` is where the agent files its own Build-field spoofing, which
#: fires once on every emulator run for benign apps and trojans alike.
_HARNESS_EVENT_BUCKETS = frozenset({"harness_action"})


def _no_sample_behaviour_observed(session: "FridaSession") -> bool:
    """
    True when nothing we collected describes something the SAMPLE did.

    `total_hook_events_received` counts harness events too. A real run held
    exactly {harness_action: 1} and reported EVENTS_CAPTURED, so the report said
    the sample had been observed when the only thing observed was ourselves.
    """
    for bucket, events in (session.collected_events or {}).items():
        if bucket in _HARNESS_EVENT_BUCKETS:
            continue
        for event in events or []:
            hook = ""
            if isinstance(event, dict):
                data = event.get("data") if isinstance(event.get("data"), dict) else {}
                hook = str(event.get("hook") or data.get("hook") or "")
            # The Build-field spoof predates the harness_action bucket and is
            # still filed under anti_analysis on older agents.
            if hook in ("Build.<static fields>", "sandbox.build_fields_spoofed"):
                continue
            return False
    return True


def _instrumentation_latency(session: "FridaSession") -> Optional[float]:
    """
    Seconds between the process appearing and the agent being loaded.

    None when either milestone is missing - an unknown latency must not be
    treated as a late one.
    """
    timeline = session.launch_timeline or {}
    first_pid = timeline.get("first_pid")
    attach = timeline.get("frida_attach")
    if not isinstance(first_pid, (int, float)) or isinstance(first_pid, bool):
        return None
    if not isinstance(attach, (int, float)) or isinstance(attach, bool):
        return None
    return max(0.0, float(attach) - float(first_pid))


def _instrumentation_was_late(session: "FridaSession") -> bool:
    """
    Whether the agent arrived too late to have seen the app start.

    A spawn-gated run loads the agent into a SUSPENDED process, so by
    construction nothing executed before the hooks were in and this is never
    true - which is what makes the status a regression detector rather than a
    permanent label.
    """
    if session.spawn_gated:
        return False
    latency = _instrumentation_latency(session)
    if latency is None:
        # Attach happened but we cannot say when. The ladder path always
        # attaches after a stable-PID wait of at least
        # LAUNCH_PID_STABLE_MIN_SECONDS, so "unknown" on that path is late.
        return True
    return latency > INSTRUMENTATION_LATENCY_BUDGET_SECONDS


def _build_investigation_records(session: "FridaSession") -> List[Dict[str, Any]]:
    """
    Reconstructor records for what the investigation itself established.

    Only VERIFIED capabilities are included. An unverified grant must not seed a
    causal chain: the behaviour downstream of it never actually had the
    capability, and a chain built on one would be fiction.

    Never raises - a failure here degrades to an empty list rather than losing
    the workflow that the Frida events alone can still support.
    """
    try:
        from sudarshan_core.engines.workflow_reconstructor import investigation_records
    except Exception:
        return []

    # `session.reports` is what the explorer returned from get_reports(); it
    # carries the "permissions" and "crashes" keys added this cycle.
    reports = getattr(session, "reports", None) or {}
    if not isinstance(reports, dict):
        return []
    permissions = reports.get("permissions") or {}
    records = permissions.get("records") or []

    granted = [
        r.get("permission", "")
        for r in records
        if isinstance(r, dict) and r.get("granted") and r.get("permission")
    ]
    accessibility = any(
        isinstance(r, dict)
        and r.get("granted")
        and "BIND_ACCESSIBILITY_SERVICE" in str(r.get("permission", ""))
        for r in records
    )
    overlay = any(
        isinstance(r, dict)
        and r.get("granted")
        and "SYSTEM_ALERT_WINDOW" in str(r.get("permission", ""))
        for r in records
    )
    try:
        return investigation_records(
            granted_permissions=granted,
            accessibility_enabled=accessibility,
            overlay_granted=overlay,
            crash_findings=reports.get("crashes") or [],
        )
    except Exception as exc:
        logger.debug("[Frida] Could not build investigation records: %s", exc)
        return []


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
    static_findings: Optional[Dict[str, Any]] = None,
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

    # Same reason as SELinux permissive above: make the guest observable. A
    # payload that is frozen while backgrounded cannot be attached to.
    FridaSession._unfreeze_guest_for_instrumentation(device_serial)

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
        static_findings=static_findings,
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
        base_result["dynamic_status"] = "INSTALL_FAILED"
        base_result["dae_pipeline"] = session.dae.to_dict()
        # Nothing was ever instrumented, so this is an absence of OBSERVATION.
        # The dynamic axis is excluded rather than scored (§P16).
        _inst_deadline = get_active_deadline()
        base_result["dynamic_coverage"] = build_dynamic_coverage(
            None,
            sandbox_available=True,
            instrumentation_ok=False,
            budget_seconds=(
                _inst_deadline.total_seconds if _inst_deadline is not None
                else float(DYNAMIC_MAX_WALL_TIME_SECONDS)
            ),
            elapsed_seconds=(
                _inst_deadline.elapsed() if _inst_deadline is not None else 0.0
            ),
        )
        base_result["dynamic_valid"] = False
        tracker = get_active_tracker()
        if tracker:
            tracker.apk_install_status = "FAILED"
            tracker.dynamic_status = "INSTALL_FAILED"
            tracker.dashboard_inclusion_status = "FAILED"
            tracker.record(
                "apk_install_completed",
                "FAILED",
                "adb",
                output[:500],
                error="INSTALL_FAILED",
            )
            tracker.attach_to_result(base_result)
            tracker.write_json(apk_dir)
        set_active_tracker(None)
        return base_result
    log_pipeline_lifecycle(2, "APK installed", package_name)
    session.dae.transition(DAEStage.VERIFY_INSTALL, "pm path verification")
    tracker = get_active_tracker()
    if tracker:
        tracker.apk_install_status = "SUCCESS"
        tracker.record(
            "apk_install_completed",
            "SUCCESS",
            "adb",
            package_name,
        )
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

    # Baseline of what was on the device BEFORE the sample ran. Anything that
    # appears after this and has a live process was installed BY the sample -
    # which is the definition of a dropped payload, and the only reliable way
    # to find one whose package name is unknown in advance.
    session.snapshot_preexisting_packages()

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

    # Remembered on the session so the explorer can record these as
    # GRANTED_WITHOUT_REQUEST. Without that the report shows a sample holding
    # SMS access with no explanation of how it got it, and the answer - that we
    # granted it ourselves before launch - is invisible.
    session.pregranted_permissions = await loop.run_in_executor(
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
        base_result["available"] = True
        base_result["runtime_attempted"] = True
        fail_status = DynamicAnalysisStatus.INSTRUMENTATION_FAILED.value
        if "attach" in err_msg.lower() or "frida" in err_msg.lower():
            fail_status = DynamicAnalysisStatus.FRIDA_ATTACH_FAILED.value
        base_result["dynamic_status"] = fail_status
        if session.crash_report is not None:
            base_result["crash_report"] = session.crash_report.to_dict()
        base_result["launch_timeline"] = _timeline_to_seconds(session.launch_timeline)
        base_result["launch_method_used"] = session.launch_method_used

        # ── Keep what the run DID observe before it failed ────────────────────
        #
        # A launch failure used to discard session.collected_events entirely, so
        # a sample that was instrumented and then died reported exactly the same
        # thing as one that was never instrumented at all: nothing.
        #
        # That is wrong whenever the spawn-gated path got its hooks in. Measured
        # on com.sina.weibo: the agent loaded BEFORE the first instruction, the
        # process then lived 1.1s and crashed in Application.onCreate - and
        # every hook that fired during that second was thrown away, even though
        # onCreate is exactly where a sample that cannot survive startup does
        # its work.
        #
        # The status stays honest - the launch DID fail, and that is reported -
        # but the events travel with it. dynamic_exclusion_reason checks
        # observed behaviour BEFORE it checks the status, so a crash-on-launch
        # run that genuinely saw fraud behaviour is now scoreable on what it
        # saw instead of being written off by how it ended.
        try:
            bfci, components, bfci_evidence = calculate_bfci(session.collected_events)
            base_result["bfci"] = bfci
            base_result["bfci_components"] = components
            base_result["bfci_evidence"] = bfci_evidence
            base_result["frida_events"] = session.collected_events
            base_result["raw_event_counts"] = {
                k: len(v or []) for k, v in session.collected_events.items()
            }
            base_result["api_calls"] = [
                (e.get("data", {}) or {}).get("hook", "") or e.get("hook", "")
                for bucket in session.collected_events.values()
                for e in (bucket or [])
            ]
            base_result["anti_analysis_events"] = list(
                session.collected_events.get("anti_analysis", []) or []
            )
            base_result["hooks_installed"] = session.hooks_installed_count
            base_result["canary_received"] = session.canary_received
            # The evidence store never got flushed on this path, so the count
            # it would have produced does not exist. Reporting nothing here
            # leaves the dashboard showing "0 runtime records" beside an axis
            # that WAS scored - measured on Hook, which contributed BFCI 6.31
            # from a DexClassLoader load and five anti-analysis events. Count
            # the events actually held instead, excluding the harness's own.
            base_result["evidence_record_count"] = sum(
                len(v or []) for k, v in session.collected_events.items()
                if k != "harness_action"
            )
            observed = sum(
                len(v or []) for k, v in session.collected_events.items()
                if k not in ("harness_action",)
            )
            if observed:
                logger.info(
                    "[Frida] Launch failed, but %d event(s) were captured while "
                    "the sample was instrumented - reporting them rather than "
                    "discarding the run.", observed,
                )
        except Exception as exc:                       # noqa: BLE001
            logger.warning(
                "[Frida] Could not carry collected events onto the failure "
                "result: %s", exc,
            )

        # CASE E: instrumentation failed. Any events the run DID collect before
        # it died still count - a spawn-gated agent that got its hooks in and
        # then watched the process crash in Application.onCreate observed real
        # behaviour, and build_dynamic_coverage decides from the evidence rather
        # than from the status, so such a run reports PARTIAL and keeps it.
        _fail_deadline = get_active_deadline()
        _fail_events = sum(
            len(events)
            for bucket, events in session.collected_events.items()
            if bucket not in _HARNESS_EVENT_BUCKETS
        )
        # ── Reconcile whatever the run DID collect before it died ────────────
        #
        # A session whose transport dies mid-run - which is what a sample
        # killing its own process while hooked looks like from this side - had
        # its events dropped on the floor, because the explorer never reached
        # its own finalisation. Those events are real observations of the
        # sample and the most diagnostic thing such a run produces.
        #
        # A fresh tracker is used rather than the explorer's, because on this
        # path the explorer may never have run at all. It is reconciliation
        # over the collected set, which is exactly what the success path does.
        _fail_goal_coverage = (session.reports or {}).get("goal_coverage") or {}
        try:
            from sudarshan_core.engines.agentic.goal_tracker import GoalTracker

            _fail_tracker = GoalTracker()
            _fail_summary = _fail_tracker.reconcile(
                normalized=normalize_collected_events(session.collected_events)
            )
            _fail_tracker.finalize(reason="instrumentation_failed")
            if _fail_summary.get("goals_changed"):
                logger.info(
                    "[Frida] Failure-path reconciliation recovered %d goal(s) "
                    "from %d event(s) collected before the session died: %s",
                    len(_fail_summary["goals_changed"]),
                    _fail_summary.get("events_considered", 0),
                    ", ".join(_fail_summary["goals_changed"]),
                )
                _fail_goal_coverage = _fail_tracker.coverage_report()
                base_result["behaviors_observed"] = _fail_summary.get(
                    "behaviors_observed", {}
                )
        except Exception as exc:                        # noqa: BLE001
            logger.warning(
                "[Frida] Failure-path goal reconciliation skipped: %s", exc,
            )

        base_result["dynamic_coverage"] = build_dynamic_coverage(
            _fail_goal_coverage,
            sandbox_available=True,
            instrumentation_ok=False,
            evidence_event_count=_fail_events,
            budget_seconds=(
                _fail_deadline.total_seconds if _fail_deadline is not None
                else float(DYNAMIC_MAX_WALL_TIME_SECONDS)
            ),
            elapsed_seconds=(
                _fail_deadline.elapsed() if _fail_deadline is not None else 0.0
            ),
            timed_out=bool(_fail_deadline is not None and _fail_deadline.expired),
        )
        base_result["dynamic_valid"] = base_result["dynamic_coverage"]["dynamic_valid"]
        base_result["limitations"] = base_result["dynamic_coverage"]["limitations"]

        tracker = get_active_tracker()
        if tracker:
            tracker.frida_status = "FAILED"
            tracker.explorer_status = session.explorer_used or "none"
            tracker.dynamic_status = fail_status
            tracker.dashboard_inclusion_status = "FAILED"
            tracker.record(
                "dynamic_analysis_completed",
                "FAILED",
                "FridaSession",
                err_msg,
                error=fail_status,
            )
            if session.reports:
                tracker.merge_explorer_reports(session.reports)
            tracker.attach_to_result(base_result)
        try:
            tl_path = apk_dir / "launch_timeline.json"
            tl_path.write_text(
                json.dumps(base_result["launch_timeline"], indent=2),
                encoding="utf-8",
            )
            logger.info("[Frida] launch_timeline.json written (failure path): %s", tl_path)
        except OSError:
            pass
        if tracker:
            tracker.write_json(apk_dir)
        set_active_tracker(None)
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
    elif _no_sample_behaviour_observed(session) and _instrumentation_was_late(session):
        # Hooks installed, the process ran, and every event we hold describes
        # the HARNESS rather than the sample - because the agent arrived after
        # the app had already done its work.
        #
        # This is the case that used to report EVENTS_CAPTURED and read, all the
        # way through to the analyst's screen, as "the sample was observed and
        # did nothing". It is the opposite claim: we were not there to see it.
        # Naming it is also what stops the regression coming back silently - a
        # future change that pushes attach latency back out shows up as this
        # status instead of as a quiet zero.
        dynamic_status = DynamicAnalysisStatus.INSTRUMENTED_TOO_LATE.value
        logger.error(
            "[Frida] INSTRUMENTED_TOO_LATE: %d hooks installed, but the agent "
            "attached %.1fs after %s started and nothing the sample did was "
            "observed. This run says nothing about the sample. spawn_gated=%s%s",
            session.hooks_installed_count,
            _instrumentation_latency(session) or -1.0,
            session.package_name,
            session.spawn_gated,
            f" (spawn fallback: {session.spawn_fallback_reason})"
            if session.spawn_fallback_reason else "",
        )
    elif session.total_hook_events_received == 0:
        dynamic_status = DynamicAnalysisStatus.RUNTIME_COMPLETED_NO_EVENTS.value
    else:
        dynamic_status = DynamicAnalysisStatus.EVENTS_CAPTURED.value

    # ── Coverage and validity (§P2/§P12/§P14) ─────────────────────────────────
    #
    # The goal graph reports what it achieved as a DISTRIBUTION - successful,
    # partial, failed, skipped, not reached, timed out - and the contract below
    # is derived from that distribution together with the evidence actually
    # observed. It is deliberately built AFTER the status ladder above and does
    # not overwrite it: `dynamic_status` remains the instrumentation-level
    # answer that risk_engine has always consumed, and `dynamic_coverage` is the
    # investigation-level one beside it.
    #
    # Nothing here is a verdict and nothing here is a score. A partial run is
    # reported as partial, with its coverage and its limitations stated, and the
    # deterministic scoring path reads the observed events exactly as before
    # (§P13/§P17).
    _deadline = get_active_deadline()
    _timed_out = bool(_deadline is not None and _deadline.expired)
    _explorer_reports = session.reports or {}
    _goal_coverage = _explorer_reports.get("goal_coverage") or {}
    # Sample-attributable events only. `total_hook_events_received` counts the
    # harness's own Build-field spoofing, which fires on every emulator run for
    # benign apps and trojans alike, and letting it establish that the sandbox
    # observed the sample is the exact misattribution _no_sample_behaviour_observed
    # exists to prevent.
    _sample_events = sum(
        len(events)
        for bucket, events in session.collected_events.items()
        if bucket not in _HARNESS_EVENT_BUCKETS
    )
    _instrumentation_ok = bool(
        session.canary_received
        and not session.java_bridge_failed
        and session.java_hooks_installed > 0
    )
    _extra_limitations = []
    if getattr(session, "anti_evasion_skipped_reason", ""):
        _extra_limitations.append(
            "The anti-evasion sequence (time warp and persona seeding) was not "
            "run: the analysis budget was exhausted before it could start, so "
            "dormancy-defeating triggers were not applied."
        )
    dynamic_coverage = build_dynamic_coverage(
        _goal_coverage,
        sandbox_available=True,
        instrumentation_ok=_instrumentation_ok,
        evidence_event_count=_sample_events,
        meaningful_transition_count=len(
            (_explorer_reports.get("state_graph") or {}).get("edges") or []
        ),
        budget_seconds=(
            _deadline.total_seconds if _deadline is not None
            else float(DYNAMIC_MAX_WALL_TIME_SECONDS)
        ),
        elapsed_seconds=_deadline.elapsed() if _deadline is not None else 0.0,
        timed_out=_timed_out,
        extra_limitations=_extra_limitations,
    )

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

    # DAEPipelineTracker seeds its metrics dict with a full set of counters and
    # only ever writes two of them (launch_retries, instrumentation_race_retries).
    # The rest were dead fields that reported 0 forever - so a run that installed
    # 80 hooks, captured 8 screenshots and received events still rendered
    # "hooks_installed: 0, events_captured: 0" in the runtime panel, which reads
    # as a sandbox that never started. Fill in the ones the session actually
    # knows, at the point where every counter is final.
    #
    # Only counters with an authoritative source are set. The others are left as
    # they are rather than being invented: a wrong number here is worse than a
    # zero, because this panel is what an analyst checks to decide whether to
    # trust the dynamic section at all.
    try:
        session.dae.metrics.update({
            "hooks_installed": session.hooks_installed_count,
            "events_captured": session.total_hook_events_received,
            "screenshots_captured": len(_collect_screenshots(session)),
            "system_dialogs_dismissed": len(session.system_dialogs_dismissed),
        })
    except Exception as exc:                                        # noqa: BLE001
        logger.debug("[Frida] DAE metrics backfill skipped: %s", exc)

    # Map to risk_engine.py's expected _calculate_dynamic_score() keys
    # This makes the BFCI directly usable by the existing pipeline
    result = {
        **base_result,
        "available": True,
        "engine": "frida",
        "dynamic_status": dynamic_status,
        # Packages the sample launched to render its own journey, and which
        # were instrumented alongside it. Reported so an analyst reading a
        # behaviour attributed to this case can see WHICH process produced it.
        "companion_packages": list(getattr(session, "companion_packages", [])),
        # Which package drew the screen the victim actually saw. Empty when the
        # target rendered its own UI; set when a loader handed the journey off.
        "first_window_package": getattr(session, "first_window_package", "") or "",
        "instrumented_packages": (
            [session.package_name]
            + list(getattr(session, "_companion_sessions", {}).keys())
        ),
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
        # Whether the agent was loaded into a SUSPENDED process, i.e. before the
        # sample executed anything. This is the difference between "the sample
        # did nothing" and "we arrived after it had already acted", which read
        # identically in every report before spawn gating existed.
        "spawn_gated":         session.spawn_gated,
        "spawn_fallback_reason": session.spawn_fallback_reason,
        "spawn_gating_enabled": getattr(session, "_spawn_gating_enabled", False),
        "foreground_mismatch": session.foreground_mismatch,
        "system_dialogs_dismissed": session.system_dialogs_dismissed,

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
        "ui_hierarchies": getattr(session, "state_ui_hierarchies", []) or [],
        "login_attempts": (session.reports or {}).get("login_attempts", 0),
        "login_outcome": (session.reports or {}).get("login_outcome", "not_attempted"),
        # Package still alive after force-stop at session end.
        "survived_force_stop": session.survived_force_stop,

        # Autonomous anti-evasion: what the time warp and the synthetic persona
        # changed in this session's own hook counts. None when the sequence did
        # not run - the UI must be able to tell "not attempted" from "attempted
        # and nothing moved".
        "anti_evasion": session.anti_evasion_result,

        # Permissions the harness granted before launch. Reported so the UI can
        # say how many, instead of asserting that grants happened at all.
        "pregranted_permissions": list(session.pregranted_permissions),
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

        # ── §P12 dynamic result contract ──────────────────────────────────────
        # Coverage, validity and limitations, spliced in at the top level as
        # well as nested so a consumer that reads `dynamic_valid` directly and
        # one that reads `dynamic_coverage["dynamic_valid"]` cannot disagree.
        "dynamic_coverage": dynamic_coverage,
        "dynamic_valid": dynamic_coverage["dynamic_valid"],
        "dynamic_complete": dynamic_coverage["dynamic_complete"],
        "coverage_status": dynamic_coverage["dynamic_status"],
        "coverage_ratio": dynamic_coverage["coverage_ratio"],
        "goals_total": dynamic_coverage["goals_total"],
        "goals_successful": dynamic_coverage["goals_successful"],
        "goals_partial": dynamic_coverage["goals_partial"],
        "goals_failed": dynamic_coverage["goals_failed"],
        "goals_skipped": dynamic_coverage["goals_skipped"],
        "goals_not_reached": dynamic_coverage["goals_not_reached"],
        "timeout_reason": dynamic_coverage["timeout_reason"],
        "limitations": dynamic_coverage["limitations"],
        "analysis_budget_seconds": dynamic_coverage["analysis_budget_seconds"],
        "analysis_elapsed_seconds": dynamic_coverage["analysis_elapsed_seconds"],
        "goal_coverage": _goal_coverage,
        "permission_screens": _explorer_reports.get("permission_screens", []),

        # ── Canonical behaviours ──────────────────────────────────────────────
        # The SEMANTIC counterpart to raw_event_counts. "50 code_execution
        # events" does not say which code execution was observed; this does,
        # and it is what the goal graph and the report both reason from.
        "behaviors_observed": dict(getattr(session, "behavior_summary", {}) or {}),
        "normalized_event_count": int(
            getattr(session, "normalized_event_count", 0) or 0
        ),

        # ── Dynamic diagnostics ───────────────────────────────────────────────
        # One place that answers "why was this APK not exercised more deeply?".
        # Every field is measured, never inferred; a value that could not be
        # read is absent rather than zero, because a zero here reads as a
        # finding about the sample rather than a gap in the record.
        "dynamic_diagnostics": {
            "instrumentation_status": dynamic_status,
            "canary_received": session.canary_received,
            "frida_attached": bool(session.canary_received),
            "java_bridge_failed": session.java_bridge_failed,
            "hook_count": session.hooks_installed_count,
            "java_hooks_installed": session.java_hooks_installed,
            "native_hooks_installed": session.native_hooks_installed,
            "hook_errors": len(session.hook_errors or []),
            "hook_invocations": session.total_hook_events_received,
            "raw_event_count": sum(
                len(v) for v in session.collected_events.values()
            ),
            "sample_event_count": _sample_events,
            "normalized_event_count": int(
                getattr(session, "normalized_event_count", 0) or 0
            ),
            "unique_behavior_count": len(
                getattr(session, "behavior_summary", {}) or {}
            ),
            "unique_screen_count": len(
                (_explorer_reports.get("state_graph") or {}).get("states") or []
            ),
            "verified_transition_count": len(
                (_explorer_reports.get("state_graph") or {}).get("edges") or []
            ),
            "actions_attempted": len(_explorer_reports.get("action_traces") or []),
            "permission_screens_seen": len(
                _explorer_reports.get("permission_screens") or []
            ),
            "boundary_events": len(_explorer_reports.get("boundary_events") or []),
            "loop_events": len(_explorer_reports.get("loop_events") or []),
            "crashes": len(_explorer_reports.get("crashes") or []),
            "network_requests": len(network_logs),
            "anti_analysis_events": len(
                session.collected_events.get("anti_analysis") or []
            ),
            "companion_packages": list(
                getattr(session, "companion_packages", []) or []
            ),
            "spawn_gated": session.spawn_gated,
            "explorer_used": session.explorer_used,
            "explorer_error": session.explorer_error,
            "anti_evasion_skipped_reason": getattr(
                session, "anti_evasion_skipped_reason", ""
            ),
            "duration_seconds": dynamic_coverage["analysis_elapsed_seconds"],
            "dynamic_conclusive_inputs": {
                "coverage_status": dynamic_coverage["dynamic_status"],
                "goals_successful": dynamic_coverage["goals_successful"],
                "goals_partial": dynamic_coverage["goals_partial"],
                "evidence_event_count": dynamic_coverage["evidence_event_count"],
            },
        },
        "anti_evasion_skipped_reason": getattr(
            session, "anti_evasion_skipped_reason", ""
        ),
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
        # Investigation state, permission findings and classified crashes, so
        # the report can show what was investigated and why - not just which
        # hooks fired. Added as new keys; nothing existing is reshaped.
        result["investigation"] = session.reports.get("investigation", {})
        result["permission_findings"] = session.reports.get("permissions", {})
        result["crashes"] = session.reports.get("crashes", [])
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
            # Surfaced separately so a report can state what the harness changed
            # on the device without that ever counting as sample behaviour.
            result["harness_actions"] = session.collected_events.get("harness_action", [])
            logger.info(f"[Frida] Evidence store flushed: {n} records written to evidence.json")
        except Exception as e:
            logger.error(f"[Frida] Failed to write evidence.json: {e}")

    # ── Fraud Workflow Reconstruction ─────────────────────────────────────────
    # Build causal chain evidence from raw collected_events. This runs after
    # the evidence store flush so workflow records are available for the report.
    # The gate used to be `total_hook_events_received > 0`, so a run where the
    # sandbox enabled accessibility and the sample then did nothing hookable
    # produced no workflow at all - not even a record of what had been enabled.
    # Investigation-derived records now count toward having something to
    # reconstruct.
    _investigation_records = _build_investigation_records(session)
    if WorkflowReconstructor is not None and (
        session.total_hook_events_received > 0 or _investigation_records
    ):
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

            # Preconditions the sandbox established, so the chain can show
            # what made later behaviour reachable. Flagged is_precondition by
            # their rules, so they cannot make a benign run look fraudulent.
            workflow_records.extend(_investigation_records)

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

    tracker = get_active_tracker()
    if tracker:
        tracker.frida_status = "ATTACHED" if session.canary_received else "DEGRADED"
        tracker.explorer_status = session.explorer_used or "none"
        tracker.runtime_event_count = int(session.total_hook_events_received)
        tracker.evidence_count = int(result.get("evidence_record_count") or 0)
        tracker.dynamic_status = str(result.get("dynamic_status") or "COMPLETED")
        if session.reports:
            tracker.merge_explorer_reports(session.reports)
        from sudarshan_core.engines.risk_engine import _dynamic_run_was_conclusive

        conclusive = _dynamic_run_was_conclusive(result)
        tracker.dashboard_inclusion_status = "INCLUDED" if conclusive else "EXCLUDED"
        tracker.persistence_status = "SUCCESS"
        tracker.record(
            "dynamic_analysis_completed",
            "COMPLETED",
            "FridaSession",
            f"status={result.get('dynamic_status')} events={session.total_hook_events_received}",
        )
        tracker.record(
            "dynamic_result_persisted",
            "SUCCESS",
            "artifact_store",
            str(apk_dir),
        )
        tracker.attach_to_result(result)
        tracker.write_json(apk_dir)
    set_active_tracker(None)

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
        "adaptive_exploration_enabled": ADAPTIVE_EXPLORATION_ENABLED,
        "max_exploration_budget_seconds": MAX_EXPLORATION_BUDGET_SECONDS,
        "bfci_weights": BFCI_WEIGHTS,
        "message": (
            "Frida sandbox is ready for dynamic analysis."
            if ready else
            "Frida sandbox not fully configured. See status fields for missing components."
        ),
    }
