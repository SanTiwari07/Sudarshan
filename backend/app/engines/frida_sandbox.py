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
import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.engines.event_bus import RuntimeEventBus

try:
    from app.engines.evidence_store import EvidenceStore
except ImportError:
    EvidenceStore = None
    logger.warning("[Frida] evidence_store module not found. Evidence collection disabled.")

try:
    from app.engines.screenshot_manager import ScreenshotManager
    from app.engines.ioc_collector import IOCCollector
    from app.engines.mitre_mapper import MitreMapper
except ImportError:
    ScreenshotManager = None
    IOCCollector = None
    MitreMapper = None
    logger.warning("[Frida] Wave 2 intelligence modules not found.")

try:
    from app.engines.permission_orchestrator import PermissionOrchestrator
    from app.engines.replay_engine import ReplayEngine
except ImportError:
    PermissionOrchestrator = None
    ReplayEngine = None
    logger.warning("[Frida] Wave 3 navigator modules not found.")

try:
    from app.engines.network_capture import NetworkCapture
    from app.engines.anti_analysis_detector import AntiAnalysisDetector
    from app.engines.yara_scanner import YARAScanner
except ImportError:
    NetworkCapture = None
    AntiAnalysisDetector = None
    YARAScanner = None
    logger.warning("[Frida] Wave 4 intelligence modules not found.")

try:
    from app.engines.analysis_history import AnalysisHistory
    from app.engines.report_generator import ReportGenerator
except ImportError:
    AnalysisHistory = None
    ReportGenerator = None
    logger.warning("[Frida] Wave 5 reporting modules not found.")

logger = logging.getLogger(__name__)

# ─── Configuration ─────────────────────────────────────────────────────────────

# Path to the Frida JS hooks script
_HOOKS_SCRIPT = Path(__file__).parent / "frida_hooks" / "banking_trojan.js"

# UI Exploration Mode
#   "ai"     : AI + Deterministic UI Explorer only
#   "monkey" : Dumb fuzzer only (legacy)
#   "hybrid" : AI Explorer + Monkey running simultaneously
EXPLORER_MODE = os.environ.get("SUDARSHAN_EXPLORER_MODE", "ai")

try:
    from app.engines.ui_explorer import UIExplorer
except ImportError:
    UIExplorer = None
    logger.warning("[Frida] ui_explorer module not found. Falling back to monkey mode.")
    EXPLORER_MODE = "monkey"

# ADB executable — tries PATH first, then common Android Studio locations
_ADB_CANDIDATES = [
    "adb",
    r"C:\Users\{user}\AppData\Local\Android\Sdk\platform-tools\adb.exe",
    r"C:\Program Files\Android\Android Studio\sdk\platform-tools\adb.exe",
]

# Default analysis duration in seconds
ANALYSIS_DURATION_SECONDS = int(os.getenv("FRIDA_ANALYSIS_DURATION", "30"))

# ── Docker / TCP ADB support ───────────────────────────────────────────────────
# When running in Docker, the Android emulator is on the HOST machine.
# Set ADB_HOST=host.docker.internal and ADB_PORT=5555 in docker-compose.yml.
# The backend will automatically run: adb connect <ADB_HOST>:<ADB_PORT>
ADB_HOST = os.getenv("ADB_HOST", "")   # e.g. host.docker.internal
ADB_PORT = os.getenv("ADB_PORT", "5555")

# ─── BFCI Weights (from proposal) ─────────────────────────────────────────────

BFCI_WEIGHTS = {
    "accessibility": 0.35,   # wa — heaviest: present in 87% of banking trojans
    "sms":           0.25,   # ws — OTP theft
    "overlay":       0.20,   # wo — phishing screens
    "banking":       0.10,   # wb — confirms target is a banking app
    "network":       0.05,   # wn — C2 communication
    "persistence":   0.05,   # wp — device admin / lockdown
}

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
                # Accept both local emulators and TCP-connected devices
                if "emulator" in serial or ":" in serial:
                    devices.append(serial.strip())
    return devices


def _adb_install_apk(apk_path: str, device: str) -> Tuple[bool, str]:
    """Install an APK onto the target device with retries.
    
    Automatically falls back to --bypass-low-target-sdk-block if the APK
    targets an older SDK version (e.g. legacy malware samples).
    """
    last_out = ""
    for attempt in range(3):
        ok, out = _adb("-s", device, "install", "-r", "-t", apk_path, timeout=120)
        if ok:
            return ok, out

        # ── Fallback: bypass deprecated SDK version block ──────────────────
        # Useful for older APKs (targetSdk < 24) on modern emulators (API 34+)
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in out:
            logger.info("[Frida] Retrying install with --bypass-low-target-sdk-block")
            ok2, out2 = _adb(
                "-s", device, "install", "-r", "-t",
                "--bypass-low-target-sdk-block",
                apk_path, timeout=120
            )
            if ok2:
                return ok2, out2
            last_out = out2
        else:
            last_out = out

        logger.warning(f"[Frida] APK install attempt {attempt+1} failed: {last_out}")
        time.sleep(2)
    return False, f"Failed to install APK after 3 attempts. Last error: {last_out}"



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

    # ── Strategy 2: androguard (pure-Python, no native tools needed) ──────────
    try:
        from androguard.misc import AnalyzeAPK
        a, _, _ = AnalyzeAPK(apk_path)
        package_name = a.get_package()
        main_activity = a.get_main_activity()
        if package_name:
            logger.debug(f"[Frida] Extracted via androguard: {package_name} / {main_activity}")
            return package_name, main_activity
    except ImportError:
        logger.warning("[Frida] androguard not installed — install it: pip install androguard")
    except Exception as e:
        logger.warning(f"[Frida] androguard failed to parse APK: {e}")

    return package_name, main_activity



def _launch_app(device: str, package_name: str) -> bool:
    """Launch the app's main activity via monkey."""
    ok, _ = _adb(
        "-s", device, "shell",
        f"monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
        timeout=15
    )
    return ok

# ─── BFCI Score Calculation ────────────────────────────────────────────────────

def _score_component(events: List[Dict], max_events: int = 5) -> float:
    """
    Convert an event list to a 0–100 component score.
    More unique hook types = higher score, capped at max_events.
    """
    if not events:
        return 0.0
    unique_hooks = len(set(e["data"].get("hook", "") for e in events))
    score = min(unique_hooks / max_events, 1.0) * 100.0
    return round(score, 2)


def calculate_bfci(collected_events: Dict[str, List[Dict]]) -> Tuple[float, Dict[str, float], List[str]]:
    """
    Compute the Behavioral Fraud Confidence Index (BFCI).

    BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)

    Returns:
        (bfci_score, component_scores, evidence_list)
    """
    components = {
        "accessibility": _score_component(collected_events.get("accessibility", []), max_events=3),
        "sms":           _score_component(collected_events.get("sms", []),           max_events=2),
        "overlay":       _score_component(collected_events.get("overlay", []),        max_events=2),
        "banking":       _score_component(collected_events.get("banking", []),        max_events=3),
        "network":       _score_component(collected_events.get("network", []),        max_events=10),
        "persistence":   _score_component(collected_events.get("persistence", []),    max_events=2),
    }

    bfci = sum(BFCI_WEIGHTS[k] * v for k, v in components.items())
    bfci = round(min(bfci, 100.0), 2)

    # Build evidence strings
    evidence: List[str] = []
    weight_labels = {
        "accessibility": ("A", "Accessibility abuse"),
        "sms":           ("S", "SMS/OTP interception"),
        "overlay":       ("O", "Overlay window attack"),
        "banking":       ("B", "Banking app targeting"),
        "network":       ("N", "C2 network communication"),
        "persistence":   ("P", "Persistence mechanism"),
    }
    for key, (symbol, label) in weight_labels.items():
        score = components[key]
        weight = BFCI_WEIGHTS[key]
        if score > 0:
            contribution = round(weight * score, 2)
            event_count = len(collected_events.get(key, []))
            evidence.append(
                f"[{symbol}] {label}: {event_count} runtime event(s) detected "
                f"— component score {score:.0f} × weight {weight} = +{contribution:.1f} to BFCI"
            )

    return bfci, components, evidence

# ─── Frida Session Manager ────────────────────────────────────────────────────

class FridaSession:
    """Manages a Frida instrumentation session against a target app."""

    def __init__(self, device_serial: str, package_name: str, main_activity: Optional[str] = None):
        self.device_serial = device_serial
        self.package_name = package_name
        self.main_activity = main_activity
        self.event_bus = RuntimeEventBus()
        self.collected_events: Dict[str, List[Dict]] = {
            "accessibility": [], "sms": [], "overlay": [],
            "banking": [], "network": [], "persistence": [],
            "dangerous_apis": [], "files_accessed": [],
            "anti_analysis": [],  # NEW: sandbox evasion events
        }
        self.hook_errors: List[str] = []
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
                event = payload.get("payload", {})
                category = event.get("category")
                if category in self.collected_events:
                    self.collected_events[category].append(event)
                    severity = event.get("severity", event.get("data", {}).get("severity", "MED"))
                    logger.debug(f"[Frida] [{severity}] {category}: {event.get('data', {}).get('hook')}")

                # Publish to Event Bus (EvidenceStore + UIExplorer subscribe here)
                self.event_bus.publish(event)

            elif msg_type == "hook_error":
                err = f"Hook failed: {payload.get('hook')} — {payload.get('error')}"
                self.hook_errors.append(err)
                logger.warning(f"[Frida] {err}")

            elif msg_type == "ready":
                logger.info(f"[Frida] {payload.get('message')}")

        elif message.get("type") == "error":
            logger.error(f"[Frida] Script error: {message.get('description')}")

    def run(self, duration_seconds: int = ANALYSIS_DURATION_SECONDS) -> bool:
        """
        Attach Frida to the target app and collect events for `duration_seconds`.

        Strategy (Android 15 / API 37 compatible):
          1. Launch app via `am start` (if main_activity known) or `monkey`
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
            
            # ── Strategy 1: Launch & Attach ──
            if self.main_activity:
                safe_act = shlex.quote(self.main_activity)
                logger.info(f"[Frida] Launching {self.package_name}/{self.main_activity} via am start")
                _adb(
                    "-s", self.device_serial, "shell",
                    f"am start -n {safe_pkg}/{safe_act}",
                    timeout=15
                )
            else:
                logger.info(f"[Frida] Launching {self.package_name} via monkey")
                _adb(
                    "-s", self.device_serial, "shell",
                    f"monkey -p {safe_pkg} -c android.intent.category.LAUNCHER 1",
                    timeout=15
                )

            # Give the app time to start up
            time.sleep(3)

            self._session = None
            for attempt in range(15):
                try:
                    self._session = device.attach(self.package_name)
                    logger.info(f"[Frida] Attached to {self.package_name} (attempt {attempt+1})")
                    break
                except frida.ProcessNotFoundError:
                    logger.warning(f"[Frida] Process not found yet (attempt {attempt+1}), waiting...")
                    time.sleep(2)
                except Exception as e:
                    logger.warning(f"[Frida] Attach attempt {attempt+1} failed: {e}")
                    time.sleep(2)

            # ── Strategy 2: fallback to spawn() for older API levels ───────────────
            if not self._session:
                logger.info("[Frida] monkey-attach failed, falling back to device.spawn()")
                pid = None
                for attempt in range(3):
                    try:
                        pid = device.spawn([self.package_name])
                        break
                    except Exception as e:
                        logger.warning(f"[Frida] Spawn attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                if not pid:
                    raise Exception("Frida attach failed. Ensure frida-server is running on emulator.")

                for attempt in range(3):
                    try:
                        self._session = device.attach(pid)
                        break
                    except Exception as e:
                        logger.warning(f"[Frida] Post-spawn attach attempt {attempt+1} failed: {e}")
                        time.sleep(2)
                if not self._session:
                    raise Exception("Failed to attach to spawned process")
                device.resume(pid)
                
                import shlex
                safe_pkg = shlex.quote(self.package_name)
                # In Android 15, spawned apps are forced into the background due to BAL.
                # Force the UI to the foreground.
                logger.info(f"[Frida] Pushing spawned app to foreground...")
                if self.main_activity:
                    safe_act = shlex.quote(self.main_activity)
                    _adb("-s", self.device_serial, "shell", f"am start -n {safe_pkg}/{safe_act}")
                else:
                    _adb("-s", self.device_serial, "shell", f"monkey -p {safe_pkg} -c android.intent.category.LAUNCHER 1")
                time.sleep(2)

            self._script = self._session.create_script(script_source)
            self._script.on("message", self._on_message)
            self._script.load()

            logger.info(f"[Frida] Monitoring {self.package_name} for {duration_seconds}s...")
            
            # ── Auto-Interaction Fuzzer ─────────────────────────────────────────────────
            logger.info(f"[Frida] Starting automated UI fuzzer (Mode: {EXPLORER_MODE}) in background...")
            fuzzer_process = None
            explorer = None
            explorer_thread = None

            if EXPLORER_MODE in ["monkey", "hybrid"]:
                import shlex
                safe_pkg = shlex.quote(self.package_name)
                fuzzer_process = subprocess.Popen(
                    [_find_adb(), "-s", self.device_serial, "shell", 
                     f"monkey -p {safe_pkg} --pct-touch 50 --pct-motion 20 --pct-nav 10 --throttle 300 -v 500"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

            if EXPLORER_MODE in ["ai", "hybrid"]:
                # ── Agentic Explorer (primary) — falls back to UIExplorer on import error ──
                try:
                    from app.engines.agentic_explorer import AgenticExplorer
                    explorer = AgenticExplorer(
                        device_serial=self.device_serial,
                        adb_path=_find_adb(),
                        package_name=self.package_name,
                        event_bus=self.event_bus,
                        mode=EXPLORER_MODE,
                    )
                    logger.info("[Frida] AgenticExplorer selected.")
                except ImportError:
                    # Graceful fallback — AgenticExplorer not yet available
                    if UIExplorer is not None:
                        explorer = UIExplorer(
                            self.device_serial, _find_adb(),
                            event_bus=self.event_bus, mode=EXPLORER_MODE
                        )
                        logger.warning("[Frida] AgenticExplorer import failed — falling back to UIExplorer.")
                    else:
                        explorer = None
                        logger.warning("[Frida] Both AgenticExplorer and UIExplorer unavailable.")

                if explorer is not None:
                    def _run_explorer():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(explorer.start(duration_seconds))
                        loop.close()

                    explorer_thread = threading.Thread(target=_run_explorer, daemon=True)
                    explorer_thread.start()

            time.sleep(duration_seconds)
            return True

        except Exception as e:
            logger.error(f"[Frida] Session failed: {type(e).__name__}: {e}")
            return False

        finally:
            # Cleanup fuzzer if it's still running
            if 'fuzzer_process' in locals() and fuzzer_process and fuzzer_process.poll() is None:
                fuzzer_process.terminate()
                
            if 'explorer' in locals() and explorer:
                try:
                    explorer.stop()
                    self.reports = explorer.get_reports()
                    # Flush agentic-only artifacts (audit_log.json, benchmark.json)
                    # UIExplorer does not have flush_artifacts() — guarded by hasattr.
                    if hasattr(explorer, 'flush_artifacts'):
                        from pathlib import Path as _Path
                        _apk_dir = _Path(getattr(self, '_apk_dir', '.'))
                        explorer.flush_artifacts(_apk_dir)
                except Exception:
                    pass

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

    # ── Step 1b: Automatically start frida-server if dead ──────────────────────
    logger.info("[Frida] Checking frida-server status...")
    ok, out = await asyncio.get_event_loop().run_in_executor(
        None, _adb, "-s", device_serial, "shell", "ps -A | grep frida-server"
    )
    if "frida-server" not in out:
        logger.info("[Frida] frida-server not running, starting it automatically...")
        # Since adb is running as root, we can run it directly and background it
        await asyncio.get_event_loop().run_in_executor(
            None, _adb, "-s", device_serial, "shell", "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
        )
        await asyncio.sleep(2) # Give it time to start up

    # ── Step 2: Extract package name ───────────────────────────────────────────
    loop = asyncio.get_event_loop()
    main_activity = None
    if not package_name:
        package_name, main_activity = await loop.run_in_executor(None, _extract_apk_info, apk_path)
        
    if not package_name:
        logger.warning("[Frida] Could not extract package name from APK")
        base_result["error"] = "Could not extract package name from APK. Ensure aapt/aapt2 is in PATH."
        return base_result

    logger.info(f"[Frida] Target package: {package_name} (Main Activity: {main_activity})")

    # ── Step 3: Install APK ────────────────────────────────────────────────────
    ok, output = await loop.run_in_executor(None, _adb_install_apk, apk_path, device_serial)
    if not ok:
        logger.error(f"[Frida] APK install failed: {output}")
        base_result["error"] = f"APK install failed: {output}"
        return base_result
    logger.info(f"[Frida] APK installed: {package_name}")

    # ── Step 4: Run Frida session ──────────────────────────────────────────────
    session = FridaSession(device_serial, package_name, main_activity=main_activity)

    apk_dir = Path(apk_path).parent
    
    # ── Wave 2: Initialize Intelligence Collectors ─────────────────────────────
    if ScreenshotManager is not None:
        session.screenshot_manager = ScreenshotManager(
            device_serial=device_serial,
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
        # Assuming YARA rules are placed in backend/yara_rules
        rules_dir = Path("yara_rules")
        session.yara_scanner = YARAScanner(rules_dir=rules_dir, event_bus=session.event_bus)

    def _run_sync():
        return session.run(duration_seconds=ANALYSIS_DURATION_SECONDS)

    success = await loop.run_in_executor(None, _run_sync)

    if not success:
        base_result["error"] = "Frida attach failed. Ensure frida-server is running on emulator."
        return base_result

    # ── Step 5: Compute BFCI ───────────────────────────────────────────────────
    bfci, components, evidence = calculate_bfci(session.collected_events)

    # ── Step 6: Build structured result ───────────────────────────────────────
    # Flatten API calls for risk_engine.py compatibility
    api_calls = [
        e["data"].get("hook", "")
        for category in ["accessibility", "sms", "overlay", "dangerous_apis"]
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
        "package_name": package_name,
        "device": device_serial,

        # BFCI result (new fields for the updated risk_engine)
        "bfci": bfci,
        "bfci_components": components,
        "bfci_evidence": evidence,

        # Legacy fields expected by risk_engine._calculate_dynamic_score()
        # Maps Frida events → string signals the existing engine checks
        "api_calls": list(set(api_calls))[:30],
        "network_logs": network_logs[:20],
        "files_accessed": list(set(files_accessed))[:20],
        "screenshots": [],  # Not implemented in static sandbox
        "activities_triggered": [package_name],

        # Metadata
        "hook_errors": session.hook_errors,
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
    apk_dir = Path(apk_path).parent
    
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
    if session.evidence_store is not None:
        try:
            n = session.evidence_store.flush(apk_dir / "evidence.json")
            result["evidence_record_count"] = n
            result["anti_analysis_events"] = session.collected_events.get("anti_analysis", [])
        except Exception as e:
            logger.error(f"[Frida] Failed to write evidence.json: {e}")
            
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
            history.save_run(result, apk_sha256="unknown", stage_name="single", explorer_mode=EXPLORER_MODE)
        except Exception as e:
            logger.error(f"[Frida] Failed to save analysis history: {e}")
            
    if ReportGenerator is not None:
        try:
            rg = ReportGenerator(apk_dir, package_name, result)
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
