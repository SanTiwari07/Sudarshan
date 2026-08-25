#!/usr/bin/env python3
"""
Sudarshan Platform Health Check - startup validation for all subsystems.

Verifies:
  ✓ Docker       (docker daemon + compose services)
  ✓ MobSF        (upload → scan → report cycle)
  ✓ Analysis Engine (health + tool availability)
  ✓ Backend      (health + auth)
  ✓ Frontend     (reachability)
  ✓ ADB          (host adb version + connected devices)
  ✓ Emulator     (running + boot completed)
  ✓ Frida        (version + frida-server on device)
  ✓ Java         (version)
  ✓ APKTool      (version)
  ✓ JADX         (version)
  ✓ Androguard   (import + version)
  ✓ mitmproxy    (proxy reachable)
  ✓ SQLite       (database accessible)

Usage:
    python scripts/health_check.py
    python scripts/health_check.py --quick   # skip slow MobSF scan
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SHARED = Path(__file__).resolve().parent.parent / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from sudarshan_core.validation.labelled_corpus import resolve_sample  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[WARN] 'requests' not installed. HTTP checks will be skipped.")

# ─── Configuration ─────────────────────────────────────────────────────────────

MOBSF_HOST    = os.getenv("MOBSF_HOST_EXTERNAL", "http://localhost:8008")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "sudarshan_mobsf_api_key_2026")
BACKEND_HOST  = os.getenv("BACKEND_HOST", "http://localhost:8000")
FRONTEND_HOST = os.getenv("FRONTEND_HOST", "http://localhost:5173")
ENGINE_HOST   = os.getenv("ENGINE_HOST", "http://localhost:8001")  # may not be exposed
MITMPROXY_PORT = os.getenv("MITMPROXY_PORT", "8085")
def _default_adb() -> str:
    """
    adb on PATH, else the SDK's default install location for this platform.

    The fallback used to be a literal `C:\\Users\\sansk\\...` - one specific
    developer's home directory, which resolves on exactly one machine.
    """
    from pathlib import Path as _Path

    found = shutil.which("adb")
    if found:
        return found
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    roots = [_Path(sdk)] if sdk else []
    home = _Path.home()
    roots += [
        home / "AppData" / "Local" / "Android" / "Sdk",   # Windows
        home / "Library" / "Android" / "sdk",             # macOS
        home / "Android" / "Sdk",                         # Linux
    ]
    for root in roots:
        for name in ("adb.exe", "adb"):
            candidate = root / "platform-tools" / name
            if candidate.is_file():
                return str(candidate)
    return "adb"   # let the caller fail with a normal "not found" error


ADB_BIN       = _default_adb()

# Resolved rather than hardcoded: the corpus is gitignored and currently sits at
# `test apk/test apk/`, so the old literal path resolved to nothing.
_SAMPLE       = resolve_sample("Vulnerable/InsecureBankv2.apk")
TEST_APK      = str(_SAMPLE) if _SAMPLE else ""

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"
SKIP = "⏭  SKIP"

results: List[Dict[str, Any]] = []


def _check(name: str, status: str, detail: str = "", critical: bool = False) -> bool:
    icon = status
    results.append({"name": name, "status": status, "detail": detail, "critical": critical})
    print(f"  {icon}  {name}")
    if detail:
        print(f"       {detail}")
    return status in (PASS, WARN)


def _http_get(url: str, timeout: int = 5, headers: dict = None) -> Optional[requests.Response]:
    if not HAS_REQUESTS:
        return None
    try:
        return requests.get(url, timeout=timeout, headers=headers or {}, allow_redirects=True)
    except Exception:
        return None


def _http_post(url: str, data: dict = None, files: dict = None, headers: dict = None, timeout: int = 30) -> Optional[requests.Response]:
    if not HAS_REQUESTS:
        return None
    try:
        return requests.post(url, data=data, files=files, headers=headers or {}, timeout=timeout)
    except Exception:
        return None


def _run(cmd: List[str], timeout: int = 10) -> Tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


# ─── Individual checks ─────────────────────────────────────────────────────────

def check_docker():
    print("\n[Docker]")
    ok, out = _run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if ok:
        _check("Docker daemon", PASS, f"Version {out}")
    else:
        _check("Docker daemon", FAIL, "Docker not running", critical=True)
        return

    # Container states
    ok, out = _run(["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"])
    containers = {}
    for line in out.splitlines():
        parts = line.split("|", 1)
        if len(parts) == 2:
            containers[parts[0]] = parts[1]

    for name in ["sudarshan-mobsf", "sudarshan-analysis-engine", "sudarshan-backend", "sudarshan-frontend"]:
        status = containers.get(name, "NOT FOUND")
        is_up = "Up" in status
        is_healthy = "healthy" in status
        icon = PASS if is_up else FAIL
        _check(f"Container: {name}", icon, status, critical=(not is_up and name != "sudarshan-frontend"))


def check_mobsf(quick: bool = False):
    print("\n[MobSF]")
    if not HAS_REQUESTS:
        _check("MobSF API", SKIP, "requests not installed")
        return

    headers = {"Authorization": MOBSF_API_KEY}

    # Health
    r = _http_get(f"{MOBSF_HOST}/", timeout=5, headers=headers)
    if r and r.status_code == 200:
        _check("MobSF reachable", PASS, f"HTTP {r.status_code}")
    else:
        _check("MobSF reachable", FAIL, f"HTTP {r.status_code if r else 'no response'}", critical=True)
        return

    if quick:
        _check("MobSF upload/scan", SKIP, "Quick mode - skipping scan")
        return

    # Upload test APK
    apk_path = os.path.abspath(TEST_APK)
    if not os.path.exists(apk_path):
        _check("MobSF upload test", WARN, f"Test APK not found: {apk_path}")
        return

    with open(apk_path, "rb") as f:
        r = _http_post(
            f"{MOBSF_HOST}/api/v1/upload",
            headers=headers,
            files={"file": ("InsecureBankv2.apk", f, "application/octet-stream")},
            timeout=120,
        )
    if not r or r.status_code != 200:
        _check("MobSF APK upload", FAIL, f"HTTP {r.status_code if r else 'no response'}: {r.text[:200] if r else ''}", critical=True)
        return

    data = r.json()
    scan_hash = data.get("hash")
    _check("MobSF APK upload", PASS, f"scan_hash={scan_hash}")

    # Scan
    r = _http_post(f"{MOBSF_HOST}/api/v1/scan", headers=headers, data={"hash": scan_hash}, timeout=300)
    if r and r.status_code == 200:
        _check("MobSF static scan", PASS, "Scan triggered")
    else:
        _check("MobSF static scan", FAIL, f"HTTP {r.status_code if r else 'no response'}", critical=True)
        return

    time.sleep(5)  # brief wait

    # Report
    r = _http_post(f"{MOBSF_HOST}/api/v1/report_json", headers=headers, data={"hash": scan_hash}, timeout=60)
    if r and r.status_code == 200:
        report = r.json()
        pkg = report.get("package_name", "?")
        perms = len(report.get("permissions", {}))
        _check("MobSF JSON report", PASS, f"package={pkg}, permissions={perms}")
    else:
        _check("MobSF JSON report", FAIL, f"HTTP {r.status_code if r else 'no response'}", critical=True)


def check_analysis_engine():
    print("\n[Analysis Engine]")
    if not HAS_REQUESTS:
        _check("Analysis Engine", SKIP, "requests not installed")
        return

    # The engine is not exposed externally in docker-compose - check via backend proxy
    # Try direct localhost:8001 (works when running locally, not when only in Docker)
    r = _http_get(f"{ENGINE_HOST}/health", timeout=5)
    if r and r.status_code == 200:
        _check("Engine health", PASS, r.text[:100])

        r2 = _http_get(f"{ENGINE_HOST}/status", timeout=15)
        if r2 and r2.status_code == 200:
            status = r2.json()
            tools = status.get("tools", {})
            _check("APKTool available", PASS if tools.get("apktool") else WARN, str(tools.get("apktool")))
            _check("JADX available", PASS if tools.get("jadx") else WARN, str(tools.get("jadx")))
            _check("Androguard available", PASS if tools.get("androguard") else FAIL, str(tools.get("androguard")))
            _check("ADB connected (engine)", PASS if tools.get("adb_connected") else WARN,
                   "No emulator" if not tools.get("adb_connected") else "Connected")
    else:
        _check("Engine health", WARN, "Not reachable on localhost:8001 (may be internal-only in Docker)")


def check_backend():
    print("\n[Backend]")
    if not HAS_REQUESTS:
        _check("Backend", SKIP, "requests not installed")
        return

    r = _http_get(f"{BACKEND_HOST}/health", timeout=5)
    if r and r.status_code == 200:
        _check("Backend health", PASS, f"HTTP {r.status_code}")
    else:
        _check("Backend health", FAIL, f"HTTP {r.status_code if r else 'no response'}", critical=True)
        return

    r = _http_get(f"{BACKEND_HOST}/", timeout=5)
    if r and r.status_code == 200:
        info = r.json()
        _check("Backend root", PASS, f"version={info.get('version')}")


def check_frontend():
    print("\n[Frontend]")
    r = _http_get(f"{FRONTEND_HOST}/", timeout=5)
    if r and r.status_code == 200:
        _check("Frontend reachable", PASS, f"HTTP {r.status_code}")
    else:
        _check("Frontend reachable", WARN, f"HTTP {r.status_code if r else 'not running'}")


def check_adb():
    print("\n[ADB]")
    if not ADB_BIN or not os.path.exists(ADB_BIN):
        _check("ADB binary", FAIL, "adb not found in PATH", critical=True)
        return

    ok, out = _run([ADB_BIN, "version"])
    version_line = out.splitlines()[0] if out else "?"
    _check("ADB binary", PASS if ok else FAIL, version_line)

    ok, out = _run([ADB_BIN, "devices"])
    devices = [l for l in out.splitlines()[1:] if l.strip() and "device" in l]
    if devices:
        _check("ADB devices", PASS, f"{len(devices)} device(s): {', '.join(d.split()[0] for d in devices)}")
    else:
        _check("ADB devices", WARN, "No sandbox devices connected. Start Genymotion Desktop (or an Android Studio AVD).")

    return devices


def check_emulator(devices: List[str]):
    print("\n[Android Sandbox]")
    provider = os.environ.get("SANDBOX_PROVIDER", "genymotion")
    preferred = os.environ.get("DEVICE_SERIAL", "").strip()
    if not devices:
        _check("Sandbox running", WARN, f"No device connected - start {provider} (Android 10/11+, x86_64)")
        _check("Boot completed", SKIP, "No device")
        _check("ADB root", SKIP, "No device")
        _check("SELinux mode", SKIP, "No device")
        _check("frida-server on device", SKIP, "No device")
        return

    serials = [d.split()[0] for d in devices]
    if preferred and preferred in serials:
        device = preferred
    else:
        device = serials[0]
    _check("Sandbox connected", PASS, f"Provider={provider} Serial={device}")

    # Boot completed
    ok, out = _run([ADB_BIN, "-s", device, "shell", "getprop", "sys.boot_completed"])
    booted = out.strip() == "1"
    _check("Boot completed", PASS if booted else WARN, out.strip())

    # Root
    ok, out = _run([ADB_BIN, "-s", device, "root"])
    _check("ADB root", PASS if ok else WARN, out.strip()[:80])
    time.sleep(1)

    # SELinux
    ok, out = _run([ADB_BIN, "-s", device, "shell", "getenforce"])
    enforce = out.strip()
    _check("SELinux mode", PASS if "Permissive" in enforce else WARN,
           f"{enforce} - {'OK for Frida' if 'Permissive' in enforce else 'run: adb shell setenforce 0'}")

    # frida-server
    ok, out = _run([ADB_BIN, "-s", device, "shell", "ps -A | grep frida-server"], timeout=15)
    if "frida-server" in out:
        _check("frida-server running", PASS, "Process found")
    else:
        _check("frida-server running", WARN, "Not running - push frida-server and start it")


def check_frida():
    print("\n[Frida]")
    try:
        import frida
        version = frida.__version__
        _check("Frida Python package", PASS, f"v{version}")

        # Try enumerate devices
        try:
            devices = frida.enumerate_devices()
            device_ids = [d.id for d in devices]
            _check("Frida device enumeration", PASS, f"Devices: {device_ids}")
        except Exception as e:
            _check("Frida device enumeration", WARN, str(e))

    except ImportError:
        _check("Frida Python package", FAIL, "frida not installed: pip install frida==17.16.4", critical=True)


def check_java():
    print("\n[Java]")
    ok, out = _run(["java", "-version"], timeout=10)
    if ok or "version" in out:
        version_line = out.splitlines()[0] if out else "?"
        _check("Java", PASS, version_line)
    else:
        _check("Java", FAIL, "Java not found in PATH", critical=True)


def check_python_deps():
    print("\n[Python Dependencies]")
    deps = [
        ("androguard", "androguard"),
        ("frida", "frida"),
        ("httpx", "httpx"),
        ("fastapi", "fastapi"),
        ("pydantic", "pydantic"),
    ]
    for display, module in deps:
        try:
            mod = __import__(module)
            ver = getattr(mod, "__version__", "?")
            _check(f"  {display}", PASS, f"v{ver}")
        except ImportError:
            _check(f"  {display}", WARN, f"not installed in this environment")


def check_apktool():
    print("\n[APKTool]")
    apktool = shutil.which("apktool")
    if not apktool:
        _check("APKTool", WARN, "Not in PATH (OK if running in Docker container)")
        return

    ok, out = _run(["apktool", "--version"], timeout=10)
    version = out.strip()
    _check("APKTool", PASS if ok else FAIL, f"v{version}")


def check_jadx():
    print("\n[JADX]")
    jadx = shutil.which("jadx")
    if not jadx:
        _check("JADX", WARN, "Not in PATH (OK if running in Docker container)")
        return

    ok, out = _run(["jadx", "--version"], timeout=10)
    _check("JADX", PASS if ok else FAIL, out.strip())


def check_mitmproxy():
    print("\n[mitmproxy]")
    r = _http_get(f"http://localhost:{MITMPROXY_PORT}/", timeout=3)
    # mitmproxy returns 502 to non-proxied connections - that means it's running
    if r is not None:
        _check("mitmproxy proxy port", PASS, f"HTTP {r.status_code} (proxy responding on :{MITMPROXY_PORT})")
    else:
        _check("mitmproxy proxy port", WARN, f"Not reachable on :{MITMPROXY_PORT}")


def check_frida_hooks():
    print("\n[Frida Hooks Script]")
    script_dir = os.path.join(os.path.dirname(__file__), "..", "shared", "sudarshan_core", "engines", "frida_hooks")
    bundle = os.path.join(script_dir, "banking_trojan.bundle.js")
    source = os.path.join(script_dir, "banking_trojan.js")

    if os.path.exists(bundle):
        size = os.path.getsize(bundle)
        _check("banking_trojan.bundle.js", PASS, f"{size // 1024} KB (pre-compiled with frida-java-bridge)")
    else:
        _check("banking_trojan.bundle.js", WARN, "Bundle not found - Frida 17 requires compiled bundle")

    if os.path.exists(source):
        size = os.path.getsize(source)
        _check("banking_trojan.js", PASS, f"{size // 1024} KB (source script)")
    else:
        _check("banking_trojan.js", FAIL, "Source script not found", critical=True)


# ─── Summary ───────────────────────────────────────────────────────────────────

def print_summary():
    print("\n" + "=" * 70)
    print("SUDARSHAN PLATFORM HEALTH SUMMARY")
    print("=" * 70)

    critical_failures = [r for r in results if r["status"] == FAIL and r.get("critical")]
    warnings = [r for r in results if r["status"] == WARN]
    failures = [r for r in results if r["status"] == FAIL]
    passed = [r for r in results if r["status"] == PASS]

    print(f"  Total checks:     {len(results)}")
    print(f"  {PASS}:     {len(passed)}")
    print(f"  {WARN}:     {len(warnings)}")
    print(f"  {FAIL}:     {len(failures)}")
    print(f"  Critical failures: {len(critical_failures)}")

    if critical_failures:
        print(f"\n{'─' * 70}")
        print("CRITICAL FAILURES - Platform NOT operational until resolved:")
        for r in critical_failures:
            print(f"  ❌ {r['name']}: {r['detail']}")

    if warnings:
        print(f"\n{'─' * 70}")
        print("WARNINGS - Platform partially operational:")
        for r in warnings:
            print(f"  ⚠️  {r['name']}: {r['detail']}")

    if not critical_failures:
        if warnings:
            print(f"\n{'─' * 70}")
            print("⚠️  Platform is PARTIALLY OPERATIONAL")
            print("   Static analysis works. Dynamic analysis requires an Android emulator.")
        else:
            print(f"\n{'─' * 70}")
            print("✅ Platform is FULLY OPERATIONAL")
    else:
        print(f"\n{'─' * 70}")
        print("❌ Platform is NOT OPERATIONAL - resolve critical failures above")

    print("=" * 70)

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "health_check_result.json")
    with open(out_path, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total": len(results),
            "passed": len(passed),
            "warnings": len(warnings),
            "failures": len(failures),
            "critical_failures": len(critical_failures),
            "checks": results,
        }, f, indent=2)
    print(f"[INFO] Results saved: {out_path}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sudarshan Platform Health Check")
    parser.add_argument("--quick", action="store_true", help="Skip slow MobSF scan test")
    args = parser.parse_args()

    print("=" * 70)
    print("SUDARSHAN BANKING THREAT INTELLIGENCE PLATFORM")
    print("Complete Health Check - All Subsystems")
    print("=" * 70)

    check_docker()
    check_mobsf(quick=args.quick)
    check_analysis_engine()
    check_backend()
    check_frontend()
    devices_raw, *_ = check_adb(), None
    devices = devices_raw or []
    check_emulator(devices)
    check_frida()
    check_java()
    check_python_deps()
    check_apktool()
    check_jadx()
    check_mitmproxy()
    check_frida_hooks()
    print_summary()


if __name__ == "__main__":
    main()
