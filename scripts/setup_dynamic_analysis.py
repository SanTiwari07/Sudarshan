#!/usr/bin/env python3
"""
Sudarshan Dynamic Analysis Setup Script
=========================================
Sets up the Android emulator + Frida for dynamic analysis.

This script:
  1. Checks for AVD (Android Virtual Device)
  2. Starts emulator if not running
  3. Waits for boot completion
  4. Enables ADB root
  5. Sets SELinux to permissive
  6. Pushes frida-server to /data/local/tmp/frida-server
  7. Starts frida-server
  8. Enables ADB over TCP (port 5555)
  9. Verifies Frida can attach
  10. Reports sandbox readiness

Usage:
    python scripts/setup_dynamic_analysis.py [--avd AVD_NAME] [--push-server]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─── Configuration ─────────────────────────────────────────────────────────────

ANDROID_SDK = os.environ.get(
    "ANDROID_SDK_ROOT",
    os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")
)
ADB_BIN = shutil.which("adb") or os.path.join(ANDROID_SDK, "platform-tools", "adb.exe")
EMULATOR_BIN = shutil.which("emulator") or os.path.join(ANDROID_SDK, "emulator", "emulator.exe")

# Frida server binary (project root)
FRIDA_SERVER_DIR = Path(__file__).parent.parent / "frida-server-17.16.4-android-x86_64"
FRIDA_SERVER_BIN = FRIDA_SERVER_DIR / "frida-server-17.16.4-android-x86_64"

# Target ADB TCP port (matches docker-compose.yml ADB_PORT)
ADB_TCP_PORT = 5555

# Preferred AVD name (user can override with --avd)
PREFERRED_AVD = os.environ.get("SUDARSHAN_AVD", "")


def _run(cmd: List[str], timeout: int = 30, check: bool = False) -> Tuple[bool, str, str]:
    """Run subprocess, return (success, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0
        return ok, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def _adb(*args: str, timeout: int = 30) -> Tuple[bool, str]:
    ok, out, err = _run([ADB_BIN] + list(args), timeout=timeout)
    return ok, (out + " " + err).strip()


def _adb_s(serial: str, *args: str, timeout: int = 30) -> Tuple[bool, str]:
    return _adb("-s", serial, *args, timeout=timeout)


def step(n: int, label: str):
    print(f"\n[STEP {n}] {label}")
    print("─" * 60)


def ok(msg: str):
    print(f"  ✅ {msg}")


def warn(msg: str):
    print(f"  ⚠️  {msg}")


def err(msg: str):
    print(f"  ❌ {msg}")


def info(msg: str):
    print(f"     {msg}")


# ─── Steps ─────────────────────────────────────────────────────────────────────

def check_tools() -> bool:
    step(0, "Tool Prerequisites")
    all_ok = True

    if ADB_BIN and os.path.exists(ADB_BIN):
        ok_f, out, _ = _run([ADB_BIN, "version"])
        ok(f"ADB: {out.splitlines()[0]}")
    else:
        err("ADB not found. Install Android SDK Platform-Tools.")
        all_ok = False

    if EMULATOR_BIN and os.path.exists(EMULATOR_BIN):
        ok(f"Emulator binary: {EMULATOR_BIN}")
    else:
        warn(f"Emulator binary not found at {EMULATOR_BIN}")
        warn("Will check for already-running emulator.")

    if FRIDA_SERVER_BIN.exists():
        ok(f"frida-server: {FRIDA_SERVER_BIN} ({FRIDA_SERVER_BIN.stat().st_size // 1024 // 1024} MB)")
    else:
        err(f"frida-server binary not found: {FRIDA_SERVER_BIN}")
        err("Download frida-server-17.16.4-android-x86_64 from github.com/frida/frida/releases")
        all_ok = False

    try:
        import frida
        ok(f"Frida Python: v{frida.__version__}")
    except ImportError:
        err("frida Python package not installed: pip install frida==17.16.4")
        all_ok = False

    return all_ok


def list_avds() -> List[str]:
    """Return list of available AVD names."""
    ok_f, out, err_msg = _run([EMULATOR_BIN, "-list-avds"], timeout=10)
    if not ok_f:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def get_connected_emulators() -> List[str]:
    """Return list of connected emulator serial numbers."""
    ok_f, out = _adb("devices")
    devices = []
    for line in out.splitlines()[1:]:
        if "\t" in line:
            serial, state = line.split("\t", 1)
            if state.strip() == "device" and ("emulator" in serial or ":" in serial):
                devices.append(serial.strip())
    return devices


def start_emulator(avd_name: str) -> Optional[str]:
    """Start an AVD emulator in background. Returns serial when booted."""
    info(f"Starting AVD: {avd_name}")
    proc = subprocess.Popen(
        [EMULATOR_BIN, "-avd", avd_name, "-no-snapshot-save",
         "-no-audio", "-gpu", "auto"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    info(f"Emulator process started (PID {proc.pid}). Waiting for boot...")

    # Wait up to 3 minutes for it to appear in adb devices
    for attempt in range(60):
        time.sleep(3)
        devices = get_connected_emulators()
        if devices:
            serial = devices[0]
            info(f"Device appeared: {serial}")
            return serial
        if attempt % 10 == 9:
            info(f"Still waiting... ({(attempt + 1) * 3}s)")
    return None


def wait_for_boot(serial: str, timeout_s: int = 180) -> bool:
    """Wait for Android to fully boot."""
    info(f"Waiting for boot completion on {serial}...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ok_f, out = _adb_s(serial, "shell", "getprop", "sys.boot_completed")
        if out.strip() == "1":
            ok("Boot completed!")
            return True
        time.sleep(3)
    err(f"Boot did not complete within {timeout_s}s")
    return False


def setup_device(serial: str, push_server: bool = True) -> bool:
    """Configure device for Frida dynamic analysis."""
    # ADB root
    step(3, "Enable ADB root")
    ok_f, out = _adb_s(serial, "root")
    if ok_f or "already running" in out:
        ok(f"ADB root: {out}")
    else:
        warn(f"ADB root failed: {out}. Ensure emulator uses userdebug/eng image.")
    time.sleep(2)

    # SELinux permissive
    step(4, "Set SELinux permissive")
    ok_f, out = _adb_s(serial, "shell", "getenforce")
    info(f"Current: {out.strip()}")
    if "Enforcing" in out:
        ok_f, out = _adb_s(serial, "shell", "setenforce 0")
        ok_f2, out2 = _adb_s(serial, "shell", "getenforce")
        if "Permissive" in out2:
            ok("SELinux set to Permissive")
        else:
            warn(f"SELinux still {out2.strip()} — Frida may fail to attach")
    else:
        ok(f"SELinux: {out.strip()}")

    # Push frida-server
    if push_server:
        step(5, "Push frida-server to device")
        remote_path = "/data/local/tmp/frida-server"

        # Check if already there with correct version
        ok_f, out = _adb_s(serial, "shell", f"ls -la {remote_path} 2>/dev/null")
        if ok_f and "frida-server" in out:
            info(f"frida-server already on device: {out}")
        else:
            info(f"Pushing {FRIDA_SERVER_BIN} → {remote_path}")
            ok_f, out = _adb_s(serial, "push", str(FRIDA_SERVER_BIN), remote_path, timeout=120)
            if ok_f:
                ok(f"Pushed: {out}")
            else:
                err(f"Push failed: {out}")
                return False

        # chmod
        ok_f, out = _adb_s(serial, "shell", f"chmod 755 {remote_path}")
        ok(f"chmod 755: {out or 'OK'}")

    # Start frida-server
    step(6, "Start frida-server")
    ok_f, out = _adb_s(serial, "shell", "ps -A | grep frida-server")
    if "frida-server" in out:
        ok("frida-server already running")
    else:
        # Kill any stale instance
        _adb_s(serial, "shell", "pkill frida-server 2>/dev/null", timeout=5)
        # Start in background
        ok_f, out = _adb_s(
            serial, "shell",
            "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &",
            timeout=10
        )
        time.sleep(2)
        ok_f2, out2 = _adb_s(serial, "shell", "ps -A | grep frida-server")
        if "frida-server" in out2:
            ok("frida-server started")
        else:
            err("frida-server failed to start. Check binary architecture matches device.")
            err("frida-server must be x86_64 for x86_64 emulator, x86 for x86.")

    # ADB TCP
    step(7, "Enable ADB over TCP")
    ok_f, out = _adb_s(serial, "tcpip", str(ADB_TCP_PORT))
    ok(f"ADB TCP on port {ADB_TCP_PORT}: {out}")
    time.sleep(1)

    return True


def verify_frida(serial: str) -> bool:
    """Verify Frida can communicate with the device."""
    step(8, "Verify Frida connectivity")
    try:
        import frida
        all_devs = frida.enumerate_devices()
        info(f"All Frida devices: {[d.id for d in all_devs]}")

        device = None
        for d in all_devs:
            if d.id == serial:
                device = d
                break

        if not device:
            # Try connecting via USB/remote
            warn(f"Device {serial} not in Frida enumerate_devices().")
            warn("This is expected if connected via TCP — Frida sees it differently.")
            # Try by getting TCP connection
            if ":" in serial:
                try:
                    host, port = serial.split(":", 1)
                    device = frida.get_device_manager().add_remote_device(f"{host}:{port}")
                    ok(f"Frida remote device added: {device.id}")
                except Exception as e:
                    warn(f"Remote device add failed: {e}")
            return True

        ok(f"Frida device found: {device.id} ({device.name})")

        # Try listing processes
        procs = device.enumerate_processes()
        ok(f"Frida process enumeration: {len(procs)} processes")
        return True

    except Exception as e:
        err(f"Frida verification failed: {e}")
        return False


def print_summary(serial: Optional[str]):
    step(9, "Dynamic Analysis Setup Complete")

    if serial:
        ok_f, out = _adb_s(serial, "shell", "ps -A | grep frida-server")
        frida_running = "frida-server" in out

        ok_f2, enforce = _adb_s(serial, "shell", "getenforce")

        print(f"""
  Emulator Serial:   {serial}
  frida-server:      {'✅ RUNNING' if frida_running else '❌ NOT RUNNING'}
  SELinux:           {enforce.strip()}
  ADB TCP port:      {ADB_TCP_PORT}

  Docker container will connect via:
    ADB_HOST=host.docker.internal
    ADB_PORT={ADB_TCP_PORT}
    → adb connect host.docker.internal:{ADB_TCP_PORT}

  To run platform:
    docker-compose up -d

  To test dynamic analysis:
    Upload an APK through the dashboard and wait for dynamic results.
""")
    else:
        warn("No emulator serial — setup may be incomplete")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sudarshan Dynamic Analysis Setup")
    parser.add_argument("--avd", default=PREFERRED_AVD, help="AVD name to start")
    parser.add_argument("--push-server", action="store_true", default=True, help="Push frida-server to device")
    parser.add_argument("--no-push-server", dest="push_server", action="store_false")
    parser.add_argument("--skip-start", action="store_true", help="Skip starting emulator (use existing)")
    args = parser.parse_args()

    print("=" * 60)
    print("SUDARSHAN — Dynamic Analysis Environment Setup")
    print("=" * 60)

    if not check_tools():
        print("\n❌ Prerequisites not met. Resolve errors above before proceeding.")
        sys.exit(1)

    serial = None

    # Check for already-running emulator
    step(1, "Check for running emulators")
    devices = get_connected_emulators()
    if devices:
        serial = devices[0]
        ok(f"Found running emulator: {serial}")
    elif args.skip_start:
        err("No emulator found and --skip-start was set. Start an AVD first.")
        sys.exit(1)
    else:
        step(2, "Start Android emulator")
        avds = list_avds()
        info(f"Available AVDs: {avds}")

        avd = args.avd
        if not avd:
            if avds:
                avd = avds[0]
                info(f"No AVD specified, using first: {avd}")
            else:
                err("No AVDs found. Create one in Android Studio:")
                err("  Tools → Device Manager → Create Device")
                err("  Recommended: Pixel 6, API 34 (Android 14), x86_64")
                sys.exit(1)

        serial = start_emulator(avd)
        if not serial:
            err("Emulator failed to appear in 'adb devices' within 3 minutes.")
            sys.exit(1)

        ok(f"Emulator serial: {serial}")
        if not wait_for_boot(serial):
            err("Emulator did not boot. Try again or check logcat.")
            sys.exit(1)

    if not setup_device(serial, push_server=args.push_server):
        err("Device setup failed. Check errors above.")
        sys.exit(1)

    verify_frida(serial)
    print_summary(serial)

    print("✅ Dynamic analysis environment is ready!")
    print("   Run: docker-compose up -d")
    print("   Then upload an APK to trigger dynamic analysis.")


if __name__ == "__main__":
    main()
