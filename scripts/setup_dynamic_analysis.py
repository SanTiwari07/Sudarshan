#!/usr/bin/env python3
"""
Sudarshan Dynamic Analysis Setup Script
=========================================
Prepares the configured sandbox (Genymotion Desktop by default, or
Android Studio AVD) + Frida for dynamic analysis.

This script:
  1. Loads SANDBOX_PROVIDER / ADB_* / DEVICE_SERIAL from the environment
  2. Detects online devices via SandboxProvider (`adb devices`)
  3. Optionally starts an Android Studio AVD when provider=android_studio
  4. Waits for boot completion
  5. Enables ADB root + verifies whoami=root
  6. Sets SELinux to permissive
  7. Pushes / starts frida-server
  8. Enables ADB over TCP (port from ADB_PORT, default 5555)
  9. Verifies Frida can attach
  10. Reports sandbox readiness

Usage:
    python scripts/setup_dynamic_analysis.py [--serial SERIAL] [--avd AVD_NAME] [--push-server]
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

# Ensure shared package is importable when run from repo root
_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from sudarshan_core.sandbox import (  # noqa: E402
    get_sandbox_provider,
    load_sandbox_config,
)

# ─── Configuration ─────────────────────────────────────────────────────────────

CFG = load_sandbox_config()
ANDROID_SDK = CFG.android_sdk_root or os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk")
EMULATOR_BIN = shutil.which("emulator") or os.path.join(ANDROID_SDK, "emulator", "emulator.exe")

FRIDA_SERVER_DIR = Path(__file__).parent.parent / "frida-server-17.16.4-android-x86_64"
FRIDA_SERVER_BIN = FRIDA_SERVER_DIR / "frida-server-17.16.4-android-x86_64"

ADB_TCP_PORT = int(CFG.adb_port or "5555")
PREFERRED_AVD = CFG.preferred_avd


def _run(cmd: List[str], timeout: int = 30, check: bool = False) -> Tuple[bool, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = r.returncode == 0
        return ok, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


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


def check_tools() -> bool:
    step(0, "Tool Prerequisites")
    all_ok = True
    provider = get_sandbox_provider()
    ok(f"Sandbox provider: {provider.name}")

    adb = provider.find_adb()
    if adb:
        ok_f, out, _ = _run([adb, "version"])
        ok(f"ADB: {(out.splitlines()[0] if out else adb)}")
    else:
        err("ADB not found. Install platform-tools or Genymotion tools.")
        all_ok = False

    if CFG.provider in ("android_studio", "androidstudio", "avd", "emulator"):
        if EMULATOR_BIN and os.path.exists(EMULATOR_BIN):
            ok(f"Emulator binary: {EMULATOR_BIN}")
        else:
            warn(f"Emulator binary not found at {EMULATOR_BIN}")
            warn("Will check for already-running AVD.")
    else:
        info("Genymotion Desktop: start your VM from the Genymotion UI before continuing.")

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
    ok_f, out, _ = _run([EMULATOR_BIN, "-list-avds"], timeout=10)
    if not ok_f:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def start_emulator(avd_name: str) -> Optional[str]:
    info(f"Starting AVD: {avd_name}")
    proc = subprocess.Popen(
        [EMULATOR_BIN, "-avd", avd_name, "-no-snapshot-save",
         "-no-audio", "-gpu", "auto"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    info(f"Emulator process started (PID {proc.pid}). Waiting for boot...")
    provider = get_sandbox_provider()
    for attempt in range(60):
        time.sleep(3)
        devices = provider.list_devices()
        if devices:
            serial = devices[0].serial
            info(f"Device appeared: {serial}")
            return serial
        if attempt % 10 == 9:
            info(f"Still waiting... ({(attempt + 1) * 3}s)")
    return None


def wait_for_boot(serial: str, timeout_s: int = 180) -> bool:
    provider = get_sandbox_provider()
    info(f"Waiting for boot completion on {serial}...")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ok_f, out = provider.adb("-s", serial, "shell", "getprop", "sys.boot_completed")
        if out.strip() == "1":
            ok("Boot completed!")
            return True
        time.sleep(3)
    err(f"Boot did not complete within {timeout_s}s")
    return False


def setup_device(serial: str, push_server: bool = True) -> bool:
    provider = get_sandbox_provider()

    step(3, "Enable ADB root + verify whoami")
    try:
        provider.ensure_root(serial)
        ok("Root verified (whoami=root)")
    except Exception as e:
        err(f"Root verification failed: {e}")
        if CFG.root_required:
            return False
        warn("Continuing because ROOT_REQUIRED=false")

    step(4, "Set SELinux permissive")
    mode = provider.ensure_selinux_permissive(serial)
    ok(f"SELinux: {mode}")

    frida_bin_name = CFG.frida_bin
    frida_port = CFG.frida_port
    remote_path = f"/data/local/tmp/{frida_bin_name}"

    if push_server:
        step(5, f"Push Frida agent server ({frida_bin_name}) to device")
        ok_f, out = provider.adb("-s", serial, "shell", f"ls -la {remote_path} 2>/dev/null")
        if ok_f and frida_bin_name in out:
            info(f"Agent server already on device: {out}")
        else:
            info(f"Pushing {FRIDA_SERVER_BIN} → {remote_path}")
            ok_f, out = provider.adb(
                "-s", serial, "push", str(FRIDA_SERVER_BIN), remote_path, timeout=120
            )
            if ok_f:
                ok(f"Pushed: {out}")
            else:
                err(f"Push failed: {out}")
                return False
            provider.adb("-s", serial, "shell", f"chmod 755 {remote_path}")
            # Also keep legacy path for older auto-start logic
            provider.adb(
                "-s", serial, "shell",
                f"cp {remote_path} /data/local/tmp/frida-server && chmod 755 /data/local/tmp/frida-server",
            )

    step(6, f"Start / verify Frida agent ({frida_bin_name}) on port {frida_port}")
    try:
        status = provider.ensure_frida(serial, restart_if_needed=True)
        ok(status.message or "Frida available")
    except Exception as e:
        err(f"Frida verification failed: {e}")
        return False

    step(7, "Enable ADB over TCP")
    ok_f, out = provider.adb("-s", serial, "tcpip", str(ADB_TCP_PORT))
    ok(f"ADB TCP on port {ADB_TCP_PORT}: {out}")
    time.sleep(1)
    return True


def verify_frida(serial: str) -> bool:
    step(8, "Verify Frida connectivity")
    try:
        import frida
        all_devs = frida.enumerate_devices()
        info(f"All Frida devices: {[d.id for d in all_devs]}")
        device = next((d for d in all_devs if d.id == serial), None)
        if not device and ":" in serial:
            try:
                host, port = serial.split(":", 1)
                device = frida.get_device_manager().add_remote_device(f"{host}:{port}")
                ok(f"Frida remote device added: {device.id}")
            except Exception as e:
                warn(f"Remote device add failed: {e}")
            return True
        if device:
            ok(f"Frida device found: {device.id} ({device.name})")
            procs = device.enumerate_processes()
            ok(f"Frida process enumeration: {len(procs)} processes")
        return True
    except Exception as e:
        err(f"Frida verification failed: {e}")
        return False


def print_summary(serial: Optional[str]):
    step(9, "Dynamic Analysis Setup Complete")
    provider = get_sandbox_provider()
    if serial:
        try:
            info_d = provider.get_device_info(serial)
        except Exception:
            info_d = None
        print(f"""
  Provider:          {provider.name}
  Device Serial:     {serial}
  Android:           {getattr(info_d, 'android_version', '?')} (API {getattr(info_d, 'api_level', '?')})
  ABI:               {getattr(info_d, 'abi', '?')}
  ADB TCP port:      {ADB_TCP_PORT}
  DEVICE_SERIAL:     {CFG.device_serial or '(auto)'}

  Docker container will connect via:
    SANDBOX_PROVIDER={CFG.provider}
    ADB_HOST=host.docker.internal
    ADB_PORT={ADB_TCP_PORT}
    DEVICE_SERIAL={serial}

  To run platform:
    docker-compose up -d
""")
    else:
        warn("No device serial — setup may be incomplete")


def main():
    parser = argparse.ArgumentParser(description="Sudarshan Dynamic Analysis Setup")
    parser.add_argument("--serial", default=CFG.device_serial, help="Device serial (DEVICE_SERIAL)")
    parser.add_argument("--avd", default=PREFERRED_AVD, help="AVD name (android_studio provider only)")
    parser.add_argument("--push-server", action="store_true", default=True, help="Push frida-server")
    parser.add_argument("--no-push-server", dest="push_server", action="store_false")
    parser.add_argument("--skip-start", action="store_true", help="Do not start an AVD; use existing device")
    args = parser.parse_args()

    print("=" * 60)
    print("SUDARSHAN — Dynamic Analysis Environment Setup")
    print(f"Provider: {CFG.provider}")
    print("=" * 60)

    if not check_tools():
        print("\n❌ Prerequisites not met. Resolve errors above before proceeding.")
        sys.exit(1)

    provider = get_sandbox_provider()
    serial = None

    step(1, "Check for running sandbox devices")
    try:
        if args.serial:
            serial = provider.select_device(args.serial).serial
        else:
            devices = provider.list_devices()
            if devices:
                serial = provider.select_device().serial
                ok(f"Found running device: {serial}")
    except Exception as e:
        warn(str(e))

    if not serial:
        if CFG.provider not in ("android_studio", "androidstudio", "avd", "emulator"):
            err(
                "No Genymotion device found. Start a virtual device in Genymotion Desktop, "
                "then re-run this script (or set DEVICE_SERIAL)."
            )
            sys.exit(1)
        if args.skip_start:
            err("No emulator found and --skip-start was set.")
            sys.exit(1)

        step(2, "Start Android Studio AVD")
        avds = list_avds()
        info(f"Available AVDs: {avds}")
        avd = args.avd
        if not avd:
            if avds:
                avd = avds[0]
            else:
                err("No AVDs found. Create one in Android Studio Device Manager.")
                sys.exit(1)
        serial = start_emulator(avd)
        if not serial:
            err("Emulator failed to appear in 'adb devices' within 3 minutes.")
            sys.exit(1)
        if not wait_for_boot(serial):
            sys.exit(1)

    # Full connect handshake (logs device/IP/ABI/root/frida)
    step(2, "SandboxProvider.connect()")
    result = provider.connect(preferred_serial=serial)
    if result.ok and result.device:
        serial = result.device.serial
        ok(f"Connected: {result.device.to_dict()}")
    else:
        warn(f"connect() reported: {result.error_code} — {result.error_message}")
        warn("Continuing with manual setup steps…")

    if not setup_device(serial, push_server=args.push_server):
        err("Device setup failed. Check errors above.")
        sys.exit(1)

    verify_frida(serial)
    print_summary(serial)
    print("✅ Dynamic analysis environment is ready!")


if __name__ == "__main__":
    main()
