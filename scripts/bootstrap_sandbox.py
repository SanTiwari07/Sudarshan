#!/usr/bin/env python3
"""
Sudarshan sandbox bootstrap (emulator-agnostic).

Discovers ADB devices, selects Genymotion / Android Studio AVD / physical,
prepares root + SELinux, pushes the ABI-matched Frida server, and prints a
machine-readable summary for start.ps1 / operators.

Usage:
    python scripts/bootstrap_sandbox.py
    python scripts/bootstrap_sandbox.py --json
    python scripts/bootstrap_sandbox.py --serial emulator-5554
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

# Load .env into process env (do not overwrite existing)
_env_path = _ROOT / ".env"
if _env_path.is_file():
    for line in _env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val

# Defaults for agnostic mode
os.environ.setdefault("SANDBOX_PROVIDER", "auto")
os.environ.setdefault("ANDROID_SANDBOX_PROVIDER", os.environ.get("SANDBOX_PROVIDER", "auto"))
os.environ.setdefault("AUTO_CONNECT", "true")
os.environ.setdefault("ROOT_REQUIRED", "true")
os.environ.setdefault("FRIDA_PORT", os.environ.get("SUDARSHAN_FRIDA_PORT", "27055"))
os.environ.setdefault("SUDARSHAN_FRIDA_BIN", "sudarshan_agent_srv")
os.environ.setdefault("FRIDA_LISTEN_HOST", "127.0.0.1")

from sudarshan_core.sandbox import (  # noqa: E402
    clear_sandbox_provider_cache,
    format_device_line,
    get_sandbox_provider,
    load_sandbox_config,
    provider_display_name,
)
from sudarshan_core.sandbox.device import (  # noqa: E402
    PROVIDER_GENYMOTION,
    transport_for_serial,
)


def _print(msg: str = "") -> None:
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))


def bootstrap(serial: Optional[str] = None, push_frida: bool = True) -> Dict[str, Any]:
    clear_sandbox_provider_cache()
    cfg = load_sandbox_config()
    provider = get_sandbox_provider(cfg, force_new=True)

    result: Dict[str, Any] = {
        "ok": False,
        "provider_mode": cfg.provider,
        "adb": provider.find_adb() or "",
        "devices": [],
        "selected": None,
        "root_available": None,
        "frida": None,
        "env": {},
        "error": None,
    }

    adb = result["adb"]
    if not adb:
        result["error"] = (
            "ADB not found. Install Android platform-tools or Genymotion tools."
        )
        return result

    # Optional: connect only when operator set a concrete ADB_HOST (not docker alias)
    host = (cfg.adb_host or "").strip()
    if (
        cfg.auto_connect
        and host
        and host.lower() not in (
            "host.docker.internal",
            "host.containers.internal",
            "gateway.docker.internal",
        )
    ):
        provider.adb("connect", f"{host}:{cfg.adb_port}", timeout=10)

    # If serial looks like host:port, try connect
    preferred = (serial or cfg.device_serial or "").strip()
    if preferred and transport_for_serial(preferred) == "tcp":
        provider.adb("connect", preferred, timeout=10)

    devices = provider.discover_devices()
    result["devices"] = [d.to_dict() for d in devices]
    if not devices:
        result["error"] = (
            "No Android sandbox detected. "
            "Start Genymotion or an Android Studio AVD, then run the bootstrap again."
        )
        return result

    try:
        selected = provider.select_device(preferred or None)
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    result["selected"] = selected.to_dict()

    # Device preparation
    root_ok = False
    try:
        root_ok = bool(provider.ensure_root(selected.serial))
    except Exception as exc:  # noqa: BLE001
        if cfg.root_required:
            result["error"] = f"Root unavailable: {exc}"
            result["root_available"] = False
            return result
        root_ok = False
    result["root_available"] = root_ok
    selected.root_available = root_ok
    selected.rooted = root_ok

    try:
        selinux = provider.ensure_selinux_permissive(selected.serial)
    except Exception:  # noqa: BLE001
        selinux = "unknown"

    frida_status = None
    try:
        frida_status = provider.ensure_frida(
            selected.serial,
            restart_if_needed=True,
            push_if_missing=push_frida,
            abi=selected.abi,
            abilist=selected.abilist,
        )
        # Always (re)apply forwarding for the selected serial
        forwarded = provider.ensure_frida_forward(selected.serial)
        frida_status.forwarded = bool(forwarded or frida_status.forwarded)
        result["frida"] = frida_status.to_dict()
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        result["frida"] = {"available": False, "message": str(exc)}
        # Still export env so Docker can start; dynamic will fail clearly
        _export_env(result, selected, cfg)
        return result

    _export_env(result, selected, cfg)
    result["ok"] = bool(frida_status and frida_status.available)
    result["selinux"] = selinux
    result["selected"] = selected.to_dict()
    return result


def _export_env(result: Dict[str, Any], selected, cfg) -> None:
    env = {
        "DEVICE_SERIAL": selected.serial,
        "ANDROID_DEVICE_SERIAL": selected.serial,
        "FRIDA_PORT": cfg.frida_port,
        "SUDARSHAN_FRIDA_PORT": cfg.frida_port,
        "FRIDA_DEVICE_SERIAL": selected.serial,
        "FRIDA_HOST": "127.0.0.1",
        "SANDBOX_PROVIDER": selected.provider or cfg.provider or "auto",
        "ANDROID_SANDBOX_PROVIDER": selected.provider or cfg.provider or "auto",
    }
    if selected.provider == PROVIDER_GENYMOTION and selected.ip:
        # Containers must target the Genymotion VM IP, not the Docker host alias.
        env["ADB_HOST"] = selected.ip
        env["ADB_PORT"] = (
            selected.serial.split(":")[-1] if ":" in selected.serial else cfg.adb_port
        )
    elif selected.transport == "emulator" or selected.provider == "android_avd":
        # Host ADB multiplexer exposes emulator-*; containers reach it via the
        # Docker host gateway. Never keep a stale Genymotion IP here.
        env["ADB_HOST"] = "host.docker.internal"
        env["ADB_PORT"] = cfg.adb_port
    else:
        if selected.ip:
            env["ADB_HOST"] = selected.ip
        elif selected.transport == "tcp" and ":" in selected.serial:
            env["ADB_HOST"] = selected.serial.split(":", 1)[0]
        env["ADB_PORT"] = cfg.adb_port
    result["env"] = env
    for k, v in env.items():
        os.environ[k] = v


def _human_report(result: Dict[str, Any]) -> None:
    _print()
    _print("[2/7] Device discovery...")
    devices = result.get("devices") or []
    if not devices:
        _print("      X   No Android sandbox detected.")
        _print("          Start Genymotion or an Android Studio AVD, then re-run.")
        return

    _print("      Detected Android devices:")
    for i, d in enumerate(devices, 1):
        # Rebuild a DeviceInfo-like line
        from sudarshan_core.sandbox.types import DeviceInfo

        info = DeviceInfo(**{k: d[k] for k in DeviceInfo.__dataclass_fields__ if k in d})
        _print(f"      {format_device_line(i, info)}")

    selected = result.get("selected") or {}
    if selected:
        label = provider_display_name(selected.get("provider", ""))
        _print()
        _print(f"[3/7] Sandbox selected: {label}")
        _print(f"      OK  Found device: {selected.get('serial')}")
        _print(f"      Provider: {label}")
        if selected.get("avd_name"):
            _print(f"      AVD: {selected.get('avd_name')}")
        _print(f"      ABI: {selected.get('abi') or '?'}")
        _print(
            f"      Android: {selected.get('android_version') or '?'} "
            f"(SDK {selected.get('api_level') or '?'})"
        )
        _print(f"      Transport: {selected.get('transport') or '?'}")
        root = result.get("root_available")
        _print(f"      Root: {'available' if root else 'unavailable'}")

    _print()
    _print("[4/7] Device preparation...")
    if result.get("root_available"):
        _print("      OK  Root available")
    else:
        _print("      !   Root unavailable")
    if result.get("selinux"):
        _print(f"      SELinux: {result.get('selinux')}")

    _print()
    _print("[5/7] Frida...")
    frida = result.get("frida") or {}
    if frida.get("available"):
        _print(f"      OK  {frida.get('message') or 'Frida agent running'}")
        _print(f"      Port: {frida.get('port')}")
        _print(f"      Forwarding: {'yes' if frida.get('forwarded') else 'no'}")
        if frida.get("abi"):
            _print(f"      ABI: {frida.get('abi')}")
        if frida.get("host_version"):
            _print(f"      Host Frida: {frida.get('host_version')}")
    else:
        _print("      X   Frida startup failed")
        msg = frida.get("message") or result.get("error") or ""
        for line in str(msg).splitlines():
            _print(f"          {line}")

    if result.get("env"):
        _print()
        _print("      Exported env:")
        for k, v in result["env"].items():
            _print(f"        {k}={v}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sudarshan emulator-agnostic sandbox bootstrap")
    parser.add_argument("--serial", default="", help="Pin ANDROID_DEVICE_SERIAL / DEVICE_SERIAL")
    parser.add_argument("--json", action="store_true", help="Print JSON summary only")
    parser.add_argument("--env-file", default="", help="Write KEY=VALUE exports for the shell")
    parser.add_argument("--no-push-frida", action="store_true", help="Do not push Frida binary")
    args = parser.parse_args()

    if not args.json:
        _print("[1/7] ADB / sandbox bootstrap...")
    result = bootstrap(serial=args.serial or None, push_frida=not args.no_push_frida)

    if args.env_file:
        lines = [f"{k}={v}" for k, v in (result.get("env") or {}).items()]
        Path(args.env_file).write_text("\n".join(lines) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _human_report(result)
        if result.get("ok"):
            _print()
            _print("      OK  Sandbox ready for dynamic analysis")
        elif result.get("error"):
            _print()
            _print(f"      X   {result['error']}")

    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
