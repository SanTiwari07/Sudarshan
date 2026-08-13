"""
Container boot-time ADB warm-up - all invocations go through adb_gateway.run_adb.

Shell entrypoint must not call the adb binary directly; policy validation lives
in sudarshan_core.security.sandbox_containment.validate_adb_invocation.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
import socket

from sudarshan_core.sandbox.factory import get_sandbox_provider
from sudarshan_core.sandbox.config import load_sandbox_config
from sudarshan_core.security.sandbox_containment import (
    validate_adb_invocation,
    ContainmentViolation,
)


def check_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def bootstrap_adb_connect(max_attempts: int = 10, retry_sleep_seconds: float = 3.0) -> int:
    from sudarshan_core.security.adb_gateway import run_adb

    cfg = load_sandbox_config()
    provider = get_sandbox_provider(cfg)
    adb_bin = shutil.which("adb") or "adb"

    print(f"[adb_bootstrap] provider={provider.name}")

    # Implicit server start
    run_adb(adb_bin, ["devices"], timeout=15)

    host = (cfg.adb_host or "").strip()
    port_str = (cfg.adb_port or "5555").strip() or "5555"

    target = ""
    # DEVICE_SERIAL explicitly configured with IP:PORT
    if cfg.device_serial and ":" in cfg.device_serial:
        target = cfg.device_serial
    elif host:
        # Genymotion provider MUST NOT default to host.docker.internal or localhost
        if provider.name == "genymotion" and host in ("host.docker.internal", "localhost", "127.0.0.1"):
            target = ""
        else:
            target = f"{host}:{port_str}"

    if target:
        print(f"[adb_bootstrap] target={target}")
        try:
            tgt_host, tgt_port_str = target.rsplit(":", 1)
            tgt_port = int(tgt_port_str)
        except ValueError:
            tgt_host = target
            tgt_port = 5555

        tcp_ok = check_tcp(tgt_host, tgt_port)
        print(f"[adb_bootstrap] tcp_connect={'OK' if tcp_ok else 'FAIL'}")

        if tcp_ok and cfg.auto_connect:
            try:
                validate_adb_invocation(["connect", target])
                ok, out = run_adb(adb_bin, ["connect", target], timeout=15)
                combined = (out or "").lower()
                if ok and ("connected" in combined or "already" in combined):
                    print("[adb_bootstrap] adb_connect=OK")
                else:
                    print("[adb_bootstrap] adb_connect=FAIL")
            except ContainmentViolation as exc:
                print(f"[adb_bootstrap] adb_connect=FAIL (policy: {exc.message})")
        elif not tcp_ok:
            print("[adb_bootstrap] adb_connect=FAIL")
        else:
            print("[adb_bootstrap] adb_connect=SKIPPED")
    else:
        # Default or missing target
        if provider.name == "genymotion":
            print("[adb_bootstrap] Genymotion requires a valid VM IP. Cannot connect.")
        print("[adb_bootstrap] target=auto")
        print("[adb_bootstrap] tcp_connect=SKIPPED")
        print("[adb_bootstrap] adb_connect=SKIPPED")

    for attempt in range(1, max_attempts + 1):
        devices = provider.list_devices()
        
        selected = None
        if cfg.device_serial:
            for d in devices:
                if d.serial == cfg.device_serial:
                    selected = d
                    break
        
        if not selected and devices:
            try:
                selected = provider.select_device(cfg.device_serial)
            except Exception:
                # If select_device fails (e.g. no supported devices), leave selected as None
                pass
        
        if selected:
            print(f"[adb_bootstrap] device={selected.serial}")
            print(f"[adb_bootstrap] state={selected.state}")
            
            if selected.state == "device":
                try:
                    frida_status = provider.verify_frida(selected.serial)
                    frida_str = "available" if frida_status.available else "unavailable"
                except Exception:
                    frida_str = "unavailable"
                print(f"[adb_bootstrap] frida={frida_str}")
                print("[adb_bootstrap] sandbox=READY")
                return 0
                
        if attempt < max_attempts:
            time.sleep(retry_sleep_seconds)

    print("[adb_bootstrap] sandbox=UNAVAILABLE")
    print("[adb_bootstrap] No emulator ready - static analysis only.")
    return 0


def main() -> None:
    sys.exit(bootstrap_adb_connect())


if __name__ == "__main__":
    main()
