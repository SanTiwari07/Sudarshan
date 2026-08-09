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


def bootstrap_adb_connect(max_attempts: int = 10, retry_sleep_seconds: float = 3.0) -> int:
    from sudarshan_core.security.adb_gateway import run_adb

    adb_bin = shutil.which("adb") or "adb"
    host = os.getenv("ADB_HOST", "").strip()
    port = os.getenv("ADB_PORT", "5555").strip() or "5555"

    # Implicit server start: `adb devices` is allowed and typically starts the daemon.
    run_adb(adb_bin, ["devices"], timeout=15)

    if not host:
        print("[adb_bootstrap] ADB_HOST unset - skipping connect.")
        return 0

    target = f"{host}:{port}"
    for attempt in range(1, max_attempts + 1):
        ok, out = run_adb(adb_bin, ["connect", target], timeout=15)
        combined = (out or "").lower()
        if ok and ("connected" in combined or "already" in combined):
            print(f"[adb_bootstrap] ADB connected to {target}")
            return 0
        print(
            f"[adb_bootstrap] Target {target} not ready (attempt {attempt}/{max_attempts})."
        )
        if attempt < max_attempts:
            time.sleep(retry_sleep_seconds)

    print(f"[adb_bootstrap] No emulator at {target} - static analysis only.")
    return 0


def main() -> None:
    sys.exit(bootstrap_adb_connect())


if __name__ == "__main__":
    main()
