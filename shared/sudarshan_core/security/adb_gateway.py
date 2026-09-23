"""
Single choke point for host-side ADB subprocess execution.

All analysis components MUST invoke ADB through this module (or
SandboxProvider.adb, which calls it) so containment policy cannot be
bypassed by parallel subprocess wrappers.
"""

from __future__ import annotations

import os
import subprocess
from typing import Sequence, Tuple

from sudarshan_core.security.sandbox_containment import validate_adb_invocation


def run_adb(
    adb_binary: str,
    args: Sequence[str],
    *,
    timeout: int = 30,
) -> Tuple[bool, str]:
    """
    Run ``adb_binary`` with ``args`` after policy validation.

    Returns (success, combined stdout+stderr) matching SandboxProvider.adb.
    """
    validate_adb_invocation(args)
    env = dict(os.environ)
    if "ADB_SERVER_SOCKET" in env:
        socket_val = env["ADB_SERVER_SOCKET"].lower()
        if "host.docker.internal" in socket_val:
            from sudarshan_core.sandbox.config import is_in_docker
            if not is_in_docker():
                del env["ADB_SERVER_SOCKET"]

    try:
        result = subprocess.run(
            [adb_binary, *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "adb command timed out"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
