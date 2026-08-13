"""
SUDARSHAN -- Dynamic Analysis Preflight
=======================================
Fail loudly, in one place, on the configuration that otherwise degrades the
dynamic pipeline in silence.

Why this exists
---------------
Every prerequisite checked here has a silent-failure path:

  * No GEMINI_API_KEY    -> the agentic planner disables itself and the
                            deterministic FallbackPlanner takes over, so the
                            explorer performs far fewer and much shallower taps.
  * No reachable ADB     -> zero devices, the sandbox never connects, and the
                            run finishes with an empty screenshot gallery.
  * No frida-server      -> instrumentation is skipped; the binary lives in a
                            gitignored directory, so a fresh clone has none.
  * Screenshots disabled -> the pipeline runs but stores no visual evidence.

Each one produces a partial run that reads like a bug in the analysis rather
than a missing prerequisite. That is precisely how "it works on my laptop"
happens, so the checks belong in front of the run, not in a log nobody reads.

This module holds the environment-level checks that are valid both on the host
and inside a container. Repo-level checks (files on disk, Docker daemon) live in
``scripts/preflight.py``, which wraps this one.

Usage
-----
    python -m sudarshan_core.preflight
    python -m sudarshan_core.preflight --json
    python -m sudarshan_core.preflight --strict      # warnings are failures too
    python -m sudarshan_core.preflight --no-device   # skip ADB / Frida probes

Inside the analysis engine -- where ADB reachability actually matters:

    docker compose exec analysis-engine python -m sudarshan_core.preflight
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

OK = "OK"
WARN = "WARN"
FAIL = "FAIL"

_STATUS_GLYPH = {OK: "[ OK ]", WARN: "[WARN]", FAIL: "[FAIL]"}


@dataclass
class CheckResult:
    """One preflight line: what was checked, what happened, how to fix it."""

    name: str
    status: str
    detail: str
    remedy: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status == FAIL

    @property
    def warned(self) -> bool:
        return self.status == WARN


def _truthy(raw: Optional[str]) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "on")


def running_in_container() -> bool:
    """Best-effort container detection; only used to label output."""
    if Path("/.dockerenv").exists():
        return True
    try:
        return "docker" in Path("/proc/1/cgroup").read_text(errors="replace")
    except OSError:
        return False


def context_label() -> str:
    return "analysis-engine container" if running_in_container() else "host"


# ── Environment checks ────────────────────────────────────────────────────────


def check_jwt_secret() -> CheckResult:
    if (os.getenv("JWT_SECRET_KEY") or "").strip():
        return CheckResult("JWT_SECRET_KEY", OK, "set")
    return CheckResult(
        "JWT_SECRET_KEY",
        FAIL,
        "empty or unset -- the backend refuses to start without it",
        "Add JWT_SECRET_KEY to .env. Generate one with: "
        'python -c "import secrets; print(secrets.token_urlsafe(48))"',
    )


def check_gemini_key() -> CheckResult:
    if (os.getenv("GEMINI_API_KEY") or "").strip():
        model = (os.getenv("GEMINI_MODEL") or "gemini-2.5-flash").strip()
        return CheckResult(
            "GEMINI_API_KEY", OK, f"set (model: {model})", data={"model": model}
        )
    return CheckResult(
        "GEMINI_API_KEY",
        WARN,
        "unset -- the AI exploration layer disables itself and the deterministic "
        "FallbackPlanner takes over, so the explorer performs far fewer UI actions",
        "Add GEMINI_API_KEY to .env (https://aistudio.google.com/app/apikey). "
        ".env is gitignored, so a fresh clone never has it.",
    )


def check_screenshots_enabled() -> CheckResult:
    if _truthy(os.getenv("SUDARSHAN_DISABLE_SCREENSHOTS")):
        return CheckResult(
            "Screenshot capture",
            WARN,
            "disabled via SUDARSHAN_DISABLE_SCREENSHOTS -- the run will store no "
            "visual evidence and the dashboard gallery will be empty",
            "Unset SUDARSHAN_DISABLE_SCREENSHOTS to capture runtime screenshots.",
        )
    return CheckResult("Screenshot capture", OK, "enabled")


# ── Sandbox checks ────────────────────────────────────────────────────────────


def _adb_route_hint() -> str:
    """Describe how this process is expected to reach an ADB server."""
    socket = (os.getenv("ADB_SERVER_SOCKET") or "").strip()
    adb_host = (os.getenv("ADB_HOST") or "").strip()
    if socket:
        return f"ADB_SERVER_SOCKET={socket}"
    if adb_host:
        port = (os.getenv("ADB_PORT") or "5555").strip()
        return f"ADB_HOST={adb_host}:{port}"
    return "local ADB server (127.0.0.1:5037)"


def check_frida_route() -> CheckResult:
    """
    Report which host the Frida client will dial for the forwarded port.

    `adb forward` binds its port wherever the ADB *server* runs. In a container
    talking to a host ADB server that is the host, not this namespace, so a
    client dialling 127.0.0.1 finds nothing -- `adb devices` looks perfectly
    healthy while instrumentation silently never attaches.
    """
    from sudarshan_core.sandbox.config import adb_server_host, frida_client_hosts

    hosts = frida_client_hosts()
    port = (
        os.getenv("FRIDA_PORT") or os.getenv("SUDARSHAN_FRIDA_PORT") or "27042"
    ).strip()
    remote = adb_server_host()

    if running_in_container() and not remote and not (os.getenv("ADB_HOST") or "").strip():
        return CheckResult(
            "Frida route",
            WARN,
            f"in a container with a local ADB server -- the Frida client will only "
            f"try {', '.join(hosts)}:{port}",
            "Set ADB_SERVER_SOCKET to the host ADB server, or ADB_HOST to the "
            "emulator's TCP endpoint, so forwarded ports resolve to the right host.",
            data={"hosts": hosts, "port": port},
        )

    return CheckResult(
        "Frida route",
        OK,
        f"client will try {', '.join(f'{h}:{port}' for h in hosts)}",
        data={"hosts": hosts, "port": port, "adb_server_host": remote},
    )


def check_adb_binary(provider: Any) -> CheckResult:
    adb_path = provider.find_adb()
    if adb_path:
        return CheckResult("ADB binary", OK, adb_path, data={"path": adb_path})
    return CheckResult(
        "ADB binary",
        FAIL,
        "not found on PATH or in any known SDK location",
        "Install Android platform-tools and put adb on PATH, or set "
        "ANDROID_SDK_ROOT to your SDK directory.",
    )


def check_devices(provider: Any) -> tuple[CheckResult, Optional[Any]]:
    """Return the device check plus the selected device (None when unusable)."""
    from sudarshan_core.sandbox.device import (
        format_device_line,
        normalize_provider_name,
        select_sandbox_device,
    )

    route = _adb_route_hint()
    try:
        devices = provider.list_devices(enrich=True)
    except Exception as exc:  # noqa: BLE001
        return (
            CheckResult(
                "Sandbox device",
                FAIL,
                f"device discovery raised {type(exc).__name__}: {exc} (via {route})",
                "Confirm the emulator is running and this process can reach an "
                "ADB server. From inside a container, `adb devices` uses "
                "ADB_SERVER_SOCKET -- the host ADB server binds 127.0.0.1 by "
                "default and is NOT reachable from Docker unless you start it "
                "with `adb -a nodaemon server start`, or set ADB_HOST to the "
                "emulator's own TCP endpoint.",
                data={"route": route},
            ),
            None,
        )

    if not devices:
        return (
            CheckResult(
                "Sandbox device",
                FAIL,
                f"no online ADB devices (via {route})",
                "Start Genymotion or an Android Studio AVD. From inside a "
                "container the host ADB server must be reachable: it binds "
                "127.0.0.1 by default, so either start it with "
                "`adb -a nodaemon server start` on the host, or set ADB_HOST to "
                "the emulator's TCP endpoint so the container connects directly.",
                data={"route": route, "count": 0},
            ),
            None,
        )

    cfg_provider = normalize_provider_name(provider.config.provider)
    try:
        device = select_sandbox_device(
            devices,
            preferred_serial=(provider.config.device_serial or "").strip(),
            preferred_provider="" if cfg_provider == "auto" else cfg_provider,
        )
    except ValueError as exc:
        return (
            CheckResult(
                "Sandbox device",
                FAIL,
                f"{len(devices)} device(s) online but none selectable: {exc}",
                "Pin one explicitly with ANDROID_DEVICE_SERIAL.",
                data={"route": route, "count": len(devices)},
            ),
            None,
        )

    listing = [format_device_line(i, d) for i, d in enumerate(devices)]
    return (
        CheckResult(
            "Sandbox device",
            OK,
            f"{format_device_line(0, device)} (via {route})",
            data={
                "route": route,
                "count": len(devices),
                "serial": device.serial,
                "abi": device.abi,
                "devices": listing,
            },
        ),
        device,
    )


def check_frida_binary(provider: Any, device: Any) -> CheckResult:
    """
    Resolve the ABI-matched frida-server, downloading it when absent.

    Doing this in preflight is deliberate: the download is the slow, network
    dependent step, and finding out it is blocked here beats finding out
    mid-analysis when the run has already been counted as started.
    """
    from sudarshan_core.sandbox.frida_assets import missing_binary_message

    try:
        spec = provider.resolve_frida_binary(
            device.serial, abi=device.abi, abilist=device.abilist
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "Frida server",
            FAIL,
            f"resolution raised {type(exc).__name__}: {exc}",
            "Download the matching binary from "
            "https://github.com/frida/frida/releases and point "
            "FRIDA_SERVER_DIR at the directory holding it.",
        )

    if spec.found and spec.path is not None:
        size_mb = spec.path.stat().st_size / (1024 * 1024)
        return CheckResult(
            "Frida server",
            OK,
            f"{spec.path} ({size_mb:.0f} MB, abi={spec.abi})",
            data={"path": str(spec.path), "abi": spec.abi, "version": spec.version},
        )

    return CheckResult(
        "Frida server",
        FAIL,
        f"no binary for abi={spec.abi or 'unknown'} (expected {spec.expected_name})",
        missing_binary_message(spec).replace("\n", " | "),
        data={"abi": spec.abi, "expected": spec.expected_name},
    )


# ── Runner ────────────────────────────────────────────────────────────────────


def run_checks(include_device: bool = True) -> List[CheckResult]:
    """Run every environment check. Never raises -- unexpected errors become FAILs."""
    results: List[CheckResult] = [
        check_jwt_secret(),
        check_gemini_key(),
        check_screenshots_enabled(),
    ]

    if not include_device:
        return results

    try:
        from sudarshan_core.sandbox import get_sandbox_provider, load_sandbox_config

        provider = get_sandbox_provider(load_sandbox_config(), force_new=True)
    except Exception as exc:  # noqa: BLE001
        results.append(
            CheckResult(
                "Sandbox provider",
                FAIL,
                f"could not initialise: {type(exc).__name__}: {exc}",
                "Check SANDBOX_PROVIDER / ANDROID_SANDBOX_PROVIDER in .env "
                "(auto | genymotion | android_avd | physical).",
            )
        )
        return results

    adb_check = check_adb_binary(provider)
    results.append(adb_check)
    results.append(check_frida_route())
    if adb_check.failed:
        return results

    device_check, device = check_devices(provider)
    results.append(device_check)
    if device is None:
        return results

    results.append(check_frida_binary(provider, device))
    return results


def render(results: List[CheckResult], context: str = "") -> str:
    """Format results as an operator-readable checklist."""
    label = context or context_label()
    width = max((len(r.name) for r in results), default=0)
    lines = [f"Sudarshan preflight -- {label}", "-" * 60]
    for r in results:
        lines.append(f"{_STATUS_GLYPH[r.status]} {r.name.ljust(width)}  {r.detail}")
        if r.remedy and r.status != OK:
            lines.append(f"{' ' * 7}-> {r.remedy}")

    failures = [r for r in results if r.failed]
    warnings = [r for r in results if r.warned]
    lines.append("-" * 60)
    if failures:
        lines.append(
            f"{len(failures)} blocking issue(s). Dynamic analysis will not "
            f"produce runtime evidence until these are resolved."
        )
    elif warnings:
        lines.append(
            f"{len(warnings)} warning(s). Dynamic analysis will run, but in a "
            f"degraded mode -- expect fewer UI actions or less evidence."
        )
    else:
        lines.append("All checks passed.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the prerequisites for Sudarshan dynamic analysis."
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--strict", action="store_true", help="treat warnings as failures"
    )
    parser.add_argument(
        "--no-device",
        action="store_true",
        help="skip ADB / Frida probes (config-only check)",
    )
    args = parser.parse_args(argv)

    results = run_checks(include_device=not args.no_device)
    context = context_label()

    if args.json:
        print(
            json.dumps(
                {
                    "context": context,
                    "checks": [asdict(r) for r in results],
                    "failures": sum(1 for r in results if r.failed),
                    "warnings": sum(1 for r in results if r.warned),
                },
                indent=2,
            )
        )
    else:
        try:
            print(render(results, context))
        except UnicodeEncodeError:
            text = render(results, context)
            print(text.encode("ascii", "replace").decode("ascii"))

    if any(r.failed for r in results):
        return 1
    if args.strict and any(r.warned for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
