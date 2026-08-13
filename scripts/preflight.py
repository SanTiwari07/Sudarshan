#!/usr/bin/env python3
"""
Sudarshan preflight -- host-side wrapper.

Answers one question before a run starts: will dynamic analysis actually
produce runtime evidence on THIS machine?

Everything it checks degrades silently today. A missing .env means no
GEMINI_API_KEY, which downgrades the agentic explorer to the deterministic
fallback planner. An ADB server the container cannot reach means zero devices
and an empty screenshot gallery. A missing frida-server means no
instrumentation. All three finish the pipeline "successfully" with a hollow
report, which is why the same commit behaves differently on two laptops.

Repo-level checks (files, Docker daemon) live here. The environment and sandbox
checks live in ``sudarshan_core.preflight`` so the identical logic can run
inside the analysis-engine container, where ADB reachability is what actually
matters.

Usage:
    python scripts/preflight.py                # host checks
    python scripts/preflight.py --container    # also check inside the engine
    python scripts/preflight.py --no-device    # config only, no ADB / Frida
    python scripts/preflight.py --strict       # warnings are failures
    python scripts/preflight.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from sudarshan_core.preflight import (  # noqa: E402
    FAIL,
    OK,
    WARN,
    CheckResult,
    render,
    run_checks,
)


def load_dotenv(path: Path) -> bool:
    """Load .env into os.environ without overwriting existing values."""
    if not path.is_file():
        return False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and not os.environ.get(key):
            os.environ[key] = val
    return True


# ── Repo-level checks ─────────────────────────────────────────────────────────


def check_root_env() -> CheckResult:
    env_path = _ROOT / ".env"
    if env_path.is_file():
        return CheckResult("Root .env", OK, str(env_path))
    return CheckResult(
        "Root .env",
        FAIL,
        f"{env_path} is missing -- it is gitignored, so a fresh clone never has one",
        "Copy the template and fill it in: cp .env.example .env "
        "(start.ps1 does this automatically). API keys must be shared out of "
        "band -- never commit .env.",
    )


def check_engine_env_override() -> CheckResult:
    """analysis-engine/.env is an optional per-service override, not a requirement."""
    override = _ROOT / "analysis-engine" / ".env"
    if override.is_file():
        return CheckResult(
            "Engine .env override",
            OK,
            f"{override} present (optional; layered over the root .env)",
        )
    return CheckResult(
        "Engine .env override",
        OK,
        "absent -- optional, the root .env supplies every value the engine needs",
    )


def check_docker() -> CheckResult:
    if not shutil.which("docker"):
        return CheckResult(
            "Docker",
            WARN,
            "docker not found on PATH",
            "Install Docker Desktop if you intend to run the containerised stack.",
        )
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return CheckResult(
            "Docker", WARN, f"could not query daemon: {exc}", "Start Docker Desktop."
        )
    if proc.returncode != 0:
        return CheckResult(
            "Docker",
            WARN,
            "daemon not reachable",
            "Start Docker Desktop and wait until it reports ready.",
        )
    return CheckResult("Docker", OK, f"daemon {proc.stdout.strip()}")


def host_checks() -> List[CheckResult]:
    return [check_root_env(), check_engine_env_override(), check_docker()]


# ── Container-side checks ─────────────────────────────────────────────────────


def container_checks(strict: bool, include_device: bool) -> List[CheckResult]:
    """
    Run the same environment checks inside the analysis engine.

    This is the check that matters most: `adb devices` resolves differently in
    the container than on the host. The host ADB server binds 127.0.0.1, so
    ADB_SERVER_SOCKET=tcp://host.docker.internal:5037 only works if the host
    server was started listening on all interfaces.
    """
    cmd = [
        "docker", "compose", "exec", "-T", "analysis-engine",
        "python", "-m", "sudarshan_core.preflight", "--json",
    ]
    if not include_device:
        cmd.append("--no-device")
    if strict:
        cmd.append("--strict")

    try:
        proc = subprocess.run(
            cmd, cwd=str(_ROOT), capture_output=True, text=True, timeout=420
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [
            CheckResult(
                "Engine container",
                FAIL,
                f"could not run preflight inside analysis-engine: {exc}",
                "Bring the stack up first: docker compose up -d",
            )
        ]

    stdout = (proc.stdout or "").strip()
    if not stdout:
        return [
            CheckResult(
                "Engine container",
                FAIL,
                f"no output from analysis-engine (exit {proc.returncode}): "
                f"{(proc.stderr or '').strip()[:300]}",
                "Is the container running? Check: docker compose ps",
            )
        ]

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return [
            CheckResult(
                "Engine container",
                FAIL,
                f"unparseable preflight output: {stdout[:300]}",
                "Run it directly to see the error: docker compose exec "
                "analysis-engine python -m sudarshan_core.preflight",
            )
        ]

    return [CheckResult(**check) for check in payload.get("checks", [])]


# ── Runner ────────────────────────────────────────────────────────────────────


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the prerequisites for Sudarshan dynamic analysis."
    )
    parser.add_argument(
        "--container",
        action="store_true",
        help="also run the checks inside the analysis-engine container",
    )
    parser.add_argument(
        "--no-device",
        action="store_true",
        help="skip ADB / Frida probes (config-only check)",
    )
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    load_dotenv(_ROOT / ".env")
    include_device = not args.no_device

    sections: List[tuple[str, List[CheckResult]]] = [
        ("host", host_checks() + run_checks(include_device=include_device))
    ]
    if args.container:
        sections.append(
            ("analysis-engine container", container_checks(args.strict, include_device))
        )

    every = [r for _, results in sections for r in results]

    if args.json:
        print(
            json.dumps(
                {
                    "sections": [
                        {
                            "context": name,
                            "checks": [
                                {
                                    "name": r.name,
                                    "status": r.status,
                                    "detail": r.detail,
                                    "remedy": r.remedy,
                                    "data": r.data,
                                }
                                for r in results
                            ],
                        }
                        for name, results in sections
                    ],
                    "failures": sum(1 for r in every if r.failed),
                    "warnings": sum(1 for r in every if r.warned),
                },
                indent=2,
            )
        )
    else:
        for name, results in sections:
            print(render(results, name))
            print()

    if any(r.failed for r in every):
        return 1
    if args.strict and any(r.warned for r in every):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
