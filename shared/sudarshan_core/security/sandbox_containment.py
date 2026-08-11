"""
Sandbox containment policy for dynamic analysis.

Malware executes on the Android guest (Genymotion / AVD), not inside the
analysis-engine container. Containment therefore has two layers:

  1. Guest posture - root + permissive SELinux are required for Frida; the guest
     must be treated as fully compromised after every session.
  2. Control-plane posture - how the engine reaches the guest (ADB target, Frida
     listen address, gateway fallbacks) must not bridge the guest onto the host
     LAN, the Docker host ADB multiplexer, or an unhardened backend container.

This module encodes those rules and fails closed when production containment is
enabled.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Tuple

if TYPE_CHECKING:
    from sudarshan_core.sandbox.config import SandboxConfig

logger = logging.getLogger(__name__)

# Host alias Docker injects; valid for Android Studio AVD on the host, invalid as
# the Genymotion VM endpoint (routes ADB through the host daemon).
_HOST_DOCKER_INTERNAL_ALIASES = frozenset(
    {"host.docker.internal", "host.containers.internal", "gateway.docker.internal"}
)

# RFC1918 + link-local + CGNAT - acceptable Genymotion host-only targets.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)

# ADB subcommands that widen the attack surface if invoked from analysis code.
_BLOCKED_ADB_SUBCOMMANDS = frozenset(
    {
        "tcpip",       # opens network ADB on device without session binding
        "usb",         # retargets default transport
        "kill-server", # disrupts other sessions / host tooling
        "start-server",
        "pair",
        "unpair",
    }
)


class ContainmentViolation(Exception):
    """Raised when sandbox connectivity violates the containment policy."""

    def __init__(self, message: str, *, code: str = "CONTAINMENT_VIOLATION"):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ContainmentFinding:
    severity: str  # "error" | "warning"
    code: str
    message: str


def containment_strict_enabled() -> bool:
    """
    When true, misconfiguration blocks dynamic analysis instead of logging alone.

    Enabled when SANDBOX_CONTAINMENT_STRICT=true or SUDARSHAN_ENV=production.
    """
    raw = os.getenv("SANDBOX_CONTAINMENT_STRICT", "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return os.getenv("SUDARSHAN_ENV", "").strip().lower() == "production"


def gateway_dynamic_allowed() -> bool:
    """
    Whether the API gateway may run Frida/ADB locally when the engine is down.

    Must remain false in production - the backend image has no cgroup/seccomp
    profile and bind-mounts the host repository read-write.
    """
    return os.getenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def frida_listen_host(config: Optional[SandboxConfig] = None) -> str:
    """Loopback-only Frida listen address on the guest (access via adb forward)."""
    host = (
        os.getenv("FRIDA_LISTEN_HOST")
        or os.getenv("SUDARSHAN_FRIDA_LISTEN_HOST")
        or "127.0.0.1"
    ).strip()
    normalized = _normalize_host(host.strip("[]"))
    allowed_loopback = frozenset({"127.0.0.1", "localhost", "::1"})
    if normalized in ("0.0.0.0", "::", ""):
        logger.warning(
            "[Containment] FRIDA_LISTEN_HOST=%s is unsafe; forcing 127.0.0.1", host
        )
        return "127.0.0.1"
    if containment_strict_enabled() and normalized not in allowed_loopback:
        raise ContainmentViolation(
            f"FRIDA_LISTEN_HOST={host!r} must be loopback-only in strict mode "
            "(127.0.0.1 or ::1).",
            code="FRIDA_LISTEN_NOT_LOOPBACK",
        )
    if normalized not in allowed_loopback:
        logger.warning(
            "[Containment] FRIDA_LISTEN_HOST=%s is not loopback; forcing 127.0.0.1",
            host,
        )
        return "127.0.0.1"
    return "127.0.0.1" if normalized in ("localhost",) else host.strip("[]") or "127.0.0.1"


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_private_or_loopback_host(host: str) -> bool:
    h = _normalize_host(host)
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    if h in _HOST_DOCKER_INTERNAL_ALIASES:
        return False
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    return any(addr in net for net in _PRIVATE_NETWORKS)


def audit_sandbox_connectivity(config: SandboxConfig) -> List[ContainmentFinding]:
    """Return containment findings for the current sandbox configuration."""
    findings: List[ContainmentFinding] = []
    provider = (config.provider or "auto").strip().lower()
    adb_host = (config.adb_host or "").strip()

    # Genymotion-specific ADB_HOST rules only apply when the operator explicitly
    # selected Genymotion (or auto has already set ADB_HOST to a VM IP).
    # Auto mode without ADB_HOST is valid - the device may be an AVD serial.
    if provider == "genymotion":
        if not adb_host:
            findings.append(
                ContainmentFinding(
                    severity="error",
                    code="GENYMOTION_ADB_HOST_UNSET",
                    message=(
                        "Genymotion requires ADB_HOST to be the VM IP from "
                        "`adb devices` (discovered automatically by bootstrap). "
                        "An empty ADB_HOST causes the engine entrypoint to default to "
                        "host.docker.internal, which attaches to the host ADB "
                        "multiplexer instead of an isolated VM."
                    ),
                )
            )
        elif _normalize_host(adb_host) in _HOST_DOCKER_INTERNAL_ALIASES:
            findings.append(
                ContainmentFinding(
                    severity="error",
                    code="GENYMOTION_HOST_DOCKER_INTERNAL",
                    message=(
                        f"ADB_HOST={adb_host!r} routes container ADB through the "
                        "Docker host. A rooted guest can reach every device and "
                        "service the host ADB server exposes - not a single "
                        "disposable Genymotion VM."
                    ),
                )
            )
        elif not _is_private_or_loopback_host(adb_host):
            findings.append(
                ContainmentFinding(
                    severity="error",
                    code="GENYMOTION_ADB_HOST_NOT_PRIVATE",
                    message=(
                        f"ADB_HOST={adb_host!r} is not a private RFC1918 address. "
                        "Point ADB at the Genymotion host-only NIC only."
                    ),
                )
            )
        elif _is_loopback_only_host(adb_host):
            findings.append(
                ContainmentFinding(
                    severity="error",
                    code="GENYMOTION_ADB_HOST_LOOPBACK",
                    message=(
                        f"ADB_HOST={adb_host!r} resolves to loopback inside the "
                        "analysis container, not the Genymotion VM. Use the VM's "
                        "host-only IP from `adb devices`."
                    ),
                )
            )
    elif provider == "auto" and adb_host and _normalize_host(adb_host) in _HOST_DOCKER_INTERNAL_ALIASES:
        findings.append(
            ContainmentFinding(
                severity="warning",
                code="AUTO_ADB_HOST_DOCKER_BRIDGE",
                message=(
                    f"ADB_HOST={adb_host!r} bridges through the Docker host. "
                    "For Genymotion, prefer the VM private IP discovered by bootstrap."
                ),
            )
        )

    if config.root_required and provider in (
        "genymotion",
        "android_studio",
        "android_avd",
        "auto",
        "physical",
    ):
        findings.append(
            ContainmentFinding(
                severity="warning",
                code="GUEST_FULL_COMPROMISE_EXPECTED",
                message=(
                    "ROOT_REQUIRED=true and SELinux permissive are required for "
                    "Frida. Treat the Android guest as fully compromised after "
                    "each session; never reuse it for trusted workloads."
                ),
            )
        )

    if not gateway_dynamic_allowed() and containment_strict_enabled():
        findings.append(
            ContainmentFinding(
                severity="warning",
                code="GATEWAY_DYNAMIC_DISABLED",
                message=(
                    "SUDARSHAN_ALLOW_GATEWAY_DYNAMIC is not set - the backend "
                    "will not run Frida when the analysis-engine is unavailable "
                    "(intended for production)."
                ),
            )
        )

    return findings


def enforce_connectivity_policy(config: SandboxConfig) -> None:
    """
    Log findings; raise ContainmentViolation on errors when strict mode is on.
    """
    findings = audit_sandbox_connectivity(config)
    for f in findings:
        log = logger.error if f.severity == "error" else logger.warning
        log("[Containment] %s: %s", f.code, f.message)

    errors = [f for f in findings if f.severity == "error"]
    if errors and containment_strict_enabled():
        raise ContainmentViolation(
            errors[0].message,
            code=errors[0].code,
        )


def _is_loopback_only_host(host: str) -> bool:
    h = _normalize_host(host)
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _adb_global_subcommand(args: Sequence[str]) -> Optional[str]:
    """
    Return the adb *global* subcommand, skipping -s SERIAL and other flags.

    Without this, ``adb -s emu tcpip 5555`` would treat ``emu`` as the subcommand
    and miss a blocked ``tcpip`` invocation.
    """
    i = 0
    while i < len(args):
        token = args[i]
        if token in ("-s", "-d", "-e"):
            i += 2
            continue
        if token.startswith("-"):
            if token in ("-H", "-P"):
                val = args[i + 1] if i + 1 < len(args) else ""
                if token == "-H":
                    _validate_adb_server_flag(token, val)
                i += 2
                continue
            i += 1
            continue
        return token
    return None


def _validate_adb_server_flag(flag: str, value: str) -> None:
    if not value:
        return
    host = value.split(":")[0] if flag == "-H" else value
    if flag == "-H":
        provider = os.getenv("SANDBOX_PROVIDER", "auto").strip().lower()
        if provider == "genymotion" and _normalize_host(host) in _HOST_DOCKER_INTERNAL_ALIASES:
            raise ContainmentViolation(
                "adb -H host.docker.internal is forbidden for Genymotion.",
                code="ADB_HOST_FLAG_BRIDGE",
            )
        if provider == "genymotion" and not _is_private_or_loopback_host(host):
            raise ContainmentViolation(
                f"adb -H {host!r} must target a private address for Genymotion.",
                code="ADB_HOST_FLAG_NOT_PRIVATE",
            )


def validate_adb_invocation(args: Sequence[str]) -> None:
    """
    Reject ADB invocations that widen exposure beyond the analysis session.

    Called from SandboxProvider.adb() before every subprocess.
    """
    if not args:
        return

    # Global listen flag - exposes host ADB to the LAN.
    if "-a" in args:
        raise ContainmentViolation(
            "adb -a (listen on all interfaces) is forbidden in analysis containers.",
            code="ADB_LISTEN_ALL",
        )

    # Subcommand is the first global adb verb (not device serial after -s).
    subcmd = _adb_global_subcommand(args)

    if subcmd in _BLOCKED_ADB_SUBCOMMANDS:
        raise ContainmentViolation(
            f"adb {subcmd} is forbidden during malware analysis.",
            code="ADB_SUBCOMMAND_BLOCKED",
        )

    if subcmd == "connect":
        target = _adb_connect_target(args)
        if target:
            host = target.split(":")[0]
            provider = os.getenv("SANDBOX_PROVIDER", "auto").strip().lower()
            if provider == "genymotion" and _normalize_host(host) in _HOST_DOCKER_INTERNAL_ALIASES:
                raise ContainmentViolation(
                    "adb connect to host.docker.internal is forbidden for Genymotion; "
                    "set ADB_HOST to the VM private IP.",
                    code="ADB_CONNECT_HOST_BRIDGE",
                )


def _adb_connect_target(args: Sequence[str]) -> Optional[str]:
    seen_connect = False
    for token in args:
        if seen_connect:
            return token
        if token == "connect":
            seen_connect = True
    return None


def build_frida_start_command(remote_binary: str, port: str, config: Optional[SandboxConfig] = None) -> str:
    """Shell command to start frida-server on the guest (loopback bind only)."""
    listen = frida_listen_host(config)
    # nohup + background - same pattern as before, but not LAN-visible.
    return f"nohup {remote_binary} -l {listen}:{port} > /dev/null 2>&1 &"


def validate_backend_production_config() -> None:
    """Fail closed when the gateway runs in production without engine mutual auth."""
    if os.getenv("SUDARSHAN_ENV", "").strip().lower() != "production":
        return
    if not os.getenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "").strip():
        raise RuntimeError(
            "SUDARSHAN_ENV=production requires ANALYSIS_ENGINE_INTERNAL_TOKEN "
            "to be set for backend → analysis-engine mutual authentication."
        )


def session_artifact_root(uploads_root: os.PathLike[str] | str, session_id: str) -> str:
    """
    Ephemeral per-session directory under the uploads volume.

    Keeps forensic artifacts out of shared mutable paths that later analyses read.
    """
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", session_id)[:64] or "session"
    root = os.path.join(os.fspath(uploads_root), ".sessions", safe_id)
    os.makedirs(root, exist_ok=True)
    return root
