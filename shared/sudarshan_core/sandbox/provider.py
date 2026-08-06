"""
SandboxProvider — abstract emulator/device backend.

The Dynamic Analysis Engine talks only to this interface. Concrete
providers (Genymotion, Android Studio AVD, future Corellium/Waydroid/
physical devices) implement lifecycle, detection, root, and Frida
verification. Analysis logic (install, launch, hooks, agentic explorer)
stays in frida_sandbox.py and is deliberately out of scope here.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.sandbox.config import SandboxConfig
from sudarshan_core.sandbox.exceptions import (
    ADBUnavailable,
    DeviceNotFound,
    FridaUnavailable,
    RootUnavailable,
    SandboxOffline,
)
from sudarshan_core.sandbox.types import ConnectionResult, DeviceInfo, FridaStatus
from sudarshan_core.security.sandbox_containment import (
    ContainmentViolation,
    build_frida_start_command,
    enforce_connectivity_policy,
    validate_adb_invocation,
)

logger = logging.getLogger(__name__)


class SandboxProvider(ABC):
    """Abstract sandbox backend used by the Dynamic Analysis Engine."""

    name: str = "base"

    def __init__(self, config: SandboxConfig):
        self.config = config
        self._adb_path: Optional[str] = None

    # ── ADB discovery ─────────────────────────────────────────────────────────

    def find_adb(self) -> Optional[str]:
        """Locate an ADB binary. Provider-specific candidates are appended."""
        if self._adb_path and os.path.exists(self._adb_path):
            return self._adb_path

        which = shutil.which("adb")
        if which:
            self._adb_path = which
            return which

        for candidate in self._adb_candidates():
            expanded = os.path.expandvars(os.path.expanduser(candidate))
            if expanded and os.path.exists(expanded):
                self._adb_path = expanded
                return expanded
        return None

    @abstractmethod
    def _adb_candidates(self) -> List[str]:
        """Return provider-specific ADB path candidates (ordered)."""

    def adb(self, *args: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run an adb command. Returns (success, combined stdout+stderr)."""
        adb = self.find_adb()
        if not adb:
            return False, "adb not found"
        try:
            validate_adb_invocation(args)
        except ContainmentViolation as exc:
            return False, exc.message
        from sudarshan_core.security.adb_gateway import run_adb

        return run_adb(adb, args, timeout=timeout)

    def adb_shell(self, serial: str, command: str, timeout: int = 30) -> Tuple[bool, str]:
        return self.adb("-s", serial, "shell", command, timeout=timeout)

    # ── Device detection ──────────────────────────────────────────────────────

    def list_devices(self) -> List[DeviceInfo]:
        """
        Parse `adb devices` and return online devices.

        If AUTO_CONNECT and ADB_HOST are set, attempt TCP connect first.
        """
        if self.config.auto_connect and self.config.adb_host:
            target = self.config.tcp_target
            ok, out = self.adb("connect", target or "", timeout=10)
            if ok:
                logger.info("[%s] ADB TCP connected: %s", self.name, target)
            else:
                logger.warning("[%s] ADB TCP connect failed (%s): %s", self.name, target, out)

        ok, output = self.adb("devices")
        if not ok:
            return []

        devices: List[DeviceInfo] = []
        for line in output.splitlines()[1:]:
            line = line.strip()
            if not line or "\t" not in line:
                # Some adb builds use spaces
                parts = line.split()
                if len(parts) < 2:
                    continue
                serial, state = parts[0], parts[1]
            else:
                serial, state = line.split("\t", 1)
                state = state.strip()
            if state != "device":
                continue
            devices.append(
                DeviceInfo(
                    serial=serial.strip(),
                    state=state,
                    provider=self.name,
                    ip=serial.split(":")[0] if ":" in serial else "",
                )
            )
        return devices

    def select_device(self, preferred_serial: Optional[str] = None) -> DeviceInfo:
        """
        Choose a device from `adb devices`.

        Priority:
          1. preferred_serial argument
          2. DEVICE_SERIAL env
          3. single online device
          4. first online device (logged)
        """
        preferred = (preferred_serial or self.config.device_serial or "").strip()
        devices = self.list_devices()
        if not devices:
            raise DeviceNotFound(
                "No online devices found via `adb devices`. "
                f"Start a {self.name} sandbox and ensure ADB can see it.",
                details={"provider": self.name, "adb_host": self.config.adb_host},
            )

        if preferred:
            for d in devices:
                if d.serial == preferred:
                    return d
            raise DeviceNotFound(
                f"Configured DEVICE_SERIAL={preferred!r} not found. "
                f"Online: {[d.serial for d in devices]}",
                details={
                    "preferred": preferred,
                    "online": [d.serial for d in devices],
                },
            )

        if len(devices) > 1:
            logger.warning(
                "[%s] Multiple devices online %s — selecting first. "
                "Set DEVICE_SERIAL to pin one.",
                self.name,
                [d.serial for d in devices],
            )
        return devices[0]

    # ── Device introspection ──────────────────────────────────────────────────

    def get_device_info(self, serial: str) -> DeviceInfo:
        """Query Android properties and return a populated DeviceInfo."""
        props = {
            "android_version": "ro.build.version.release",
            "api_level": "ro.build.version.sdk",
            "abi": "ro.product.cpu.abi",
            "model": "ro.product.model",
            "manufacturer": "ro.product.manufacturer",
        }
        values: Dict[str, str] = {}
        for key, prop in props.items():
            ok, out = self.adb_shell(serial, f"getprop {prop}", timeout=10)
            values[key] = out.strip() if ok else ""

        return DeviceInfo(
            serial=serial,
            state="device",
            provider=self.name,
            ip=serial.split(":")[0] if ":" in serial else self.config.adb_host,
            **values,
        )

    def verify_online(self, serial: str) -> bool:
        """Return True if serial appears as state=device."""
        for d in self.list_devices():
            if d.serial == serial:
                return True
        return False

    # ── Root ──────────────────────────────────────────────────────────────────

    def ensure_root(self, serial: str) -> None:
        """
        Run `adb root`, then verify `whoami` == root.

        Raises RootUnavailable / SandboxNotRooted when ROOT_REQUIRED and
        the device is not rooted.
        """
        ok, out = self.adb("-s", serial, "root", timeout=30)
        if not ok and "already running as root" not in (out or "").lower():
            logger.warning("[%s] adb root returned: %s", self.name, out)
        time.sleep(1.5)

        # After adb root, TCP devices may need reconnect
        if self.config.auto_connect and self.config.adb_host:
            self.adb("connect", self.config.tcp_target or "", timeout=10)
            time.sleep(0.5)

        ok, who = self.adb_shell(serial, "whoami", timeout=10)
        who = (who or "").strip().splitlines()[-1].strip() if who else ""
        if who == "root":
            logger.info("[%s] Root verified on %s (whoami=root)", self.name, serial)
            return

        # Fallback: su -c whoami (some Genymotion images)
        ok2, who2 = self.adb_shell(serial, "su -c whoami", timeout=10)
        who2 = (who2 or "").strip().splitlines()[-1].strip() if who2 else ""
        if who2 == "root":
            logger.info("[%s] Root verified on %s via su (whoami=root)", self.name, serial)
            return

        msg = (
            f"Sandbox not rooted on {serial}: whoami={who!r}, su={who2!r}. "
            f"adb root output: {out!r}"
        )
        if self.config.root_required:
            raise RootUnavailable(msg, details={"serial": serial, "whoami": who})
        logger.warning("[%s] %s (ROOT_REQUIRED=false — continuing)", self.name, msg)

    def verify_root(self, serial: str) -> bool:
        try:
            self.ensure_root(serial)
            return True
        except RootUnavailable:
            return False

    def ensure_selinux_permissive(self, serial: str) -> str:
        """Set SELinux permissive when Enforcing. Returns final mode string."""
        ok, enforce = self.adb_shell(serial, "getenforce", timeout=10)
        mode = (enforce or "unknown").strip()
        if "Enforcing" in mode:
            logger.warning(
                "[%s] SELinux Enforcing on %s — setting Permissive for Frida attach",
                self.name,
                serial,
            )
            self.adb_shell(serial, "setenforce 0", timeout=10)
            ok, enforce = self.adb_shell(serial, "getenforce", timeout=10)
            mode = (enforce or "unknown").strip()
        return mode

    # ── Frida ─────────────────────────────────────────────────────────────────

    def _frida_process_names(self) -> List[str]:
        names = [self.config.frida_bin, "frida-server"]
        # Deduplicate while preserving order
        seen = set()
        out = []
        for n in names:
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def _frida_remote_paths(self) -> List[str]:
        paths = []
        for name in self._frida_process_names():
            paths.append(f"/data/local/tmp/{name}")
        return paths

    def _frida_process_running(self, serial: str, names: List[str]) -> Tuple[bool, str]:
        """Detect frida-server via pgrep (ps NAME column may truncate long binary names)."""
        patterns: List[str] = []
        for n in names:
            if not n:
                continue
            patterns.append(n)
            if len(n) > 15:
                patterns.append(n[:15])
        if not patterns:
            patterns = ["frida-server"]
        # Unique, order preserved
        seen = set()
        uniq = []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        grep_pat = "|".join(uniq)
        ok, out = self.adb_shell(
            serial,
            f"pgrep -f '{uniq[0]}' 2>/dev/null || pgrep -f frida-server 2>/dev/null "
            f"|| ps -A 2>/dev/null | grep -E '{grep_pat}' || true",
            timeout=20,
        )
        text = out or ""
        running = bool(text.strip()) and any(p in text for p in uniq)
        if not running and text.strip().isdigit():
            running = True
        return running, text

    def ensure_frida(self, serial: str, restart_if_needed: bool = True) -> FridaStatus:
        """
        Verify frida-server is running; restart if necessary.

        Also checks host frida package version when available.
        """
        host_version = ""
        try:
            import frida as _frida  # local import — optional at import time

            host_version = getattr(_frida, "__version__", "") or ""
        except ImportError:
            host_version = ""

        names = self._frida_process_names()
        running, out = self._frida_process_running(serial, names)

        status = FridaStatus(
            available=False,
            running=running,
            binary_name=self.config.frida_bin,
            port=self.config.frida_port,
            host_version=host_version,
            message="",
        )

        if running:
            status.available = True
            status.compatible = True  # best-effort; deep probe is optional
            status.message = f"frida agent running ({out.strip()[:120]})"
            return status

        if not restart_if_needed:
            status.message = "frida-server not running"
            raise FridaUnavailable(status.message, details=status.to_dict())

        # Attempt restart from known paths
        logger.info("[%s] frida-server not running on %s — attempting start", self.name, serial)
        started = False
        for remote in self._frida_remote_paths():
            # Check existence
            ok_ls, ls_out = self.adb_shell(serial, f"ls {remote}", timeout=10)
            if not ok_ls or "No such file" in (ls_out or ""):
                continue
            status.binary_path = remote
            # Kill stale then start
            for n in names:
                self.adb_shell(serial, f"pkill -f {n} 2>/dev/null", timeout=5)
            port = self.config.frida_port
            start_cmd = build_frida_start_command(remote, port, self.config)
            self.adb_shell(serial, start_cmd, timeout=10)
            time.sleep(3)
            started_run, out2 = self._frida_process_running(serial, names)
            if started_run:
                started = True
                status.running = True
                status.restarted = True
                status.available = True
                status.compatible = True
                status.message = f"Started {remote} on port {port}"
                # Forward ports for Docker / host Frida clients
                self.adb("-s", serial, "forward", f"tcp:{port}", f"tcp:{port}", timeout=10)
                self.adb("-s", serial, "forward", "tcp:27042", f"tcp:{port}", timeout=10)
                break

        if not started:
            # Last-ditch: try configured binary name with configured port or default frida-server
            bin_name = self.config.frida_bin or "frida-server"
            port = self.config.frida_port or "27055"
            legacy_cmd = build_frida_start_command(
                f"/data/local/tmp/{bin_name}", port, self.config
            )
            self.adb_shell(serial, legacy_cmd, timeout=10)
            time.sleep(3)
            started_run, out3 = self._frida_process_running(serial, [bin_name, "frida-server"])
            if started_run:
                status.running = True
                status.restarted = True
                status.available = True
                status.compatible = True
                status.binary_path = f"/data/local/tmp/{bin_name}"
                status.message = f"Started /data/local/tmp/{bin_name} on port {port}"
                self.adb("-s", serial, "forward", f"tcp:{port}", f"tcp:{port}", timeout=10)
                return status

            status.message = (
                f"frida agent ({bin_name}) not running and could not be started. "
                "Push a matching ABI binary to /data/local/tmp/."
            )
            raise FridaUnavailable(status.message, details=status.to_dict())

        return status

    def verify_frida(self, serial: str) -> FridaStatus:
        try:
            return self.ensure_frida(serial, restart_if_needed=False)
        except FridaUnavailable as exc:
            return FridaStatus(
                available=False,
                running=False,
                message=exc.message,
                port=self.config.frida_port,
                binary_name=self.config.frida_bin,
            )

    # ── Full connection handshake ─────────────────────────────────────────────

    def connect(self, preferred_serial: Optional[str] = None) -> ConnectionResult:
        """
        Connect → verify online → verify root → verify adb → verify Frida.

        Always returns a ConnectionResult. Never raises out of this method
        (exceptions are captured into the result) so the DAE never crashes.
        """
        t0 = time.monotonic()
        stages: List[Dict[str, Any]] = []

        def _stage(name: str, ok: bool, detail: str = "") -> None:
            stages.append({"stage": name, "ok": ok, "detail": detail})
            level = logging.INFO if ok else logging.WARNING
            logger.log(
                level,
                "[%s] connect/%s: %s %s",
                self.name,
                name,
                "OK" if ok else "FAIL",
                detail,
            )

        try:
            enforce_connectivity_policy(self.config)

            adb_path = self.find_adb()
            if not adb_path:
                _stage("adb", False, "adb not found")
                raise ADBUnavailable(
                    "ADB binary not found. Install platform-tools or Genymotion tools.",
                    details={"provider": self.name},
                )
            _stage("adb", True, adb_path)

            device = self.select_device(preferred_serial)
            _stage("device_detect", True, device.serial)

            if not self.verify_online(device.serial):
                _stage("online", False, device.serial)
                raise SandboxOffline(
                    f"Device {device.serial} is not online",
                    details={"serial": device.serial},
                )
            _stage("online", True, device.serial)

            info = self.get_device_info(device.serial)
            _stage(
                "props",
                True,
                f"android={info.android_version} api={info.api_level} abi={info.abi}",
            )

            try:
                self.ensure_root(device.serial)
                info.rooted = True
                _stage("root", True, "whoami=root")
            except RootUnavailable as exc:
                info.rooted = False
                _stage("root", False, exc.message)
                if self.config.root_required:
                    raise

            selinux = self.ensure_selinux_permissive(device.serial)
            _stage("selinux", "Permissive" in selinux or "Disabled" in selinux, selinux)

            frida_status = self.ensure_frida(device.serial, restart_if_needed=True)
            info.frida_running = frida_status.running
            info.frida_version = frida_status.host_version
            _stage("frida", frida_status.available, frida_status.message)

            elapsed = (time.monotonic() - t0) * 1000
            info.connection_time_ms = elapsed
            logger.info(
                "[%s] Connected serial=%s ip=%s android=%s abi=%s root=%s frida=%s "
                "connect_ms=%.1f",
                self.name,
                info.serial,
                info.ip,
                info.android_version,
                info.abi,
                info.rooted,
                info.frida_running,
                elapsed,
            )
            return ConnectionResult(
                ok=True,
                device=info,
                frida=frida_status,
                stages=stages,
                connection_time_ms=elapsed,
            )

        except (
            ADBUnavailable,
            DeviceNotFound,
            SandboxOffline,
            RootUnavailable,
            FridaUnavailable,
            ContainmentViolation,
        ) as exc:
            elapsed = (time.monotonic() - t0) * 1000
            return ConnectionResult(
                ok=False,
                error_code=getattr(exc, "code", "SANDBOX_ERROR"),
                error_message=getattr(exc, "message", str(exc)),
                stages=stages,
                connection_time_ms=elapsed,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.monotonic() - t0) * 1000
            logger.exception("[%s] Unexpected connect failure", self.name)
            return ConnectionResult(
                ok=False,
                error_code="SANDBOX_ERROR",
                error_message=str(exc),
                stages=stages,
                connection_time_ms=elapsed,
            )

    # ── Device-state simulation (provider-specific) ───────────────────────────

    @abstractmethod
    def apply_state_profile(self, serial: str, profile: str) -> bool:
        """Apply a multi-stage device state profile (wifi, GPS, battery, …)."""

    @abstractmethod
    def reset_state(self, serial: str) -> bool:
        """Restore default device state after multi-stage runs."""

    def package_installed(self, serial: str, package_name: str) -> bool:
        """Verify a package is installed (used by connection diagnostics)."""
        ok, out = self.adb_shell(serial, f"pm path {package_name}", timeout=15)
        return ok and bool(out.strip()) and "package:" in out
