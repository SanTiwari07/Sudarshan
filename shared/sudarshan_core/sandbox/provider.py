"""
SandboxProvider - abstract emulator/device backend.

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
from sudarshan_core.sandbox.device import (
    enrich_device_info,
    fetch_device_props,
    format_device_line,
    ip_from_serial,
    parse_adb_devices_l,
    provider_display_name,
    select_sandbox_device,
    transport_for_serial,
)
from sudarshan_core.sandbox.exceptions import (
    ADBUnavailable,
    DeviceNotFound,
    FridaUnavailable,
    RootUnavailable,
    SandboxOffline,
)
from sudarshan_core.sandbox.frida_assets import (
    FridaBinarySpec,
    ensure_frida_server,
    locate_frida_server,
    missing_binary_message,
    supported_host_abis,
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

    def _maybe_tcp_connect(self) -> None:
        """
        Optionally `adb connect` when AUTO_CONNECT + ADB_HOST are set.

        Never blindly connect to a hardcoded Genymotion IP. Emulator transports
        (emulator-5554) are already visible via the local ADB server.

        If any device is already online, skip connect - avoids long timeouts on
        stale ADB_HOST values left in `.env` after a VM IP change.
        """
        if not self.config.auto_connect:
            return
        host = (self.config.adb_host or "").strip()
        if not host:
            return
        if host.lower() in (
            "host.docker.internal",
            "host.containers.internal",
            "gateway.docker.internal",
        ):
            return

        # Fast path: already have online devices
        ok_dev, output = self.adb("devices", "-l", timeout=8)
        if ok_dev and parse_adb_devices_l(output or ""):
            return

        target = self.config.tcp_target
        if not target:
            return
        ok, out = self.adb("connect", target, timeout=5)
        if ok:
            logger.info("[%s] ADB TCP connected: %s", self.name, target)
        else:
            logger.warning("[%s] ADB TCP connect failed (%s): %s", self.name, target, out)

    def list_devices(self, *, enrich: bool = False) -> List[DeviceInfo]:
        """
        Parse `adb devices -l` and return online devices.

        When enrich=True, query Android properties and fingerprint the provider
        (Genymotion / android_avd / physical) for each device.
        """
        self._maybe_tcp_connect()

        ok, output = self.adb("devices", "-l")
        if not ok:
            # Fallback without -l for older adb
            ok, output = self.adb("devices")
            if not ok:
                return []

        raw = parse_adb_devices_l(output)
        if not raw:
            # parse_adb_devices_l handles both -l and plain formats
            return []

        devices: List[DeviceInfo] = []
        for meta in raw:
            serial = meta["serial"]
            info = DeviceInfo(
                serial=serial,
                state=meta.get("state", "device"),
                provider=self.name if self.name != "auto" else "",
                ip=ip_from_serial(serial),
                transport=transport_for_serial(serial),
                model=meta.get("model", ""),
            )
            if enrich:
                info = self._enrich_device(info, adb_meta=meta)
            else:
                # Lightweight fingerprint from adb -l product/model alone
                info = enrich_device_info(info, adb_meta=meta)
            devices.append(info)
        return devices

    def _enrich_device(
        self,
        info: DeviceInfo,
        *,
        adb_meta: Optional[Dict[str, str]] = None,
    ) -> DeviceInfo:
        def _getprop(serial: str, prop: str) -> str:
            ok, out = self.adb_shell(serial, f"getprop {prop}", timeout=10)
            return out.strip() if ok else ""

        props = fetch_device_props(info.serial, _getprop)
        return enrich_device_info(info, props=props, adb_meta=adb_meta or {})

    def discover_devices(self) -> List[DeviceInfo]:
        """Fully enriched device list for startup logs / selection."""
        devices = self.list_devices(enrich=True)
        if devices:
            logger.info("[%s] Detected Android devices:", self.name)
            for i, d in enumerate(devices, 1):
                logger.info("  %s", format_device_line(i, d))
        return devices

    def select_device(self, preferred_serial: Optional[str] = None) -> DeviceInfo:
        """
        Choose a sandbox device.

        Priority:
          1. preferred_serial argument / ANDROID_DEVICE_SERIAL / DEVICE_SERIAL
          2. Emulator over physical
          3. Rooted when known
          4. Frida ABI supported on host
          5. Deterministic serial tie-break
        """
        preferred = (preferred_serial or self.config.device_serial or "").strip()
        devices = self.discover_devices()
        try:
            chosen = select_sandbox_device(
                devices,
                preferred_serial=preferred,
                preferred_provider=self.config.provider if self.name != "auto" else "",
                supported_abis=supported_host_abis(),
            )
        except ValueError as exc:
            raise DeviceNotFound(
                str(exc),
                details={"provider": self.name, "adb_host": self.config.adb_host},
            ) from exc

        logger.info(
            "[%s] Selected sandbox: %s (%s)",
            self.name,
            provider_display_name(chosen.provider or self.name),
            chosen.serial,
        )
        return chosen

    # ── Device introspection ──────────────────────────────────────────────────

    def get_device_info(self, serial: str) -> DeviceInfo:
        """Query Android properties and return a populated DeviceInfo."""
        info = DeviceInfo(
            serial=serial,
            state="device",
            provider=self.name if self.name != "auto" else "",
            ip=ip_from_serial(serial) or self.config.adb_host,
            transport=transport_for_serial(serial),
            frida_port=self.config.frida_port,
        )
        return self._enrich_device(info)

    def verify_online(self, serial: str) -> bool:
        """Return True if serial appears as state=device."""
        for d in self.list_devices():
            if d.serial == serial:
                return True
        return False

    # ── Root ──────────────────────────────────────────────────────────────────

    def _whoami(self, serial: str) -> str:
        ok, who = self.adb_shell(serial, "whoami", timeout=10)
        if ok and who:
            return who.strip().splitlines()[-1].strip()
        return ""

    def check_root(self, serial: str) -> bool:
        """Return True if the shell is already root (no adb root attempt)."""
        if self._whoami(serial) == "root":
            return True
        ok2, who2 = self.adb_shell(serial, "su -c whoami", timeout=10)
        who2 = (who2 or "").strip().splitlines()[-1].strip() if who2 else ""
        return who2 == "root"

    def _wait_for_device(self, serial: str, timeout_s: float = 30.0) -> bool:
        """Poll until serial is online again (adb root restarts adbd)."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            ok, out = self.adb("devices", "-l", timeout=8)
            if ok:
                for meta in parse_adb_devices_l(out or ""):
                    if meta.get("serial") == serial:
                        return True
            # Emulator transport sometimes needs a short settle after adbd restart
            time.sleep(1.0)
        return False

    def ensure_root(self, serial: str) -> bool:
        """
        Ensure a root shell when possible.

        Returns True if root is available. When ROOT_REQUIRED=false, returns
        False instead of raising. Never treats `adb root` failure as fatal
        unless root is required by the selected analysis mode.
        """
        if self.check_root(serial):
            logger.info("[%s] Root already available on %s", self.name, serial)
            return True

        ok, out = self.adb("-s", serial, "root", timeout=45)
        out_l = (out or "").lower()
        if not ok and "already running as root" not in out_l:
            logger.warning("[%s] adb root returned: %s", self.name, out)

        # adb root restarts adbd - emulators often drop offline briefly.
        transport = transport_for_serial(serial)
        time.sleep(2.0 if transport == "emulator" else 1.5)

        if transport == "tcp" or (self.config.auto_connect and self.config.adb_host):
            target = serial if transport == "tcp" else (self.config.tcp_target or "")
            if target and ":" in target:
                self.adb("connect", target, timeout=10)

        if not self._wait_for_device(serial, timeout_s=45.0 if transport == "emulator" else 20.0):
            logger.warning(
                "[%s] Device %s did not return online quickly after adb root",
                self.name,
                serial,
            )

        if self.check_root(serial):
            logger.info("[%s] Root verified on %s (whoami=root)", self.name, serial)
            return True

        # One more settle+retry - AVDs occasionally need it
        time.sleep(2.0)
        self._wait_for_device(serial, timeout_s=15.0)
        if self.check_root(serial):
            logger.info("[%s] Root verified on %s after retry", self.name, serial)
            return True

        msg = (
            f"Root unavailable on {serial}. "
            f"adb root output: {(out or '').strip()!r}. "
            "Use a rooted/userdebug image, or set ROOT_REQUIRED=false."
        )
        if self.config.root_required:
            raise RootUnavailable(msg, details={"serial": serial, "root_available": False})
        logger.warning("[%s] %s (ROOT_REQUIRED=false - continuing)", self.name, msg)
        return False

    def verify_root(self, serial: str) -> bool:
        try:
            return bool(self.ensure_root(serial))
        except RootUnavailable:
            return False

    def ensure_selinux_permissive(self, serial: str) -> str:
        """Set SELinux permissive when Enforcing. Returns final mode string."""
        ok, enforce = self.adb_shell(serial, "getenforce", timeout=10)
        mode = (enforce or "unknown").strip()
        if "Enforcing" in mode:
            logger.warning(
                "[%s] SELinux Enforcing on %s - setting Permissive for Frida attach",
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
        seen = set()
        uniq = []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        grep_pat = "|".join(uniq)
        ok, out = self.adb_shell(
            serial,
            f"su 0 pgrep -f '{uniq[0]}' 2>/dev/null || su 0 pgrep -f frida-server 2>/dev/null || "
            f"su 0 ps -A 2>/dev/null | grep -E '{grep_pat}' || "
            f"pgrep -f '{uniq[0]}' 2>/dev/null || ps -A 2>/dev/null | grep -E '{grep_pat}' || true",
            timeout=20,
        )
        text = out or ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        running = bool(lines) and (
            any(p in text for p in uniq)
            or any(line.isdigit() for line in lines)
        )
        return running, text

    def resolve_frida_binary(self, serial: str, abi: str = "", abilist: str = "") -> FridaBinarySpec:
        """
        Locate the host Frida server matching the device ABI, fetching it if absent.

        The binary lives in a gitignored directory (it exceeds GitHub's file size
        limit), so a fresh clone has none and dynamic analysis fails until
        somebody downloads one by hand - the reason this works on one machine and
        not the next. ensure_frida_server() downloads the pinned version for the
        detected ABI on first use and caches it; set
        SUDARSHAN_FRIDA_AUTO_DOWNLOAD=0 on air-gapped hosts to keep the old
        locate-only behaviour.
        """
        if not abi:
            info = self.get_device_info(serial)
            abi = info.abi
            abilist = info.abilist
        if self.config.frida_server_dir:
            from pathlib import Path

            spec = locate_frida_server(
                abi,
                abilist=abilist,
                version=self.config.frida_version,
                search_dirs=[Path(self.config.frida_server_dir)],
            )
            if spec.found and spec.path is not None:
                return spec

        return ensure_frida_server(
            abi,
            abilist=abilist,
            version=self.config.frida_version,
        )

    def push_frida_server(self, serial: str, abi: str = "", abilist: str = "") -> str:
        """
        Push the ABI-matched Frida server to the device.

        Returns the remote path of the primary agent binary.
        Raises FridaUnavailable with an actionable message if the host binary
        is missing - never silently pushes the wrong architecture.
        """
        spec = self.resolve_frida_binary(serial, abi=abi, abilist=abilist)
        if not spec.found or spec.path is None:
            raise FridaUnavailable(
                missing_binary_message(spec),
                details={
                    "serial": serial,
                    "abi": spec.abi,
                    "expected": spec.expected_name,
                    "found": False,
                },
            )

        remote = f"/data/local/tmp/{self.config.frida_bin}"
        legacy = "/data/local/tmp/frida-server"
        logger.info(
            "[%s] Pushing Frida %s (%s) → %s on %s",
            self.name,
            spec.path.name,
            spec.abi,
            remote,
            serial,
        )
        ok, out = self.adb(
            "-s", serial, "push", str(spec.path), remote, timeout=120
        )
        if not ok and "pushed" not in (out or "").lower():
            raise FridaUnavailable(
                f"Failed to push Frida binary to {serial}: {out}",
                details={"serial": serial, "host_binary": str(spec.path)},
            )
        self.adb_shell(serial, f"chmod 755 {remote}", timeout=10)
        self.adb_shell(
            serial,
            f"cp {remote} {legacy} && chmod 755 {legacy}",
            timeout=15,
        )
        return remote

    def ensure_frida_forward(self, serial: str, port: Optional[str] = None) -> bool:
        """Configure ADB port forwarding for the Frida listen port.

        Host TCP ports bind to one device. When a Genymotion TCP device and an
        Android emulator are both online, ``adb -s emulator-* forward`` fails
        with a misleading \"more than one device\" error - work around by
        temporarily disconnecting other TCP devices, then reconnecting them.
        """
        port = port or self.config.frida_port
        transport = transport_for_serial(serial)

        def _try_forward() -> Tuple[bool, str, str]:
            ok1, out1 = self.adb(
                "-s", serial, "forward", f"tcp:{port}", f"tcp:{port}", timeout=10
            )
            ok2, out2 = self.adb(
                "-s", serial, "forward", "tcp:27042", f"tcp:{port}", timeout=10
            )
            return bool(ok1 or ok2), out1 or "", out2 or ""

        ok, out1, out2 = _try_forward()
        if ok:
            logger.info(
                "[%s] Frida forwarded tcp:%s -> %s:%s", self.name, port, serial, port
            )
            return True

        combined = f"{out1} {out2}".lower()
        needs_workaround = (
            "more than one device" in combined
            or "cannot bind" in combined
            or "address already in use" in combined
        )
        if not needs_workaround:
            logger.warning(
                "[%s] Frida forward failed on %s: %s | %s",
                self.name,
                serial,
                out1,
                out2,
            )
            return False

        # Disconnect other TCP sandboxes so the emulator (or selected TCP
        # device) can own the host Frida ports.
        online = self.list_devices(enrich=False)
        disconnected: List[str] = []
        for d in online:
            if d.serial == serial:
                continue
            if transport_for_serial(d.serial) == "tcp":
                logger.info(
                    "[%s] Temporarily disconnecting %s so Frida forward can bind on %s",
                    self.name,
                    d.serial,
                    serial,
                )
                self.adb("disconnect", d.serial, timeout=5)
                disconnected.append(d.serial)

        # Also clear host ports owned by the selected TCP device if rebinding
        if transport == "tcp":
            self.adb("-s", serial, "forward", "--remove", f"tcp:{port}", timeout=5)
            self.adb("-s", serial, "forward", "--remove", "tcp:27042", timeout=5)

        ok, out1, out2 = _try_forward()

        for other in disconnected:
            self.adb("connect", other, timeout=5)

        if ok:
            logger.info(
                "[%s] Frida forwarded tcp:%s -> %s:%s (after multi-device workaround)",
                self.name,
                port,
                serial,
                port,
            )
            return True

        logger.warning(
            "[%s] Frida forward failed on %s after workaround: %s | %s. "
            "Disconnect other ADB devices and retry.",
            self.name,
            serial,
            out1,
            out2,
        )
        return False

    def ensure_frida(
        self,
        serial: str,
        restart_if_needed: bool = True,
        *,
        push_if_missing: bool = True,
        abi: str = "",
        abilist: str = "",
    ) -> FridaStatus:
        """
        Verify frida-server is running; push/start if necessary.

        ABI is detected from the device when not provided. The wrong-arch
        binary is never used as a silent fallback.
        """
        host_version = ""
        try:
            import frida as _frida

            host_version = getattr(_frida, "__version__", "") or ""
        except ImportError:
            host_version = ""

        if not abi:
            try:
                info = self.get_device_info(serial)
                abi = info.abi
                abilist = abilist or info.abilist
            except Exception:  # noqa: BLE001
                abi = abi or ""

        names = self._frida_process_names()
        running, out = self._frida_process_running(serial, names)

        status = FridaStatus(
            available=False,
            running=running,
            binary_name=self.config.frida_bin,
            port=self.config.frida_port,
            host_version=host_version,
            abi=abi,
            message="",
        )

        if running:
            status.available = True
            status.compatible = True
            status.message = f"frida agent running ({out.strip()[:120]})"
            status.forwarded = self.ensure_frida_forward(serial)
            return status

        if not restart_if_needed:
            status.message = "frida-server not running"
            raise FridaUnavailable(status.message, details=status.to_dict())

        logger.info("[%s] frida-server not running on %s - attempting start", self.name, serial)

        # Ensure a binary exists on device; push ABI-matched host binary if needed
        remote_paths = self._frida_remote_paths()
        have_remote = False
        for remote in remote_paths:
            ok_ls, ls_out = self.adb_shell(serial, f"ls {remote}", timeout=10)
            if ok_ls and "No such file" not in (ls_out or ""):
                have_remote = True
                status.binary_path = remote
                break

        if not have_remote and push_if_missing:
            try:
                status.binary_path = self.push_frida_server(
                    serial, abi=abi, abilist=abilist
                )
                have_remote = True
                spec = self.resolve_frida_binary(serial, abi=abi, abilist=abilist)
                status.host_binary = str(spec.path) if spec.path else ""
            except FridaUnavailable:
                raise

        if not have_remote:
            spec = self.resolve_frida_binary(serial, abi=abi, abilist=abilist)
            raise FridaUnavailable(
                missing_binary_message(spec),
                details={
                    "serial": serial,
                    "abi": spec.abi,
                    "expected": spec.expected_name,
                },
            )

        started = False
        for remote in remote_paths:
            ok_ls, ls_out = self.adb_shell(serial, f"ls {remote}", timeout=10)
            if not ok_ls or "No such file" in (ls_out or ""):
                continue
            status.binary_path = remote
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
                status.forwarded = self.ensure_frida_forward(serial, port)
                break

        if not started:
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
                status.forwarded = self.ensure_frida_forward(serial, port)
                return status

            spec = self.resolve_frida_binary(serial, abi=abi, abilist=abilist)
            status.message = (
                f"Frida startup failed\n"
                f"Device: {serial}\n"
                f"ABI: {abi or spec.abi or '(unknown)'}\n"
                f"Expected binary: {spec.expected_name}\n"
                f"Binary found: {'yes - ' + str(spec.path) if spec.found else 'no'}\n"
                f"Agent still not running after push/start."
            )
            raise FridaUnavailable(status.message, details=status.to_dict())

        return status

    def verify_frida(self, serial: str) -> FridaStatus:
        try:
            return self.ensure_frida(serial, restart_if_needed=False, push_if_missing=False)
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
                rooted = self.ensure_root(device.serial)
                info.rooted = rooted
                info.root_available = rooted
                _stage("root", True if rooted else False, "available" if rooted else "unavailable")
            except RootUnavailable as exc:
                info.rooted = False
                info.root_available = False
                _stage("root", False, f"unavailable - {exc.message}")
                if self.config.root_required:
                    raise

            selinux = self.ensure_selinux_permissive(device.serial)
            _stage("selinux", "Permissive" in selinux or "Disabled" in selinux, selinux)

            frida_status = self.ensure_frida(
                device.serial,
                restart_if_needed=True,
                push_if_missing=True,
                abi=info.abi,
                abilist=info.abilist,
            )
            info.frida_running = frida_status.running
            info.frida_available = frida_status.available
            info.frida_version = frida_status.host_version or frida_status.version
            info.frida_port = frida_status.port
            info.adb_forwarding = frida_status.forwarded
            _stage("frida", frida_status.available, frida_status.message)

            elapsed = (time.monotonic() - t0) * 1000
            info.connection_time_ms = elapsed
            logger.info(
                "[%s] Connected serial=%s provider=%s transport=%s ip=%s "
                "android=%s abi=%s root=%s frida=%s forward=%s connect_ms=%.1f",
                self.name,
                info.serial,
                info.provider,
                info.transport,
                info.ip,
                info.android_version,
                info.abi,
                info.root_available,
                info.frida_running,
                info.adb_forwarding,
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
