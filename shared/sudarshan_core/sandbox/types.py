"""Shared data types for the sandbox abstraction layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

TransportType = Literal["usb", "tcp", "emulator", "unknown"]


@dataclass
class DeviceInfo:
    """
    Structured description of a connected sandbox device (SandboxDevice).

    The Dynamic Analysis Engine and bootstrap talk to the selected device via
    these fields - never via hardcoded Genymotion IPs or emulator serials.
    """

    serial: str
    state: str = "device"
    provider: str = ""
    android_version: str = ""
    api_level: str = ""
    abi: str = ""
    abilist: str = ""
    model: str = ""
    manufacturer: str = ""
    ip: str = ""
    transport: TransportType = "unknown"
    is_emulator: Optional[bool] = None
    avd_name: str = ""
    rooted: Optional[bool] = None
    root_available: Optional[bool] = None
    frida_running: Optional[bool] = None
    frida_available: Optional[bool] = None
    frida_version: str = ""
    frida_port: str = ""
    adb_forwarding: Optional[bool] = None
    connection_time_ms: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Public alias matching the architectural name in the design doc.
SandboxDevice = DeviceInfo


@dataclass
class FridaStatus:
    """Result of frida-server verification on a device."""

    available: bool
    running: bool = False
    binary_path: str = ""
    binary_name: str = ""
    host_binary: str = ""
    port: str = ""
    version: str = ""
    host_version: str = ""
    abi: str = ""
    compatible: Optional[bool] = None
    restarted: bool = False
    forwarded: bool = False
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectionResult:
    """Structured outcome of SandboxProvider.connect()."""

    ok: bool
    device: Optional[DeviceInfo] = None
    frida: Optional[FridaStatus] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    stages: List[Dict[str, Any]] = field(default_factory=list)
    connection_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "device": self.device.to_dict() if self.device else None,
            "frida": self.frida.to_dict() if self.frida else None,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "stages": self.stages,
            "connection_time_ms": self.connection_time_ms,
        }
