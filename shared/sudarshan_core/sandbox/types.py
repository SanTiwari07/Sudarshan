"""Shared data types for the sandbox abstraction layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DeviceInfo:
    """Structured description of a connected sandbox device."""

    serial: str
    state: str = "device"
    provider: str = ""
    android_version: str = ""
    api_level: str = ""
    abi: str = ""
    model: str = ""
    manufacturer: str = ""
    ip: str = ""
    rooted: Optional[bool] = None
    frida_running: Optional[bool] = None
    frida_version: str = ""
    connection_time_ms: Optional[float] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FridaStatus:
    """Result of frida-server verification on a device."""

    available: bool
    running: bool = False
    binary_path: str = ""
    binary_name: str = ""
    port: str = ""
    version: str = ""
    host_version: str = ""
    compatible: Optional[bool] = None
    restarted: bool = False
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
