"""Security utilities shared by gateway and analysis-engine."""

from sudarshan_core.security.internal_auth import (
    HEADER_NAME,
    internal_auth_headers,
    internal_service_token,
)
from sudarshan_core.security.sandbox_containment import (
    ContainmentViolation,
    audit_sandbox_connectivity,
    build_frida_start_command,
    containment_strict_enabled,
    enforce_connectivity_policy,
    frida_listen_host,
    gateway_dynamic_allowed,
    validate_adb_invocation,
)

__all__ = [
    "HEADER_NAME",
    "ContainmentViolation",
    "audit_sandbox_connectivity",
    "build_frida_start_command",
    "containment_strict_enabled",
    "enforce_connectivity_policy",
    "frida_listen_host",
    "gateway_dynamic_allowed",
    "internal_auth_headers",
    "internal_service_token",
    "validate_adb_invocation",
]
