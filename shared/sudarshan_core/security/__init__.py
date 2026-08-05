"""Security utilities shared by gateway and analysis-engine."""

from sudarshan_core.security.internal_auth import (
    HEADER_NAME,
    internal_auth_headers,
    internal_service_token,
)

__all__ = [
    "HEADER_NAME",
    "internal_auth_headers",
    "internal_service_token",
]
