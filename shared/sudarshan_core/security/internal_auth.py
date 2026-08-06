"""Shared secret for backend → analysis-engine calls."""

from __future__ import annotations

import os

HEADER_NAME = "X-Sudarshan-Internal-Token"


def internal_service_token() -> str:
    return os.getenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "").strip()


def internal_auth_headers() -> dict[str, str]:
    token = internal_service_token()
    if not token:
        return {}
    return {HEADER_NAME: token}
