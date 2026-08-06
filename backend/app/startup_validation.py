"""Production startup checks for the API gateway (no schema / infra changes)."""

from __future__ import annotations

import logging
import os

from app.registration_policy import is_production_env, log_registration_policy_at_startup

logger = logging.getLogger(__name__)

DEFAULT_MOBSF_API_KEY = "sudarshan_mobsf_api_key_2026"


def _gateway_dynamic_enabled() -> bool:
    return os.getenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def validate_production_environment() -> None:
    """
    Fail closed on dangerous production misconfiguration.
    JWT_SECRET_KEY is enforced at import time in app.auth.auth.
    ANALYSIS_ENGINE_INTERNAL_TOKEN is enforced via validate_backend_production_config().
    """
    if not is_production_env():
        return

    log_registration_policy_at_startup()

    if not os.getenv("JWT_SECRET_KEY", "").strip():
        raise RuntimeError(
            "SUDARSHAN_ENV=production requires JWT_SECRET_KEY to be set."
        )

    if not os.getenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "").strip():
        raise RuntimeError(
            "SUDARSHAN_ENV=production requires ANALYSIS_ENGINE_INTERNAL_TOKEN to be set."
        )

    mobsf_key = os.getenv("MOBSF_API_KEY", "").strip()
    if not mobsf_key:
        logger.error(
            "[Security] MOBSF_API_KEY is not set in production — set a dedicated API key."
        )
    elif mobsf_key == DEFAULT_MOBSF_API_KEY:
        raise RuntimeError(
            "MOBSF_API_KEY is still the default compose value "
            f"({DEFAULT_MOBSF_API_KEY!r}). Change it before production deployment."
        )

    if _gateway_dynamic_enabled():
        raise RuntimeError(
            "SUDARSHAN_ALLOW_GATEWAY_DYNAMIC must not be enabled when "
            "SUDARSHAN_ENV=production."
        )
