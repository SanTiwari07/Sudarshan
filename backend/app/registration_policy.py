"""Public self-registration policy (hackathon / gateway hardening)."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


def is_production_env() -> bool:
    return os.getenv("SUDARSHAN_ENV", "").strip().lower() == "production"


def registration_env_explicitly_set() -> bool:
    raw = os.getenv("SUDARSHAN_ALLOW_REGISTRATION")
    return raw is not None and raw.strip() != ""


def public_registration_allowed() -> bool:
    """
    Development: default allow registration.
    Production: default deny unless SUDARSHAN_ALLOW_REGISTRATION is explicitly true.
    """
    raw = os.getenv("SUDARSHAN_ALLOW_REGISTRATION")
    if raw is None or raw.strip() == "":
        return not is_production_env()
    norm = raw.strip().lower()
    if norm in _TRUTHY:
        return True
    if norm in _FALSY:
        return False
    # Unknown value - fail secure in production.
    return not is_production_env()


def log_registration_policy_at_startup() -> None:
    if is_production_env() and not registration_env_explicitly_set():
        logger.info(
            "[Security] Public registration is disabled (production default; "
            "set SUDARSHAN_ALLOW_REGISTRATION=true to enable)."
        )
    elif is_production_env() and public_registration_allowed():
        logger.warning(
            "[Security] SUDARSHAN_ALLOW_REGISTRATION=true - public signup is enabled in production."
        )
