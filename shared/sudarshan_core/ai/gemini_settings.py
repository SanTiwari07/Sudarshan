"""Load Gemini primary / fallback settings from the environment."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DOTENV_DONE = False

DEFAULT_MODEL = "gemini-2.5-flash"
DEFAULT_COOLDOWN_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_SECONDS = 0.5


def _strip(value: Optional[str]) -> str:
    return (value or "").strip()


def _load_dotenv_once() -> None:
    """Walk toward repo root for a .env; Docker already injects env, so no override."""
    global _DOTENV_DONE
    if _DOTENV_DONE:
        return
    _DOTENV_DONE = True
    try:
        from dotenv import load_dotenv
    except Exception:
        return
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        env_file = parent / ".env"
        if env_file.is_file():
            load_dotenv(dotenv_path=env_file, override=False)
            return


def _float_env(name: str, default: float) -> float:
    raw = _strip(os.getenv(name))
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("[Gemini] Invalid %s=%s; using %s", name, raw, default)
        return default


def _int_env(name: str, default: int) -> int:
    raw = _strip(os.getenv(name))
    if not raw:
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("[Gemini] Invalid %s=%s; using %s", name, raw, default)
        return default


@dataclass(frozen=True)
class GeminiProviderSpec:
    role: str  # "primary" | "fallback"
    api_key: str
    model: str

    def __repr__(self) -> str:
        return f"GeminiProviderSpec(role={self.role!r}, model={self.model!r}, api_key=*** )"


@dataclass(frozen=True)
class GeminiSettings:
    primary: Optional[GeminiProviderSpec]
    fallback: Optional[GeminiProviderSpec]
    cooldown_seconds: float
    max_retries: int
    retry_base_seconds: float
    mode: str  # failover | primary_only | fallback_only | unconfigured

    @property
    def configured(self) -> bool:
        return self.primary is not None or self.fallback is not None

    @property
    def preferred_model(self) -> str:
        if self.primary:
            return self.primary.model
        if self.fallback:
            return self.fallback.model
        return DEFAULT_MODEL


def load_gemini_settings() -> GeminiSettings:
    """
    Resolve keys and models.

    New:
      GEMINI_PRIMARY_API_KEY / GEMINI_PRIMARY_MODEL
      GEMINI_FALLBACK_API_KEY / GEMINI_FALLBACK_MODEL
      GEMINI_PRIMARY_COOLDOWN_SECONDS

    Legacy (primary aliases):
      GEMINI_API_KEY, GOOGLE_API_KEY
      GEMINI_MODEL, SUDARSHAN_AGENT_MODEL
    """
    _load_dotenv_once()

    primary_key = (
        _strip(os.getenv("GEMINI_PRIMARY_API_KEY"))
        or _strip(os.getenv("GEMINI_API_KEY"))
        or _strip(os.getenv("GOOGLE_API_KEY"))
    )
    fallback_key = _strip(os.getenv("GEMINI_FALLBACK_API_KEY"))

    legacy_model = (
        _strip(os.getenv("GEMINI_PRIMARY_MODEL"))
        or _strip(os.getenv("GEMINI_MODEL"))
        or _strip(os.getenv("SUDARSHAN_AGENT_MODEL"))
        or DEFAULT_MODEL
    )
    fallback_model = _strip(os.getenv("GEMINI_FALLBACK_MODEL")) or DEFAULT_MODEL

    # If the operator only set the legacy key, it is primary (not a sibling to load-balance).
    primary = (
        GeminiProviderSpec(role="primary", api_key=primary_key, model=legacy_model)
        if primary_key
        else None
    )
    fallback = (
        GeminiProviderSpec(role="fallback", api_key=fallback_key, model=fallback_model)
        if fallback_key
        else None
    )

    # Same key twice is not failover — keep a single slot so we do not "fail over" to ourselves.
    if primary and fallback and primary.api_key == fallback.api_key and primary.model == fallback.model:
        logger.info(
            "[Gemini] Fallback key/model identical to primary; running primary-only"
        )
        fallback = None

    if primary and fallback:
        mode = "failover"
    elif primary:
        mode = "primary_only"
    elif fallback:
        mode = "fallback_only"
        logger.info("[Gemini] Only fallback provider configured; running fallback-only")
    else:
        mode = "unconfigured"

    cooldown = _float_env("GEMINI_PRIMARY_COOLDOWN_SECONDS", DEFAULT_COOLDOWN_SECONDS)
    cooldown = max(1.0, cooldown)
    max_retries = _int_env("GEMINI_MAX_RETRIES", DEFAULT_MAX_RETRIES)
    retry_base = _float_env("GEMINI_RETRY_BASE_SECONDS", DEFAULT_RETRY_BASE_SECONDS)

    return GeminiSettings(
        primary=primary,
        fallback=fallback,
        cooldown_seconds=cooldown,
        max_retries=max_retries,
        retry_base_seconds=max(0.05, retry_base),
        mode=mode,
    )
