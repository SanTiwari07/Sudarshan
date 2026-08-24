"""Shared AI helpers. Gemini transport lives here so backend and the analysis engine share one failover path."""

from sudarshan_core.ai.gemini_errors import (
    GeminiAllProvidersFailed,
    GeminiErrorClassification,
    GeminiNonRetryableError,
    GeminiNotConfiguredError,
    classify_gemini_error,
    is_fallback_eligible_error,
    is_retryable_error,
)
from sudarshan_core.ai.gemini_provider import (
    GeminiCallResult,
    GeminiProviderManager,
    gemini_is_configured,
    get_gemini_manager,
    reset_gemini_manager,
)
from sudarshan_core.ai.gemini_settings import GeminiSettings, load_gemini_settings

__all__ = [
    "GeminiAllProvidersFailed",
    "GeminiCallResult",
    "GeminiErrorClassification",
    "GeminiNonRetryableError",
    "GeminiNotConfiguredError",
    "GeminiProviderManager",
    "GeminiSettings",
    "classify_gemini_error",
    "gemini_is_configured",
    "get_gemini_manager",
    "is_fallback_eligible_error",
    "is_retryable_error",
    "load_gemini_settings",
    "reset_gemini_manager",
]
