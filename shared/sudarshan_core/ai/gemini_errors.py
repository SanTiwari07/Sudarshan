"""
Classify Gemini / Google GenAI failures for retry and provider failover.

Fallback is for provider-side unavailability (quota, rate limit, 5xx, auth that
makes a key unusable). Application bugs and invalid requests stay on the same
provider so the second key is not burned on a prompt that cannot succeed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Never log raw keys if they leak into exception strings.
_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{8,}")
_QUERY_KEY_RE = re.compile(r"(?i)(key|token|authorization)=([^&\s]+)")


def redact_secrets(text: str) -> str:
    """Strip API keys and bearer-like query params from a string."""
    if not text:
        return ""
    out = _KEY_RE.sub("[REDACTED_KEY]", text)
    out = _QUERY_KEY_RE.sub(r"\1=[REDACTED]", out)
    return out


@dataclass(frozen=True)
class GeminiErrorClassification:
    """Structured view of a transport failure. Safe to log."""

    failure_type: str
    retryable: bool
    fallback_eligible: bool
    http_status: Optional[int] = None
    thinking_incompatible: bool = False


class GeminiNotConfiguredError(RuntimeError):
    """No Gemini API key is configured (primary, fallback, or legacy alias)."""


class GeminiNonRetryableError(RuntimeError):
    """Request is invalid or otherwise will not succeed on another provider."""

    def __init__(self, message: str, *, failure_type: str = "invalid_request"):
        super().__init__(redact_secrets(message))
        self.failure_type = failure_type


class GeminiAllProvidersFailed(RuntimeError):
    """Primary (and fallback, if configured) could not complete the request."""

    def __init__(
        self,
        message: str,
        *,
        failure_type: str = "all_providers_failed",
        fallback_used: bool = False,
    ):
        super().__init__(redact_secrets(message))
        self.failure_type = failure_type
        self.fallback_used = fallback_used


_QUOTA_MARKERS = (
    "resource_exhausted",
    "resource exhausted",
    "quota",
    "rate limit",
    "rate_limit",
    "too many requests",
    "exceeded your current quota",
)

_UNAVAILABLE_MARKERS = (
    "unavailable",
    "temporarily",
    "internal error",
    "backend error",
    "connection",
    "connect timeout",
    "timed out",
    "timeout",
    "deadline",
    "reset by peer",
    "broken pipe",
)

_AUTH_MARKERS = (
    "unauthenticated",
    "unauthorized",
    "permission_denied",
    "permission denied",
    "api key not valid",
    "api_key_invalid",
    "invalid api key",
    "forbidden",
)

_INVALID_MARKERS = (
    "invalid_argument",
    "invalid argument",
    "invalid json",
    "parse error",
    "unknown name",
    "unknown field",
    "schema",
    "failed to parse",
    "malformed",
    "not supported",
    "unsupported",
    "invalid request",
)

_THINKING_MARKERS = (
    "thinking_budget",
    "thinking budget",
    "thinking_config",
    "thinkingconfig",
    "thinking_level",
)


def _http_status(exc: BaseException) -> Optional[int]:
    for attr in ("status_code", "code", "status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int) and 100 <= val <= 599:
            return val
        if isinstance(val, str) and val.isdigit():
            n = int(val)
            if 100 <= n <= 599:
                return n
    resp = getattr(exc, "response", None)
    if resp is not None:
        code = getattr(resp, "status_code", None) or getattr(resp, "status", None)
        if isinstance(code, int):
            return code
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        code = details.get("code") or details.get("status_code")
        if isinstance(code, int) and 100 <= code <= 599:
            return code
    text = f"{type(exc).__name__} {exc}".lower()
    for code in (429, 503, 502, 504, 500, 401, 403, 400, 404, 413, 499):
        if re.search(rf"\b{code}\b", text):
            return code
    return None


def _blob(exc: BaseException) -> str:
    return redact_secrets(f"{type(exc).__name__}: {exc}").lower()


def classify_gemini_error(exc: BaseException) -> GeminiErrorClassification:
    """Map an exception to retry / failover behaviour."""
    if isinstance(exc, TimeoutError):
        return GeminiErrorClassification(
            failure_type="timeout", retryable=True, fallback_eligible=True
        )
    if isinstance(exc, (ConnectionError, BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
        return GeminiErrorClassification(
            failure_type="connection_error", retryable=True, fallback_eligible=True
        )

    status = _http_status(exc)
    text = _blob(exc)
    thinking = any(m in text for m in _THINKING_MARKERS)

    if status == 429 or any(m in text for m in _QUOTA_MARKERS):
        return GeminiErrorClassification(
            failure_type="quota_exhausted" if ("quota" in text or status == 429) else "rate_limited",
            retryable=True,
            fallback_eligible=True,
            http_status=status or 429,
        )

    if status in {500, 502, 503, 504} or (
        any(m in text for m in _UNAVAILABLE_MARKERS) and status is None
    ):
        failure = "unavailable"
        if status == 503:
            failure = "unavailable"
        elif status == 500:
            failure = "internal"
        return GeminiErrorClassification(
            failure_type=failure,
            retryable=True,
            fallback_eligible=True,
            http_status=status,
        )

    if status in {401, 403} or any(m in text for m in _AUTH_MARKERS):
        return GeminiErrorClassification(
            failure_type="auth_failed",
            retryable=False,
            fallback_eligible=True,
            http_status=status,
        )

    if thinking and (status == 400 or "invalid" in text):
        return GeminiErrorClassification(
            failure_type="thinking_incompatible",
            retryable=True,
            fallback_eligible=False,
            http_status=status or 400,
            thinking_incompatible=True,
        )

    if status == 400 or any(m in text for m in _INVALID_MARKERS):
        return GeminiErrorClassification(
            failure_type="invalid_request",
            retryable=False,
            fallback_eligible=False,
            http_status=status or 400,
        )

    if status == 404:
        return GeminiErrorClassification(
            failure_type="not_found",
            retryable=False,
            fallback_eligible=False,
            http_status=404,
        )

    if isinstance(exc, (TimeoutError, ConnectionError)):
        return GeminiErrorClassification(
            failure_type="timeout",
            retryable=True,
            fallback_eligible=True,
        )

    # Unknown: retry once on the same provider, do not failover (could be a bug).
    return GeminiErrorClassification(
        failure_type="unknown",
        retryable=True,
        fallback_eligible=False,
        http_status=status,
    )


def is_fallback_eligible_error(exc: BaseException) -> bool:
    """True when a second Gemini provider should be tried."""
    return classify_gemini_error(exc).fallback_eligible


def is_retryable_error(exc: BaseException) -> bool:
    """True when another attempt on the same provider could succeed."""
    return classify_gemini_error(exc).retryable
