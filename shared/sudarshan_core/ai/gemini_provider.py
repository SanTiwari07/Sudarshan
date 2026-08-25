"""
Central Gemini client: primary first, retry, cooldown, then fallback.

Callers must not create google.genai.Client themselves. Deterministic scoring
never imports this module.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional

from sudarshan_core.ai.gemini_errors import (
    GeminiAllProvidersFailed,
    GeminiNonRetryableError,
    GeminiNotConfiguredError,
    classify_gemini_error,
    redact_secrets,
)
from sudarshan_core.ai.gemini_settings import (
    GeminiProviderSpec,
    GeminiSettings,
    load_gemini_settings,
)

logger = logging.getLogger(__name__)

ClientFactory = Callable[[str], Any]


class CircuitState(str, Enum):
    AVAILABLE = "AVAILABLE"
    DEGRADED = "DEGRADED"
    OPEN = "OPEN"


class _NeedFallback(Exception):
    def __init__(self, exc: BaseException, failure_type: str) -> None:
        super().__init__(redact_secrets(str(exc)))
        self.cause = exc
        self.failure_type = failure_type


@dataclass
class GeminiCallResult:
    response: Any
    provider: str
    model: str
    fallback_used: bool
    retry_count: int
    latency_ms: float
    failure_type: Optional[str] = None

    @property
    def text(self) -> str:
        if self.response is None:
            return ""
        return getattr(self.response, "text", None) or ""

    def __getattr__(self, name: str) -> Any:
        return getattr(self.response, name)


@dataclass
class _Slot:
    spec: GeminiProviderSpec
    client: Any
    state: CircuitState = CircuitState.AVAILABLE
    open_until: float = 0.0
    consecutive_failures: int = 0


def _default_client_factory(api_key: str) -> Any:
    from google import genai

    return genai.Client(api_key=api_key)


def _is_gemini_3(model: str) -> bool:
    return "gemini-3" in (model or "").lower()


def _thinking_budget(config: Any) -> Optional[int]:
    if config is None:
        return None
    thinking = getattr(config, "thinking_config", None)
    if thinking is None:
        return None
    budget = getattr(thinking, "thinking_budget", None)
    if budget is None:
        budget = getattr(thinking, "thinkingBudget", None)
    try:
        return int(budget) if budget is not None else None
    except (TypeError, ValueError):
        return None


def _compat_config(config: Any, model: str, *, strip_thinking: bool) -> Any:
    """Drop thinking knobs that Gemini 3.x or 2.5 Flash will reject."""
    if config is None:
        return None
    drop = strip_thinking
    if _is_gemini_3(model) and _thinking_budget(config) == 0:
        drop = True
    if not _is_gemini_3(model) and getattr(config, "thinking_config", None) is not None:
        drop = True
    if not drop:
        return config
    try:
        from google.genai import types

        kwargs: Dict[str, Any] = {}
        for name in (
            "system_instruction",
            "temperature",
            "max_output_tokens",
            "response_mime_type",
            "response_schema",
            "safety_settings",
            "tools",
            "automatic_function_calling",
            "candidate_count",
            "stop_sequences",
            "top_p",
            "top_k",
        ):
            val = getattr(config, name, None)
            if val is not None:
                kwargs[name] = val
        return types.GenerateContentConfig(**kwargs)
    except Exception:
        return config


def _log(event: str, **fields: Any) -> None:
    parts = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    logger.info("[Gemini] %s %s", event, parts)


class GeminiProviderManager:
    """
    Process-local failover. Circuit state is shared across concurrent analyses.
    Tests call reset_gemini_manager().
    """

    def __init__(
        self,
        settings: Optional[GeminiSettings] = None,
        *,
        client_factory: Optional[ClientFactory] = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings or load_gemini_settings()
        self._client_factory = client_factory or _default_client_factory
        self._clock = clock
        self._sleep = sleeper
        self._lock = threading.RLock()
        self._slots: Dict[str, _Slot] = {}
        self._build_slots()

    def _build_slots(self) -> None:
        self._slots.clear()
        for spec in (self._settings.primary, self._settings.fallback):
            if spec is None:
                continue
            try:
                client = self._client_factory(spec.api_key)
            except Exception as exc:
                logger.warning(
                    "[Gemini] Failed to initialise %s client: %s",
                    spec.role,
                    redact_secrets(f"{type(exc).__name__}: {exc}"),
                )
                continue
            self._slots[spec.role] = _Slot(spec=spec, client=client)

    @property
    def settings(self) -> GeminiSettings:
        return self._settings

    @property
    def is_configured(self) -> bool:
        return bool(self._slots)

    @property
    def preferred_model(self) -> str:
        primary = self._slots.get("primary")
        if primary:
            return primary.spec.model
        fallback = self._slots.get("fallback")
        if fallback:
            return fallback.spec.model
        return self._settings.preferred_model

    def _expire_cooldown_locked(self, slot: _Slot) -> None:
        if slot.state == CircuitState.OPEN and self._clock() >= slot.open_until:
            slot.state = CircuitState.DEGRADED
            _log(
                "Primary cooldown expired; probing on next request"
                if slot.spec.role == "primary"
                else "Provider cooldown expired; probing on next request",
                provider=slot.spec.role,
                model=slot.spec.model,
                circuit=slot.state.value,
            )

    def _open_circuit(self, slot: _Slot, failure_type: str) -> None:
        with self._lock:
            slot.state = CircuitState.OPEN
            slot.open_until = self._clock() + self._settings.cooldown_seconds
            slot.consecutive_failures += 1
        _log(
            "Primary provider entering cooldown"
            if slot.spec.role == "primary"
            else "Provider entering cooldown",
            provider=slot.spec.role,
            model=slot.spec.model,
            failure_type=failure_type,
            cooldown_seconds=self._settings.cooldown_seconds,
            circuit=CircuitState.OPEN.value,
        )

    def _on_success(self, slot: _Slot) -> None:
        with self._lock:
            slot.state = CircuitState.AVAILABLE
            slot.open_until = 0.0
            slot.consecutive_failures = 0

    def _ordered_slots(self) -> List[_Slot]:
        with self._lock:
            primary = self._slots.get("primary")
            fallback = self._slots.get("fallback")
            ordered: List[_Slot] = []
            if primary:
                self._expire_cooldown_locked(primary)
                if primary.state != CircuitState.OPEN:
                    ordered.append(primary)
                else:
                    remaining = max(0.0, primary.open_until - self._clock())
                    _log(
                        "Primary in cooldown; skipping to fallback"
                        if fallback
                        else "Primary in cooldown; no fallback configured",
                        provider="primary",
                        model=primary.spec.model,
                        cooldown_remaining_s=round(remaining, 1),
                        circuit=primary.state.value,
                    )
            if fallback:
                self._expire_cooldown_locked(fallback)
                if fallback.state != CircuitState.OPEN:
                    ordered.append(fallback)
            return ordered

    def _invoke(
        self,
        slot: _Slot,
        *,
        contents: Any,
        config: Any,
        stream: bool,
        strip_thinking: bool,
        extra: Dict[str, Any],
    ) -> Any:
        cfg = _compat_config(config, slot.spec.model, strip_thinking=strip_thinking)
        models = slot.client.models
        if stream:
            return models.generate_content_stream(
                model=slot.spec.model, contents=contents, config=cfg, **extra
            )
        return models.generate_content(
            model=slot.spec.model, contents=contents, config=cfg, **extra
        )

    def _call_slot(
        self,
        slot: _Slot,
        *,
        contents: Any,
        config: Any,
        stream: bool,
        extra: Dict[str, Any],
    ) -> Any:
        last_exc: Optional[BaseException] = None
        strip_thinking = False
        attempts = self._settings.max_retries
        for attempt in range(attempts):
            _log(
                f"{slot.spec.role.capitalize()} request started",
                provider=slot.spec.role,
                model=slot.spec.model,
                attempt=attempt + 1,
                stream=stream,
            )
            try:
                response = self._invoke(
                    slot,
                    contents=contents,
                    config=config,
                    stream=stream,
                    strip_thinking=strip_thinking,
                    extra=extra,
                )
                if stream:
                    first = next(response)

                    def _chained(first_chunk: Any, rest: Any) -> Iterator[Any]:
                        yield first_chunk
                        yield from rest

                    _log(
                        f"{slot.spec.role.capitalize()} request succeeded",
                        provider=slot.spec.role,
                        model=slot.spec.model,
                        status="success",
                    )
                    self._on_success(slot)
                    return _chained(first, response)

                text = getattr(response, "text", None) if response is not None else None
                if response is None or not (text or ""):
                    err = RuntimeError("503 UNAVAILABLE: empty Gemini response")
                    err.status_code = 503  # type: ignore[attr-defined]
                    raise err
                _log(
                    f"{slot.spec.role.capitalize()} request succeeded",
                    provider=slot.spec.role,
                    model=slot.spec.model,
                    status="success",
                )
                self._on_success(slot)
                return response
            except StopIteration:
                last_exc = RuntimeError("503 UNAVAILABLE: empty Gemini stream")
                last_exc.status_code = 503  # type: ignore[attr-defined]
                classified = classify_gemini_error(last_exc)
            except Exception as exc:
                last_exc = exc
                classified = classify_gemini_error(exc)

            safe = redact_secrets(f"{type(last_exc).__name__}: {last_exc}")
            _log(
                f"{slot.spec.role.capitalize()} request failed: {classified.failure_type}",
                provider=slot.spec.role,
                model=slot.spec.model,
                failure_type=classified.failure_type,
                http_status=classified.http_status,
                attempt=attempt + 1,
            )
            logger.warning("[Gemini] %s error: %s", slot.spec.role, safe)

            if classified.thinking_incompatible and not strip_thinking:
                strip_thinking = True
                logger.info(
                    "[Gemini] Retrying %s without thinking_config (model compatibility)",
                    slot.spec.role,
                )
                continue

            if not classified.retryable:
                if classified.fallback_eligible:
                    raise _NeedFallback(last_exc, classified.failure_type)
                raise GeminiNonRetryableError(
                    safe, failure_type=classified.failure_type
                ) from last_exc

            if attempt < attempts - 1:
                backoff = self._settings.retry_base_seconds * (2 ** attempt)
                logger.info("[Gemini] Retrying %s in %.1fs", slot.spec.role, backoff)
                self._sleep(backoff)

        assert last_exc is not None
        classified = classify_gemini_error(last_exc)
        if classified.fallback_eligible:
            raise _NeedFallback(last_exc, classified.failure_type)
        raise GeminiAllProvidersFailed(
            redact_secrets(f"{type(last_exc).__name__}: {last_exc}"),
            failure_type=classified.failure_type,
            fallback_used=False,
        ) from last_exc

    def _execute(
        self,
        *,
        contents: Any,
        config: Any = None,
        stream: bool = False,
        **extra: Any,
    ) -> GeminiCallResult:
        if not self._slots:
            raise GeminiNotConfiguredError(
                "No Gemini API key configured. Set GEMINI_PRIMARY_API_KEY / "
                "GEMINI_FALLBACK_API_KEY or legacy GEMINI_API_KEY."
            )

        started = self._clock()
        last_fail: Optional[str] = None
        slots = self._ordered_slots()
        if not slots:
            raise GeminiAllProvidersFailed(
                "All Gemini providers are in cooldown and no provider is eligible",
                failure_type="circuit_open",
                fallback_used=False,
            )

        tried_fallback = False
        last_exc: Optional[BaseException] = None
        retry_count = 0
        for index, slot in enumerate(slots):
            is_fallback = slot.spec.role == "fallback"
            try:
                if is_fallback and index > 0:
                    tried_fallback = True
                    _log(
                        "Switching to fallback provider",
                        provider="fallback",
                        model=slot.spec.model,
                        failure_type=last_fail,
                    )
                response = self._call_slot(
                    slot, contents=contents, config=config, stream=stream, extra=extra
                )
                latency = (self._clock() - started) * 1000.0
                # A primary is configured but did not serve this request, so
                # the fallback stood in for it - that is what fallback_used
                # reports. Deriving it from `tried_fallback` instead missed
                # every request made while the primary was in cooldown: those
                # skip the primary in _ordered_slots(), leaving the fallback
                # at index 0, so the whole cooldown window was recorded as
                # normal primary traffic. When the fallback is the ONLY
                # configured provider there is nothing to fall back from.
                only_fallback = "primary" not in self._slots
                return GeminiCallResult(
                    response=response,
                    provider=slot.spec.role,
                    model=slot.spec.model,
                    fallback_used=is_fallback and not only_fallback,
                    retry_count=retry_count,
                    latency_ms=latency,
                    failure_type=last_fail,
                )
            except GeminiNonRetryableError:
                raise
            except _NeedFallback as need:
                last_exc = need.cause
                last_fail = need.failure_type
                retry_count += self._settings.max_retries
                self._open_circuit(slot, need.failure_type)
                if index + 1 < len(slots):
                    continue
                break

        latency = (self._clock() - started) * 1000.0
        msg = redact_secrets(
            f"Gemini providers failed ({last_fail or 'unknown'}): {last_exc}"
        )
        logger.error("[Gemini] All providers failed latency_ms=%.0f %s", latency, msg)
        raise GeminiAllProvidersFailed(
            msg,
            failure_type=last_fail or "all_providers_failed",
            fallback_used=tried_fallback,
        ) from last_exc

    def generate_content(
        self,
        *,
        contents: Any,
        config: Any = None,
        **kwargs: Any,
    ) -> GeminiCallResult:
        return self._execute(contents=contents, config=config, stream=False, **kwargs)

    def generate_content_stream(
        self,
        *,
        contents: Any,
        config: Any = None,
        **kwargs: Any,
    ) -> Iterator[Any]:
        result = self._execute(contents=contents, config=config, stream=True, **kwargs)
        yield from result.response

    async def generate_content_async(
        self,
        *,
        contents: Any,
        config: Any = None,
        **kwargs: Any,
    ) -> GeminiCallResult:
        return await asyncio.to_thread(
            self.generate_content, contents=contents, config=config, **kwargs
        )

    async def generate_content_stream_async(
        self,
        *,
        contents: Any,
        config: Any = None,
        **kwargs: Any,
    ):
        def _open() -> Iterator[Any]:
            return self.generate_content_stream(
                contents=contents, config=config, **kwargs
            )

        iterator = await asyncio.to_thread(_open)
        while True:
            try:
                chunk = await asyncio.to_thread(next, iterator)
            except StopIteration:
                break
            yield chunk


_MANAGER_LOCK = threading.Lock()
_MANAGER: Optional[GeminiProviderManager] = None


def get_gemini_manager() -> GeminiProviderManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = GeminiProviderManager()
            settings = _MANAGER.settings
            _log(
                "Manager initialised",
                mode=settings.mode,
                primary_model=settings.primary.model if settings.primary else None,
                fallback_model=settings.fallback.model if settings.fallback else None,
                cooldown_seconds=settings.cooldown_seconds,
            )
        return _MANAGER


def reset_gemini_manager(manager: Optional[GeminiProviderManager] = None) -> None:
    """Replace the process singleton. Pass None to rebuild from the environment."""
    global _MANAGER
    with _MANAGER_LOCK:
        _MANAGER = manager


def gemini_is_configured() -> bool:
    return load_gemini_settings().configured
