"""Gemini primary/fallback behaviour — mocked SDK only (no live quota)."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))
sys.path.insert(0, str(_ROOT / "backend"))

from sudarshan_core.ai.gemini_errors import (  # noqa: E402
    GeminiAllProvidersFailed,
    GeminiNonRetryableError,
    classify_gemini_error,
    is_fallback_eligible_error,
    redact_secrets,
)
from sudarshan_core.ai.gemini_provider import GeminiProviderManager, reset_gemini_manager  # noqa: E402
from sudarshan_core.ai.gemini_settings import GeminiProviderSpec, GeminiSettings  # noqa: E402


class FakeHTTPError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        if status_code is not None:
            self.status_code = status_code


class FakeModels:
    def __init__(self, owner: "FakeClient") -> None:
        self._owner = owner

    def generate_content(self, **kwargs):
        return self._owner._next(**kwargs)


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.models = FakeModels(self)

    def _next(self, **kwargs):
        self.calls += 1
        if not self.script:
            raise RuntimeError("unexpected call")
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        return item


def _ok(text: str):
    return SimpleNamespace(text=text, usage_metadata=None)


def _settings(**kwargs) -> GeminiSettings:
    defaults = dict(
        primary=GeminiProviderSpec("primary", "primary-key", "gemini-3.6-flash"),
        fallback=GeminiProviderSpec("fallback", "fallback-key", "gemini-2.5-flash"),
        cooldown_seconds=60.0,
        max_retries=3,
        retry_base_seconds=0.0,
        mode="failover",
    )
    defaults.update(kwargs)
    return GeminiSettings(**defaults)


def _manager(clients, settings=None, clock=None):
    return GeminiProviderManager(
        settings or _settings(),
        client_factory=lambda k: clients[k],
        clock=clock or (lambda: 0.0),
        sleeper=lambda _s: None,
    )


@pytest.fixture(autouse=True)
def _reset():
    reset_gemini_manager(None)
    yield
    reset_gemini_manager(None)


def test_primary_success():
    primary = FakeClient([_ok("PRIMARY_SUCCESS")])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    result = _manager({"primary-key": primary, "fallback-key": fallback}).generate_content(
        contents="x"
    )
    assert result.text == "PRIMARY_SUCCESS"
    assert result.provider == "primary"
    assert result.fallback_used is False
    assert primary.calls == 1
    assert fallback.calls == 0


def test_primary_429_triggers_fallback():
    primary = FakeClient([FakeHTTPError("429 RESOURCE_EXHAUSTED", 429)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    result = _manager(
        {"primary-key": primary, "fallback-key": fallback}, _settings(max_retries=1)
    ).generate_content(contents="x")
    assert result.text == "FALLBACK_SUCCESS"
    assert result.fallback_used is True
    assert primary.calls >= 1
    assert fallback.calls == 1


def test_primary_503_retries_then_fallback():
    primary = FakeClient([FakeHTTPError("503 UNAVAILABLE", 503)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    result = _manager(
        {"primary-key": primary, "fallback-key": fallback}, _settings(max_retries=2)
    ).generate_content(contents="x")
    assert primary.calls == 2
    assert fallback.calls == 1
    assert result.text == "FALLBACK_SUCCESS"


def test_non_fallback_error():
    primary = FakeClient([FakeHTTPError("400 INVALID_ARGUMENT", 400)])
    fallback = FakeClient([_ok("nope")])
    with pytest.raises(GeminiNonRetryableError):
        _manager({"primary-key": primary, "fallback-key": fallback}).generate_content(
            contents="x"
        )
    assert fallback.calls == 0


def test_both_providers_fail():
    primary = FakeClient([FakeHTTPError("429 quota", 429)])
    fallback = FakeClient([FakeHTTPError("503 UNAVAILABLE", 503)])
    with pytest.raises(GeminiAllProvidersFailed) as exc:
        _manager(
            {"primary-key": primary, "fallback-key": fallback}, _settings(max_retries=1)
        ).generate_content(contents="x")
    assert exc.value.fallback_used is True
    assert "primary-key" not in str(exc.value)


def test_cooldown_and_recovery():
    now = [100.0]
    primary = FakeClient([FakeHTTPError("429 RESOURCE_EXHAUSTED", 429), _ok("PRIMARY_PROBE")])
    fallback = FakeClient([_ok("fb1"), _ok("fb2")])
    mgr = _manager(
        {"primary-key": primary, "fallback-key": fallback},
        _settings(max_retries=1, cooldown_seconds=60.0),
        clock=lambda: now[0],
    )
    first = mgr.generate_content(contents="a")
    assert first.fallback_used is True
    calls_after = primary.calls
    second = mgr.generate_content(contents="b")
    assert second.provider == "fallback"
    assert primary.calls == calls_after
    now[0] = 161.0
    third = mgr.generate_content(contents="c")
    assert third.provider == "primary"
    assert third.text == "PRIMARY_PROBE"


def test_concurrent_requests():
    barrier = threading.Barrier(6)
    primary = FakeClient([FakeHTTPError("429 RESOURCE_EXHAUSTED", 429)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    mgr = _manager(
        {"primary-key": primary, "fallback-key": fallback},
        _settings(max_retries=1, cooldown_seconds=30.0),
    )
    errors: list[BaseException] = []

    def worker():
        try:
            barrier.wait()
            res = mgr.generate_content(contents="c")
            assert res.text == "FALLBACK_SUCCESS"
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert fallback.calls == 6


def test_api_key_redaction():
    msg = redact_secrets("failure AIzaSyABCDEF0123456789012345678901234567890")
    assert "AIzaSy" not in msg
    assert "[REDACTED_KEY]" in msg


def test_classify_errors():
    assert is_fallback_eligible_error(FakeHTTPError("429 RESOURCE_EXHAUSTED", 429))
    assert is_fallback_eligible_error(FakeHTTPError("503 UNAVAILABLE", 503))
    assert not is_fallback_eligible_error(FakeHTTPError("400 INVALID_ARGUMENT", 400))
    assert classify_gemini_error(FakeHTTPError("429", 429)).failure_type in {
        "quota_exhausted",
        "rate_limited",
    }
