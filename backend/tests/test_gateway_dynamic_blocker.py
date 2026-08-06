"""Gateway must not run dynamic analysis locally when the engine is unavailable."""

import os

os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-jwt-secret-for-gateway-blocker-tests-not-for-production",
)

import pytest
from unittest.mock import patch
from fastapi import HTTPException

from app.routes.upload import _run_analysis_pipeline


@pytest.mark.anyio
async def test_gateway_returns_503_when_engine_down_and_dynamic_disabled(monkeypatch):
    monkeypatch.delenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", raising=False)

    async def _no_engine(*_a, **_k):
        return None

    with patch("app.routes.upload._call_analysis_engine", side_effect=_no_engine):
        with pytest.raises(HTTPException) as exc:
            await _run_analysis_pipeline("/tmp/x.apk", "a" * 64, analyst_id=1)
    assert exc.value.status_code == 503
    assert "SUDARSHAN_ALLOW_GATEWAY_DYNAMIC" in str(exc.value.detail)
