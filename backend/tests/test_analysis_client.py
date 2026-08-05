"""
Unit tests for backend orchestrator gateway client:
  1. Test _call_analysis_engine fallback when container is unreachable.
  2. Test _call_analysis_engine HTTP 200 response processing.
"""

import pytest
from unittest.mock import MagicMock, patch
from app.routes.upload import _call_analysis_engine


@pytest.mark.anyio
async def test_call_analysis_engine_fallback():
    # Test graceful fallback when microservice is offline / connection fails
    with patch("app.routes.upload.httpx.AsyncClient.post", side_effect=Exception("Connection refused")):
        res = await _call_analysis_engine("/tmp/test.apk", "a" * 64)
        assert res is None


@pytest.mark.anyio
async def test_call_analysis_engine_success():
    # Test successful HTTP 200 OK response from analysis-engine container
    mock_payload = {"sha256": "a" * 64, "final_risk_score": 85.0, "risk_band": "CRITICAL"}
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_payload

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
        async def post(self, url, json=None, headers=None):
            return mock_resp

    with patch("app.routes.upload.httpx.AsyncClient", side_effect=MockAsyncClient):
        res = await _call_analysis_engine("/app/uploads/test.apk", "a" * 64)
        assert res is not None
        assert res["sha256"] == "a" * 64
        assert res["final_risk_score"] == 85.0
