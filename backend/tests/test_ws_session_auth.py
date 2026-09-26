"""
The resilience WebSocket must enforce the same session checks as REST routes.

Regression: the handshake used to verify only the JWT signature, so a token
revoked by logout (or belonging to a disabled account) could keep streaming
live analysis events until it expired.
"""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.auth.auth import issue_session_token
from app.db.security import revoke_session
from app.routes import resilience
from auth_helpers import ensure_user
from jose import jwt


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(resilience.router, prefix="/api/v1")
    return app


async def _token(username: str) -> str:
    user = await ensure_user(username)
    return await issue_session_token(user)


def test_ws_accepts_live_session():
    token = asyncio.run(_token("ws_live_user"))
    with TestClient(_app()) as client:
        with client.websocket_connect(f"/api/v1/analysis/s1/events/ws?token={token}"):
            pass  # accepted


def test_ws_rejects_revoked_session():
    token = asyncio.run(_token("ws_revoked_user"))
    jti = jwt.get_unverified_claims(token)["jti"]
    asyncio.run(revoke_session(jti, revoked_by=None, reason="test"))
    with TestClient(_app()) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/api/v1/analysis/s1/events/ws?token={token}") as ws:
                ws.receive_json()
        assert exc.value.code == 4401


def test_ws_rejects_missing_token():
    with TestClient(_app()) as client:
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/api/v1/analysis/s1/events/ws") as ws:
                ws.receive_json()
        assert exc.value.code == 4401
