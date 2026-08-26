"""
Test helpers for minting usable auth tokens.

Tokens are now bound to a row in `sessions`: `get_current_user` rejects a token
whose jti has no live session, which is what makes server-side logout work. A
test that calls `create_access_token()` directly therefore gets a 401.

These helpers mint a token the way the login route does - user row plus session
row - so tests exercise the real authentication path instead of a bypass.
"""

from __future__ import annotations

import asyncio
from typing import Dict

from app.auth.auth import issue_session_token
from app.db.database import create_user, get_user_by_id, get_user_by_username, init_db


async def ensure_user(username: str, role: str = "analyst") -> dict:
    """Return the named user, creating it if absent."""
    await init_db()
    user = await get_user_by_username(username)
    if user is None:
        await create_user(username, "not-a-real-hash", role=role)
        user = await get_user_by_username(username)
    return user


async def auth_headers(username: str = "testanalyst", role: str = "analyst") -> Dict[str, str]:
    """Authorization header for a real, session-backed token."""
    user = await ensure_user(username, role)
    token = await issue_session_token(user)
    return {"Authorization": f"Bearer {token}"}


def auth_headers_sync(username: str = "testanalyst", role: str = "analyst") -> Dict[str, str]:
    """Blocking variant, for tests driving the app through TestClient."""
    return asyncio.run(auth_headers(username, role))


async def auth_headers_for_id(user_id: int, role: str = "analyst") -> Dict[str, str]:
    """
    Header for an existing user id.

    Falls back to creating a user when the id is absent, because several tests
    assume "user 1" exists without ever inserting it.
    """
    await init_db()
    user = await get_user_by_id(user_id)
    if user is None:
        user = await ensure_user(f"user{user_id}", role)
    token = await issue_session_token(user)
    return {"Authorization": f"Bearer {token}"}
