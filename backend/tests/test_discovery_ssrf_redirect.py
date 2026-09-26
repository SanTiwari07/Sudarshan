"""
SSRF: a redirect from a public host to an internal address must be refused.

Regression: the check lived in AsyncClient.send(), which httpx does not
re-enter for followed redirects, so `302 -> http://127.0.0.1/` was fetched.
HTTPS fetches also failed outright because the pinned IP was used for SNI.
"""

import asyncio
import socket

import httpx
import pytest
from fastapi import HTTPException

from app.services.discovery import security


def _fake_getaddrinfo(host, *a, **k):
    table = {"public.example": "93.184.216.34", "127.0.0.1": "127.0.0.1"}
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table.get(host, "93.184.216.34"), 0))]


def test_redirect_to_loopback_is_blocked(monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", _fake_getaddrinfo)
    seen = []

    async def fake_upstream(self, request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/internal"}, request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fake_upstream)

    async def run():
        async with security.SSRFSafeAsyncClient() as client:
            await client.get("http://public.example/", follow_redirects=True)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(run())
    assert exc.value.status_code == 403
    assert len(seen) == 1  # the internal hop never left the process


def test_https_request_keeps_real_hostname_for_tls(monkeypatch):
    monkeypatch.setattr(security.socket, "getaddrinfo", _fake_getaddrinfo)
    seen = []

    async def fake_upstream(self, request):
        seen.append(request)
        return httpx.Response(200, request=request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fake_upstream)

    async def run():
        async with security.SSRFSafeAsyncClient() as client:
            return await client.get("https://public.example/x")

    resp = asyncio.run(run())
    assert resp.status_code == 200
    sent = seen[0]
    assert sent.url.host == "93.184.216.34"
    assert sent.extensions.get("sni_hostname") == "public.example"
    assert sent.headers["host"] == "public.example"
