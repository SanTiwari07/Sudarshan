"""
Without an injected persistent cache (the analysis-engine case), a provider
answer - including a 404 "not in database" - must not be re-fetched within TTL.
"""

import asyncio

import httpx

from sudarshan_core.services import threat_correlator as tc


class _Resp:
    status_code = 404

    def raise_for_status(self):
        return None

    def json(self):
        return {}


def test_vt_hash_404_is_cached_in_process(monkeypatch):
    monkeypatch.setattr(tc, "_cache_get", None)
    monkeypatch.setattr(tc, "_cache_put", None)
    monkeypatch.setattr(tc, "_MEM_CACHE", {})
    monkeypatch.setattr(tc, "_get_vt_key", lambda: "k")
    calls = {"n": 0}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            calls["n"] += 1
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    sha = "a" * 64
    first = asyncio.run(tc._vt_check_hash(sha))
    second = asyncio.run(tc._vt_check_hash(sha))
    assert first == second == {"found": False, "in_database": False}
    assert calls["n"] == 1


def test_memory_cache_expires(monkeypatch):
    monkeypatch.setattr(tc, "_MEM_CACHE", {})
    tc._mem_put("x", "t", {"v": 1})
    assert tc._mem_get("x", "t") == {"v": 1}
    tc._MEM_CACHE[("x", "t")] = (0.0, {"v": 1})
    assert tc._mem_get("x", "t") is None


def test_sentences_are_reduced_to_their_url_before_lookup():
    assert tc._indicator_from_string(
        ") Please report to Google or use https://goo.gle/compose-feedback"
    ) == "https://goo.gle/compose-feedback"
    assert tc._indicator_from_string("connect to 10.0.0.5 now") == "10.0.0.5"
    assert tc._indicator_from_string("Kotlin reflection is not yet supported.") is None
    assert tc._indicators(["evil.example.com", "evil.example.com"]) == ["evil.example.com"]
