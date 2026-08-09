"""
Regression tests for the planner action cache.

Root defect: `_ACTION_CACHE` was a module-level dict, never cleared and never
bounded, keyed only on `(screen_hash, goal_name)`. Because `screen_hash` does
not include the package name, an action cached while analysing one APK could be
served to a completely different APK - with no LLM call and no audit trail.
In a long-lived FastAPI worker the dict also grew forever.

The cache is now per-instance, package- and version-scoped, and LRU-bounded.
"""

import pytest

from sudarshan_core.engines.agentic.planner import (
    ACTION_CACHE_MAX_ENTRIES,
    PLANNER_VERSION,
    AgentPlanner,
)


def _planner(package="com.a.app"):
    # api_key=None keeps the Gemini client uninitialised; the cache is
    # independent of the LLM transport.
    return AgentPlanner(
        api_key=None, device_serial="emulator-5554",
        package_name=package, action_budget=25,
    )


ACTION = {"tool": "tap", "x": 10, "y": 20, "goal": "g", "reasoning": "r", "confidence": 0.9}


# ─── Isolation ────────────────────────────────────────────────────────────────

def test_cache_is_per_instance_not_module_level():
    a, b = _planner(), _planner()
    a._cache_put(a._cache_key("screen1", "goal1"), ACTION)
    assert a.cache_size == 1
    assert b.cache_size == 0, "cache leaked across planner instances"


def test_no_cross_package_bleed_on_identical_screen_hash():
    """
    The exact defect: same screen_hash + same goal, different APK.
    Before the fix this returned APK A's action to APK B.
    """
    a = _planner("com.bank.real")
    b = _planner("com.malware.fake")
    a._cache_put(a._cache_key("SHARED_HASH", "Login Flow"), ACTION)
    assert b._cache_get(b._cache_key("SHARED_HASH", "Login Flow")) is None


def test_package_is_part_of_the_key():
    p = _planner("com.x")
    assert p._cache_key("h", "g")[0] == "com.x"


def test_planner_version_is_part_of_the_key():
    p = _planner()
    assert PLANNER_VERSION in p._cache_key("h", "g")


def test_version_change_invalidates_entries(monkeypatch):
    p = _planner()
    p._cache_put(p._cache_key("h", "g"), ACTION)
    assert p._cache_get(p._cache_key("h", "g")) is not None

    monkeypatch.setattr("sudarshan_core.engines.agentic.planner.PLANNER_VERSION", "999")
    assert p._cache_get(p._cache_key("h", "g")) is None, "stale planner version served"


# ─── Hit / miss ───────────────────────────────────────────────────────────────

def test_cache_hit_returns_stored_action():
    p = _planner()
    key = p._cache_key("h", "g")
    p._cache_put(key, ACTION)
    assert p._cache_get(key)["tool"] == "tap"


def test_cache_miss_returns_none():
    p = _planner()
    assert p._cache_get(p._cache_key("never", "stored")) is None


def test_cache_returns_defensive_copy():
    """A caller mutating the result must not corrupt the cached entry."""
    p = _planner()
    key = p._cache_key("h", "g")
    p._cache_put(key, ACTION)
    p._cache_get(key)["tool"] = "MUTATED"
    assert p._cache_get(key)["tool"] == "tap"


def test_stored_entry_is_decoupled_from_caller_dict():
    p = _planner()
    mutable = dict(ACTION)
    key = p._cache_key("h", "g")
    p._cache_put(key, mutable)
    mutable["tool"] = "MUTATED"
    assert p._cache_get(key)["tool"] == "tap"


# ─── Bounding / LRU ───────────────────────────────────────────────────────────

def test_cache_is_bounded():
    """A hostile app can mint unlimited unique screens - memory must not grow."""
    p = _planner()
    for i in range(ACTION_CACHE_MAX_ENTRIES * 3):
        p._cache_put(p._cache_key(f"screen{i}", "goal"), ACTION)
    assert p.cache_size <= ACTION_CACHE_MAX_ENTRIES


def test_lru_evicts_oldest_first():
    p = _planner()
    first = p._cache_key("screen0", "goal")
    p._cache_put(first, ACTION)
    for i in range(1, ACTION_CACHE_MAX_ENTRIES + 1):
        p._cache_put(p._cache_key(f"screen{i}", "goal"), ACTION)
    assert p._cache_get(first) is None, "least-recently-used entry survived eviction"


def test_recent_use_protects_entry_from_eviction():
    p = _planner()
    keep = p._cache_key("keepme", "goal")
    p._cache_put(keep, ACTION)
    for i in range(ACTION_CACHE_MAX_ENTRIES - 1):
        p._cache_put(p._cache_key(f"s{i}", "goal"), ACTION)
        p._cache_get(keep)                     # keep refreshing it
    p._cache_put(p._cache_key("overflow", "goal"), ACTION)
    assert p._cache_get(keep) is not None


# ─── Invalidation ─────────────────────────────────────────────────────────────

def test_failed_action_invalidates_every_goal_on_that_screen():
    p = _planner()
    p._cache_put(p._cache_key("screenX", "goal1"), ACTION)
    p._cache_put(p._cache_key("screenX", "goal2"), ACTION)
    p._cache_put(p._cache_key("screenY", "goal1"), ACTION)

    removed = p.invalidate_cache_for_screen("screenX")
    assert removed == 2
    assert p._cache_get(p._cache_key("screenX", "goal1")) is None
    assert p._cache_get(p._cache_key("screenY", "goal1")) is not None


def test_invalidating_unknown_screen_is_a_noop():
    p = _planner()
    p._cache_put(p._cache_key("a", "g"), ACTION)
    assert p.invalidate_cache_for_screen("does-not-exist") == 0
    assert p.cache_size == 1


# ─── Concurrency ──────────────────────────────────────────────────────────────

def test_concurrent_writes_do_not_corrupt_the_cache():
    """Two analyses hitting one planner must not break the LRU invariant."""
    import threading

    p = _planner()
    errors = []

    def hammer(offset):
        try:
            for i in range(200):
                k = p._cache_key(f"s{offset}_{i}", "goal")
                p._cache_put(k, ACTION)
                p._cache_get(k)
        except Exception as exc:                     # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent access raised: {errors}"
    assert p.cache_size <= ACTION_CACHE_MAX_ENTRIES
