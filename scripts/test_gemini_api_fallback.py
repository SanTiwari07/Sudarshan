#!/usr/bin/env python3
"""
Sudarshan Gemini primary → fallback verification.

Default (--mock): simulated failures only; no real quota consumption.
Optional (--real): one minimal request per configured provider for connectivity.

Exit codes:
  0 — required checks passed
  1 — one or more required checks failed
  2 — configuration / setup problem
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
_BACKEND = _ROOT / "backend"
for _p in (_SHARED, _BACKEND):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from sudarshan_core.ai.gemini_errors import (  # noqa: E402
    GeminiAllProvidersFailed,
    GeminiNonRetryableError,
    classify_gemini_error,
    is_fallback_eligible_error,
    redact_secrets,
)
from sudarshan_core.ai.gemini_provider import (  # noqa: E402
    GeminiProviderManager,
    reset_gemini_manager,
)
from sudarshan_core.ai.gemini_settings import (  # noqa: E402
    GeminiProviderSpec,
    GeminiSettings,
    load_gemini_settings,
)


def _load_repo_dotenv() -> None:
    env_file = _ROOT / ".env"
    if not env_file.is_file():
        return
    try:
        from dotenv import load_dotenv

        load_dotenv(dotenv_path=env_file, override=False)
    except ImportError:
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val


# ---------------------------------------------------------------------------
# Mock SDK
# ---------------------------------------------------------------------------


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

    def generate_content_stream(self, **kwargs):
        result = self._owner._next(**kwargs)
        if isinstance(result, list):
            return iter(result)
        return iter([result])


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.kwargs: list[dict] = []
        self.models = FakeModels(self)

    def _next(self, **kwargs):
        self.calls += 1
        self.kwargs.append(kwargs)
        if not self.script:
            raise RuntimeError("unexpected Gemini call")
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


def _manager(
    clients: dict[str, FakeClient],
    settings: GeminiSettings | None = None,
    clock: Callable[[], float] | None = None,
) -> GeminiProviderManager:
    def factory(api_key: str) -> FakeClient:
        return clients[api_key]

    return GeminiProviderManager(
        settings or _settings(),
        client_factory=factory,
        clock=clock or (lambda: 0.0),
        sleeper=lambda _s: None,
    )


class CheckResult:
    __slots__ = ("name", "passed", "detail")

    def __init__(self, name: str, passed: bool, detail: str = ""):
        self.name = name
        self.passed = passed
        self.detail = detail


# ---------------------------------------------------------------------------
# Architecture audit (static)
# ---------------------------------------------------------------------------

EXPECTED_CONSUMERS = [
    _BACKEND / "app" / "ai" / "gemini_client.py",
    _BACKEND / "app" / "ai" / "gemini_rag.py",
    _SHARED / "sudarshan_core" / "engines" / "agentic" / "planner.py",
    _SHARED / "sudarshan_core" / "engines" / "ui_explorer.py",
    _SHARED / "sudarshan_core" / "engines" / "agentic" / "caption_generator.py",
    _SHARED / "sudarshan_core" / "engines" / "vide" / "semantic_matcher.py",
]

MANAGER_FILE = _SHARED / "sudarshan_core" / "ai" / "gemini_provider.py"


def _file_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def audit_architecture() -> Tuple[List[CheckResult], Dict[str, Any]]:
    results: List[CheckResult] = []
    info: Dict[str, Any] = {"bypasses": []}

    results.append(
        CheckResult(
            "Centralized Client",
            MANAGER_FILE.is_file(),
            str(MANAGER_FILE),
        )
    )

    settings = load_gemini_settings()
    settings_src = _file_text(_SHARED / "sudarshan_core" / "ai" / "gemini_settings.py")
    provider_src = _file_text(MANAGER_FILE) if MANAGER_FILE.is_file() else ""

    results.append(
        CheckResult(
            "Primary Provider",
            "GEMINI_PRIMARY_API_KEY" in settings_src and 'role="primary"' in settings_src,
            "settings loader supports primary slot",
        )
    )
    results.append(
        CheckResult(
            "Fallback Provider",
            "GEMINI_FALLBACK_API_KEY" in settings_src and 'role="fallback"' in settings_src,
            "settings loader supports fallback slot",
        )
    )
    results.append(
        CheckResult(
            "Failure Classification",
            "classify_gemini_error" in provider_src and "_NeedFallback" in provider_src,
        )
    )
    results.append(
        CheckResult(
            "Retry Logic",
            "max_retries" in provider_src and "retry_base_seconds" in provider_src,
        )
    )
    results.append(
        CheckResult(
            "Circuit Breaker",
            "CircuitState" in provider_src and "_open_circuit" in provider_src,
        )
    )
    results.append(
        CheckResult(
            "Cooldown",
            "cooldown_seconds" in provider_src and "open_until" in provider_src,
        )
    )

    routed = 0
    for path in EXPECTED_CONSUMERS:
        if not path.is_file():
            results.append(CheckResult(f"Consumer exists: {path.name}", False, "missing"))
            continue
        text = _file_text(path)
        uses_manager = "get_gemini_manager" in text
        if uses_manager:
            routed += 1
        else:
            results.append(CheckResult(f"Routes via manager: {path.name}", False))
        if "genai.Client(" in text and path != MANAGER_FILE:
            info["bypasses"].append(str(path.relative_to(_ROOT)))

    # caption_generator allows injected client for tests only
    cap = _SHARED / "sudarshan_core" / "engines" / "agentic" / "caption_generator.py"
    if cap.is_file():
        cap_text = _file_text(cap)
        if "client is None" in cap_text and "get_gemini_manager" in cap_text:
            routed += 0  # already counted
        if "client.models.generate_content" in cap_text:
            info["bypasses"].append(
                "shared/sudarshan_core/engines/agentic/caption_generator.py "
                "(only when optional `client` test hook is injected)"
            )

    results.append(
        CheckResult(
            "All Gemini callers routed",
            routed == len(EXPECTED_CONSUMERS),
            f"{routed}/{len(EXPECTED_CONSUMERS)} use get_gemini_manager",
        )
    )

    # Hardcoded keys scan (simple pattern)
    hardcoded = []
    for py in _ROOT.rglob("*.py"):
        if "test_" in py.name or py.parts[-2:] == ("scripts", "test_gemini_api_fallback.py"):
            continue
        try:
            text = py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "AIzaSy" in text and ".env" not in py.name:
            hardcoded.append(str(py.relative_to(_ROOT)))
    results.append(
        CheckResult("API key security (no hardcoded keys)", len(hardcoded) == 0, ", ".join(hardcoded[:3])),
    )

    info["settings"] = settings
    return results, info


# ---------------------------------------------------------------------------
# Mock behaviour tests
# ---------------------------------------------------------------------------


def run_mock_behavior_tests() -> Tuple[List[CheckResult], List[str]]:
    results: List[CheckResult] = []
    lines: List[str] = []
    reset_gemini_manager(None)

    # TEST 1 — primary success
    primary = FakeClient([_ok("PRIMARY_SUCCESS")])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    mgr = _manager({"primary-key": primary, "fallback-key": fallback})
    r = mgr.generate_content(contents="hello")
    ok = (
        r.text == "PRIMARY_SUCCESS"
        and primary.calls == 1
        and fallback.calls == 0
        and r.provider == "primary"
    )
    results.append(CheckResult("Primary Success", ok))
    if ok:
        lines.append("[PASS] Primary success uses primary provider only")

    # TEST 2 — 429 / quota
    primary = FakeClient([FakeHTTPError("429 RESOURCE_EXHAUSTED quota", 429)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    mgr = _manager({"primary-key": primary, "fallback-key": fallback}, _settings(max_retries=1))
    r = mgr.generate_content(contents="hello")
    ok = r.text == "FALLBACK_SUCCESS" and primary.calls >= 1 and fallback.calls == 1
    results.append(CheckResult("429 → Fallback", ok))
    if ok:
        lines.append("[PASS] Primary quota exhaustion triggers fallback")

    # TEST 3 — 503 with retries
    primary = FakeClient([FakeHTTPError("503 UNAVAILABLE", 503)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    mgr = _manager(
        {"primary-key": primary, "fallback-key": fallback},
        _settings(max_retries=2),
    )
    r = mgr.generate_content(contents="hello")
    ok = (
        r.text == "FALLBACK_SUCCESS"
        and primary.calls == 2
        and fallback.calls == 1
        and r.fallback_used
    )
    results.append(CheckResult("503 → Fallback", ok, f"primary_calls={primary.calls}"))
    if ok:
        lines.append("[PASS] Primary 503 triggers fallback")

    # TEST 4 — non-fallback error
    primary = FakeClient([FakeHTTPError("400 INVALID_ARGUMENT unknown field", 400)])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS")])
    mgr = _manager({"primary-key": primary, "fallback-key": fallback})
    caught = False
    try:
        mgr.generate_content(contents="bad")
    except GeminiNonRetryableError:
        caught = True
    ok = caught and fallback.calls == 0 and primary.calls == 1
    results.append(CheckResult("Invalid Request", ok))
    if ok:
        lines.append("[PASS] Non-fallback error does not unnecessarily switch provider")

    # TEST 5 — both fail
    primary = FakeClient([FakeHTTPError("429 quota", 429)])
    fallback = FakeClient([FakeHTTPError("503 UNAVAILABLE", 503)])
    mgr = _manager({"primary-key": primary, "fallback-key": fallback}, _settings(max_retries=1))
    exc_msg = ""
    both_ok = False
    try:
        mgr.generate_content(contents="x")
    except GeminiAllProvidersFailed as exc:
        exc_msg = str(exc)
        both_ok = (
            primary.calls >= 1
            and fallback.calls >= 1
            and "primary-key" not in exc_msg
            and "fallback-key" not in exc_msg
            and exc.fallback_used
        )
    results.append(CheckResult("Both Providers Fail", both_ok))
    if both_ok:
        lines.append("[PASS] Both providers fail gracefully")

    # TEST 6 — cooldown
    now = [100.0]
    primary = FakeClient([FakeHTTPError("429 RESOURCE_EXHAUSTED", 429), _ok("PRIMARY_PROBE")])
    fallback = FakeClient([_ok("FALLBACK_SUCCESS"), _ok("FALLBACK_AGAIN")])
    mgr = _manager(
        {"primary-key": primary, "fallback-key": fallback},
        _settings(max_retries=1, cooldown_seconds=60.0),
        clock=lambda: now[0],
    )
    first = mgr.generate_content(contents="a")
    calls_after_first = primary.calls
    second = mgr.generate_content(contents="b")
    cooldown_ok = (
        first.fallback_used
        and second.provider == "fallback"
        and primary.calls == calls_after_first
    )
    results.append(CheckResult("Cooldown", cooldown_ok))
    if cooldown_ok:
        lines.append("[PASS] Primary cooldown prevents repeated failed primary requests")

    # TEST 7 — cooldown recovery
    now[0] = 161.0
    third = mgr.generate_content(contents="c")
    recovery_ok = third.provider == "primary" and third.text == "PRIMARY_PROBE"
    results.append(CheckResult("Cooldown Recovery", recovery_ok))
    if recovery_ok:
        lines.append("[PASS] Primary becomes eligible after cooldown")

    # TEST 8 — concurrency
    barrier = threading.Barrier(8)
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

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    conc_ok = errors == [] and fallback.calls == 8
    leak = any("primary-key" in str(e) or "fallback-key" in str(e) for e in errors)
    results.append(CheckResult("Concurrency", conc_ok and not leak))
    if conc_ok:
        lines.append("[PASS] Concurrent provider state remains consistent")

    # Classification spot-checks
    results.append(
        CheckResult(
            "Failure Classification (429)",
            is_fallback_eligible_error(FakeHTTPError("429 RESOURCE_EXHAUSTED", 429)),
        )
    )
    results.append(
        CheckResult(
            "Failure Classification (503)",
            is_fallback_eligible_error(FakeHTTPError("503 UNAVAILABLE", 503)),
        )
    )
    results.append(
        CheckResult(
            "Failure Classification (invalid)",
            not is_fallback_eligible_error(FakeHTTPError("400 INVALID_ARGUMENT", 400)),
        )
    )

    reset_gemini_manager(None)
    return results, lines


# ---------------------------------------------------------------------------
# Real API health (--real)
# ---------------------------------------------------------------------------


def run_real_health() -> Tuple[List[CheckResult], str, str]:
    results: List[CheckResult] = []
    settings = load_gemini_settings()
    if not settings.configured:
        return [CheckResult("Real API configuration", False, "no keys in environment")], "FAIL", "FAIL"

    try:
        from google import genai  # noqa: F401
    except ImportError:
        return [CheckResult("google-genai installed", False)], "FAIL", "FAIL"

    primary_status = "SKIP"
    fallback_status = "SKIP"

    async def _ping(spec: GeminiProviderSpec, label: str) -> CheckResult:
        try:
            client = genai.Client(api_key=spec.api_key)
            resp = await asyncio.to_thread(
                client.models.generate_content,
                model=spec.model,
                contents=f"Reply with exactly: {label}_OK",
            )
            text = (getattr(resp, "text", "") or "").strip()
            ok = f"{label}_OK" in text or len(text) > 0
            safe_err = redact_secrets(text)
            return CheckResult(
                f"Real {label}",
                ok,
                f"model={spec.model} response={safe_err[:80]}",
            )
        except Exception as exc:
            return CheckResult(
                f"Real {label}",
                False,
                redact_secrets(f"{type(exc).__name__}: {exc}"),
            )

    async def _run_all():
        out: List[CheckResult] = []
        if settings.primary:
            out.append(await _ping(settings.primary, "PRIMARY"))
        if settings.fallback:
            out.append(await _ping(settings.fallback, "FALLBACK"))
        return out

    ping_results = asyncio.run(_run_all())
    results.extend(ping_results)

    for pr in ping_results:
        if pr.name == "Real PRIMARY":
            primary_status = "PASS" if pr.passed else "FAIL"
        if pr.name == "Real FALLBACK":
            fallback_status = "PASS" if pr.passed else "FAIL"

    return results, primary_status, fallback_status


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _line(title: str) -> None:
    print(title)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Sudarshan Gemini failover")
    parser.add_argument(
        "--real",
        action="store_true",
        help="Also run one minimal live request per configured provider (default: mock only)",
    )
    args = parser.parse_args(argv)

    _load_repo_dotenv()

    print("=" * 50)
    print(" SUDARSHAN GEMINI FALLBACK VERIFICATION")
    print("=" * 50)
    print()

    settings = load_gemini_settings()
    print("Configuration")
    print("-------------")
    print(f"Mode            : {settings.mode}")
    print(f"Primary Model   : {settings.primary.model if settings.primary else '(none)'}")
    print(f"Fallback Model  : {settings.fallback.model if settings.fallback else '(none)'}")
    print(f"Cooldown (s)    : {settings.cooldown_seconds}")
    print(f"Max Retries     : {settings.max_retries}")
    print()

    arch_results, arch_info = audit_architecture()
    print("Architecture")
    print("------------")
    for chk in arch_results:
        status = "PASS" if chk.passed else "FAIL"
        detail = f" — {chk.detail}" if chk.detail else ""
        print(f"{chk.name:<28}: {status}{detail}")
    if arch_info.get("bypasses"):
        print()
        print("Direct-client bypass notes:")
        for note in arch_info["bypasses"]:
            print(f"  - {note}")
    print()

    mock_results, pass_lines = run_mock_behavior_tests()
    print("Behavior Tests (mocked)")
    print("-----------------------")
    for chk in mock_results:
        status = "PASS" if chk.passed else "FAIL"
        detail = f" — {chk.detail}" if chk.detail else ""
        print(f"{chk.name:<28}: {status}{detail}")
    print()
    for line in pass_lines:
        print(line)
    print()

    primary_real = "SKIP"
    fallback_real = "SKIP"
    real_results: List[CheckResult] = []
    if args.real:
        if not settings.configured:
            print("Real API Health (--real)")
            print("------------------------")
            print("SKIP — no GEMINI_PRIMARY_API_KEY / GEMINI_FALLBACK_API_KEY in .env")
            print()
            return 2
        print("Real API Health (--real)")
        print("------------------------")
        real_results, primary_real, fallback_real = run_real_health()
        for chk in real_results:
            status = "PASS" if chk.passed else "FAIL"
            detail = f" — {chk.detail}" if chk.detail else ""
            print(f"{chk.name:<28}: {status}{detail}")
        print()
        print(
            "Real API connectivity verified where PASS; quota-exhaustion failover "
            "was NOT intentionally triggered (mock tests prove that path)."
        )
        print()

    required = arch_results + mock_results
    if args.real:
        required = required + real_results

    failed = [c for c in required if not c.passed]
    passed = len(required) - len(failed)

    print("=" * 50)
    if failed:
        print("RESULT: GEMINI FALLBACK NOT FULLY VERIFIED")
        print()
        print("Failures:")
        for f in failed:
            print(f"- {f.name}" + (f" ({f.detail})" if f.detail else ""))
    else:
        print("RESULT: GEMINI FALLBACK VERIFIED")
    print("=" * 50)
    print(f"Summary: {passed}/{len(required)} checks passed")
    if args.real:
        print(f"Real API — Primary: {primary_real}, Fallback: {fallback_real}")

    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
