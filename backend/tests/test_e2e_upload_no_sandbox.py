"""
End-to-end: a benign APK through the synchronous upload API with NO sandbox.

What is real: the FastAPI route, upload validation, artifact storage, the
SQLite job/case tables, Androguard static analysis of a real benign APK
(tests/apks/BASE-07-BOI.apk, the project's own baseline banking UI build),
risk scoring, case persistence and PDF generation.

What is substituted: the analysis-engine microservice is reported unreachable
(`_call_analysis_engine` returns None, exactly as it does when the HTTP call
fails) so the gateway's local pipeline runs. No emulator exists on the test
host, so the sandbox status is genuinely "not ready" - this test is about
truthful behaviour when runtime telemetry is unavailable, and it never runs
the sample.
"""

import io
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(BACKEND))

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.auth.auth import require_analyst  # noqa: E402
from app.db.database import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routes import upload  # noqa: E402

APK = ROOT / "tests" / "apks" / "BASE-07-BOI.apk"


@pytest.mark.skipif(not APK.is_file(), reason="baseline APK not present")
async def test_benign_apk_without_sandbox_is_reported_truthfully(monkeypatch):
    async def engine_unreachable(*_a, **_k):
        return None

    await init_db()
    sys.path.insert(0, str(BACKEND / "tests"))
    from auth_helpers import ensure_user
    user = await ensure_user("e2e_no_sandbox_analyst")
    monkeypatch.setattr(upload, "_call_analysis_engine", engine_unreachable)
    monkeypatch.setenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", "true")
    app.dependency_overrides[require_analyst] = lambda: {"id": user["id"], "role": "analyst"}
    responses = []
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test",
                               timeout=300) as c:
            for _ in range(2):
                responses.append(await c.post(
                    "/api/v1/analyze",
                    files={"file": ("BASE-07-BOI.apk", APK.read_bytes(),
                                    "application/vnd.android.package-archive")},
                ))
    finally:
        app.dependency_overrides.pop(require_analyst, None)
    r = responses[0]

    # The endpoint used to raise UnboundLocalError on its first line.
    assert r.status_code == 200, r.text[:500]
    body = r.json()

    dyn = body.get("dynamic_analysis") or {}
    assert dyn.get("available") is False
    assert dyn.get("dynamic_status") == "EMULATOR_UNAVAILABLE"
    assert dyn.get("error"), "the reason dynamic analysis did not run must reach the API"

    frs = body.get("frs_breakdown") or {}
    # Missing telemetry is excluded from the score, never scored as clean.
    assert frs.get("dynamic_ran") is False
    assert frs.get("dynamic_exclusion_reason")
    assert "dynamic" in (frs.get("axes_excluded") or []) or frs.get("dynamic_conclusive") is False

    # Same verdict on a second identical submission: deterministic scoring.
    sha = body.get("sha256")
    assert sha and len(sha) == 64
    second = responses[1]
    assert second.status_code == 200, second.text[:300]
    again = second.json()
    assert again["sha256"] == sha
    for key in ("final_risk_score", "risk_band"):
        assert again.get(key) == body.get(key), key

    # Report generation from the persisted case discloses the gap.
    from sudarshan_core.engines.pdf_generator import build_pdf_report
    from pypdf import PdfReader

    case = dict(body)
    case.setdefault("dynamic_result", dyn)
    text = "\n".join(
        (p.extract_text() or "") for p in PdfReader(io.BytesIO(build_pdf_report(case))).pages
    )
    flat = text.replace("\n", " ")
    assert "EMULATOR_UNAVAILABLE" in flat
    # Regression: any non-empty dynamic dict used to count as "ran".
    assert "An instrumented run was performed" not in flat
    assert "not evidence of benign behaviour" in flat
