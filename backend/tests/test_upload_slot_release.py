"""
A rejected upload must release the job slot it reserved.

reserve_job_slot_atomically inserts the job as UPLOADING, and UPLOADING
counts toward MAX_QUEUE_DEPTH. Before the fix a rejected upload (not an
APK, bad magic, too large) left its row UPLOADING forever, so bad uploads
permanently consumed queue capacity.

Exercises the real route through ASGI with a real (temporary) database; the
analyst dependency is overridden, nothing else is mocked.
"""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.auth.auth import require_analyst  # noqa: E402
from app.db.database import _connect, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routes import upload  # noqa: E402

ANALYST_ID = 4242


@pytest.fixture
def client():
    app.dependency_overrides[require_analyst] = lambda: {"id": ANALYST_ID, "role": "analyst"}
    try:
        yield AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    finally:
        app.dependency_overrides.pop(require_analyst, None)


async def _uploading_rows() -> int:
    async with _connect() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM analysis_jobs WHERE analyst_id = ? AND status = 'UPLOADING'",
            (ANALYST_ID,),
        ) as cur:
            return (await cur.fetchone())[0]


@pytest.mark.parametrize("path", ["/api/v1/analyze/async", "/api/v1/analyze"])
@pytest.mark.parametrize("name,content,code", [
    ("evil.txt", b"PK\x03\x04data", 400),          # wrong extension
    ("sample.apk", b"MZ\x90\x00not-a-zip", 400),     # bad magic
    ("sample.apk", b"", 400),                        # empty
])
async def test_rejected_upload_releases_reserved_slot(client, path, name, content, code):
    await init_db()
    before = await _uploading_rows()
    async with client as c:
        r = await c.post(path, files={"file": (name, content, "application/octet-stream")})
    assert r.status_code == code, r.text
    assert await _uploading_rows() == before, "rejected upload left an UPLOADING row"


async def test_oversized_upload_releases_slot(client, monkeypatch):
    await init_db()
    monkeypatch.setattr(upload, "MAX_UPLOAD_BYTES", 16)
    before = await _uploading_rows()
    async with client as c:
        r = await c.post("/api/v1/analyze/async",
                         files={"file": ("big.apk", b"PK\x03\x04" + b"x" * 64, "application/octet-stream")})
    assert r.status_code == 413
    assert await _uploading_rows() == before


def test_dynamic_exception_becomes_structured_failure():
    out = upload._dynamic_failure_result(TimeoutError("device lock wait exceeded"))
    assert out["available"] is False
    assert out["runtime_attempted"] is True
    assert out["dynamic_status"] == "FAILED"
    assert "TimeoutError" in out["error"]
    from sudarshan_core.engines.risk_engine import dynamic_exclusion_reason
    # Excluded from scoring with its real reason - never read as "clean".
    assert dynamic_exclusion_reason(out) == "FAILED"
