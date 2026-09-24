"""Screenshot API path resolution and auth."""

import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from app.routes.screenshots import _resolve_image_path  # noqa: E402


def test_resolve_image_path_under_artifact_dir(tmp_path):
    shots = tmp_path / "screenshots"
    shots.mkdir()
    png = shots / "001_test.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n")

    resolved = _resolve_image_path(tmp_path, "screenshots/001_test.png")
    assert resolved == png.resolve()

    resolved2 = _resolve_image_path(tmp_path, "001_test.png")
    assert resolved2 == png.resolve()


def test_resolve_rejects_traversal(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    with pytest.raises(HTTPException):
        _resolve_image_path(tmp_path, "../etc/passwd")


@pytest.mark.anyio
async def test_screenshot_endpoint_requires_auth():
    from httpx import ASGITransport, AsyncClient
    from app.main import app

    transport = ASGITransport(app=app)
    sha = "a" * 64
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(f"/api/v1/screenshots/{sha}/001.png")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_screenshot_endpoint_serves_file(tmp_path, monkeypatch):
    from httpx import ASGITransport, AsyncClient
    from app.main import app
    from app.auth.auth import hash_password
    from app.db import database as db

    monkeypatch.setenv("UPLOADS_DIR", str(tmp_path))

    sha = "b" * 64
    artifact = tmp_path / "artifacts"
    
    # Place file where LocalArtifactStorage will look for it
    storage_path = tmp_path / "evidence" / sha / "screenshots"
    storage_path.mkdir(parents=True, exist_ok=True)
    png = storage_path / "001_demo.png"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 8)

    fake_report = {
        "sha256": sha,
        "dynamic_result": {
            "artifact_dir": str(artifact),
            "screenshots": ["screenshots/001_demo.png"],
        },
    }

    async def _auth_case(_sha, _user):
        if _sha != sha:
            raise HTTPException(status_code=404, detail="Case not found.")
        return fake_report

    monkeypatch.setattr("app.routes.screenshots.get_authorized_case", _auth_case)

    await db.init_db()
    if not await db.username_exists("shot_tester"):
        await db.create_user("shot_tester", hash_password("password123"), "analyst")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        login = await ac.post(
            "/api/v1/auth/login",
            json={"username": "shot_tester", "password": "password123"},
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        resp = await ac.get(
            f"/api/v1/screenshots/{sha}/001_demo.png",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/")
    assert b"PNG" in resp.content
