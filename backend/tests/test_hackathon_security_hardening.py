"""Hackathon security hardening: registration, case scope, production checks, upload limits."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")
os.environ.setdefault("SUDARSHAN_RATE_LIMIT_DISABLED", "true")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from app.registration_policy import (  # noqa: E402
    public_registration_allowed,
    registration_env_explicitly_set,
)


# ─── Registration policy ───────────────────────────────────────────────────────


def test_registration_allowed_by_default_in_development(monkeypatch):
    monkeypatch.delenv("SUDARSHAN_ENV", raising=False)
    monkeypatch.delenv("SUDARSHAN_ALLOW_REGISTRATION", raising=False)
    assert public_registration_allowed() is True


def test_registration_disabled_by_default_in_production(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.delenv("SUDARSHAN_ALLOW_REGISTRATION", raising=False)
    assert public_registration_allowed() is False
    assert registration_env_explicitly_set() is False


def test_registration_enabled_when_explicitly_set_in_production(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("SUDARSHAN_ALLOW_REGISTRATION", "true")
    assert public_registration_allowed() is True


# ─── HTTP register endpoint ────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_register_returns_403_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.delenv("SUDARSHAN_ALLOW_REGISTRATION", raising=False)
    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(tmp_path / "t.db"))
    from app.db import database as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))

    from httpx import ASGITransport, AsyncClient
    from app.main import app

    await db.init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/auth/register",
            json={"username": "newuser1", "password": "password123"},
        )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Public registration is disabled."


@pytest.mark.anyio
async def test_register_succeeds_when_enabled(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDARSHAN_ENV", raising=False)
    monkeypatch.setenv("SUDARSHAN_ALLOW_REGISTRATION", "true")
    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(tmp_path / "t2.db"))
    from app.db import database as db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t2.db"))

    from httpx import ASGITransport, AsyncClient
    from app.main import app

    await db.init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post(
            "/api/v1/auth/register",
            json={"username": "enabled_user", "password": "password123"},
        )
    assert resp.status_code == 201
    assert resp.json()["username"] == "enabled_user"


# ─── Case visibility ───────────────────────────────────────────────────────────


async def _token_for(username: str, password: str, monkeypatch, db_path: Path) -> str:
    from httpx import ASGITransport, AsyncClient
    from app.db import database as db
    from app.main import app
    from app.auth.auth import hash_password

    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(db_path))
    await db.init_db()
    if not await db.username_exists(username):
        role = "admin" if username == "admin_vis" else (
            "soc_lead" if username == "soc_vis" else "analyst"
        )
        await db.create_user(username, hash_password(password), role)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        login = await ac.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
    assert login.status_code == 200
    return login.json()["access_token"]


@pytest.mark.anyio
async def test_analyst_only_sees_own_cases(monkeypatch, tmp_path):
    from httpx import ASGITransport, AsyncClient
    from app.db import database as db
    from app.main import app
    from app.auth.auth import hash_password

    db_path = tmp_path / "cases.db"
    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    await db.init_db()

    await db.create_user("analyst_a", hash_password("password123"), "analyst")
    await db.create_user("analyst_b", hash_password("password123"), "analyst")
    user_a = await db.get_user_by_username("analyst_a")
    user_b = await db.get_user_by_username("analyst_b")

    await db.save_case("a" * 64, {"package_name": "com.a", "sha256": "a" * 64}, analyst_id=user_a["id"])
    await db.save_case("b" * 64, {"package_name": "com.b", "sha256": "b" * 64}, analyst_id=user_b["id"])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        login_a = await ac.post("/api/v1/auth/login", json={"username": "analyst_a", "password": "password123"})
        token_a = login_a.json()["access_token"]
        list_a = await ac.get("/api/v1/cases", headers={"Authorization": f"Bearer {token_a}"})
        assert list_a.status_code == 200
        body = list_a.json()
        assert body["total"] == 1
        assert body["cases"][0]["sha256"] == "a" * 64

        other = await ac.get(f"/api/v1/cases/{'b' * 64}", headers={"Authorization": f"Bearer {token_a}"})
        assert other.status_code == 404


@pytest.mark.anyio
async def test_admin_and_soc_lead_see_all_cases(monkeypatch, tmp_path):
    from httpx import ASGITransport, AsyncClient
    from app.db import database as db
    from app.main import app
    from app.auth.auth import hash_password

    db_path = tmp_path / "cases2.db"
    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    await db.init_db()

    await db.create_user("analyst_x", hash_password("password123"), "analyst")
    await db.create_user("admin_vis", hash_password("password123"), "admin")
    await db.create_user("soc_vis", hash_password("password123"), "soc_lead")
    ax = await db.get_user_by_username("analyst_x")

    await db.save_case("c" * 64, {"package_name": "com.c", "sha256": "c" * 64}, analyst_id=ax["id"])
    await db.save_case("d" * 64, {"package_name": "com.d", "sha256": "d" * 64}, analyst_id=ax["id"])

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for user in ("admin_vis", "soc_vis"):
            login = await ac.post("/api/v1/auth/login", json={"username": user, "password": "password123"})
            token = login.json()["access_token"]
            listed = await ac.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}"})
            assert listed.status_code == 200
            assert listed.json()["total"] == 2


# ─── Production startup validation ─────────────────────────────────────────────


def test_production_validation_rejects_default_mobsf_key(monkeypatch):
    from app.startup_validation import validate_production_environment

    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "engine-secret")
    monkeypatch.setenv("MOBSF_API_KEY", "sudarshan_mobsf_api_key_2026")
    monkeypatch.delenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", raising=False)

    with pytest.raises(RuntimeError, match="MOBSF_API_KEY"):
        validate_production_environment()


def test_production_validation_rejects_gateway_dynamic(monkeypatch):
    from app.startup_validation import validate_production_environment

    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "engine-secret")
    monkeypatch.setenv("MOBSF_API_KEY", "custom-mobsf-key-not-default")
    monkeypatch.setenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", "true")

    with pytest.raises(RuntimeError, match="SUDARSHAN_ALLOW_GATEWAY_DYNAMIC"):
        validate_production_environment()


def test_production_validation_passes_with_safe_config(monkeypatch):
    from app.startup_validation import validate_production_environment

    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 48)
    monkeypatch.setenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "engine-secret")
    monkeypatch.setenv("MOBSF_API_KEY", "custom-mobsf-key-not-default")
    monkeypatch.delenv("SUDARSHAN_ALLOW_GATEWAY_DYNAMIC", raising=False)
    validate_production_environment()


# ─── Upload rate limits (decorator regression) ─────────────────────────────────


def test_upload_endpoints_use_ten_per_minute_limit():
  upload_path = BACKEND / "app" / "routes" / "upload.py"
  text = upload_path.read_text(encoding="utf-8")
  assert text.count('@limiter.limit("10/minute")') >= 2
