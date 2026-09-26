"""Demo user seed on startup."""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))


@pytest.mark.anyio
async def test_seed_demo_users_creates_soclead_and_analyst(monkeypatch, tmp_path):
    from app.db import database as db
    from app.demo_seed import seed_demo_users

    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "demo.db"))
    monkeypatch.setenv("SUDARSHAN_SEED_DEMO_USERS", "true")
    monkeypatch.setenv("DEMO_SOCLEAD_USERNAME", "soclead_test")
    monkeypatch.setenv("DEMO_SOCLEAD_PASSWORD", "test-soclead-password")
    monkeypatch.setenv("DEMO_ANALYST_USERNAME", "analyst1_test")
    monkeypatch.setenv("DEMO_ANALYST_PASSWORD", "test-analyst-password")

    await db.init_db()
    await seed_demo_users()

    soc = await db.get_user_by_username("soclead_test")
    ana = await db.get_user_by_username("analyst1_test")
    assert soc is not None
    assert soc["role"] == "soc_lead"
    assert ana is not None
    assert ana["role"] == "analyst"

    await seed_demo_users()
    assert (await db.get_user_by_username("soclead_test"))["role"] == "soc_lead"


@pytest.mark.anyio
async def test_seed_demo_users_has_no_default_passwords(monkeypatch, tmp_path):
    """Without an explicit password no demo account is created."""
    from app.db import database as db
    from app.demo_seed import seed_demo_users

    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(tmp_path / "demo2.db"))
    monkeypatch.setenv("SUDARSHAN_SEED_DEMO_USERS", "true")
    monkeypatch.setenv("DEMO_SOCLEAD_USERNAME", "soclead_nopw")
    monkeypatch.delenv("DEMO_SOCLEAD_PASSWORD", raising=False)
    monkeypatch.setenv("DEMO_ANALYST_USERNAME", "analyst_nopw")
    monkeypatch.delenv("DEMO_ANALYST_PASSWORD", raising=False)

    await db.init_db()
    await seed_demo_users()
    assert await db.get_user_by_username("soclead_nopw") is None
    assert await db.get_user_by_username("analyst_nopw") is None


@pytest.mark.anyio
async def test_seed_demo_users_refused_in_production(monkeypatch, tmp_path):
    from app.db import database as db
    from app.demo_seed import seed_demo_users

    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(tmp_path / "demo3.db"))
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("SUDARSHAN_SEED_DEMO_USERS", "true")
    monkeypatch.setenv("DEMO_SOCLEAD_USERNAME", "soclead_prod")
    monkeypatch.setenv("DEMO_SOCLEAD_PASSWORD", "a-long-enough-password")

    await db.init_db()
    await seed_demo_users()
    assert await db.get_user_by_username("soclead_prod") is None
