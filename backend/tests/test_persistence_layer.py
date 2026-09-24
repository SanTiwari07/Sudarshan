"""
Tests for the persistence layer added in the database hardening work.

Covers:
  * migrations - fresh, existing, idempotent, ordering
  * sessions   - real logout, revocation, disabled accounts
  * lockout    - durable, temporary, per-account and per-IP
  * audit      - recorded, queryable, never fails the request
  * lifecycle  - the analyst verdict never overwrites the engine's
  * runs       - placeholders excluded from comparisons
  * IOCs       - extraction, the cross-case pivot, noise suppression
  * chat       - server-side history is authoritative
"""

from __future__ import annotations

import os
import sqlite3

import pytest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def db(tmp_path, monkeypatch):
    """A fresh, fully-migrated database, isolated per test."""
    path = tmp_path / "test.db"
    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(path))
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret_key")
    monkeypatch.delenv("DATABASE_URL", raising=False)

    from app.db import database as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(path))

    await dbmod.init_db()
    return path


# ─── Migrations ───────────────────────────────────────────────────────────────

async def test_migrations_apply_and_are_idempotent(db):
    from app.db.database import connect
    from app.db.migrations import MIGRATIONS, migration_status, run_migrations

    async with connect() as conn:
        status = await migration_status(conn)
        assert status["pending"] == []
        assert len(status["applied"]) == len(MIGRATIONS)
        assert status["unknown"] == []

        # Running again must be a no-op, not an error.
        assert await run_migrations(conn) == []


async def test_migration_adopts_a_preexisting_legacy_database(tmp_path, monkeypatch):
    """
    The real upgrade path: a database created by the OLD code, migrated by the
    new. analysis_runs is the hard case - it was created by analysis_history.py
    without the columns the new indexes reference.
    """
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
                            hashed_pw TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst',
                            created_at TEXT NOT NULL);
        -- Mirrors the pre-change shape, analyst_id included: idx_cases_analyst
        -- has always indexed it, so a fixture without it would test a schema
        -- that never shipped.
        CREATE TABLE cases (sha256 TEXT PRIMARY KEY, package_name TEXT,
                            analyst_id INTEGER, created_at TEXT NOT NULL);
        CREATE TABLE analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL,
            apk_sha256 TEXT NOT NULL, run_timestamp TEXT NOT NULL,
            stage_name TEXT DEFAULT 'single', duration_seconds INTEGER,
            bfci_score REAL, bfci_components TEXT, mitre_techniques TEXT,
            ioc_count INTEGER DEFAULT 0, screenshot_count INTEGER DEFAULT 0,
            yara_matches TEXT, anti_analysis TEXT, explorer_mode TEXT);
        INSERT INTO users (username, hashed_pw, role, created_at)
             VALUES ('legacy_analyst', 'hash', 'analyst', '2026-01-01T00:00:00Z');
        INSERT INTO cases (sha256, package_name, created_at)
             VALUES ('a'||substr(hex(randomblob(32)),1,63), 'com.legacy', '2026-01-01T00:00:00Z');
        INSERT INTO analysis_runs (package_name, apk_sha256, run_timestamp, bfci_score)
             VALUES ('com.legacy', 'unknown', '2026-01-01T00:00:00Z', 0.0);
        """
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("SUDARSHAN_DB_PATH", str(path))
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret_key")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from app.db import database as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(path))

    await dbmod.init_db()

    check = sqlite3.connect(path)
    # Existing data survived.
    assert check.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert check.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 1
    assert check.execute("SELECT COUNT(*) FROM analysis_runs").fetchone()[0] == 1
    # New columns exist on the pre-existing tables.
    user_cols = {r[1] for r in check.execute("PRAGMA table_info(users)")}
    assert {"is_active", "last_login_at", "must_change_password"} <= user_cols
    case_cols = {r[1] for r in check.execute("PRAGMA table_info(cases)")}
    assert {"status", "analyst_verdict", "verdict_reason"} <= case_cols
    # The legacy run was flagged, not deleted.
    assert check.execute(
        "SELECT is_placeholder FROM analysis_runs"
    ).fetchone()[0] == 1
    # A pre-existing user defaults to active, because it was.
    assert check.execute("SELECT is_active FROM users").fetchone()[0] == 1
    check.close()


# ─── Sessions ─────────────────────────────────────────────────────────────────

async def _make_user(username="analyst1", role="analyst"):
    from app.auth.auth import hash_password
    from app.db.database import create_user, get_user_by_username

    await create_user(username, hash_password("correct-horse-battery"), role)
    return await get_user_by_username(username)


async def test_logout_actually_invalidates_the_token(db):
    """The bug this whole table exists for: logout used to be client-side only."""
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    from app.auth.auth import get_current_user, issue_session_token
    from app.db.security import revoke_session

    user = await _make_user()
    token = await issue_session_token(user)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    class _Req:
        state = type("S", (), {})()
        headers: dict = {}
        client = None

    authed = await get_current_user(_Req(), creds)
    assert authed["username"] == "analyst1"

    await revoke_session(authed["_jti"], revoked_by=user["id"])

    with pytest.raises(HTTPException) as exc:
        await get_current_user(_Req(), creds)
    assert exc.value.status_code == 401


async def test_token_without_a_session_is_rejected(db):
    """A signed token is not enough; it must correspond to a live session."""
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    from app.auth.auth import create_access_token, get_current_user

    user = await _make_user()
    token = create_access_token(user["id"], user["username"], user["role"])

    class _Req:
        state = type("S", (), {})()
        headers: dict = {}
        client = None

    with pytest.raises(HTTPException) as exc:
        await get_current_user(_Req(), HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=token))
    assert exc.value.status_code == 401


async def test_revoke_all_can_spare_the_current_session(db):
    from app.auth.auth import issue_session_token
    from app.db.security import list_active_sessions, revoke_all_sessions_for_user
    from jose import jwt

    user = await _make_user()
    keep = await issue_session_token(user)
    await issue_session_token(user)
    await issue_session_token(user)
    assert len(await list_active_sessions(user["id"])) == 3

    keep_jti = jwt.get_unverified_claims(keep)["jti"]
    revoked = await revoke_all_sessions_for_user(user["id"], except_jti=keep_jti)

    assert revoked == 2
    remaining = await list_active_sessions(user["id"])
    assert len(remaining) == 1
    assert remaining[0]["jti"] == keep_jti


async def test_disabled_account_cannot_authenticate(db):
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    from app.auth.auth import get_current_user, issue_session_token
    from app.db.database import set_user_active

    user = await _make_user()
    token = await issue_session_token(user)

    class _Req:
        state = type("S", (), {})()
        headers: dict = {}
        client = None

    await set_user_active(user["id"], False)
    with pytest.raises(HTTPException) as exc:
        await get_current_user(_Req(), HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=token))
    assert exc.value.status_code == 403


# ─── Login attempts / lockout ────────────────────────────────────────────────

async def test_failure_counter_resets_after_a_success(db):
    """
    A user who mistypes twice then succeeds must start from zero, otherwise
    normal use drifts toward a lockout.
    """
    from app.db.security import count_recent_failures, record_login_attempt

    for _ in range(3):
        await record_login_attempt("bob", success=False, ip="10.0.0.1",
                                   failure_reason="bad_password")
    assert await count_recent_failures(username="bob") == 3

    await record_login_attempt("bob", success=True, ip="10.0.0.1")
    assert await count_recent_failures(username="bob") == 0

    await record_login_attempt("bob", success=False, ip="10.0.0.1",
                               failure_reason="bad_password")
    assert await count_recent_failures(username="bob") == 1


async def test_ip_and_account_failures_are_counted_separately(db):
    from app.db.security import count_recent_failures, record_login_attempt

    # One address spraying many usernames: no single account reaches its
    # threshold, but the address does. That is the intended asymmetry.
    for i in range(12):
        await record_login_attempt(f"user{i}", success=False, ip="10.9.9.9",
                                   failure_reason="unknown_user")

    assert await count_recent_failures(username="user0") == 1
    assert await count_recent_failures(ip="10.9.9.9") == 12


async def test_login_attempts_never_store_the_password(db):
    from app.db.database import connect
    from app.db.security import record_login_attempt

    await record_login_attempt("bob", success=False, ip="10.0.0.1",
                               failure_reason="bad_password")
    async with connect() as conn:
        async with conn.execute("SELECT * FROM login_attempts") as cur:
            row = await cur.fetchone()
            
    row_str = str(dict(row)) if row else ""
    assert "correct-horse-battery" not in row_str
    assert "bad_password" in row_str


# ─── Audit ────────────────────────────────────────────────────────────────────

async def test_audit_event_is_recorded_and_queryable(db):
    from app.db.security import query_audit_events
    from app.services import audit_service
    from app.services.audit_service import Action

    user = await _make_user("soc1", "soc_lead")
    await audit_service.record(
        Action.ROLE_CHANGED,
        actor=user,
        target_type="user",
        target_id="42",
        detail={"from_role": "analyst", "to_role": "admin"},
        ip="10.0.0.5",
    )

    events = await query_audit_events(action=Action.ROLE_CHANGED)
    assert len(events) == 1
    assert events[0]["actor_username"] == "soc1"
    assert events[0]["target_id"] == "42"
    assert events[0]["detail"]["to_role"] == "admin"
    assert events[0]["ip"] == "10.0.0.5"


async def test_audit_failure_never_propagates(db, monkeypatch):
    """Auditing must not be able to fail the action it is auditing."""
    from app.services import audit_service

    async def _boom(*a, **kw):
        raise RuntimeError("database is on fire")

    monkeypatch.setattr(audit_service, "insert_audit_event", _boom)
    await audit_service.record("LOGIN_SUCCESS", actor_username="bob")  # must not raise


# ─── Case lifecycle ───────────────────────────────────────────────────────────

async def test_analyst_verdict_does_not_overwrite_the_engine(db):
    """
    The core guarantee of Phase 7: an analyst calling a CRITICAL/94 sample a
    false positive must not erase what the engine measured.
    """
    from app.db.database import get_case, save_case, set_case_verdict

    sha = "b" * 64
    await save_case(sha, {
        "sha256": sha,
        "package_name": "com.test.sample",
        "final_risk_score": 94.0,
        "risk_band": "CRITICAL",
        "family_classification": "BankBot",
        "confidence": 88.0,
        "frs_breakdown": {"stei": 71.2},
    })

    user = await _make_user("lead", "soc_lead")
    await set_case_verdict(sha, "FALSE_POSITIVE", "Known internal test APK", user["id"])

    case = await get_case(sha)
    # Engine output: untouched.
    assert case["final_risk_score"] == 94.0
    assert case["risk_band"] == "CRITICAL"
    assert case["family_classification"] == "BankBot"
    assert case["frs_breakdown"]["stei"] == 71.2
    # Analyst decision: recorded alongside, attributable.
    assert case["analyst_verdict"] == "FALSE_POSITIVE"
    assert case["verdict_reason"] == "Known internal test APK"
    assert case["verdict_set_by"] == user["id"]


async def test_case_status_defaults_to_open_and_transitions(db):
    from app.db.database import get_case, save_case, set_case_status

    sha = "c" * 64
    await save_case(sha, {"sha256": sha, "package_name": "com.x"})
    assert (await get_case(sha))["status"] == "OPEN"

    await set_case_status(sha, "IN_REVIEW")
    case = await get_case(sha)
    assert case["status"] == "IN_REVIEW"
    assert case["closed_at"] is None

    await set_case_status(sha, "CLOSED")
    assert (await get_case(sha))["closed_at"] is not None


async def test_invalid_status_is_refused(db):
    from app.db.database import set_case_status

    with pytest.raises(ValueError):
        await set_case_status("d" * 64, "WHATEVER")


# ─── Analysis runs ────────────────────────────────────────────────────────────

async def test_compare_runs_ignores_placeholder_rows(db):
    """
    140 historical rows carry apk_sha256='unknown' and bfci_score=0.0. Comparing
    against them would fabricate a score movement.
    """
    from app.db.database import connect
    from app.db.intel import compare_runs, record_analysis_run

    async with connect() as conn:
        await conn.execute(
            "INSERT INTO analysis_runs (package_name, apk_sha256, run_timestamp, "
            "bfci_score, is_placeholder) VALUES ('com.x','unknown','2026-01-01T00:00:00Z',0.0,1)"
        )
        await conn.commit()

    await record_analysis_run({
        "package_name": "com.x", "sha256": "e" * 64,
        "run_timestamp": "2026-02-01T00:00:00Z",
        "frs_score": 50.0, "bfci_score": 20.0, "risk_band": "MEDIUM",
    })

    # One real run + one placeholder is still insufficient data.
    result = await compare_runs("com.x")
    assert result["status"] == "insufficient_data"
    assert result["real_runs_available"] == 1

    await record_analysis_run({
        "package_name": "com.x", "sha256": "f" * 64,
        "run_timestamp": "2026-03-01T00:00:00Z",
        "frs_score": 80.0, "bfci_score": 35.0, "risk_band": "HIGH",
    })

    result = await compare_runs("com.x")
    assert result["status"] == "success"
    assert result["frs_delta"] == 30.0
    assert result["bfci_delta"] == 15.0
    assert result["risk_band_changed"] is True


async def test_run_recorder_maps_real_fields_and_never_invents_zeros(db):
    from app.services.run_recorder import build_run_record

    record = build_run_record({
        "sha256": "a" * 64,
        "package_name": "com.bank.fake",
        "final_risk_score": 91.5,
        "risk_band": "CRITICAL",
        "analysis_mode": "full",
        "frs_breakdown": {"stei": 64.3},
        "dynamic_result": {
            "bfci": 42.0, "dynamic_status": "COMPLETED",
            "duration_seconds": 90, "engine": "frida",
            "screenshots": ["a.png", "b.png"],
        },
        "intelligence_report": {"mitre_techniques_used": ["T1417", {"technique_id": "T1422"}]},
    })

    assert record["frs_score"] == 91.5
    assert record["stei_score"] == 64.3
    assert record["bfci_score"] == 42.0
    assert record["risk_band"] == "CRITICAL"
    assert record["dynamic_status"] == "COMPLETED"
    assert record["screenshot_count"] == 2
    assert record["mitre_techniques"] == ["T1417", "T1422"]

    # An absent measurement is NULL, never 0.0 - conflating them is what made
    # the original table useless.
    empty = build_run_record({"sha256": "b" * 64, "package_name": "com.y"})
    assert empty["frs_score"] is None
    assert empty["bfci_score"] is None
    assert empty["stei_score"] is None


# ─── IOCs ─────────────────────────────────────────────────────────────────────

def test_ioc_extraction_filters_noise_and_normalises_types():
    from app.services.ioc_extraction import extract_iocs

    iocs = extract_iocs({
        "sha256": "a" * 64,
        "package_name": "com.evil.bank",
        "hardcoded_urls_ips": [
            # Real prose from a stored case - the host in it is noise.
            "Analytics service at risk of not starting. See http://goo.gl/8Rd3yj for instructions.",
            "http://evil-c2.example-bad.net/gate.php",
            "www.google-analytics.com",
        ],
        "threat_correlation": {
            "malicious_ips": ["203.0.113.9"],
            # Correlator casing differs from static extraction.
            "ioc_reputation": [{"type": "Domain", "indicator": "bad-actor.tld",
                                "reputation": "malicious"}],
        },
    })
    by_indicator = {i["indicator"].lower(): i for i in iocs}

    assert "evil-c2.example-bad.net" in by_indicator
    assert "203.0.113.9" in by_indicator
    assert "bad-actor.tld" in by_indicator
    # Suppressed.
    assert "goo.gl" not in by_indicator
    assert "www.google-analytics.com" not in by_indicator
    # Types are lowercase everywhere, so the composite key cannot split.
    assert {i["ioc_type"] for i in iocs} <= {"sha256", "package", "domain", "ip", "url", "email"}
    assert by_indicator["bad-actor.tld"]["ioc_type"] == "domain"


async def test_indicator_pivot_finds_other_cases(db):
    """The question the JSON blob could never answer."""
    from app.db.database import save_case
    from app.db.intel import cases_for_indicator

    shared_host = "c2.badactor-example.tld"
    for n, sha in enumerate(("a" * 64, "b" * 64)):
        await save_case(sha, {
            "sha256": sha,
            "package_name": f"com.sample{n}",
            "risk_band": "HIGH",
            "hardcoded_urls_ips": [f"https://{shared_host}/gate"],
        })

    hits = await cases_for_indicator(shared_host, "domain")
    assert {h["sha256"] for h in hits} == {"a" * 64, "b" * 64}
    assert {h["package_name"] for h in hits} == {"com.sample0", "com.sample1"}


async def test_ioc_upsert_preserves_first_seen(db):
    from app.db.intel import iocs_for_case, upsert_case_iocs
    from app.db.database import save_case

    sha = "a" * 64
    await save_case(sha, {"sha256": sha, "package_name": "com.x"})

    await upsert_case_iocs(sha, [{"indicator": "x.tld", "ioc_type": "domain"}])
    first = (await iocs_for_case(sha))[0]

    await upsert_case_iocs(sha, [
        {"indicator": "x.tld", "ioc_type": "domain", "reputation": "malicious"}
    ])
    second = [i for i in await iocs_for_case(sha) if i["indicator"] == "x.tld"][0]

    assert second["first_seen"] == first["first_seen"]
    assert second["reputation"] == "malicious"


# ─── Chat history ─────────────────────────────────────────────────────────────

async def test_chat_history_is_stored_and_ordered(db):
    from app.db.database import save_case
    from app.db.intel import append_chat_message, get_chat_history

    sha = "a" * 64
    await save_case(sha, {"sha256": sha, "package_name": "com.x"})

    await append_chat_message(sha, "user", "What does this sample do?", user_id=None)
    await append_chat_message(sha, "assistant", "It overlays banking apps.",
                              sections_used=["permissions", "dynamic_findings"])

    history = await get_chat_history(sha)
    assert [m["role"] for m in history] == ["user", "assistant"]
    assert history[1]["sections_used"] == ["permissions", "dynamic_findings"]


async def test_chat_history_survives_a_new_connection(db):
    """It used to live only in the request body, so a refresh lost it."""
    from app.db.database import save_case
    from app.db.intel import append_chat_message, get_chat_history

    sha = "a" * 64
    await save_case(sha, {"sha256": sha, "package_name": "com.x"})
    await append_chat_message(sha, "user", "first question")

    # A fresh connection is what a restarted process gets.
    assert len(await get_chat_history(sha)) == 1


def test_sse_token_extraction_ignores_non_token_frames():
    from app.routes.report import _sse_token_text

    assert _sse_token_text('event: token\ndata: "hello "\n\n') == "hello "
    assert _sse_token_text('event: sections\ndata: ["permissions"]\n\n') == ""
    assert _sse_token_text('event: done\ndata: ""\n\n') == ""
    assert _sse_token_text('event: error\ndata: "boom"\n\n') == ""


# ─── Export ledger ────────────────────────────────────────────────────────────

async def test_export_is_recorded_with_a_reference_not_the_payload(db):
    from app.db.database import save_case
    from app.db.intel import exports_for_case, record_export

    sha = "a" * 64
    await save_case(sha, {"sha256": sha, "package_name": "com.x"})
    await record_export(sha, "pdf", user_id=None, username="analyst1",
                        artifact_ref="sudarshan_report_aaaa.pdf", byte_size=284_113)

    rows = await exports_for_case(sha)
    assert len(rows) == 1
    assert rows[0]["export_type"] == "pdf"
    assert rows[0]["artifact_ref"] == "sudarshan_report_aaaa.pdf"
    assert rows[0]["byte_size"] == 284_113
