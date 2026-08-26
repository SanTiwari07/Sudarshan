"""
Security persistence: sessions, login attempts, audit trail.
============================================================

Three tables, one purpose: make authentication revocable and make analyst
activity accountable.

sessions
    JWTs were stateless. The frontend "logged out" by deleting the token from
    localStorage (AuthContext.tsx), which does nothing to the token itself - it
    stayed valid for the full JWT_EXPIRE_HOURS window. There was no server-side
    logout endpoint at all, so a copied token could not be invalidated, an
    admin could not disable an account mid-session, and "sign out everywhere"
    was impossible. This table is the revocation list.

    We store the token's **jti**, never the token. A stored JWT is a stored
    credential; a stored jti is an opaque identifier that cannot be replayed.

login_attempts
    Rate limiting was slowapi keyed on the remote address, held in process
    memory: it reset on every restart and would not be shared across replicas.
    That is a fine first layer and it stays, but nothing durable recorded who
    tried to log in, from where, or how often - so there was no lockout and no
    way to review an attack after the fact.

audit_events
    Nothing recorded who did what. Granting admin via
    PATCH /auth/users/{id}/role left no trace, and neither did a case view or a
    report export. For a banking-fraud platform that is the gap that matters
    most.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import aiosqlite

from app.db.database import connect

logger = logging.getLogger(__name__)


# ─── DDL ──────────────────────────────────────────────────────────────────────

_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    jti         TEXT    PRIMARY KEY,   -- the JWT's jti claim, never the token
    user_id     INTEGER NOT NULL,
    issued_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    revoked_at  TEXT,
    revoked_by  INTEGER,               -- NULL for self-logout, set for admin revocation
    revoke_reason TEXT,
    ip          TEXT,
    user_agent  TEXT,
    last_seen_at TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

_CREATE_LOGIN_ATTEMPTS = """
CREATE TABLE IF NOT EXISTS login_attempts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT    NOT NULL,
    ip             TEXT,
    success        INTEGER NOT NULL,
    failure_reason TEXT,               -- a category, never the submitted secret
    attempted_at   TEXT    NOT NULL
);
"""

_CREATE_AUDIT_EVENTS = """
CREATE TABLE IF NOT EXISTS audit_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id  INTEGER,
    -- Denormalised on purpose. The FK is ON DELETE SET NULL, so a deleted
    -- account would otherwise erase the identity from its own history. The
    -- username is what an auditor reads; the id is what they join on.
    actor_username TEXT,
    action         TEXT    NOT NULL,
    target_type    TEXT,
    target_id      TEXT,
    detail         TEXT,               -- JSON
    ip             TEXT,
    occurred_at    TEXT    NOT NULL,
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
"""

_INDEXES = (
    # get_current_user hits sessions on every authenticated request, by primary
    # key - no index needed for that. These two serve revoke-all and cleanup.
    "CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id, revoked_at);",
    "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);",

    # Both lockout queries are "recent attempts for X", i.e. an equality on the
    # subject plus a range on time - so the composite must lead with the subject.
    "CREATE INDEX IF NOT EXISTS idx_login_user ON login_attempts(username, attempted_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_login_ip   ON login_attempts(ip, attempted_at DESC);",

    # The three ways an auditor asks the question: by actor, by object, by kind.
    "CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_events(actor_user_id, occurred_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(target_type, target_id, occurred_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action, occurred_at DESC);",
)


async def create_tables(db: aiosqlite.Connection) -> None:
    await db.execute(_CREATE_SESSIONS)
    await db.execute(_CREATE_LOGIN_ATTEMPTS)
    await db.execute(_CREATE_AUDIT_EVENTS)


async def create_indexes(db: aiosqlite.Connection) -> None:
    """Build indexes. Runs after migrations - see intel.create_indexes."""
    for stmt in _INDEXES:
        await db.execute(stmt)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Sessions ─────────────────────────────────────────────────────────────────

async def create_session(
    jti: str,
    user_id: int,
    issued_at: datetime,
    expires_at: datetime,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    async with connect() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO sessions
              (jti, user_id, issued_at, expires_at, ip, user_agent, last_seen_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                jti, user_id, issued_at.isoformat(), expires_at.isoformat(),
                ip, (user_agent or "")[:400] or None, issued_at.isoformat(),
            ),
        )
        await db.commit()


async def get_session(jti: str) -> Optional[Dict[str, Any]]:
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM sessions WHERE jti = ?", (jti,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def is_session_active(jti: str) -> bool:
    """
    True only if the session exists, is unrevoked, and has not expired.

    A missing row is treated as inactive. That is deliberate: tokens minted
    before this table existed have no session row, and the safe reading of "I
    have no record of this session" is to reject it rather than to trust it.
    """
    async with connect() as db:
        async with db.execute(
            "SELECT 1 FROM sessions WHERE jti = ? AND revoked_at IS NULL AND expires_at > ?",
            (jti, _now()),
        ) as cur:
            return await cur.fetchone() is not None


async def touch_session(jti: str) -> None:
    """Best-effort last-seen stamp. Never allowed to fail a request."""
    try:
        async with connect() as db:
            await db.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE jti = ? AND revoked_at IS NULL",
                (_now(), jti),
            )
            await db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.debug("[Sessions] last-seen update skipped for %s: %s", jti[:8], exc)


async def revoke_session(
    jti: str,
    revoked_by: Optional[int] = None,
    reason: str = "logout",
) -> bool:
    """Revoke one session. Returns True if it was active before this call."""
    async with connect() as db:
        cur = await db.execute(
            "UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
            "WHERE jti = ? AND revoked_at IS NULL",
            (_now(), revoked_by, reason, jti),
        )
        await db.commit()
        return cur.rowcount > 0


async def revoke_all_sessions_for_user(
    user_id: int,
    revoked_by: Optional[int] = None,
    reason: str = "logout_all",
    except_jti: Optional[str] = None,
) -> int:
    """Revoke every active session for a user. Returns how many were revoked."""
    sql = (
        "UPDATE sessions SET revoked_at = ?, revoked_by = ?, revoke_reason = ? "
        "WHERE user_id = ? AND revoked_at IS NULL"
    )
    params: List[Any] = [_now(), revoked_by, reason, user_id]
    if except_jti:
        sql += " AND jti != ?"
        params.append(except_jti)

    async with connect() as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.rowcount


async def list_active_sessions(user_id: int) -> List[Dict[str, Any]]:
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT jti, issued_at, expires_at, ip, user_agent, last_seen_at "
            "FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? "
            "ORDER BY issued_at DESC",
            (user_id, _now()),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def purge_expired_sessions(grace_days: int = 7) -> int:
    """
    Delete sessions that expired more than `grace_days` ago.

    Safe to delete: an expired session can no longer authorise anything, and the
    fact that a login happened is recorded permanently in login_attempts and
    audit_events. This table is operational state, not the audit trail.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=grace_days)).isoformat()
    async with connect() as db:
        cur = await db.execute("DELETE FROM sessions WHERE expires_at < ?", (cutoff,))
        await db.commit()
        return cur.rowcount


# ─── Login attempts ───────────────────────────────────────────────────────────

async def record_login_attempt(
    username: str,
    success: bool,
    ip: Optional[str] = None,
    failure_reason: Optional[str] = None,
) -> None:
    """
    Record one authentication attempt.

    `failure_reason` is a fixed category ("bad_password", "unknown_user",
    "account_disabled", "locked_out") - never the submitted password, never a
    token, never anything the caller supplied verbatim.
    """
    async with connect() as db:
        await db.execute(
            "INSERT INTO login_attempts (username, ip, success, failure_reason, attempted_at) "
            "VALUES (?,?,?,?,?)",
            (username[:150], ip, 1 if success else 0, failure_reason, _now()),
        )
        await db.commit()


async def count_recent_failures(
    *,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    window_minutes: int = 15,
) -> int:
    """
    Consecutive-window failure count for an account or an address.

    Counts failures since the most recent *success* inside the window, so a
    user who mistypes twice and then logs in successfully starts from zero
    again rather than carrying the failures until the window slides.
    """
    if not username and not ip:
        return 0
    since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    column, value = ("username", username) if username else ("ip", ip)

    async with connect() as db:
        async with db.execute(
            f"SELECT MAX(attempted_at) FROM login_attempts "
            f"WHERE {column} = ? AND success = 1 AND attempted_at >= ?",
            (value, since),
        ) as cur:
            row = await cur.fetchone()
        floor_ts = (row[0] if row else None) or since

        async with db.execute(
            f"SELECT COUNT(*) FROM login_attempts "
            f"WHERE {column} = ? AND success = 0 AND attempted_at > ?",
            (value, floor_ts),
        ) as cur:
            row = await cur.fetchone()
    return row[0] if row else 0


async def purge_old_login_attempts(retain_days: int = 90) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).isoformat()
    async with connect() as db:
        cur = await db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
        await db.commit()
        return cur.rowcount


# ─── Audit events ─────────────────────────────────────────────────────────────

async def insert_audit_event(
    action: str,
    actor_user_id: Optional[int] = None,
    actor_username: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
) -> None:
    """Low-level insert. Callers should use app.services.audit_service instead."""
    detail_json: Optional[str] = None
    if detail:
        try:
            detail_json = json.dumps(detail, default=str)
        except Exception:  # noqa: BLE001
            detail_json = json.dumps({"_unserialisable": True})

    async with connect() as db:
        await db.execute(
            """
            INSERT INTO audit_events
              (actor_user_id, actor_username, action, target_type, target_id,
               detail, ip, occurred_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (actor_user_id, actor_username, action, target_type,
             target_id, detail_json, ip, _now()),
        )
        await db.commit()


async def query_audit_events(
    *,
    actor_user_id: Optional[int] = None,
    action: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    clauses: List[str] = []
    params: List[Any] = []
    if actor_user_id is not None:
        clauses.append("actor_user_id = ?"); params.append(actor_user_id)
    if action:
        clauses.append("action = ?"); params.append(action)
    if target_type:
        clauses.append("target_type = ?"); params.append(target_type)
    if target_id:
        clauses.append("target_id = ?"); params.append(target_id)
    if since:
        clauses.append("occurred_at >= ?"); params.append(since)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([min(limit, 500), offset])

    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            f"SELECT * FROM audit_events {where} ORDER BY occurred_at DESC, id DESC "
            f"LIMIT ? OFFSET ?",
            params,
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

    for r in rows:
        if r.get("detail"):
            try:
                r["detail"] = json.loads(r["detail"])
            except Exception:  # noqa: BLE001
                pass
    return rows


async def count_audit_events() -> int:
    async with connect() as db:
        async with db.execute("SELECT COUNT(*) FROM audit_events") as cur:
            row = await cur.fetchone()
    return row[0] if row else 0
