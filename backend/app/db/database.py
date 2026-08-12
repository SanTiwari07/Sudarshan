"""
Sudarshan Database Layer
========================
Async SQLite database using aiosqlite.

Tables:
  - users        → analyst accounts with roles
  - cases        → every APK analysis result
  - ioc_cache    → IOC reputation cache (24h TTL)
"""

import json
import logging
import os
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("SUDARSHAN_DB_PATH", "sudarshan.db")

# ─── DDL ─────────────────────────────────────────────────────────────────────

_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    hashed_pw   TEXT    NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'analyst',   -- analyst | soc_lead | admin
    created_at  TEXT    NOT NULL
);
"""

_CREATE_CASES = """
CREATE TABLE IF NOT EXISTS cases (
    sha256              TEXT    PRIMARY KEY,
    package_name        TEXT,
    app_name            TEXT,
    analysis_mode       TEXT,
    family_classification TEXT,
    final_risk_score    REAL,
    risk_band           TEXT,
    confidence          REAL,
    dynamic_available   INTEGER DEFAULT 0,
    obfuscation_score   REAL    DEFAULT 0.0,
    has_reflection      INTEGER DEFAULT 0,
    frs_breakdown       TEXT,    -- JSON
    threat_scenario_table TEXT,  -- JSON
    intelligence_report TEXT,    -- JSON
    analyst_id          INTEGER,
    created_at          TEXT    NOT NULL,
    -- Full analysis result as JSON.
    --
    -- The 15 typed columns above are a SUMMARY: they are what /cases needs to
    -- render a list. Everything else the pipeline computed - permissions, IOCs,
    -- manifest and code findings, components, certificate, dynamic result,
    -- fraud workflow, enrichment - was discarded at save time. Three visible
    -- consequences: reopening a case rendered a different, emptier case than
    -- the one just analysed; the export endpoints could not be rebuilt from the
    -- database and 404'd after any restart; and the RAG chat index could not be
    -- reconstructed, so the AI assistant only worked for cases analysed since
    -- the last boot.
    --
    -- The typed columns stay (they are indexed and queried). This is the
    -- complete record they summarise.
    raw_result          TEXT,
    FOREIGN KEY (analyst_id) REFERENCES users(id)
);
"""

_CREATE_IOC_CACHE = """
CREATE TABLE IF NOT EXISTS ioc_cache (
    indicator   TEXT    NOT NULL,
    ioc_type    TEXT    NOT NULL,
    reputation  TEXT,
    source      TEXT,
    threat_score REAL   DEFAULT 0.0,
    raw_data    TEXT,    -- JSON full response
    cached_at   TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    PRIMARY KEY (indicator, ioc_type)
);
"""


# ─── Indexes ──────────────────────────────────────────────────────────────────
# Without these, every /api/v1/cases request full-scans and sorts the cases
# table (once for the page, once for COUNT). SQLite does NOT index foreign keys
# automatically, so analyst_id needs an explicit one too.
_CREATE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_cases_analyst    ON cases(analyst_id);",
    "CREATE INDEX IF NOT EXISTS idx_ioc_expires      ON ioc_cache(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_jobs_status      ON analysis_jobs(status);",
)


_CREATE_NOTES = """
CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL,
    text        TEXT NOT NULL,
    author      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""

_CREATE_ANALYSIS_JOBS = """
CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id          TEXT PRIMARY KEY,
    status          TEXT NOT NULL,
    sha256          TEXT,
    analyst_id      INTEGER,
    queued_at       TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    result_json     TEXT,
    error           TEXT
);
"""

_CREATE_DISCOVERY_SESSIONS = """
CREATE TABLE IF NOT EXISTS discovery_sessions (
    id            TEXT PRIMARY KEY,
    target_url    TEXT NOT NULL,
    domain        TEXT NOT NULL,
    status        TEXT NOT NULL,
    pages_scanned INTEGER DEFAULT 0,
    error         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    progress_logs TEXT  -- JSON list
);
"""

_CREATE_DISCOVERY_CANDIDATES = """
CREATE TABLE IF NOT EXISTS discovery_candidates (
    id                TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    source_url        TEXT NOT NULL,
    discovery_url     TEXT NOT NULL,
    filename          TEXT,
    source_type       TEXT NOT NULL,
    package_id        TEXT,
    download_status   TEXT NOT NULL,
    validation_status TEXT,
    sha256            TEXT,
    size              INTEGER,
    storage_path      TEXT,
    error             TEXT,
    created_at        TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES discovery_sessions(id)
);
"""


@asynccontextmanager
async def _connect() -> AsyncIterator[aiosqlite.Connection]:
    """
    Open a connection with the pragmas this app depends on.

    These are per-connection in SQLite, so they must be set on every handle:
      journal_mode=WAL  readers no longer block on a writer
      busy_timeout      wait for a lock instead of raising 'database is locked'
                        immediately (the default is 0)
      foreign_keys=ON   without this the cases.analyst_id REFERENCES clause is
                        silently unenforced
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout=5000;")
        await db.execute("PRAGMA foreign_keys=ON;")
        yield db


# ─── Additive migrations ──────────────────────────────────────────────────────
#
# `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so it cannot add
# a column - a schema change would silently not apply to any database that
# already existed, and the first INSERT naming the new column would fail.
#
# This handles the only migration shape SQLite makes safe and idempotent:
# ALTER TABLE ... ADD COLUMN. Anything beyond that (type changes, constraints,
# backfills) needs a real migration tool; this is not a substitute for one, it
# is the minimum that stops additive changes from breaking existing installs.
_MIGRATIONS: tuple = (
    ("cases", "raw_result", "ALTER TABLE cases ADD COLUMN raw_result TEXT"),
)


async def _apply_migrations(db: aiosqlite.Connection) -> None:
    for table, column, stmt in _MIGRATIONS:
        async with db.execute(f"PRAGMA table_info({table})") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if column not in cols:
            await db.execute(stmt)
            logger.info(f"[DB] Migration applied: {table}.{column} added")


async def init_db() -> None:
    """Create all tables and indexes if they don't exist, then migrate."""
    async with _connect() as db:
        await db.execute(_CREATE_USERS)
        await db.execute(_CREATE_CASES)
        await db.execute(_CREATE_IOC_CACHE)
        await db.execute(_CREATE_NOTES)
        await db.execute(_CREATE_ANALYSIS_JOBS)
        await db.execute(_CREATE_DISCOVERY_SESSIONS)
        await db.execute(_CREATE_DISCOVERY_CANDIDATES)
        for stmt in _CREATE_INDEXES:
            await db.execute(stmt)
        await _apply_migrations(db)
        await db.commit()
    logger.info(f"[DB] Initialized SQLite at {DB_PATH} (WAL, FK enforced, indexed)")



# ─── Cases ───────────────────────────────────────────────────────────────────

async def save_case(sha256: str, result: Dict[str, Any], analyst_id: Optional[int] = None) -> None:
    """Persist an analysis result to the cases table."""
    now = datetime.now(timezone.utc).isoformat()
    frs_json = json.dumps(result.get("frs_breakdown", {}))
    scenario_json = json.dumps(result.get("threat_scenario_table", []))
    intel_json = json.dumps(result.get("intelligence_report") or {})

    # Full record. Serialised defensively: a value that will not serialise must
    # not take the whole save down - a case row with a summary is far better
    # than no case row at all.
    try:
        raw_json = json.dumps(result, default=str)
    except Exception as exc:
        logger.warning(
            f"[DB] Could not serialise full result for {sha256[:12]}… "
            f"({type(exc).__name__}: {exc}); storing summary only."
        )
        raw_json = None

    async with _connect() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO cases
              (sha256, package_name, app_name, analysis_mode, family_classification,
               final_risk_score, risk_band, confidence, dynamic_available,
               obfuscation_score, has_reflection, frs_breakdown,
               threat_scenario_table, intelligence_report, analyst_id, created_at,
               raw_result)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                sha256,
                result.get("package_name"),
                result.get("app_name"),
                result.get("analysis_mode"),
                result.get("family_classification"),
                result.get("final_risk_score"),
                result.get("risk_band"),
                result.get("confidence"),
                1 if result.get("dynamic_available") else 0,
                result.get("obfuscation_score", 0.0),
                1 if result.get("has_reflection") else 0,
                frs_json,
                scenario_json,
                intel_json,
                analyst_id,
                now,
                raw_json,
            ),
        )
        await db.commit()
    logger.info(f"[DB] Case saved: {sha256[:12]}… family={result.get('family_classification')}")


async def get_case(sha256: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single case by SHA256 (exact or prefix)."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM cases WHERE sha256 = ? OR sha256 LIKE ?", (sha256, f"{sha256}%")) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return _row_to_case(dict(row))


async def list_cases(limit: int = 50, offset: int = 0, analyst_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return paginated list of cases, newest first."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        if analyst_id is not None:
            sql = "SELECT * FROM cases WHERE analyst_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params = (analyst_id, limit, offset)
        else:
            sql = "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params = (limit, offset)
        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()
    return [_row_to_case(dict(r)) for r in rows]


async def count_cases(analyst_id: Optional[int] = None) -> int:
    async with _connect() as db:
        if analyst_id is not None:
            async with db.execute(
                "SELECT COUNT(*) FROM cases WHERE analyst_id = ?", (analyst_id,)
            ) as cur:
                row = await cur.fetchone()
        else:
            async with db.execute("SELECT COUNT(*) FROM cases") as cur:
                row = await cur.fetchone()
    return row[0] if row else 0


def _row_to_case(row: Dict) -> Dict[str, Any]:
    """
    Deserialize a SQLite row into the full analysis result.

    When `raw_result` is present it is expanded and the typed summary columns
    are layered ON TOP - the columns are authoritative for the fields they
    cover (they are what queries filter and sort on), while raw_result supplies
    everything the summary omits. That makes a restored case identical to the
    one originally returned, which is what the export endpoints, the RAG index
    and the technical view all need.
    """
    raw: Dict[str, Any] = {}
    if row.get("raw_result"):
        try:
            parsed = json.loads(row["raw_result"])
            if isinstance(parsed, dict):
                raw = parsed
        except Exception as exc:
            logger.warning(
                f"[DB] raw_result for {str(row.get('sha256'))[:12]}… is not valid "
                f"JSON ({type(exc).__name__}); falling back to summary columns."
            )
    row.pop("raw_result", None)

    for field in ("frs_breakdown", "threat_scenario_table", "intelligence_report"):
        if row.get(field):
            try:
                row[field] = json.loads(row[field])
            except Exception:
                row[field] = {}

    row["dynamic_available"] = bool(row.get("dynamic_available"))
    row["has_reflection"] = bool(row.get("has_reflection"))

    if not raw:
        return row

    merged = dict(raw)
    # Summary columns win: they are the indexed, queryable truth.
    merged.update({k: v for k, v in row.items() if v is not None})
    return merged


# ─── IOC Cache ────────────────────────────────────────────────────────────────

async def get_cached_ioc(indicator: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """Return cached IOC reputation if not expired."""
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM ioc_cache WHERE indicator=? AND ioc_type=? AND expires_at>?",
            (indicator, ioc_type, now),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("raw_data"):
        try:
            d["raw_data"] = json.loads(d["raw_data"])
        except Exception:
            pass
    return d


async def save_ioc_cache(
    indicator: str,
    ioc_type: str,
    reputation: str,
    source: str,
    threat_score: float,
    raw_data: Dict,
    ttl_hours: int = 24,
) -> None:
    """Cache an IOC reputation result."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(hours=ttl_hours)).isoformat()
    async with _connect() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO ioc_cache
              (indicator, ioc_type, reputation, source, threat_score, raw_data, cached_at, expires_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (indicator, ioc_type, reputation, source, threat_score,
             json.dumps(raw_data), now.isoformat(), expires),
        )
        await db.commit()


# ─── Users ────────────────────────────────────────────────────────────────────

async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE username=?", (username,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id=?", (user_id,)) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def create_user(username: str, hashed_pw: str, role: str = "analyst") -> int:
    """Insert a new user, return the new row id."""
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        cur = await db.execute(
            "INSERT INTO users (username, hashed_pw, role, created_at) VALUES (?,?,?,?)",
            (username, hashed_pw, role, now),
        )
        await db.commit()
        return cur.lastrowid


async def update_user_role(user_id: int, role: str) -> None:
    """Change a user's role. Callers must enforce that the actor is an admin."""
    async with _connect() as db:
        await db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        await db.commit()


async def username_exists(username: str) -> bool:
    async with _connect() as db:
        async with db.execute("SELECT id FROM users WHERE username=?", (username,)) as cur:
            return await cur.fetchone() is not None


# ─── Case Notes ───────────────────────────────────────────────────────────────

async def add_case_note(sha256: str, text: str, author: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        cur = await db.execute(
            "INSERT INTO case_notes (sha256, text, author, created_at) VALUES (?,?,?,?)",
            (sha256, text, author, now),
        )
        await db.commit()
        return {"id": cur.lastrowid, "sha256": sha256, "text": text, "author": author, "created_at": now}


async def get_case_notes(sha256: str) -> List[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM case_notes WHERE sha256=? ORDER BY id ASC", (sha256,)) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


# ─── Async analysis jobs (durable poll state) ───────────────────────────────

async def upsert_analysis_job(job: Dict[str, Any]) -> None:
    """Persist gateway async job state for restart-safe polling."""
    result_json = None
    if job.get("result") is not None:
        result_json = json.dumps(job["result"])
    async with _connect() as db:
        await db.execute(
            """
            INSERT INTO analysis_jobs (
                job_id, status, sha256, analyst_id, queued_at, started_at,
                completed_at, result_json, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                status=excluded.status,
                sha256=excluded.sha256,
                analyst_id=excluded.analyst_id,
                started_at=excluded.started_at,
                completed_at=excluded.completed_at,
                result_json=excluded.result_json,
                error=excluded.error
            """,
            (
                job["job_id"],
                job["status"],
                job.get("sha256"),
                job.get("analyst_id"),
                job.get("queued_at"),
                job.get("started_at"),
                job.get("completed_at"),
                result_json,
                job.get("error"),
            ),
        )
        await db.commit()


async def load_analysis_job(job_id: str) -> Optional[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_jobs WHERE job_id = ?", (job_id,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    data = dict(row)
    result = None
    if data.get("result_json"):
        try:
            result = json.loads(data["result_json"])
        except json.JSONDecodeError:
            logger.warning("[DB] analysis_jobs.result_json corrupt for %s", job_id[:8])
# ─── Discovery State ────────────────────────────────────────────────────────

async def save_discovery_session(session: Dict[str, Any]) -> None:
    async with _connect() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO discovery_sessions
            (id, target_url, domain, status, pages_scanned, error, created_at, updated_at, progress_logs)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["id"], session["target_url"], session["domain"], session["status"],
                session.get("pages_scanned", 0), session.get("error"),
                session.get("created_at"), session.get("updated_at"),
                json.dumps(session.get("progress_logs", []))
            )
        )
        await db.commit()

async def get_discovery_session(session_id: str) -> Optional[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM discovery_sessions WHERE id = ?", (session_id,)) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    d = dict(row)
    d["progress_logs"] = json.loads(d.get("progress_logs") or "[]")
    return d

async def save_discovery_candidate(candidate: Dict[str, Any]) -> None:
    async with _connect() as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO discovery_candidates
            (id, session_id, source_url, discovery_url, filename, source_type, package_id, 
             download_status, validation_status, sha256, size, storage_path, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate["id"], candidate["session_id"], candidate["source_url"],
                candidate["discovery_url"], candidate.get("filename"), candidate["source_type"],
                candidate.get("package_id"), candidate["download_status"], candidate.get("validation_status"),
                candidate.get("sha256"), candidate.get("size"), candidate.get("storage_path"),
                candidate.get("error"), candidate.get("created_at")
            )
        )
        await db.commit()

async def get_discovery_candidates(session_id: str) -> List[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM discovery_candidates WHERE session_id = ?", (session_id,)) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]

