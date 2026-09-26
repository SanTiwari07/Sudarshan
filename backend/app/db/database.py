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
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import aiosqlite

from app.db.paths import ensure_parent, resolve_db_path

logger = logging.getLogger(__name__)

# The path resolved at import time. Kept as a module attribute because the test
# suite overrides persistence with `monkeypatch.setattr(db, "DB_PATH", ...)`,
# and that contract predates this module.
#
# `_active_db_path()` - not this constant - is what connections actually use.
DB_PATH = str(resolve_db_path())
_IMPORT_TIME_DB_PATH = DB_PATH


def _active_db_path() -> str:
    """
    The database file this process should open, right now.

    Two override styles both have to keep working:

      monkeypatch.setattr(db, "DB_PATH", p)   → the attribute diverges from the
                                                import-time value, so it wins.
      monkeypatch.setenv("SUDARSHAN_DB_PATH") → the attribute is untouched, so
                                                we re-resolve from the env.

    Re-resolving on every call also means a path set after import (Compose, a
    CLI flag, a fixture) is honoured instead of being frozen at import.
    """
    if DB_PATH != _IMPORT_TIME_DB_PATH:
        return DB_PATH
    return str(resolve_db_path())

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
    # Enterprise Batch Scan indexes
    "CREATE INDEX IF NOT EXISTS idx_batches_created_by ON analysis_batches(created_by, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_batch_jobs_batch   ON analysis_batch_jobs(batch_id, queue_position ASC);",
    "CREATE INDEX IF NOT EXISTS idx_batch_jobs_status  ON analysis_batch_jobs(status);",
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


# ─── Enterprise Batch Scan Tables ────────────────────────────────────────────

_CREATE_ANALYSIS_BATCHES = """
CREATE TABLE IF NOT EXISTS analysis_batches (
    batch_id        TEXT    PRIMARY KEY,
    created_by      INTEGER NOT NULL,
    created_at      TEXT    NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,
    total_jobs      INTEGER NOT NULL DEFAULT 0,
    completed_jobs  INTEGER NOT NULL DEFAULT 0,
    failed_jobs     INTEGER NOT NULL DEFAULT 0,
    cancelled_jobs  INTEGER NOT NULL DEFAULT 0,
    status          TEXT    NOT NULL DEFAULT 'QUEUED',
    current_job_id  TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
"""

_CREATE_ANALYSIS_BATCH_JOBS = """
CREATE TABLE IF NOT EXISTS analysis_batch_jobs (
    job_id               TEXT    PRIMARY KEY,
    batch_id             TEXT    NOT NULL,
    filename             TEXT    NOT NULL,
    sha256               TEXT,
    queue_position       INTEGER NOT NULL,
    status               TEXT    NOT NULL DEFAULT 'QUEUED',
    progress_pct         INTEGER DEFAULT 0,
    current_stage        TEXT,
    created_at           TEXT    NOT NULL,
    started_at           TEXT,
    completed_at         TEXT,
    error                TEXT,
    case_sha256          TEXT,
    temp_path            TEXT,
    analyst_queue_job_id TEXT,
    FOREIGN KEY (batch_id) REFERENCES analysis_batches(batch_id)
);
"""


from app.db.pool import connect, init_pool, is_postgres

# Public alias. New persistence modules (security.py, intel.py) import this
# rather than reaching for the underscore-prefixed name, so that the pragma
# setup above stays the single place a connection is configured.
_connect = connect


# ─── Additive migrations ──────────────────────────────────────────────────────
#
# `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so it cannot add
# a column - a schema change would silently not apply to any database that
# already existed, and the first INSERT naming the new column would fail.
#
# The mechanism now lives in app.db.migrations, which keeps the same additive,
# no-framework approach and adds a `schema_migrations` ledger, ordering, and
# visible failure. `cases.raw_result` - the only migration this tuple used to
# carry - is version 0001 there, guarded by the same column-existence check, so
# a database that already has the column records the version and moves on.


async def init_db() -> Dict[str, Any]:
    """
    Create every table and index if absent, then run pending migrations.

    Order matters: CREATE first, migrate second. On a fresh database the CREATE
    statements build the base shape and the migrations then add the columns they
    own; on an existing one the CREATEs are no-ops and the migrations do the
    work. Columns introduced after a table's first release (users.is_active,
    cases.status, ...) are declared *only* in app.db.migrations, so there is one
    source of truth for them rather than two that can drift.

    Returns a diagnostics dict for the startup banner.
    """
    from app.db import intel, security
    from app.db.migrations import migration_status, run_migrations
    from app.db.artifact_metadata import init_artifact_metadata
    
    await init_pool()

    path = _active_db_path()
    async with _connect() as db:
        await db.execute(_CREATE_USERS)
        await db.execute(_CREATE_CASES)
        await db.execute(_CREATE_IOC_CACHE)
        await db.execute(_CREATE_NOTES)
        await db.execute(_CREATE_ANALYSIS_JOBS)
        await db.execute(_CREATE_DISCOVERY_SESSIONS)
        await db.execute(_CREATE_DISCOVERY_CANDIDATES)
        await db.execute(_CREATE_ANALYSIS_BATCHES)
        await db.execute(_CREATE_ANALYSIS_BATCH_JOBS)
        await security.create_tables(db)
        await intel.create_tables(db)

        # Migrations before indexes: an index can reference a column that a
        # migration is about to add, and on a pre-existing table the CREATE
        # above was a no-op that did not add it.
        applied = await run_migrations(db)

        for stmt in _CREATE_INDEXES:
            await db.execute(stmt)
        await security.create_indexes(db)
        await intel.create_indexes(db)
        await db.commit()

        status = await migration_status(db)

    # Must run outside of _connect since it manages its own transaction via get_db
    await init_artifact_metadata()

    if is_postgres():
        # `path` is the unused SQLite location; naming it here made the logs
        # claim SQLite while every query went to PostgreSQL.
        path = "postgresql (DATABASE_URL)"
    logger.info(
        "[DB] Initialized %s; migrations %d/%d applied%s",
        path if is_postgres() else f"SQLite at {path} (WAL, FK enforced, indexed)",
        len(status["applied"]), status["total"],
        f" (+{len(applied)} this boot)" if applied else "",
    )
    if status["unknown"]:
        logger.warning(
            "[DB] Ledger contains %d migration(s) this build does not know about "
            "(%s). The database was probably written by a newer deployment.",
            len(status["unknown"]), ", ".join(status["unknown"]),
        )
    return {"path": path, "migrations": status, "applied_this_boot": applied}



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
        if is_postgres():
            sql = """
                INSERT INTO cases
                  (sha256, package_name, app_name, analysis_mode, family_classification,
                   final_risk_score, risk_band, confidence, dynamic_available,
                   obfuscation_score, has_reflection, frs_breakdown,
                   threat_scenario_table, intelligence_report, analyst_id, created_at,
                   raw_result)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT (sha256) DO UPDATE SET
                   package_name = EXCLUDED.package_name,
                   app_name = EXCLUDED.app_name,
                   analysis_mode = EXCLUDED.analysis_mode,
                   family_classification = EXCLUDED.family_classification,
                   final_risk_score = EXCLUDED.final_risk_score,
                   risk_band = EXCLUDED.risk_band,
                   confidence = EXCLUDED.confidence,
                   dynamic_available = EXCLUDED.dynamic_available,
                   obfuscation_score = EXCLUDED.obfuscation_score,
                   has_reflection = EXCLUDED.has_reflection,
                   frs_breakdown = EXCLUDED.frs_breakdown,
                   threat_scenario_table = EXCLUDED.threat_scenario_table,
                   intelligence_report = EXCLUDED.intelligence_report,
                   analyst_id = EXCLUDED.analyst_id,
                   raw_result = EXCLUDED.raw_result
            """
        else:
            sql = """
                INSERT OR REPLACE INTO cases
                  (sha256, package_name, app_name, analysis_mode, family_classification,
                   final_risk_score, risk_band, confidence, dynamic_available,
                   obfuscation_score, has_reflection, frs_breakdown,
                   threat_scenario_table, intelligence_report, analyst_id, created_at,
                   raw_result)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """
        await db.execute(sql,
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

    await _sync_case_iocs(sha256, result)


async def _sync_case_iocs(sha256: str, result: Dict[str, Any]) -> None:
    """
    Mirror the result's indicators into the queryable `case_iocs` table.

    Runs on every save, which is safe because the upsert is idempotent -
    re-saving a case refreshes `last_seen` and leaves `first_seen` alone.
    save_case is also called after threat-intel re-enrichment on case open, and
    that is exactly when newly-resolved indicators should be picked up.

    Never raises: `raw_result` is the forensic record and it is already durably
    written by this point. Losing the searchable index is a degraded search, not
    a lost case.
    """
    try:
        from app.db.intel import upsert_case_iocs
        from app.services.ioc_extraction import extract_iocs

        iocs = extract_iocs(result)
        if iocs:
            await upsert_case_iocs(sha256, iocs)
            logger.debug("[DB] Indexed %d indicator(s) for %s…", len(iocs), sha256[:12])
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[DB] IOC indexing failed for %s… (%s); the case itself is saved and "
            "raw_result still holds every indicator.",
            sha256[:12], exc,
        )


# ─── Case lifecycle ──────────────────────────────────────────────────────────
#
# The analyst's judgement is stored in its OWN columns, never over the engine's.
# `final_risk_score`, `risk_band`, `frs_breakdown` (which carries STEI),
# `confidence` and everything inside `raw_result` are the deterministic output
# of the pipeline and are the evidence a case rests on; overwriting them with a
# human decision would destroy the record of what the system actually measured.
#
# So an analyst who marks a CRITICAL/94 sample as a false positive produces:
#     final_risk_score = 94.0        risk_band = CRITICAL      (engine, unchanged)
#     analyst_verdict  = FALSE_POSITIVE
#     verdict_reason   = "Known internal test APK"
# and both halves stay readable and attributable.

CASE_STATUSES = ("OPEN", "IN_REVIEW", "CLOSED", "FALSE_POSITIVE")
ANALYST_VERDICTS = ("CONFIRMED_MALICIOUS", "SUSPICIOUS", "BENIGN", "FALSE_POSITIVE", "INCONCLUSIVE")


async def set_case_status(
    sha256: str,
    status: str,
    closed: bool = False,
) -> bool:
    """Move a case through its lifecycle. Returns False if the case is unknown."""
    if status not in CASE_STATUSES:
        raise ValueError(f"status must be one of {CASE_STATUSES}")

    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        cur = await db.execute(
            "UPDATE cases SET status = ?, closed_at = ? WHERE sha256 = ?",
            (status, now if (closed or status in ("CLOSED", "FALSE_POSITIVE")) else None, sha256),
        )
        await db.commit()
        return cur.rowcount > 0


async def set_case_verdict(
    sha256: str,
    verdict: str,
    reason: str,
    set_by: int,
) -> bool:
    """Record an analyst verdict alongside - never instead of - the engine's."""
    if verdict not in ANALYST_VERDICTS:
        raise ValueError(f"verdict must be one of {ANALYST_VERDICTS}")

    async with _connect() as db:
        cur = await db.execute(
            "UPDATE cases SET analyst_verdict = ?, verdict_reason = ?, "
            "verdict_set_by = ?, verdict_set_at = ? WHERE sha256 = ?",
            (verdict, reason, set_by, datetime.now(timezone.utc).isoformat(), sha256),
        )
        await db.commit()
        return cur.rowcount > 0


async def assign_case(sha256: str, assignee_id: Optional[int]) -> bool:
    async with _connect() as db:
        cur = await db.execute(
            "UPDATE cases SET assigned_to = ? WHERE sha256 = ?", (assignee_id, sha256)
        )
        await db.commit()
        return cur.rowcount > 0


async def get_case(sha256: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single case by SHA256 (exact or prefix)."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM cases WHERE sha256 = ? OR sha256 LIKE ?", (sha256, f"{sha256}%")) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    return _row_to_case(dict(row))


def _case_filter_sql(
    analyst_id: Optional[int],
    q: Optional[str],
    band: Optional[str],
) -> tuple[str, list]:
    """
    Build the shared WHERE clause for the case registry.

    The history page used to filter the fifteen rows it had already fetched,
    so searching for a package that existed on page four returned "no cases
    found". Search and band filtering have to happen where the rows are, which
    is here; `list_cases` and `count_cases` share this so the pagination
    footer can never disagree with the table above it.
    """
    clauses: list[str] = []
    params: list = []

    if analyst_id is not None:
        clauses.append("(analyst_id = ? OR sha256 IN (SELECT sha256 FROM analysis_jobs WHERE analyst_id = ?))")
        params.extend([analyst_id, analyst_id])

    if q:
        needle = f"%{q.strip().lower()}%"
        clauses.append(
            "(LOWER(sha256) LIKE ?"
            " OR LOWER(COALESCE(package_name, '')) LIKE ?"
            " OR LOWER(COALESCE(app_name, '')) LIKE ?"
            " OR LOWER(COALESCE(family_classification, '')) LIKE ?)"
        )
        params.extend([needle] * 4)

    if band and band.lower() != "all":
        clauses.append("LOWER(COALESCE(risk_band, '')) = ?")
        params.append(band.strip().lower())

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


async def list_cases(
    limit: int = 50,
    offset: int = 0,
    analyst_id: Optional[int] = None,
    q: Optional[str] = None,
    band: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return paginated list of cases, newest first."""
    where, params = _case_filter_sql(analyst_id, q, band)
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        sql = f"SELECT * FROM cases{where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        async with db.execute(sql, (*params, limit, offset)) as cur:
            rows = await cur.fetchall()
    return [_row_to_case(dict(r)) for r in rows]


async def count_cases(
    analyst_id: Optional[int] = None,
    q: Optional[str] = None,
    band: Optional[str] = None,
) -> int:
    where, params = _case_filter_sql(analyst_id, q, band)
    async with _connect() as db:
        async with db.execute(f"SELECT COUNT(*) FROM cases{where}", params) as cur:
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
        return _with_lifecycle_defaults(row)

    merged = dict(raw)
    # Summary columns win: they are the indexed, queryable truth.
    merged.update({k: v for k, v in row.items() if v is not None})
    return _with_lifecycle_defaults(merged)


# Lifecycle columns are NULL until an analyst acts, and the merge above drops
# NULLs so that an unset column cannot blank a value carried in raw_result.
# These fields never appear in raw_result - the engine does not produce them -
# so there is nothing to protect, and dropping them instead makes a caller
# guess whether a missing key means "unset" or "not supported". Always present,
# explicitly null.
_LIFECYCLE_FIELDS = (
    "status", "assigned_to", "closed_at",
    "analyst_verdict", "verdict_reason", "verdict_set_by", "verdict_set_at",
)


def _with_lifecycle_defaults(case: Dict[str, Any]) -> Dict[str, Any]:
    for field in _LIFECYCLE_FIELDS:
        case.setdefault(field, "OPEN" if field == "status" else None)
    return case


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
        if is_postgres():
            sql = """
                INSERT INTO ioc_cache
                  (indicator, ioc_type, reputation, source, threat_score, raw_data, cached_at, expires_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT (indicator, ioc_type) DO UPDATE SET
                  reputation = EXCLUDED.reputation,
                  source = EXCLUDED.source,
                  threat_score = EXCLUDED.threat_score,
                  raw_data = EXCLUDED.raw_data,
                  cached_at = EXCLUDED.cached_at,
                  expires_at = EXCLUDED.expires_at
            """
        else:
            sql = """
                INSERT OR REPLACE INTO ioc_cache
                  (indicator, ioc_type, reputation, source, threat_score, raw_data, cached_at, expires_at)
                VALUES (?,?,?,?,?,?,?,?)
            """
        await db.execute(sql,
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
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute(
                "INSERT INTO users (username, hashed_pw, role, created_at) VALUES (?,?,?,?) RETURNING id",
                (username, hashed_pw, role, now),
            )
            row = await cur.fetchone()
            await db.commit()
            return row["id"] if row else None
        else:
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


async def set_user_active(user_id: int, is_active: bool) -> None:
    """
    Enable or disable an account.

    Disabling stops future logins and is checked on every authenticated request,
    but it does not by itself invalidate tokens already issued - the caller must
    also revoke the user's sessions. app.auth.auth.set_user_active_state does
    both.
    """
    async with _connect() as db:
        await db.execute(
            "UPDATE users SET is_active=? WHERE id=?", (1 if is_active else 0, user_id)
        )
        await db.commit()


async def touch_last_login(user_id: int) -> None:
    async with _connect() as db:
        await db.execute(
            "UPDATE users SET last_login_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), user_id),
        )
        await db.commit()


async def set_password(user_id: int, hashed_pw: str, must_change: bool = False) -> None:
    """Replace a password hash and stamp when it changed."""
    async with _connect() as db:
        await db.execute(
            "UPDATE users SET hashed_pw=?, password_changed_at=?, must_change_password=? "
            "WHERE id=?",
            (hashed_pw, datetime.now(timezone.utc).isoformat(),
             1 if must_change else 0, user_id),
        )
        await db.commit()


async def list_users(limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    """Admin user listing. Never returns hashed_pw."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, username, role, created_at, is_active, last_login_at "
            "FROM users ORDER BY id ASC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def username_exists(username: str) -> bool:
    async with _connect() as db:
        async with db.execute("SELECT id FROM users WHERE username=?", (username,)) as cur:
            return await cur.fetchone() is not None


# ─── Case Notes ───────────────────────────────────────────────────────────────

async def add_case_note(sha256: str, text: str, author: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute(
                "INSERT INTO case_notes (sha256, text, author, created_at) VALUES (?,?,?,?) RETURNING id",
                (sha256, text, author, now),
            )
            row = await cur.fetchone()
            row_id = row["id"] if row else None
        else:
            cur = await db.execute(
                "INSERT INTO case_notes (sha256, text, author, created_at) VALUES (?,?,?,?)",
                (sha256, text, author, now),
            )
            row_id = cur.lastrowid
        await db.commit()
        return {"id": row_id, "sha256": sha256, "text": text, "author": author, "created_at": now}


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
                completed_at, result_json, error, canonical_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                status=excluded.status,
                sha256=excluded.sha256,
                analyst_id=excluded.analyst_id,
                started_at=excluded.started_at,
                completed_at=excluded.completed_at,
                result_json=excluded.result_json,
                error=excluded.error,
                canonical_fingerprint=excluded.canonical_fingerprint
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
                job.get("canonical_fingerprint")
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
    # This function had no return statement: it decoded result_json and then fell
    # off the end, so every caller got None. get_job() falls back to it whenever
    # the job is not in the in-memory _jobs dict - after a backend restart, or
    # once retention has evicted it - so GET /status/<job_id> answered 404 for
    # jobs that were sitting in the table with status 'done'. The row is only
    # useful rehydrated into the shape the worker and the status route expect.
    data["result"] = result
    data.pop("result_json", None)
    # Live pipeline telemetry is in-memory only; a rehydrated job is either
    # finished or was interrupted, so report terminal progress rather than 0%.
    data.setdefault("progress_pct", 100 if data.get("status") == "done" else 0)
    data.setdefault("pipeline_stage", "COMPLETED" if data.get("status") == "done" else "")
    data.setdefault("pipeline_substage", "")
    data.setdefault("pipeline_message", "")
    data.setdefault("elapsed_ms", 0)
    data.setdefault("stage_timings", [])
    return data

# ─── Durable Canonical Analysis (Phase 5) ────────────────────────────────────

async def get_canonical_analysis(fingerprint: str) -> Optional[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM canonical_analyses WHERE fingerprint = ?", (fingerprint,)
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    data = dict(row)
    if data.get("result_json"):
        try:
            data["result"] = json.loads(data["result_json"])
        except json.JSONDecodeError:
            pass
        data.pop("result_json", None)
    return data

async def upsert_canonical_analysis(analysis: Dict[str, Any]) -> None:
    result_json = None
    if analysis.get("result") is not None:
        result_json = json.dumps(analysis["result"])
    async with _connect() as db:
        await db.execute(
            """
            INSERT INTO canonical_analyses (
                fingerprint, sha256, status, progress_pct, current_stage,
                result_json, error, claimed_by, claimed_at,
                lease_expires_at, last_heartbeat_at, attempt_count, max_attempts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                status=excluded.status,
                progress_pct=excluded.progress_pct,
                current_stage=excluded.current_stage,
                result_json=excluded.result_json,
                error=excluded.error,
                claimed_by=excluded.claimed_by,
                claimed_at=excluded.claimed_at,
                lease_expires_at=excluded.lease_expires_at,
                last_heartbeat_at=excluded.last_heartbeat_at,
                attempt_count=excluded.attempt_count
            """,
            (
                analysis["fingerprint"],
                analysis["sha256"],
                analysis["status"],
                analysis.get("progress_pct", 0),
                analysis.get("current_stage"),
                result_json,
                analysis.get("error"),
                analysis.get("claimed_by"),
                analysis.get("claimed_at"),
                analysis.get("lease_expires_at"),
                analysis.get("last_heartbeat_at"),
                analysis.get("attempt_count", 0),
                analysis.get("max_attempts", 3),
            ),
        )
        await db.commit()

async def update_canonical_analysis(fingerprint: str, updates: Dict[str, Any]) -> None:
    allowed = {
        "status", "progress_pct", "current_stage", "error", 
        "claimed_by", "claimed_at", "lease_expires_at", "last_heartbeat_at", 
        "attempt_count", "result_json"
    }
    safe = {k: v for k, v in updates.items() if k in allowed}
    if "result" in updates:
        safe["result_json"] = json.dumps(updates["result"])
    if not safe:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe)
    values = list(safe.values()) + [fingerprint]
    async with _connect() as db:
        await db.execute(
            f"UPDATE canonical_analyses SET {set_clause} WHERE fingerprint = ?", values
        )
        await db.commit()

async def get_analysis_jobs_by_canonical(fingerprint: str) -> List[Dict[str, Any]]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_jobs WHERE canonical_fingerprint = ?", (fingerprint,)
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]

async def claim_next_canonical_job(worker_id: str, lease_seconds: int = 900) -> Optional[Dict[str, Any]]:
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    lease_expires = (now + timedelta(seconds=lease_seconds)).isoformat()

    async with _connect() as db:
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute("""
                UPDATE canonical_analyses
                SET status = 'PROCESSING',
                    claimed_by = ?,
                    claimed_at = ?,
                    last_heartbeat_at = ?,
                    lease_expires_at = ?,
                    attempt_count = attempt_count + 1
                WHERE fingerprint = (
                    SELECT fingerprint
                    FROM canonical_analyses
                    WHERE status = 'QUEUED' 
                       OR (status = 'PROCESSING' AND lease_expires_at < ?)
                       OR (status = 'RETRYING' AND attempt_count < max_attempts)
                    ORDER BY attempt_count ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING fingerprint
            """, (worker_id, now_iso, now_iso, lease_expires, now_iso))
            row = await cur.fetchone()
            if row:
                await db.commit()
                return await get_canonical_analysis(row[0])
            return None
        else:
            await db.execute("BEGIN IMMEDIATE")
            try:
                cur = await db.execute("""
                    SELECT fingerprint FROM canonical_analyses
                    WHERE status = 'QUEUED'
                       OR (status = 'PROCESSING' AND lease_expires_at < ?)
                       OR (status = 'RETRYING' AND attempt_count < max_attempts)
                    ORDER BY attempt_count ASC
                    LIMIT 1
                """, (now_iso,))
                row = await cur.fetchone()
                if row:
                    fp = row[0]
                    await db.execute("""
                        UPDATE canonical_analyses 
                        SET status = 'PROCESSING', claimed_by = ?, claimed_at = ?, 
                            last_heartbeat_at = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
                        WHERE fingerprint = ?
                    """, (worker_id, now_iso, now_iso, lease_expires, fp))
                    await db.commit()
                    return await get_canonical_analysis(fp)
                else:
                    await db.rollback()
                    return None
            except Exception:
                await db.rollback()
                raise

async def heartbeat_canonical_job(fingerprint: str, lease_seconds: int = 900) -> None:
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    lease_expires = (now + timedelta(seconds=lease_seconds)).isoformat()
    now_iso = now.isoformat()
    async with _connect() as db:
        await db.execute("""
            UPDATE canonical_analyses
            SET last_heartbeat_at = ?, lease_expires_at = ?
            WHERE fingerprint = ? AND status = 'PROCESSING'
        """, (now_iso, lease_expires, fingerprint))
        await db.commit()



# ─── Discovery State ────────────────────────────────────────────────────────

async def save_discovery_session(session: Dict[str, Any]) -> None:
    async with _connect() as db:
        if is_postgres():
            sql = """
                INSERT INTO discovery_sessions
                (id, target_url, domain, status, pages_scanned, error, created_at, updated_at, progress_logs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    target_url = EXCLUDED.target_url,
                    domain = EXCLUDED.domain,
                    status = EXCLUDED.status,
                    pages_scanned = EXCLUDED.pages_scanned,
                    error = EXCLUDED.error,
                    created_at = EXCLUDED.created_at,
                    updated_at = EXCLUDED.updated_at,
                    progress_logs = EXCLUDED.progress_logs
            """
        else:
            sql = """
                INSERT OR REPLACE INTO discovery_sessions
                (id, target_url, domain, status, pages_scanned, error, created_at, updated_at, progress_logs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        await db.execute(sql,
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
        if is_postgres():
            sql = """
                INSERT INTO discovery_candidates
                (id, session_id, source_url, discovery_url, filename, source_type, package_id, 
                 download_status, validation_status, sha256, size, storage_path, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET
                    session_id = EXCLUDED.session_id,
                    source_url = EXCLUDED.source_url,
                    discovery_url = EXCLUDED.discovery_url,
                    filename = EXCLUDED.filename,
                    source_type = EXCLUDED.source_type,
                    package_id = EXCLUDED.package_id,
                    download_status = EXCLUDED.download_status,
                    validation_status = EXCLUDED.validation_status,
                    sha256 = EXCLUDED.sha256,
                    size = EXCLUDED.size,
                    storage_path = EXCLUDED.storage_path,
                    error = EXCLUDED.error,
                    created_at = EXCLUDED.created_at
            """
        else:
            sql = """
                INSERT OR REPLACE INTO discovery_candidates
                (id, session_id, source_url, discovery_url, filename, source_type, package_id, 
                 download_status, validation_status, sha256, size, storage_path, error, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        await db.execute(sql,
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


# ─── Enterprise Batch Scan CRUD ───────────────────────────────────────────────

async def create_batch(batch_id: str, created_by: int, total_jobs: int) -> None:
    """Persist a new batch record."""
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        await db.execute(
            """
            INSERT INTO analysis_batches
              (batch_id, created_by, created_at, total_jobs, status)
            VALUES (?, ?, ?, ?, 'QUEUED')
            """,
            (batch_id, created_by, now, total_jobs),
        )
        await db.commit()
    logger.info(f"[DB] Batch created: {batch_id} ({total_jobs} jobs)")


async def get_batch(batch_id: str) -> Optional[Dict[str, Any]]:
    """Return a single batch record or None."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_batches WHERE batch_id = ?", (batch_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def list_batches(
    limit: int = 20,
    offset: int = 0,
    created_by: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return paginated batch records, newest first."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        if created_by is not None:
            sql = (
                "SELECT * FROM analysis_batches WHERE created_by = ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?"
            )
            params = (created_by, limit, offset)
        else:
            sql = "SELECT * FROM analysis_batches ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params = (limit, offset)
        async with db.execute(sql, params) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def count_batches(created_by: Optional[int] = None) -> int:
    """Count total batches, optionally scoped to an analyst."""
    async with _connect() as db:
        if created_by is not None:
            async with db.execute(
                "SELECT COUNT(*) FROM analysis_batches WHERE created_by = ?", (created_by,)
            ) as cur:
                row = await cur.fetchone()
        else:
            async with db.execute("SELECT COUNT(*) FROM analysis_batches") as cur:
                row = await cur.fetchone()
    return row[0] if row else 0


async def update_batch(batch_id: str, updates: Dict[str, Any]) -> None:
    """
    Partial update on analysis_batches.
    `updates` is a dict of column→value pairs. Only whitelisted columns
    are applied to prevent injection via caller-controlled keys.
    """
    allowed = {
        "status", "started_at", "completed_at",
        "completed_jobs", "failed_jobs", "cancelled_jobs",
        "current_job_id", "total_jobs",
    }
    safe = {k: v for k, v in updates.items() if k in allowed}
    if not safe:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe)
    values = list(safe.values()) + [batch_id]
    async with _connect() as db:
        await db.execute(
            f"UPDATE analysis_batches SET {set_clause} WHERE batch_id = ?", values
        )
        await db.commit()


async def create_batch_job(job: Dict[str, Any]) -> None:
    """Persist a new batch job record."""
    async with _connect() as db:
        await db.execute(
            """
            INSERT INTO analysis_batch_jobs
              (job_id, batch_id, filename, sha256, queue_position,
               status, created_at, temp_path)
            VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?)
            """,
            (
                job["job_id"],
                job["batch_id"],
                job["filename"],
                job.get("sha256"),
                job["queue_position"],
                job["created_at"],
                job.get("temp_path"),
            ),
        )
        await db.commit()


async def get_batch_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Return a single batch job record."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_batch_jobs WHERE job_id = ?", (job_id,)
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def get_batch_jobs(batch_id: str, limit: int = 10000, offset: int = 0) -> List[Dict[str, Any]]:
    """Return all jobs for a batch, ordered by queue_position."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_batch_jobs WHERE batch_id = ? ORDER BY queue_position ASC LIMIT ? OFFSET ?",
            (batch_id, limit, offset),
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def get_next_queued_batch_job(batch_id: str) -> Optional[Dict[str, Any]]:
    """Return the lowest-queue_position QUEUED job for a batch (FIFO)."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """
            SELECT * FROM analysis_batch_jobs
            WHERE batch_id = ? AND status = 'QUEUED'
            ORDER BY queue_position ASC
            LIMIT 1
            """,
            (batch_id,),
        ) as cur:
            row = await cur.fetchone()
    return dict(row) if row else None


async def update_batch_job(job_id: str, updates: Dict[str, Any]) -> None:
    """
    Partial update on analysis_batch_jobs.
    Only whitelisted columns are applied.
    """
    allowed = {
        "status", "started_at", "completed_at", "error",
        "case_sha256", "progress_pct", "current_stage",
        "analyst_queue_job_id", "sha256", "temp_path",
    }
    safe = {k: v for k, v in updates.items() if k in allowed}
    if not safe:
        return
    set_clause = ", ".join(f"{k} = ?" for k in safe)
    values = list(safe.values()) + [job_id]
    async with _connect() as db:
        await db.execute(
            f"UPDATE analysis_batch_jobs SET {set_clause} WHERE job_id = ?", values
        )
        await db.commit()


async def cancel_queued_batch_jobs(batch_id: str) -> int:
    """Set all QUEUED jobs in a batch to CANCELLED. Returns the count cancelled."""
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        cur = await db.execute(
            """
            UPDATE analysis_batch_jobs
            SET status = 'CANCELLED', completed_at = ?, current_stage = 'CANCELLED'
            WHERE batch_id = ? AND status = 'QUEUED'
            """,
            (now, batch_id),
        )
        count = cur.rowcount
        await db.commit()
    return count


async def cancel_all_batch_jobs(batch_id: str) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Cancel both QUEUED and SCANNING jobs in a batch.
    Returns (total_count_cancelled, list_of_scanning_jobs_cancelled).
    """
    now = datetime.now(timezone.utc).isoformat()
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        # Fetch scanning jobs before cancelling so caller can abort running tasks
        async with db.execute(
            "SELECT * FROM analysis_batch_jobs WHERE batch_id = ? AND status = 'SCANNING'",
            (batch_id,),
        ) as cur:
            scanning_rows = await cur.fetchall()
            scanning_jobs = [dict(r) for r in scanning_rows]

        cur = await db.execute(
            """
            UPDATE analysis_batch_jobs
            SET status = 'CANCELLED', completed_at = ?, current_stage = 'CANCELLED'
            WHERE batch_id = ? AND status IN ('QUEUED', 'SCANNING')
            """,
            (now, batch_id),
        )
        total_count = cur.rowcount
        await db.commit()

    return total_count, scanning_jobs


async def get_active_batches() -> List[Dict[str, Any]]:
    """Return all batches in QUEUED or RUNNING state (for worker recovery on startup)."""
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_batches WHERE status IN ('QUEUED', 'RUNNING', 'PAUSED') ORDER BY created_at ASC"
        ) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]

async def count_pending_jobs() -> int:
    async with _connect() as db:
        async with db.execute("SELECT COUNT(*) FROM analysis_jobs WHERE status IN ('queued', 'QUEUED', 'processing', 'PROCESSING')") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

async def count_user_jobs_today(analyst_id: int) -> int:
    from datetime import datetime, timezone, timedelta
    start_of_day = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    async with _connect() as db:
        async with db.execute("SELECT COUNT(*) FROM analysis_jobs WHERE analyst_id = ? AND queued_at >= ?", (analyst_id, start_of_day)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0

async def reserve_job_slot_atomically(job_id: str, analyst_id: int, user_quota: int, max_queue: int) -> str:
    """
    Atomically checks queue and user quotas, and reserves a job slot if allowed.
    Returns:
        "OK" if reserved.
        "QUEUE_FULL" if system max queue reached.
        "QUOTA_EXCEEDED" if user quota reached.
    """
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc).isoformat()
    start_of_day = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    
    # First we do a quick read to give the specific error (since atomic insert fails silently on both)
    q_count = await count_pending_jobs()
    if q_count >= max_queue:
        return "QUEUE_FULL"
    u_count = await count_user_jobs_today(analyst_id)
    if u_count >= user_quota:
        return "QUOTA_EXCEEDED"
        
    async with _connect() as db:
        # Atomic insert
        sql = """
        INSERT INTO analysis_jobs (job_id, status, analyst_id, queued_at)
        SELECT ?, 'UPLOADING', ?, ?
        WHERE (
            SELECT COUNT(*) FROM analysis_jobs WHERE status IN ('QUEUED', 'PROCESSING', 'UPLOADING')
        ) < ?
        AND (
            SELECT COUNT(*) FROM analysis_jobs WHERE analyst_id = ? AND queued_at >= ?
        ) < ?
        """
        params = (job_id, analyst_id, now, max_queue, analyst_id, start_of_day, user_quota)
        async with db.execute(sql, params) as cursor:
            if cursor.rowcount == 0:
                # One of the limits was hit during the race window
                # Do a fresh read to return the correct error
                if await count_pending_jobs() >= max_queue:
                    return "QUEUE_FULL"
                return "QUOTA_EXCEEDED"
                
        await db.commit()
    return "OK"

