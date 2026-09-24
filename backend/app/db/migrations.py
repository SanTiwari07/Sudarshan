"""
Schema migrations.
==================

The project already had a hand-written additive mechanism: a tuple of
``(table, column, ALTER statement)`` triples, applied by reading
``PRAGMA table_info`` and adding the column if it was missing. That was correct
for the one migration it carried, but it had no ordering, no record of what had
run, and no way to express anything other than ADD COLUMN.

This keeps the same spirit - plain SQL, no framework, no SQLAlchemy - and adds
the three things it was missing:

  * a ledger (``schema_migrations``) so each version runs once and the applied
    set is inspectable,
  * ordered, named migrations that can carry any statement, not just ADD COLUMN,
  * loud failure: a broken migration aborts startup with the version in the
    message, instead of leaving a half-migrated database running.

Two rules for anything added here
---------------------------------
1. **Never destructive.** No DROP, no DELETE, no type rewrites. SQLite cannot
   roll those back safely on a live file, and this database holds forensic
   evidence.
2. **Independently idempotent.** Do not rely on the ledger alone. Existing
   installs already have ``cases.raw_result`` applied by the previous mechanism
   and no ledger row to show for it, so version 0001 must be a no-op there
   rather than an error. Every migration below re-checks the actual schema.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, NamedTuple, Sequence, Set

import aiosqlite

logger = logging.getLogger(__name__)


_CREATE_LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at  TEXT NOT NULL
);
"""


class Migration(NamedTuple):
    version: str
    description: str
    # Receives an open connection. Must be safe to run against a database where
    # the change is already present.
    apply: Callable[[aiosqlite.Connection], Any]


# ─── Helpers for writing migrations ──────────────────────────────────────────

async def _columns(db: aiosqlite.Connection, table: str) -> Set[str]:
    from app.db.pool import is_postgres
    if is_postgres():
        async with db.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = $1", (table,)
        ) as cur:
            return {row["column_name"] for row in await cur.fetchall()}
    else:
        async with db.execute(f"PRAGMA table_info({table})") as cur:
            return {row[1] for row in await cur.fetchall()}


async def _table_exists(db: aiosqlite.Connection, table: str) -> bool:
    from app.db.pool import is_postgres
    if is_postgres():
        async with db.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name = $1", (table,)
        ) as cur:
            return await cur.fetchone() is not None
    else:
        async with db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ) as cur:
            return await cur.fetchone() is not None


def add_columns(table: str, columns: Sequence[tuple]) -> Callable:
    """
    Build an apply-fn that adds each missing column.

    `columns` is a sequence of (name, column_definition) pairs, e.g.
    ("is_active", "INTEGER NOT NULL DEFAULT 1").

    SQLite's ADD COLUMN cannot take a non-constant DEFAULT, so defaults here
    must be literals. Existing rows take the default, which is why every column
    added to a populated table needs one that is correct for historical rows.
    """
    async def _apply(db: aiosqlite.Connection) -> None:
        if not await _table_exists(db, table):
            # init_db's CREATE TABLE IF NOT EXISTS already declares these
            # columns on a fresh database, so there is nothing to migrate.
            return
        existing = await _columns(db, table)
        for name, definition in columns:
            if name in existing:
                continue
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
            logger.info("[DB] migration: %s.%s added", table, name)

    return _apply


def run_sql(*statements: str) -> Callable:
    """Build an apply-fn that runs statements verbatim. Each must be IF-NOT-EXISTS safe."""
    async def _apply(db: aiosqlite.Connection) -> None:
        for stmt in statements:
            await db.execute(stmt)

    return _apply


# ─── The migration list ───────────────────────────────────────────────────────
#
# Append only. Never renumber, never edit an applied version in place - a
# database that already recorded it will not re-run it.

MIGRATIONS: List[Migration] = [
    Migration(
        "0001_cases_raw_result",
        "Store the full analysis result alongside the typed summary columns",
        add_columns("cases", [("raw_result", "TEXT")]),
    ),
    Migration(
        "0002_users_security_columns",
        "Account state needed for session revocation and lockout",
        add_columns("users", [
            # Historical rows predate the concept, and every one of them belongs
            # to an account that was usable, so the default has to be 'active'.
            ("is_active", "INTEGER NOT NULL DEFAULT 1"),
            ("last_login_at", "TEXT"),
            ("password_changed_at", "TEXT"),
            ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ]),
    ),
    Migration(
        "0003_case_lifecycle",
        "Analyst decision, stored separately from the engine's deterministic verdict",
        add_columns("cases", [
            ("status", "TEXT NOT NULL DEFAULT 'OPEN'"),
            ("assigned_to", "INTEGER"),
            ("closed_at", "TEXT"),
            ("analyst_verdict", "TEXT"),
            ("verdict_reason", "TEXT"),
            ("verdict_set_by", "INTEGER"),
            ("verdict_set_at", "TEXT"),
        ]),
    ),
    Migration(
        "0004_case_notes_index",
        "case_notes was full-scanned on every case open",
        run_sql("CREATE INDEX IF NOT EXISTS idx_case_notes_sha256 ON case_notes(sha256, id)"),
    ),
    Migration(
        "0005_analysis_runs_provenance",
        "Mark pre-existing analysis_runs rows as placeholders and link them to cases",
        add_columns("analysis_runs", [
            # Every historical row was written with apk_sha256='unknown',
            # bfci_score=0.0 and empty JSON columns. They are not real
            # measurements and must never be compared against real ones.
            ("is_placeholder", "INTEGER NOT NULL DEFAULT 0"),
            ("sha256", "TEXT"),
            ("frs_score", "REAL"),
            ("stei_score", "REAL"),
            ("risk_band", "TEXT"),
            ("dynamic_status", "TEXT"),
            ("status", "TEXT"),
            ("started_at", "TEXT"),
            ("completed_at", "TEXT"),
            ("analysis_mode", "TEXT"),
        ]),
    ),
    Migration(
        "0006_backfill_placeholder_runs",
        "Flag the historical placeholder analysis_runs rows",
        run_sql(
            # An UPDATE, not a DELETE: the rows are preserved, just labelled
            # honestly so compare_runs() can exclude them.
            "UPDATE analysis_runs SET is_placeholder = 1 "
            "WHERE is_placeholder = 0 AND (apk_sha256 IS NULL OR apk_sha256 = 'unknown')"
        ),
    ),
    Migration(
        "0007_durable_queue",
        "Create canonical_analyses for deduplication and durable worker queueing",
        # Use an async def to wrap multiple statements, or just do it inside
        lambda db: _run_0007_migration(db)
    ),
    Migration(
        "0008_queue_indexes",
        "Add indexes to canonical_analyses and analysis_jobs to speed up queue polling and mapping",
        lambda db: _run_0008_migration(db)
    ),
]

async def _run_0008_migration(db):
    await db.execute("CREATE INDEX IF NOT EXISTS idx_canonical_queue ON canonical_analyses(status, attempt_count, lease_expires_at)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_analysis_jobs_canonical ON analysis_jobs(canonical_fingerprint)")

async def _run_0007_migration(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS canonical_analyses (
            fingerprint TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            status TEXT NOT NULL,
            progress_pct INTEGER DEFAULT 0,
            current_stage TEXT,
            result_json TEXT,
            error TEXT,
            claimed_by TEXT,
            claimed_at TEXT,
            lease_expires_at TEXT,
            last_heartbeat_at TEXT,
            attempt_count INTEGER DEFAULT 0,
            max_attempts INTEGER DEFAULT 3
        )
        """
    )
    # add_columns logic handles checking if column exists
    from app.db.pool import is_postgres
    if is_postgres():
        # Postgres add column
        try:
            await db.execute("ALTER TABLE analysis_jobs ADD COLUMN canonical_fingerprint TEXT")
        except Exception as e:
            if "already exists" not in str(e):
                raise
    else:
        # SQLite
        cur = await db.execute("PRAGMA table_info(analysis_jobs)")
        columns = [row[1] for row in await cur.fetchall()]
        if "canonical_fingerprint" not in columns:
            await db.execute("ALTER TABLE analysis_jobs ADD COLUMN canonical_fingerprint TEXT")


# ─── Runner ───────────────────────────────────────────────────────────────────

async def applied_versions(db: aiosqlite.Connection) -> Set[str]:
    await db.execute(_CREATE_LEDGER)
    async with db.execute("SELECT version FROM schema_migrations") as cur:
        return {row[0] for row in await cur.fetchall()}


async def run_migrations(db: aiosqlite.Connection) -> List[str]:
    """
    Apply every unapplied migration in order. Returns the versions applied.

    Each migration commits individually: a failure leaves earlier migrations
    durably applied and stops, rather than silently continuing with a partial
    schema. The exception propagates so startup fails visibly.
    """
    done = await applied_versions(db)
    newly_applied: List[str] = []

    for mig in MIGRATIONS:
        if mig.version in done:
            continue
        try:
            await mig.apply(db)
            from app.db.pool import is_postgres
            if is_postgres():
                await db.execute(
                    "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?,?,?) ON CONFLICT (version) DO UPDATE SET description=EXCLUDED.description, applied_at=EXCLUDED.applied_at",
                    (mig.version, mig.description, datetime.now(timezone.utc).isoformat()),
                )
            else:
                await db.execute(
                    "INSERT OR REPLACE INTO schema_migrations (version, description, applied_at) "
                    "VALUES (?,?,?)",
                    (mig.version, mig.description, datetime.now(timezone.utc).isoformat()),
                )
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error(
                "[DB] MIGRATION FAILED at %s (%s): %s",
                mig.version, mig.description, exc,
            )
            raise RuntimeError(
                f"Database migration {mig.version} failed: {exc}. "
                f"The database has been left at the last successfully applied "
                f"version; no data was modified by the failed step."
            ) from exc

        newly_applied.append(mig.version)
        logger.info("[DB] migration applied: %s - %s", mig.version, mig.description)

    return newly_applied


async def migration_status(db: aiosqlite.Connection) -> Dict[str, Any]:
    """Applied/pending breakdown, for the startup banner and health endpoint."""
    done = await applied_versions(db)
    known = {m.version for m in MIGRATIONS}
    return {
        "total": len(MIGRATIONS),
        "applied": sorted(done & known),
        "pending": [m.version for m in MIGRATIONS if m.version not in done],
        # A version in the ledger that this build does not know about means the
        # database was written by a newer deployment. Worth surfacing.
        "unknown": sorted(done - known),
    }
