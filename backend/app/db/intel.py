"""
Investigation persistence: analysis runs, IOC relationships, chat, exports,
runtime evidence metadata.
==========================================================================

Everything here follows one rule: **the database holds searchable metadata, the
artifact store holds the forensic payload.**

`cases.raw_result` keeps the complete analysis result and is not touched by any
of this. These tables exist because a JSON blob cannot answer relational
questions - "which other cases contacted this C2", "how did this package's
score move between runs" - and those are exactly the questions an analyst
asks. The blob stays authoritative for evidence; these tables make it queryable.
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

# Historically created by shared/sudarshan_core/engines/analysis_history.py in
# whatever directory the sandbox happened to be running from, using synchronous
# sqlite3 with no busy_timeout. The original columns are preserved verbatim so
# that an existing file is adopted rather than rebuilt; migration 0005 adds the
# rest, and 0006 flags the historical rows as placeholders.
_CREATE_ANALYSIS_RUNS = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name     TEXT    NOT NULL,
    apk_sha256       TEXT    NOT NULL,
    run_timestamp    TEXT    NOT NULL,
    stage_name       TEXT    DEFAULT 'single',
    duration_seconds INTEGER,
    bfci_score       REAL,
    bfci_components  TEXT,   -- JSON
    mitre_techniques TEXT,   -- JSON array
    ioc_count        INTEGER DEFAULT 0,
    screenshot_count INTEGER DEFAULT 0,
    yara_matches     TEXT,   -- JSON
    anti_analysis    TEXT,   -- JSON
    explorer_mode    TEXT,
    -- Added by migration 0005; declared here so a fresh database matches.
    is_placeholder   INTEGER NOT NULL DEFAULT 0,
    sha256           TEXT,
    frs_score        REAL,
    stei_score       REAL,
    risk_band        TEXT,
    dynamic_status   TEXT,
    status           TEXT,
    started_at       TEXT,
    completed_at     TEXT,
    analysis_mode    TEXT
);
"""

# No FK to cases(sha256). A run is recorded by the sandbox as the analysis
# finishes, which is *before* upload.py writes the case row - a FK would make
# the insert fail exactly when there is something to record. The relationship
# is enforced by the query side instead (see runs_for_case).
_CREATE_CASE_IOCS = """
CREATE TABLE IF NOT EXISTS case_iocs (
    sha256      TEXT NOT NULL,
    indicator   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,   -- domain | ip | url | email | sha256 | package
    context     TEXT,            -- where in the sample it came from
    source      TEXT,            -- static | dynamic | correlation
    reputation  TEXT,
    confidence  REAL,
    first_seen  TEXT,
    last_seen   TEXT,
    PRIMARY KEY (sha256, indicator, ioc_type),
    FOREIGN KEY (sha256) REFERENCES cases(sha256) ON DELETE CASCADE
);
"""

_CREATE_CHAT_MESSAGES = """
CREATE TABLE IF NOT EXISTS chat_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        TEXT    NOT NULL,
    user_id       INTEGER,
    role          TEXT    NOT NULL,   -- user | assistant
    content       TEXT    NOT NULL,
    sections_used TEXT,               -- JSON: which RAG sections grounded the answer
    created_at    TEXT    NOT NULL,
    FOREIGN KEY (sha256) REFERENCES cases(sha256) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
"""

_CREATE_EXPORT_EVENTS = """
CREATE TABLE IF NOT EXISTS export_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT    NOT NULL,
    user_id      INTEGER,
    username     TEXT,
    export_type  TEXT    NOT NULL,   -- pdf | stix | iocs_csv | yara | mitre | ...
    status       TEXT    NOT NULL,   -- SUCCESS | FAILED
    artifact_ref TEXT,               -- path/reference, never the payload itself
    byte_size    INTEGER,
    ip           TEXT,
    created_at   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
"""

# Deliberately narrow. A dynamic run emits thousands of events, and the full
# payload of each already lives in the per-session evidence store
# (shared/sudarshan_core/engines/evidence_store.py writes a WAL SQLite file per
# case under artifacts/evidence/). Copying those blobs into the gateway
# database would multiply its size for no query benefit. This table is the
# index into them: enough to filter and count, plus a reference to the payload.
_CREATE_RUNTIME_EVENTS = """
CREATE TABLE IF NOT EXISTS runtime_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT    NOT NULL,
    job_id      TEXT,
    seq         INTEGER,
    event_type  TEXT,
    severity    TEXT,
    ts          TEXT    NOT NULL,
    evidence_id TEXT,              -- EVID-NNN in the per-session evidence store
    payload_ref TEXT,              -- path to that store, or to an artifact file
    summary     TEXT               -- short human-readable line, not the payload
);
"""

_INDEXES = (
    # compare_runs filters by package and orders by time.
    "CREATE INDEX IF NOT EXISTS idx_runs_package ON analysis_runs(package_name, run_timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_runs_sha     ON analysis_runs(sha256, run_timestamp DESC);",

    # The pivot that was impossible before: indicator → every case that saw it.
    "CREATE INDEX IF NOT EXISTS idx_case_iocs_indicator ON case_iocs(indicator, ioc_type);",
    # PRIMARY KEY (sha256, ...) already serves lookups by case, so no second
    # index on sha256 alone - it would be redundant with the PK's prefix.

    "CREATE INDEX IF NOT EXISTS idx_chat_case ON chat_messages(sha256, created_at ASC);",
    "CREATE INDEX IF NOT EXISTS idx_export_case ON export_events(sha256, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_export_user ON export_events(user_id, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_runtime_case ON runtime_events(sha256, seq ASC);",
    "CREATE INDEX IF NOT EXISTS idx_runtime_job  ON runtime_events(job_id, seq ASC);",
)


async def create_tables(db: aiosqlite.Connection) -> None:
    await db.execute(_CREATE_ANALYSIS_RUNS)
    await db.execute(_CREATE_CASE_IOCS)
    await db.execute(_CREATE_CHAT_MESSAGES)
    await db.execute(_CREATE_EXPORT_EVENTS)
    await db.execute(_CREATE_RUNTIME_EVENTS)


async def create_indexes(db: aiosqlite.Connection) -> None:
    """
    Build indexes. Must run *after* migrations, never with create_tables().

    `analysis_runs` predates this module - analysis_history.py created it in
    whatever directory the sandbox ran from, without the columns added by
    migration 0005. On such a database `CREATE TABLE IF NOT EXISTS` is a no-op,
    so indexing analysis_runs(sha256) before 0005 runs fails with
    "no such column: sha256". Schema first, then migrations, then indexes.
    """
    for stmt in _INDEXES:
        await db.execute(stmt)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── Analysis runs ────────────────────────────────────────────────────────────

async def record_analysis_run(run: Dict[str, Any]) -> int:
    """
    Persist one completed analysis run.

    Every column is populated from the real result; see
    app.services.run_recorder for the mapping. Rows written here always have
    is_placeholder=0, which is what separates them from the historical rows that
    were written with apk_sha256='unknown' and bfci_score=0.0.
    """
    async with connect() as db:
        sql = """
            INSERT INTO analysis_runs
              (package_name, apk_sha256, sha256, run_timestamp, stage_name,
               duration_seconds, bfci_score, bfci_components, mitre_techniques,
               ioc_count, screenshot_count, yara_matches, anti_analysis,
               explorer_mode, is_placeholder, frs_score, stei_score, risk_band,
               dynamic_status, status, started_at, completed_at, analysis_mode)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?)
            """
        params = (
            run.get("package_name") or "unknown",
            run.get("sha256") or "unknown",
            run.get("sha256"),
            run.get("run_timestamp") or _now(),
            run.get("stage_name") or "single",
            run.get("duration_seconds"),
            run.get("bfci_score"),
            json.dumps(run.get("bfci_components") or {}),
            json.dumps(run.get("mitre_techniques") or []),
            run.get("ioc_count") or 0,
            run.get("screenshot_count") or 0,
            json.dumps(run.get("yara_matches") or []),
            json.dumps(run.get("anti_analysis") or []),
            run.get("explorer_mode"),
            run.get("frs_score"),
            run.get("stei_score"),
            run.get("risk_band"),
            run.get("dynamic_status"),
            run.get("status") or "COMPLETED",
            run.get("started_at"),
            run.get("completed_at") or _now(),
            run.get("analysis_mode"),
        )
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute(sql + " RETURNING id", params)
            row = await cur.fetchone()
            row_id = row["id"] if row else None
        else:
            cur = await db.execute(sql, params)
            row_id = cur.lastrowid
        await db.commit()
        return row_id


def _row_to_run(row: Dict[str, Any]) -> Dict[str, Any]:
    for field in ("bfci_components", "mitre_techniques", "yara_matches", "anti_analysis"):
        if row.get(field):
            try:
                row[field] = json.loads(row[field])
            except Exception:  # noqa: BLE001
                row[field] = None
    row["is_placeholder"] = bool(row.get("is_placeholder"))
    return row


async def runs_for_case(sha256: str, limit: int = 50) -> List[Dict[str, Any]]:
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_runs WHERE sha256 = ? AND is_placeholder = 0 "
            "ORDER BY run_timestamp DESC LIMIT ?",
            (sha256, limit),
        ) as cur:
            return [_row_to_run(dict(r)) for r in await cur.fetchall()]


async def runs_for_package(package_name: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Real runs for a package, newest first.

    Placeholder rows are excluded rather than deleted. They record that an
    analysis happened; they do not record what it measured, so including them
    in a comparison would fabricate a score movement.
    """
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM analysis_runs WHERE package_name = ? AND is_placeholder = 0 "
            "ORDER BY run_timestamp DESC LIMIT ?",
            (package_name, limit),
        ) as cur:
            return [_row_to_run(dict(r)) for r in await cur.fetchall()]


async def compare_runs(package_name: str, limit: int = 5) -> Dict[str, Any]:
    """Compare the two most recent real runs for a package."""
    rows = await runs_for_package(package_name, limit=limit)
    if len(rows) < 2:
        return {
            "status": "insufficient_data",
            "package": package_name,
            "real_runs_available": len(rows),
        }

    latest, previous = rows[0], rows[1]

    def _delta(field: str) -> Optional[float]:
        a, b = latest.get(field), previous.get(field)
        return round(a - b, 4) if a is not None and b is not None else None

    return {
        "status": "success",
        "package": package_name,
        "latest_run": latest["run_timestamp"],
        "previous_run": previous["run_timestamp"],
        "frs_delta": _delta("frs_score"),
        "bfci_delta": _delta("bfci_score"),
        "stei_delta": _delta("stei_score"),
        "latest": {
            "frs": latest.get("frs_score"), "bfci": latest.get("bfci_score"),
            "stei": latest.get("stei_score"), "risk_band": latest.get("risk_band"),
            "sha256": latest.get("sha256"),
        },
        "previous": {
            "frs": previous.get("frs_score"), "bfci": previous.get("bfci_score"),
            "stei": previous.get("stei_score"), "risk_band": previous.get("risk_band"),
            "sha256": previous.get("sha256"),
        },
        "risk_band_changed": latest.get("risk_band") != previous.get("risk_band"),
        "same_binary": latest.get("sha256") == previous.get("sha256"),
    }


# ─── Case ↔ IOC ───────────────────────────────────────────────────────────────

async def upsert_case_iocs(sha256: str, iocs: List[Dict[str, Any]]) -> int:
    """
    Link indicators to a case.

    `first_seen` survives a re-analysis: ON CONFLICT updates last_seen and the
    enrichment fields but leaves first_seen alone, so "when did we first see
    this indicator on this sample" stays true across re-runs.
    """
    if not iocs:
        return 0

    now = _now()
    rows = [
        (
            sha256,
            str(i.get("indicator", ""))[:500],
            str(i.get("ioc_type") or i.get("type") or "unknown")[:40],
            i.get("context"),
            i.get("source"),
            i.get("reputation"),
            i.get("confidence"),
            now, now,
        )
        for i in iocs
        if i.get("indicator")
    ]
    if not rows:
        return 0

    async with connect() as db:
        await db.executemany(
            """
            INSERT INTO case_iocs
              (sha256, indicator, ioc_type, context, source, reputation,
               confidence, first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sha256, indicator, ioc_type) DO UPDATE SET
              last_seen  = excluded.last_seen,
              context    = COALESCE(excluded.context, case_iocs.context),
              source     = COALESCE(excluded.source, case_iocs.source),
              reputation = COALESCE(excluded.reputation, case_iocs.reputation),
              confidence = COALESCE(excluded.confidence, case_iocs.confidence)
            """,
            rows,
        )
        await db.commit()
    return len(rows)


async def iocs_for_case(sha256: str) -> List[Dict[str, Any]]:
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM case_iocs WHERE sha256 = ? ORDER BY ioc_type, indicator",
            (sha256,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def cases_for_indicator(
    indicator: str,
    ioc_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Every case that saw this indicator - the pivot the platform could not do.

    This is the one place a JOIN earns its keep: the answer needs the case's
    package name and risk band, which live in `cases`, not in `case_iocs`.
    """
    sql = """
        SELECT ci.sha256, ci.ioc_type, ci.context, ci.source, ci.reputation,
               ci.first_seen, ci.last_seen,
               c.package_name, c.app_name, c.risk_band, c.final_risk_score,
               c.family_classification, c.created_at
        FROM case_iocs ci
        LEFT JOIN cases c ON c.sha256 = ci.sha256
        WHERE ci.indicator = ?
    """
    params: List[Any] = [indicator]
    if ioc_type:
        sql += " AND ci.ioc_type = ?"
        params.append(ioc_type)
    sql += " ORDER BY ci.last_seen DESC"

    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def shared_indicators(
    sha256: str,
    min_cases: int = 2,
    max_prevalence: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Indicators from this case that also appear on other cases.

    Filtered by prevalence. An indicator present on more than `max_prevalence`
    of all cases is shared infrastructure - a CDN, an ad network, an SDK
    endpoint - not a campaign link, and surfacing it would bury the two or three
    indicators that actually mean something.

    app.services.ioc_extraction has a denylist for the well-known offenders, but
    a denylist can only cover what someone thought of. This is the general
    defence: whatever the corpus shows is ubiquitous is treated as ubiquitous,
    including hosts nobody listed.

    The sample's own hash and package are excluded - they are unique to it by
    construction, so they can never be a meaningful "shared" indicator.
    """
    async with connect() as db:
        db.row_factory = aiosqlite.Row

        async with db.execute("SELECT COUNT(DISTINCT sha256) FROM case_iocs") as cur:
            row = await cur.fetchone()
        total_cases = (row[0] if row else 0) or 0

        # Below this, "appears on 2 of 3 cases" is not evidence of ubiquity and
        # the prevalence ratio would suppress genuine matches.
        prevalence_cap = (
            int(total_cases * max_prevalence) if total_cases >= 8 else total_cases
        )

        async with db.execute(
            """
            SELECT indicator, ioc_type, COUNT(DISTINCT sha256) AS case_count
            FROM case_iocs
            WHERE ioc_type NOT IN ('sha256', 'package')
              AND (indicator, ioc_type) IN (
                    SELECT indicator, ioc_type FROM case_iocs WHERE sha256 = ?
              )
            GROUP BY indicator, ioc_type
            HAVING case_count >= ? AND case_count <= ?
            ORDER BY case_count DESC, indicator
            """,
            (sha256, min_cases, prevalence_cap),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ─── Chat history ─────────────────────────────────────────────────────────────

async def append_chat_message(
    sha256: str,
    role: str,
    content: str,
    user_id: Optional[int] = None,
    sections_used: Optional[List[str]] = None,
) -> int:
    async with connect() as db:
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute(
                "INSERT INTO chat_messages (sha256, user_id, role, content, sections_used, created_at) "
                "VALUES (?,?,?,?,?,?) RETURNING id",
                (
                    sha256, user_id, role, content,
                    json.dumps(sections_used) if sections_used else None,
                    _now(),
                ),
            )
            row = await cur.fetchone()
            row_id = row["id"] if row else None
        else:
            cur = await db.execute(
                "INSERT INTO chat_messages (sha256, user_id, role, content, sections_used, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    sha256, user_id, role, content,
                    json.dumps(sections_used) if sections_used else None,
                    _now(),
                ),
            )
            row_id = cur.lastrowid
        await db.commit()
        return row_id


async def get_chat_history(
    sha256: str,
    user_id: Optional[int] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """
    Conversation for a case, oldest first.

    Returns the last `limit` messages but in chronological order, so a long
    conversation is truncated at the start (where context matters least) rather
    than at the end.
    """
    sql = "SELECT * FROM chat_messages WHERE sha256 = ?"
    params: List[Any] = [sha256]
    if user_id is not None:
        sql += " AND user_id = ?"
        params.append(user_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            rows = [dict(r) for r in await cur.fetchall()]

    rows.reverse()
    for r in rows:
        if r.get("sections_used"):
            try:
                r["sections_used"] = json.loads(r["sections_used"])
            except Exception:  # noqa: BLE001
                r["sections_used"] = None
    return rows


async def clear_chat_history(sha256: str, user_id: Optional[int] = None) -> int:
    sql = "DELETE FROM chat_messages WHERE sha256 = ?"
    params: List[Any] = [sha256]
    if user_id is not None:
        sql += " AND user_id = ?"
        params.append(user_id)
    async with connect() as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.rowcount


# ─── Export ledger ────────────────────────────────────────────────────────────

async def record_export(
    sha256: str,
    export_type: str,
    status: str = "SUCCESS",
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    artifact_ref: Optional[str] = None,
    byte_size: Optional[int] = None,
    ip: Optional[str] = None,
) -> int:
    async with connect() as db:
        sql = """
            INSERT INTO export_events
              (sha256, user_id, username, export_type, status, artifact_ref,
               byte_size, ip, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """
        params = (sha256, user_id, username, export_type, status, artifact_ref,
             byte_size, ip, _now())
        from app.db.pool import is_postgres
        if is_postgres():
            cur = await db.execute(sql + " RETURNING id", params)
            row = await cur.fetchone()
            row_id = row["id"] if row else None
        else:
            cur = await db.execute(sql, params)
            row_id = cur.lastrowid
        await db.commit()
        return row_id


async def exports_for_case(sha256: str, limit: int = 100) -> List[Dict[str, Any]]:
    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM export_events WHERE sha256 = ? ORDER BY created_at DESC LIMIT ?",
            (sha256, limit),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ─── Runtime event index ──────────────────────────────────────────────────────

async def record_runtime_events(events: List[Dict[str, Any]]) -> int:
    """
    Index a batch of runtime events. Metadata only - see the module docstring.

    `summary` is truncated hard: this column exists so an analyst can scan a
    timeline, not so the payload can be reconstructed from it.
    """
    if not events:
        return 0
    rows = [
        (
            e.get("sha256") or "",
            e.get("job_id"),
            e.get("seq"),
            e.get("event_type"),
            e.get("severity"),
            e.get("ts") or _now(),
            e.get("evidence_id"),
            e.get("payload_ref"),
            (e.get("summary") or "")[:500] or None,
        )
        for e in events
        if e.get("sha256")
    ]
    if not rows:
        return 0

    async with connect() as db:
        await db.executemany(
            """
            INSERT INTO runtime_events
              (sha256, job_id, seq, event_type, severity, ts, evidence_id,
               payload_ref, summary)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        await db.commit()
    return len(rows)


async def runtime_events_for_case(
    sha256: str,
    severity: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM runtime_events WHERE sha256 = ?"
    params: List[Any] = [sha256]
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    sql += " ORDER BY seq ASC, id ASC LIMIT ?"
    params.append(limit)

    async with connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]


async def purge_old_runtime_events(retain_days: int = 30) -> int:
    """
    Drop the runtime index for old cases.

    Only the index is dropped. The per-session evidence store on disk is the
    forensic record and is untouched by this - a purged case can still be read
    from its artifact directory.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retain_days)).isoformat()
    async with connect() as db:
        cur = await db.execute("DELETE FROM runtime_events WHERE ts < ?", (cutoff,))
        await db.commit()
        return cur.rowcount
