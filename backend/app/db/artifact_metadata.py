import logging
from typing import Optional, Dict, Any

import aiosqlite

logger = logging.getLogger(__name__)

_CREATE_ARTIFACT_METADATA = """
CREATE TABLE IF NOT EXISTS artifact_metadata (
    artifact_id     TEXT    PRIMARY KEY,
    analysis_id     TEXT,
    job_id          TEXT,
    artifact_type   TEXT    NOT NULL,
    object_key      TEXT    NOT NULL,
    content_type    TEXT,
    size_bytes      INTEGER,
    sha256          TEXT,
    status          TEXT    NOT NULL,  -- UPLOADING, UPLOADED, VERIFIED, DELETED
    created_at      TEXT    NOT NULL
);
"""

_CREATE_ARTIFACT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_artifact_analysis ON artifact_metadata(analysis_id);
"""

async def init_artifact_metadata() -> None:
    from app.db.database import _connect as get_db
    async with get_db() as db:
        await db.execute(_CREATE_ARTIFACT_METADATA)
        await db.execute(_CREATE_ARTIFACT_INDEX)
        await db.commit()

async def record_artifact(
    artifact_id: str,
    artifact_type: str,
    object_key: str,
    status: str,
    analysis_id: Optional[str] = None,
    job_id: Optional[str] = None,
    content_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
    sha256: Optional[str] = None,
) -> None:
    from datetime import datetime, timezone
    from app.db.database import _connect as get_db
    now = datetime.now(timezone.utc).isoformat()
    
    async with get_db() as db:
        await db.execute(
            """
            INSERT INTO artifact_metadata (
                artifact_id, analysis_id, job_id, artifact_type, object_key,
                content_type, size_bytes, sha256, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                status=excluded.status,
                size_bytes=excluded.size_bytes,
                sha256=excluded.sha256
            """,
            (
                artifact_id, analysis_id, job_id, artifact_type, object_key,
                content_type, size_bytes, sha256, status, now
            )
        )
        await db.commit()

async def get_artifact(artifact_id: str) -> Optional[Dict[str, Any]]:
    from app.db.database import _connect as get_db
    async with get_db() as db:
        async with db.execute("SELECT * FROM artifact_metadata WHERE artifact_id = ?", (artifact_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
    return None

async def get_artifacts_for_analysis(analysis_id: str) -> list[Dict[str, Any]]:
    from app.db.database import _connect as get_db
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM artifact_metadata WHERE analysis_id = ?", (analysis_id,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

async def delete_artifact_record(artifact_id: str) -> None:
    from app.db.database import _connect as get_db
    async with get_db() as db:
        await db.execute("DELETE FROM artifact_metadata WHERE artifact_id = ?", (artifact_id,))
        await db.commit()
