"""Case visibility checks shared across API routes."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.db.database import get_case


def list_scope_analyst_id(user: dict) -> Optional[int]:
    if user.get("role") == "analyst":
        return int(user["id"])
    return None


async def assert_case_visible(user: dict, case_row: dict) -> None:
    scope = list_scope_analyst_id(user)
    if scope is None:
        return
    owner = case_row.get("analyst_id")
    if owner is None or int(owner) == scope:
        return
        
    sha256 = case_row.get("sha256")
    from app.db.database import _connect
    async with _connect() as db:
        async with db.execute("SELECT 1 FROM analysis_jobs WHERE sha256 = ? AND analyst_id = ? LIMIT 1", (sha256, scope)) as cur:
            has_job = await cur.fetchone()
            
    if not has_job:
        raise HTTPException(status_code=404, detail="Case not found.")


async def get_authorized_case(sha256: str, user: dict) -> Dict[str, Any]:
    row = await get_case(sha256)
    if not row:
        raise HTTPException(status_code=404, detail="Case not found. Analyze the APK first.")
    await assert_case_visible(user, row)
    return row
