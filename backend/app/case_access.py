"""Case visibility checks shared across API routes."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.db.database import get_case


def list_scope_analyst_id(user: dict) -> Optional[int]:
    if user.get("role") == "analyst":
        return int(user["id"])
    return None


def assert_case_visible(user: dict, case_row: dict) -> None:
    scope = list_scope_analyst_id(user)
    if scope is None:
        return
    owner = case_row.get("analyst_id")
    if owner is not None and int(owner) != scope:
        raise HTTPException(status_code=404, detail="Case not found.")


async def get_authorized_case(sha256: str, user: dict) -> Dict[str, Any]:
    row = await get_case(sha256)
    if not row:
        raise HTTPException(status_code=404, detail="Case not found. Analyze the APK first.")
    assert_case_visible(user, row)
    return row
