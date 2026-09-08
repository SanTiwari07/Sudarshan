"""
Audit trail API.
================

Read-only. There is deliberately no endpoint that writes, edits, or deletes an
audit event: entries are produced by `app.services.audit_service` as a
side-effect of the action being audited, and an audit trail that the
application can rewrite on request is not evidence.

Restricted to soc_lead and admin. The trail records which analyst opened which
case, so exposing it to every analyst would turn it into a surveillance feed on
colleagues.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from app.auth.auth import require_soc_lead
from app.db.security import count_audit_events, query_audit_events
from app.services.audit_service import Action

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["Audit"])


@router.get("/events")
async def list_audit_events(
    user: dict = Depends(require_soc_lead),
    actor_user_id: Optional[int] = Query(None),
    action: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None, description="user | case | session"),
    target_id: Optional[str] = Query(None),
    since: Optional[str] = Query(None, description="ISO-8601 lower bound"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """Query the audit trail: who did what, to which object, when, from where."""
    events = await query_audit_events(
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        since=since,
        limit=limit,
        offset=offset,
    )
    return {
        "events": events,
        "count": len(events),
        "total": await count_audit_events(),
        "limit": limit,
        "offset": offset,
    }


@router.get("/case/{sha256}")
async def case_audit_trail(
    sha256: str,
    user: dict = Depends(require_soc_lead),
    limit: int = Query(200, ge=1, le=500),
) -> Dict[str, Any]:
    """Everything that has happened to one case, newest first."""
    events = await query_audit_events(target_type="case", target_id=sha256, limit=limit)
    return {"sha256": sha256, "events": events, "count": len(events)}


@router.get("/actions")
async def known_actions(user: dict = Depends(require_soc_lead)) -> Dict[str, List[str]]:
    """
    The action vocabulary, so a UI filter does not have to hardcode it.

    Every value here is emitted by real code - see the note in
    app.services.audit_service on why the list is closed.
    """
    actions = sorted(
        v for k, v in vars(Action).items()
        if not k.startswith("_") and isinstance(v, str)
    )
    return {"actions": actions}
