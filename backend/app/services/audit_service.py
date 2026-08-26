"""
Centralised audit trail.
========================

One interface for "who did what, to which object, when, and from where".

Everything that writes to `audit_events` goes through `record()`. Routes do not
build INSERT statements - that is how audit trails end up inconsistent, with
half the actions recording an actor id and the other half a username, and three
different spellings of the same action.

Design rules
------------
**Auditing never breaks the request it is auditing.** A failed INSERT is logged
at ERROR and swallowed. Refusing to serve a case because the audit row could not
be written would turn a degraded database into an outage, and the application
log still carries the event.

**The action vocabulary is closed.** `Action` lists every action the application
actually performs. Nothing is listed here that no code path emits - an audit
schema advertising events that are never recorded is worse than one that admits
its scope, because an auditor reading it cannot tell the difference between
"this never happened" and "this was never instrumented".

**Client IP is not taken on trust.** `X-Forwarded-For` is attacker-controlled
unless a proxy is known to rewrite it, so it is honoured only when
TRUST_PROXY_HEADERS is set.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from app.db.security import insert_audit_event

logger = logging.getLogger(__name__)


def _trust_proxy_headers() -> bool:
    return os.getenv("TRUST_PROXY_HEADERS", "").lower() in ("1", "true", "yes")


class Action:
    """
    Every audited action. Each constant is emitted by real code - see the
    module docstring on why this list is closed.
    """

    # Authentication
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    SESSION_REVOKED = "SESSION_REVOKED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"

    # User administration
    USER_CREATED = "USER_CREATED"
    ROLE_CHANGED = "ROLE_CHANGED"
    USER_DISABLED = "USER_DISABLED"
    USER_ENABLED = "USER_ENABLED"

    # Case operations
    CASE_CREATED = "CASE_CREATED"
    CASE_VIEWED = "CASE_VIEWED"
    CASE_NOTE_ADDED = "CASE_NOTE_ADDED"
    CASE_STATUS_CHANGED = "CASE_STATUS_CHANGED"
    CASE_VERDICT_CHANGED = "CASE_VERDICT_CHANGED"
    CASE_ASSIGNED = "CASE_ASSIGNED"

    # Analysis
    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"

    # Batch
    BATCH_CREATED = "BATCH_CREATED"
    BATCH_CANCELLED = "BATCH_CANCELLED"

    # Reporting
    REPORT_EXPORTED = "REPORT_EXPORTED"


def client_ip(request: Optional[Any]) -> Optional[str]:
    """
    Best-effort client address.

    Prefers the socket peer. `X-Forwarded-For` is only consulted when
    TRUST_PROXY_HEADERS says a proxy in front of us rewrites it; otherwise any
    client could forge the address recorded against its own actions, which is
    precisely the field an attacker would want to control.
    """
    if request is None:
        return None
    try:
        if _trust_proxy_headers():
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                # Left-most entry is the original client.
                return fwd.split(",")[0].strip()[:64] or None
        client = getattr(request, "client", None)
        return getattr(client, "host", None)
    except Exception:  # noqa: BLE001
        return None


def user_agent(request: Optional[Any]) -> Optional[str]:
    if request is None:
        return None
    try:
        return (request.headers.get("user-agent") or "")[:400] or None
    except Exception:  # noqa: BLE001
        return None


async def record(
    action: str,
    *,
    actor: Optional[Dict[str, Any]] = None,
    actor_username: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
    request: Optional[Any] = None,
    ip: Optional[str] = None,
) -> None:
    """
    Write one audit event.

    `actor` is the user dict from get_current_user. For a failed login there is
    no authenticated actor, so `actor_username` carries the attempted name
    instead - that is the whole value of the record.
    """
    uid: Optional[int] = None
    uname: Optional[str] = actor_username
    if actor:
        uid = actor.get("id")
        uname = uname or actor.get("username")

    try:
        await insert_audit_event(
            action=action,
            actor_user_id=uid,
            actor_username=uname,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            ip=ip if ip is not None else client_ip(request),
        )
    except Exception as exc:  # noqa: BLE001
        # Deliberately swallowed - see the module docstring. Logged at ERROR
        # because a persistently failing audit write is an incident in itself.
        logger.error(
            "[Audit] FAILED to record %s (actor=%s target=%s/%s): %s",
            action, uname, target_type, target_id, exc,
        )
