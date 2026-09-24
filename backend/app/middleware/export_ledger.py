"""
Export ledger middleware.
=========================

Records every report/IOC/rule export to `export_events` and `audit_events`.

Why middleware rather than a line in each handler: `report.py` exposes ten
export endpoints (pdf, html, stix, iocs csv, iocs txt, yara, suricata, snort,
mitre, technical-pdf) and more will be added. Instrumenting each one by hand
guarantees the eleventh is forgotten, and a ledger with a hole in it is worse
than no ledger, because it reads as complete.

Only the *reference* is stored - export type, who, when, byte size, status.
Never the payload. A PDF in SQLite would bloat the database that holds the case
records, for no query anyone wants to run.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger(__name__)

# /api/v1/report/<type>/<sha256>   - the sha may be a prefix, so no length anchor
_EXPORT_PATH = re.compile(r"/report/(?P<kind>[a-z0-9\-]+)/(?P<sha>[A-Fa-f0-9]{6,64})/?$")

# Rendering the report in the UI is a read, not an export. Counting every page
# view as an export would drown the genuine "analyst took the data out of the
# system" events that the ledger exists to capture.
_VIEW_ONLY = {"html"}


class ExportLedgerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception as e:
            import traceback
            print(f"CRITICAL ERROR IN MIDDLEWARE: {e}", flush=True)
            print(traceback.format_exc(), flush=True)
            raise

        try:
            if request.method != "GET":
                return response
            match = _EXPORT_PATH.search(request.url.path)
            if not match:
                return response

            kind = match.group("kind").lower()
            if kind in _VIEW_ONLY:
                return response

            await self._record(request, response, kind, match.group("sha"))
        except Exception as exc:  # noqa: BLE001
            # Never turn a successful export into a 500 because bookkeeping
            # failed. Logged at ERROR: a silently broken ledger is the failure
            # mode this middleware exists to prevent.
            logger.error("[ExportLedger] failed to record export: %s", exc)

        return response

    @staticmethod
    async def _record(request: Request, response, kind: str, sha: str) -> None:
        from app.db.intel import record_export
        from app.services import audit_service
        from app.services.audit_service import Action

        user = getattr(request.state, "user", None) or {}
        status = "SUCCESS" if response.status_code < 400 else "FAILED"

        size: Optional[int] = None
        raw_len = response.headers.get("content-length")
        if raw_len and raw_len.isdigit():
            size = int(raw_len)

        disposition = response.headers.get("content-disposition") or ""
        artifact_ref = None
        if "filename=" in disposition:
            artifact_ref = disposition.split("filename=", 1)[1].strip('"; ')

        ip = audit_service.client_ip(request)

        await record_export(
            sha256=sha,
            export_type=kind,
            status=status,
            user_id=user.get("id"),
            username=user.get("username"),
            artifact_ref=artifact_ref,
            byte_size=size,
            ip=ip,
        )

        # Only successful exports reach the audit trail as REPORT_EXPORTED. A
        # failed one is in export_events with status=FAILED; recording it as an
        # export would misstate that data left the system.
        if status == "SUCCESS":
            await audit_service.record(
                Action.REPORT_EXPORTED,
                actor=user or None,
                target_type="case",
                target_id=sha,
                detail={"export_type": kind, "bytes": size},
                ip=ip,
            )
