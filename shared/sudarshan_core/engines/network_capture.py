"""
SUDARSHAN - Network Capture
============================
Captures network traffic from two sources and merges them into a unified
flow list for evidence analysis:

  1. Frida OkHttp/URLConnection/Socket hooks (primary, always active)
  2. mitmproxy HAR dump file (secondary - active when MITMPROXY_HAR_PATH is set)

The mitmproxy HAR source provides decrypted HTTPS request/response metadata
(method, URL, status, sizes, headers) for connections that trusted the proxy
CA. The hook-based capture only sees the endpoint at connection time.

The two sources are merged by URL deduplication; mitmproxy entries take
precedence over hook entries since they contain more data.

What is NOT claimed
-------------------
Hook flows are endpoints the app reached, observed at the API/syscall layer -
not inspected traffic. Encrypted content is visible only through the HAR, and
only for connections that trusted the proxy (certificate-pinned traffic is
not). `collection_report()` states which of these applied to a run, so a
report never implies traffic inspection that did not happen.

Attribution
-----------
The sidecar writes ONE HAR for every analysis it proxies. When a capture is
bound to a session (`session_started_at`), only HAR entries that started
inside that session's window are attributed to it; entries outside it, or
with no parseable start time, are counted and excluded.

Environment:
  MITMPROXY_HAR_PATH   Absolute path to the HAR file written by the mitmproxy
                       sidecar (see docker-compose.yml). If not set or file
                       does not exist, only Frida hooks are used.
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

MITMPROXY_HAR_PATH: str = os.getenv("MITMPROXY_HAR_PATH", "")

#: Request headers whose VALUES are credentials. Kept by name (that the app
#: sent one is evidence) but never copied into results or reports.
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "x-auth-token",
})


def _redact_headers(headers: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in (headers or [])[:20]:
        if not isinstance(h, dict) or "name" not in h:
            continue
        name = str(h.get("name"))
        out[name] = "[REDACTED]" if name.lower() in _SENSITIVE_HEADERS else str(h.get("value", ""))
    return out


class NetworkCapture:
    """
    Merges Frida hook events and mitmproxy HAR entries into a unified
    network evidence list.
    """

    #: Slack either side of the session window when attributing HAR entries:
    #: the proxy stamps a request when it STARTS, which can precede our own
    #: bookkeeping by a moment.
    HAR_WINDOW_SLACK_S: float = 5.0

    def __init__(
        self,
        event_bus: Optional[RuntimeEventBus] = None,
        *,
        session_started_at: Optional[float] = None,
    ) -> None:
        self.flows: List[Dict[str, Any]] = []
        self._seen_urls: set = set()
        self.session_started_at: Optional[float] = session_started_at
        self.collection: Dict[str, Any] = {
            "frida_hook_flows": 0,
            "har_configured": bool(MITMPROXY_HAR_PATH),
            "har_found": False,
            "har_entries_total": 0,
            "har_entries_in_window": 0,
            "har_entries_out_of_window": 0,
            "har_entries_undated": 0,
            "har_error": "",
        }

        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[NetworkCapture] Subscribed to RuntimeEventBus")

    # ── Frida hook event handler ───────────────────────────────────────────────

    def _on_event(self, event: Dict[str, Any]) -> None:
        if event.get("category") != "network":
            return
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        url = data.get("url", "")
        if not url:
            return

        hook = str(data.get("hook") or event.get("hook") or "")
        # A native connect() is a TCP connection, not an HTTP request. It used
        # to be labelled "GET", which reports then presented as an observed
        # HTTP method. Say only what the hook saw.
        method = data.get("method") or (
            "TCP_CONNECT" if hook == "libc.connect" else "UNKNOWN"
        )
        ts = event.get("timestamp", 0)
        flow = {
            "source":      "frida_hook",
            "timestamp":   ts,
            "url":         url,
            "method":      method,
            "hook":        hook,
            "description": data.get("description", "") or event.get("evidence", ""),
            "status_code": None,
            "response_size": None,
            "ip":          data.get("ip"),
            "port":        data.get("port"),
            "observation_count": 1,
            "first_seen":  ts,
            "last_seen":   ts,
            "observed":    True,
            "payload_inspected": False,
        }

        # Deduplicate by (method, url)
        key = f"{method}:{url}"
        if key not in self._seen_urls:
            self._seen_urls.add(key)
            self.flows.append(flow)
            self.collection["frida_hook_flows"] += 1
        else:
            for f in self.flows:
                if f.get("method") == method and f.get("url") == url:
                    f["observation_count"] = int(f.get("observation_count") or 1) + 1
                    if isinstance(ts, (int, float)) and ts:
                        f["last_seen"] = max(ts, f.get("last_seen") or ts)
                    break

    # ── mitmproxy HAR reader ───────────────────────────────────────────────────

    @staticmethod
    def _har_started_epoch(entry: Dict[str, Any]) -> Optional[float]:
        raw = entry.get("startedDateTime") or ""
        if not raw:
            return None
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None

    def _har_window(self) -> Optional[Tuple[float, float]]:
        if self.session_started_at is None:
            return None
        return (
            self.session_started_at - self.HAR_WINDOW_SLACK_S,
            time.time() + self.HAR_WINDOW_SLACK_S,
        )

    def ingest_mitmproxy_har(self, har_path: Optional[str] = None) -> int:
        """
        Parse a mitmproxy HAR dump and merge entries into self.flows.

        HAR format: { "log": { "entries": [ ... ] } }
        Each entry has: request.url, request.method, response.status, response.bodySize

        Returns the count of new flows added from the HAR.
        """
        path = har_path or MITMPROXY_HAR_PATH
        if path:
            self.collection["har_configured"] = True
        if not path or not Path(path).exists():
            if path:
                logger.debug(f"[NetworkCapture] mitmproxy HAR not found at {path} - skipping")
            return 0
        self.collection["har_found"] = True

        try:
            har_data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            logger.warning(f"[NetworkCapture] Failed to read mitmproxy HAR: {e}")
            self.collection["har_error"] = f"{type(e).__name__}: {e}"[:200]
            return 0

        entries = har_data.get("log", {}).get("entries", [])
        added = 0
        window = self._har_window()
        in_window = out_window = undated = 0

        for entry in entries:
            if window is not None:
                started = self._har_started_epoch(entry)
                if started is None:
                    # Cannot be placed in time, so cannot be attributed.
                    undated += 1
                    continue
                if not (window[0] <= started <= window[1]):
                    out_window += 1
                    continue
                in_window += 1
            try:
                req = entry.get("request", {})
                resp = entry.get("response", {})
                url = req.get("url", "")
                method = req.get("method", "GET")
                if not url:
                    continue

                key = f"{method}:{url}"
                flow = {
                    "source":         "mitmproxy_har",
                    "timestamp":      0,                        # HAR uses ISO startedDateTime
                    "started_at":     entry.get("startedDateTime", ""),
                    "url":            url,
                    "method":         method,
                    "hook":           "mitmproxy",
                    "description":    f"HTTP {method} {url}",
                    "status_code":    resp.get("status"),
                    "response_size":  resp.get("bodySize"),
                    "headers":        _redact_headers(req.get("headers")),
                    "observed":       True,
                    "payload_inspected": True,
                }

                if key in self._seen_urls:
                    # mitmproxy entry is richer - update the existing frida hook entry
                    for i, f in enumerate(self.flows):
                        if f.get("method") == method and f.get("url") == url:
                            self.flows[i].update({
                                "source": "frida+mitmproxy",
                                "status_code": flow["status_code"],
                                "response_size": flow["response_size"],
                                "started_at": flow["started_at"],
                                "payload_inspected": True,
                            })
                            break
                else:
                    self._seen_urls.add(key)
                    self.flows.append(flow)
                    added += 1
            except Exception as e:
                logger.debug(f"[NetworkCapture] HAR entry parse error: {e}")

        self.collection["har_entries_total"] = len(entries)
        self.collection["har_entries_in_window"] = in_window if window else len(entries)
        self.collection["har_entries_out_of_window"] = out_window
        self.collection["har_entries_undated"] = undated
        if added or entries:
            logger.info(
                f"[NetworkCapture] mitmproxy HAR: {len(entries)} entries, "
                f"{added} new flows added; attributed to this session: "
                f"{self.collection['har_entries_in_window']}, outside window: {out_window}, "
                f"undated: {undated}"
            )
        return added

    # ── Flush ──────────────────────────────────────────────────────────────────

    def flush(self, output_path: Path) -> int:
        """
        Ingest mitmproxy HAR then write all captured flows to a JSON file.

        Called by frida_sandbox.py at the end of every analysis session.
        """
        # Always attempt HAR ingest at flush time - mitmproxy may have captured
        # more flows during the analysis session than were visible mid-session.
        self.ingest_mitmproxy_har()

        if not self.flows:
            return 0

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.flows, f, indent=4)
            logger.info(
                f"[NetworkCapture] Flushed {len(self.flows)} network flows → {output_path} "
                f"({sum(1 for f in self.flows if 'mitmproxy' in f.get('source',''))} from mitmproxy)"
            )
        except Exception as e:
            logger.error(f"[NetworkCapture] Failed to write network.json: {e}")

        return len(self.flows)

    def collection_report(self) -> Dict[str, Any]:
        """
        What network collection did and did not cover, for the result and report.

        Stated, not implied: hook-layer flows are endpoints the app reached,
        not inspected traffic, and HTTPS content is visible only when a
        mitmproxy HAR was configured, found, attributed to this window, and
        the app trusted the proxy.
        """
        c = dict(self.collection)
        har_used = bool(c["har_found"] and c["har_entries_in_window"] > 0)
        limitations = [
            "Frida hook flows record the endpoint (URL or IP:port) at the API or "
            "connect() layer; request and response bodies are not captured.",
        ]
        if not c["har_configured"]:
            limitations.append(
                "No mitmproxy HAR configured (MITMPROXY_HAR_PATH): encrypted "
                "application traffic was NOT inspected."
            )
        elif not c["har_found"]:
            limitations.append(
                "mitmproxy HAR configured but not found: encrypted traffic was NOT inspected."
            )
        elif not har_used:
            limitations.append(
                "mitmproxy HAR held no entries inside this analysis window: encrypted "
                "traffic was NOT inspected for this run."
            )
        else:
            limitations.append(
                "HTTPS metadata visible via mitmproxy only for connections that "
                "trusted the proxy CA; certificate-pinned traffic is not decrypted."
            )
        if c["har_entries_out_of_window"] or c["har_entries_undated"]:
            limitations.append(
                f"{c['har_entries_out_of_window']} HAR entries outside this analysis "
                f"window and {c['har_entries_undated']} undated entries were not "
                "attributed to this sample."
            )
        c.update({
            "session_bounded": self.session_started_at is not None,
            "flows_total": len(self.flows),
            "encrypted_traffic_inspected": har_used,
            "limitations": limitations,
        })
        return c
