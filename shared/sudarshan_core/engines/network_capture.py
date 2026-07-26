"""
SUDARSHAN — Network Capture
============================
Captures network traffic from two sources and merges them into a unified
flow list for evidence analysis:

  1. Frida OkHttp/URLConnection/Socket hooks (primary, always active)
  2. mitmproxy HAR dump file (secondary — active when MITMPROXY_HAR_PATH is set)

The mitmproxy HAR source provides decrypted full HTTPS request/response pairs,
including bodies, headers, and response codes. This is significantly richer
than the hook-based capture which only sees the URL at connection time.

The two sources are merged by URL deduplication; mitmproxy entries take
precedence over hook entries since they contain more data.

Environment:
  MITMPROXY_HAR_PATH   Absolute path to the HAR file written by the mitmproxy
                       sidecar (see docker-compose.yml). If not set or file
                       does not exist, only Frida hooks are used.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

MITMPROXY_HAR_PATH: str = os.getenv("MITMPROXY_HAR_PATH", "")


class NetworkCapture:
    """
    Merges Frida hook events and mitmproxy HAR entries into a unified
    network evidence list.
    """

    def __init__(self, event_bus: Optional[RuntimeEventBus] = None) -> None:
        self.flows: List[Dict[str, Any]] = []
        self._seen_urls: set = set()

        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[NetworkCapture] Subscribed to RuntimeEventBus")

    # ── Frida hook event handler ───────────────────────────────────────────────

    def _on_event(self, event: Dict[str, Any]) -> None:
        if event.get("category") != "network":
            return
        data = event.get("data", {})
        url = data.get("url", "")
        if not url:
            return

        flow = {
            "source":      "frida_hook",
            "timestamp":   event.get("timestamp", 0),
            "url":         url,
            "method":      data.get("method", "GET"),
            "hook":        data.get("hook", ""),
            "description": data.get("description", ""),
            "status_code": None,
            "response_size": None,
        }

        # Deduplicate by (method, url)
        key = f"{flow['method']}:{url}"
        if key not in self._seen_urls:
            self._seen_urls.add(key)
            self.flows.append(flow)

    # ── mitmproxy HAR reader ───────────────────────────────────────────────────

    def ingest_mitmproxy_har(self, har_path: Optional[str] = None) -> int:
        """
        Parse a mitmproxy HAR dump and merge entries into self.flows.

        HAR format: { "log": { "entries": [ ... ] } }
        Each entry has: request.url, request.method, response.status, response.bodySize

        Returns the count of new flows added from the HAR.
        """
        path = har_path or MITMPROXY_HAR_PATH
        if not path or not Path(path).exists():
            if path:
                logger.debug(f"[NetworkCapture] mitmproxy HAR not found at {path} — skipping")
            return 0

        try:
            har_data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            logger.warning(f"[NetworkCapture] Failed to read mitmproxy HAR: {e}")
            return 0

        entries = har_data.get("log", {}).get("entries", [])
        added = 0

        for entry in entries:
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
                    "headers":        {h["name"]: h["value"] for h in req.get("headers", [])[:20]},
                }

                if key in self._seen_urls:
                    # mitmproxy entry is richer — update the existing frida hook entry
                    for i, f in enumerate(self.flows):
                        if f.get("method") == method and f.get("url") == url:
                            self.flows[i].update({
                                "source": "frida+mitmproxy",
                                "status_code": flow["status_code"],
                                "response_size": flow["response_size"],
                                "started_at": flow["started_at"],
                            })
                            break
                else:
                    self._seen_urls.add(key)
                    self.flows.append(flow)
                    added += 1
            except Exception as e:
                logger.debug(f"[NetworkCapture] HAR entry parse error: {e}")

        if added or entries:
            logger.info(
                f"[NetworkCapture] mitmproxy HAR: {len(entries)} entries, "
                f"{added} new flows added, {len(entries) - added} merged with Frida hooks"
            )
        return added

    # ── Flush ──────────────────────────────────────────────────────────────────

    def flush(self, output_path: Path) -> int:
        """
        Ingest mitmproxy HAR then write all captured flows to a JSON file.

        Called by frida_sandbox.py at the end of every analysis session.
        """
        # Always attempt HAR ingest at flush time — mitmproxy may have captured
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
