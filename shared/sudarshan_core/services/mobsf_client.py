# backend/app/services/mobsf_client.py
"""
Sudarshan × MobSF Integration Client
======================================
MobSF (Mobile Security Framework) REST API wrapper.

MobSF is the malware analysis engine.
Sudarshan is the intelligence platform built on top.

This client handles:
  - APK upload to MobSF
  - Polling for analysis completion
  - Parsing static analysis JSON report
  - Parsing dynamic analysis report (if available)
  - Graceful fallback when MobSF is not available

Usage:
  from sudarshan_core.services.mobsf_client import MobSFClient, MobSFNotAvailable

  client = MobSFClient()
  if await client.is_available():
      report = await client.analyze(apk_path)
  else:
      # Fall back to Androguard
      ...
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────

MOBSF_HOST = (os.getenv("MOBSF_HOST") or "http://mobsf:8000").strip()
MOBSF_API_KEY = (os.getenv("MOBSF_API_KEY") or "").strip()

_HEADERS = {"Authorization": MOBSF_API_KEY}

# ─── Health-probe policy ──────────────────────────────────────────────────────
# One probe, short timeout, cached verdict. See MobSFClient.is_available for
# what this replaced and why.
HEALTH_TIMEOUT_SECONDS: float = float(os.getenv("MOBSF_HEALTH_TIMEOUT", "2.0"))
# MobSF was up: re-check soon, it could go down mid-session.
HEALTH_CACHE_TTL_UP: float = float(os.getenv("MOBSF_HEALTH_TTL_UP", "60"))
# MobSF was down: circuit breaker. Do not pay a round trip per analysis to
# rediscover that a service which is not deployed is still not deployed.
HEALTH_CACHE_TTL_DOWN: float = float(os.getenv("MOBSF_HEALTH_TTL_DOWN", "300"))

# MobSF /api/v1/scan blocks until JADX/SAST finish. Large APKs routinely exceed
# 5 minutes; a short client timeout aborts the HTTP call while MobSF keeps
# scanning, which led to full re-upload/re-scan retries and sqlite lock storms.
MOBSF_UPLOAD_TIMEOUT_SECONDS: float = float(
    os.getenv("MOBSF_UPLOAD_TIMEOUT_SECONDS", "300")
)
MOBSF_SCAN_TIMEOUT_SECONDS: float = float(os.getenv("MOBSF_SCAN_TIMEOUT_SECONDS", "900"))
MOBSF_REPORT_TIMEOUT_SECONDS: float = float(
    os.getenv("MOBSF_REPORT_TIMEOUT_SECONDS", "120")
)
MOBSF_POLL_INTERVAL_SECONDS: float = float(
    os.getenv("MOBSF_POLL_INTERVAL_SECONDS", "15")
)
MOBSF_POLL_MAX_SECONDS: float = float(os.getenv("MOBSF_POLL_MAX_SECONDS", "600"))

MOBSF_RESULT_CACHE_VERSION = os.getenv("MOBSF_RESULT_CACHE_VERSION", "1")
MOBSF_RESULT_CACHE_ENABLED = os.getenv("MOBSF_RESULT_CACHE", "true").lower() in (
    "1",
    "true",
    "yes",
)

# ─── Exceptions ───────────────────────────────────────────────────────────────

class MobSFNotAvailable(Exception):
    """Raised when MobSF is not reachable."""
    pass

class MobSFAnalysisError(Exception):
    """Raised when MobSF analysis fails."""
    pass

# ─── MobSF Parsed Models (plain dicts — not Pydantic to avoid coupling) ──────

def _empty_report() -> Dict[str, Any]:
    return {
        "available": False,
        "scan_hash": None,
        "package_name": None,
        "app_name": None,
        "file_name": None,
        "size": None,
        "md5": None,
        "sha1": None,
        "sha256": None,
        "min_sdk": None,
        "target_sdk": None,
        "version_name": None,
        "version_code": None,
        "icon_path": None,
        "permissions": {},
        "dangerous_permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": [],
        "urls": [],
        "domains": {},
        "emails": [],
        "hardcoded_secrets": [],
        "firebase_urls": [],
        "certificate": {},
        "manifest_analysis": [],
        "binary_analysis": [],
        "code_analysis": {},
        "network_security": {},
        "trackers": [],
        "dynamic": None,
        "appsec_score": None,
        "security_score": None,
    }

# ─── MobSF Client ─────────────────────────────────────────────────────────────

class MobSFClient:
    """REST client for MobSF Docker instance."""

    # host -> (available, checked_at_monotonic). Class-level: the analysis
    # engine builds a fresh client per request, so a per-instance cache would
    # never be hit there.
    _availability_cache: Dict[str, tuple] = {}

    def __init__(self, host: Optional[str] = None, api_key: Optional[str] = None):
        # Whether a host was passed explicitly, as opposed to falling back to
        # the compose-network default. Used by is_available() to avoid probing
        # an address nobody configured.
        self._host_explicit = bool(host)
        self.host = (host or os.getenv("MOBSF_HOST") or "http://mobsf:8000").rstrip("/")
        self.api_key = (api_key or os.getenv("MOBSF_API_KEY") or "sudarshan_mobsf_api_key_2026").strip()
        self.headers = {"Authorization": self.api_key} if self.api_key else {}

    async def is_available(self) -> bool:
        """
        Is MobSF reachable right now? Single probe, result cached.

        This used to make FIVE attempts with a 5 s timeout and `sleep(3)`
        between them — up to 37 s added to EVERY analysis whenever MobSF was
        unreachable, just to re-confirm an answer that had not changed. Measured
        against an unresolvable host it cost ~28 s per analysis.

        Retrying a health check defeats its purpose. The question is "is it up
        now?", and "no" is a perfectly good answer: the pipeline falls back to
        Androguard, which is the designed behaviour. So: one attempt, short
        timeout, and the verdict is cached — briefly when up (it may go down),
        for longer when down (a circuit breaker, so a dead MobSF is not
        re-probed on every single upload).

        The cache is CLASS-level because the analysis engine constructs a fresh
        MobSFClient per request; a per-instance cache would never hit there.
        """
        # Not configured is not a failure, and must not cost a network round
        # trip. The constructor defaults host to http://mobsf:8000, so an
        # unconfigured gateway would otherwise probe a name that cannot resolve
        # on every analysis. The engine already guards on MOBSF_HOST; the
        # gateway did not.
        if not (os.getenv("MOBSF_HOST") or self._host_explicit):
            logger.debug("[MobSF] MOBSF_HOST not configured — skipping probe.")
            return False

        now = time.monotonic()
        cached = MobSFClient._availability_cache.get(self.host)
        if cached is not None:
            verdict, checked_at = cached
            ttl = HEALTH_CACHE_TTL_UP if verdict else HEALTH_CACHE_TTL_DOWN
            if now - checked_at < ttl:
                return verdict

        available = False
        try:
            async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT_SECONDS) as client:
                r = await client.get(f"{self.host}/api_docs", headers=self.headers)
                # 302/401/403 all mean "MobSF is up and answering" — /api_docs
                # requires auth and may redirect.
                available = r.status_code in (200, 302, 401, 403)
                if not available:
                    logger.warning(f"[MobSF] Health check unexpected status: {r.status_code}")
        except Exception as e:
            logger.info(
                f"[MobSF] Not reachable at {self.host} ({type(e).__name__}: {e}) — "
                f"falling back to Androguard. Re-probing in {HEALTH_CACHE_TTL_DOWN:.0f}s."
            )

        MobSFClient._availability_cache[self.host] = (available, now)
        return available

    @classmethod
    def reset_availability_cache(cls) -> None:
        """Forget cached health verdicts. For tests and for config reloads."""
        cls._availability_cache.clear()

    async def upload(self, apk_path: str) -> str:
        """
        Upload APK to MobSF.
        Returns: scan_hash (used for all subsequent API calls)
        """
        file_name = os.path.basename(apk_path)

        with open(apk_path, "rb") as f:
            async with httpx.AsyncClient(timeout=MOBSF_UPLOAD_TIMEOUT_SECONDS) as client:
                r = await client.post(
                    f"{self.host}/api/v1/upload",
                    headers=self.headers,
                    files={"file": (file_name, f, "application/octet-stream")},
                )
                r.raise_for_status()
                data = r.json()

        scan_hash = data.get("hash")
        if not scan_hash:
            raise MobSFAnalysisError(f"MobSF upload returned no hash: {data}")
        logger.info(f"MobSF upload complete — scan_hash={scan_hash}")
        return scan_hash

    async def scan(self, scan_hash: str, rescan: bool = False) -> None:
        """Trigger static analysis scan for an uploaded APK."""
        timeout = httpx.Timeout(MOBSF_SCAN_TIMEOUT_SECONDS, connect=30.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    f"{self.host}/api/v1/scan",
                    headers=self.headers,
                    data={"hash": scan_hash, "re_scan": 1 if rescan else 0},
                )
                r.raise_for_status()
        except httpx.TimeoutException:
            logger.warning(
                "MobSF scan HTTP timed out after %.0fs for hash=%s; "
                "scan may still be running — polling report",
                MOBSF_SCAN_TIMEOUT_SECONDS,
                scan_hash,
            )
            await self._wait_for_report(scan_hash)
            return
        logger.info(f"MobSF scan triggered for hash={scan_hash}")

    @staticmethod
    def _report_ready(raw: Dict[str, Any]) -> bool:
        """True when MobSF has produced a usable static report."""
        if not isinstance(raw, dict):
            return False
        if raw.get("package_name") or raw.get("app_name"):
            return True
        perms = raw.get("permissions")
        return isinstance(perms, dict) and len(perms) > 0

    async def _wait_for_report(self, scan_hash: str) -> None:
        """Poll report_json until the scan completes or the poll budget expires."""
        deadline = time.monotonic() + MOBSF_POLL_MAX_SECONDS
        while time.monotonic() < deadline:
            try:
                raw = await self.get_report(scan_hash)
                if self._report_ready(raw):
                    logger.info("MobSF report ready after poll for hash=%s", scan_hash)
                    return
            except httpx.HTTPStatusError as e:
                if e.response.status_code not in (400, 404):
                    raise
            except httpx.TimeoutException:
                pass
            await asyncio.sleep(MOBSF_POLL_INTERVAL_SECONDS)
        raise MobSFAnalysisError(
            f"MobSF scan did not complete within {MOBSF_POLL_MAX_SECONDS:.0f}s poll window"
        )

    async def get_report(self, scan_hash: str) -> Dict[str, Any]:
        """Fetch complete JSON report for a scan hash."""
        async with httpx.AsyncClient(timeout=MOBSF_REPORT_TIMEOUT_SECONDS) as client:
            r = await client.post(
                f"{self.host}/api/v1/report_json",
                headers=self.headers,
                data={"hash": scan_hash},
            )
            r.raise_for_status()
            return r.json()

    async def get_scorecard(self, scan_hash: str) -> Dict[str, Any]:
        """Fetch AppSec scorecard for a scan hash."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    f"{self.host}/api/v1/scorecard",
                    headers=self.headers,
                    data={"hash": scan_hash},
                )
                r.raise_for_status()
                return r.json()
        except Exception as e:
            logger.warning(f"Scorecard fetch failed: {e}")
            return {}

    async def analyze(self, apk_path: str) -> Dict[str, Any]:
        """
        Full pipeline: upload → scan → report → parse.
        Returns a normalized dict consumed by Sudarshan's engines.
        """
        file_sha256 = await asyncio.to_thread(self._sha256_file, apk_path)
        cached = self._load_cached_report(file_sha256)
        if cached is not None:
            logger.info("MobSF cache hit for SHA-256 %s", file_sha256[:12])
            return cached

        max_retries = 3
        scan_hash: Optional[str] = None

        for attempt in range(max_retries):
            try:
                logger.info(
                    "MobSF analysis attempt %s/%s for %s",
                    attempt + 1,
                    max_retries,
                    apk_path,
                )
                scan_hash = await self.upload(apk_path)
                await self.scan(scan_hash)
                raw = await self.get_report(scan_hash)
                if not self._report_ready(raw):
                    await self._wait_for_report(scan_hash)
                    raw = await self.get_report(scan_hash)
                scorecard = await self.get_scorecard(scan_hash)
                return self._finalize_report(
                    file_sha256,
                    self._parse_report(raw, scorecard, scan_hash),
                )

            except MobSFNotAvailable:
                raise
            except httpx.TimeoutException as e:
                # Do not re-upload while a server-side scan may still be running.
                if scan_hash:
                    logger.warning(
                        "MobSF client timeout on attempt %s (hash=%s): %s — polling",
                        attempt + 1,
                        scan_hash,
                        e,
                    )
                    try:
                        await self._wait_for_report(scan_hash)
                        raw = await self.get_report(scan_hash)
                        scorecard = await self.get_scorecard(scan_hash)
                        return self._finalize_report(
                            file_sha256,
                            self._parse_report(raw, scorecard, scan_hash),
                        )
                    except Exception as poll_err:
                        logger.error(
                            "MobSF poll after timeout failed on attempt %s: %s",
                            attempt + 1,
                            poll_err,
                        )
                        if attempt == max_retries - 1:
                            raise MobSFAnalysisError(str(poll_err)) from poll_err
                else:
                    logger.error("MobSF upload timed out on attempt %s: %s", attempt + 1, e)
                    if attempt == max_retries - 1:
                        raise MobSFAnalysisError(str(e)) from e
            except Exception as e:
                logger.error(f"MobSF analysis failed on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    raise MobSFAnalysisError(str(e)) from e
            await asyncio.sleep(2.0 ** (attempt + 1))
        raise MobSFAnalysisError("MobSF analysis failed after retries")

    @staticmethod
    def _sha256_file(apk_path: str) -> str:
        hasher = hashlib.sha256()
        with open(apk_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _cache_file(self, sha256: str) -> Path:
        root = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
        return root / sha256 / "mobsf_parsed_cache.json"

    def _load_cached_report(self, sha256: str) -> Optional[Dict[str, Any]]:
        if not MOBSF_RESULT_CACHE_ENABLED:
            return None
        path = self._cache_file(sha256)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("cache_version") != MOBSF_RESULT_CACHE_VERSION:
                return None
            if payload.get("mobsf_host") != self.host:
                return None
            report = payload.get("report")
            if isinstance(report, dict) and report.get("available"):
                return report
        except (OSError, json.JSONDecodeError, TypeError):
            return None
        return None

    def _store_cached_report(self, sha256: str, report: Dict[str, Any]) -> None:
        if not MOBSF_RESULT_CACHE_ENABLED or not report.get("available"):
            return
        path = self._cache_file(sha256)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "cache_version": MOBSF_RESULT_CACHE_VERSION,
                        "mobsf_host": self.host,
                        "sha256": sha256,
                        "report": report,
                    }
                ),
                encoding="utf-8",
            )
        except OSError as e:
            logger.warning("MobSF cache write failed for %s: %s", sha256[:12], e)

    def _finalize_report(self, sha256: str, report: Dict[str, Any]) -> Dict[str, Any]:
        self._store_cached_report(sha256, report)
        return report

    def _parse_report(
        self, raw: Dict[str, Any], scorecard: Dict[str, Any], scan_hash: str
    ) -> Dict[str, Any]:
        """
        Normalize MobSF JSON report into Sudarshan's internal format.
        Only reads fields — never writes to MobSF.
        """
        report = _empty_report()
        report["available"] = True
        report["scan_hash"] = scan_hash

        # ── Identity ────────────────────────────────────────────────────────────
        report["package_name"] = raw.get("package_name", "")
        report["app_name"] = raw.get("app_name", "")
        report["file_name"] = raw.get("file_name", "")
        report["size"] = raw.get("size", "")
        report["md5"] = raw.get("md5", "")
        report["sha1"] = raw.get("sha1", "")
        report["sha256"] = raw.get("sha256", "")
        report["min_sdk"] = raw.get("min_sdk", "")
        report["target_sdk"] = raw.get("target_sdk", "")
        report["version_name"] = raw.get("version_name", "")
        report["version_code"] = raw.get("version_code", "")

        # ── Permissions ─────────────────────────────────────────────────────────
        # MobSF returns permissions as dict: {perm_name: {status, info, description}}
        perms_raw = raw.get("permissions", {})
        report["permissions"] = perms_raw

        dangerous = []
        for perm_name, perm_info in perms_raw.items():
            if isinstance(perm_info, dict):
                status = perm_info.get("status", "").lower()
                if status in ("dangerous", "signature"):
                    short = perm_name.split(".")[-1]
                    dangerous.append({
                        "permission": perm_name,
                        "short": short,
                        "status": status,
                        "info": perm_info.get("info", ""),
                        "description": perm_info.get("description", "")
                    })
        report["dangerous_permissions"] = dangerous

        # ── Manifest Components ─────────────────────────────────────────────────
        report["activities"] = raw.get("activities", [])
        report["services"] = raw.get("services", [])
        report["receivers"] = raw.get("receivers", [])
        report["providers"] = raw.get("providers", [])

        # Exported components — full attack surface extraction
        # MobSF stores exported=true in browsable_activities and in component dicts
        exported_acts: List[str] = []
        browsable = raw.get("browsable_activities", {})
        if isinstance(browsable, dict):
            for act in browsable.get("browsable", []):
                if isinstance(act, str) and act not in exported_acts:
                    exported_acts.append(act)
            for act in browsable.get("activities", []):
                if isinstance(act, str) and act not in exported_acts:
                    exported_acts.append(act)
        # Also pick up components with explicit exported=true in the raw manifest
        for act in raw.get("activities", []):
            if isinstance(act, dict) and act.get("exported") in (True, "true", "True"):
                name = act.get("name", "")
                if name and name not in exported_acts:
                    exported_acts.append(name)
        report["exported_activities"] = exported_acts

        exported_svcs: List[str] = []
        for svc in raw.get("services", []):
            if isinstance(svc, dict):
                if svc.get("exported") in (True, "true", "True"):
                    name = svc.get("name", "")
                    if name:
                        exported_svcs.append(name)
            elif isinstance(svc, str) and "exported" in svc.lower():
                exported_svcs.append(svc)
        report["exported_services"] = exported_svcs

        exported_rcvs: List[str] = []
        for rcv in raw.get("receivers", []):
            if isinstance(rcv, dict):
                if rcv.get("exported") in (True, "true", "True"):
                    name = rcv.get("name", "")
                    if name:
                        exported_rcvs.append(name)
        report["exported_receivers"] = exported_rcvs

        report["urls"] = raw.get("urls", [])
        report["domains"] = raw.get("domains", {})
        report["emails"] = raw.get("emails", [])
        report["firebase_urls"] = raw.get("firebase_urls", [])

        # ── Hardcoded Secrets ───────────────────────────────────────────────────
        secrets = []
        for item in raw.get("secrets", []):
            if isinstance(item, str):
                secrets.append(item)
            elif isinstance(item, dict):
                secrets.append(item.get("secret", str(item)))
        report["hardcoded_secrets"] = secrets[:100]  # raised from 20 — full exposure list

        # ── Certificate ─────────────────────────────────────────────────────────
        report["certificate"] = raw.get("certificate_analysis", {})

        # ── Manifest Analysis (security findings) ───────────────────────────────
        manifest_analysis = raw.get("manifest_analysis", {})
        findings = []
        if isinstance(manifest_analysis, dict):
            mf_list = manifest_analysis.get("manifest_findings", [])
            if isinstance(mf_list, list) and mf_list:
                for item in mf_list:
                    if isinstance(item, dict):
                        comp = item.get("component", "")
                        if isinstance(comp, list):
                            comp = ", ".join(str(c) for c in comp)
                        findings.append({
                            "severity": item.get("severity", "info"),
                            "title": item.get("title", item.get("name", "")),
                            "description": item.get("description", item.get("desc", "")),
                            "component": str(comp)
                        })
            else:
                for severity in ("high", "warning", "info"):
                    for item in manifest_analysis.get(severity, []):
                        if isinstance(item, dict):
                            comp = item.get("component", "")
                            if isinstance(comp, list):
                                comp = ", ".join(str(c) for c in comp)
                            findings.append({
                                "severity": severity,
                                "title": item.get("title", ""),
                                "description": item.get("description", item.get("desc", "")),
                                "component": str(comp)
                            })
            report["manifest_analysis"] = findings
        elif isinstance(manifest_analysis, list):
            report["manifest_analysis"] = manifest_analysis

        # ── Binary Analysis ─────────────────────────────────────────────────
        # Normalize MobSF binary_analysis list — each item is a native SO file record
        binary_raw = raw.get("binary_analysis", [])
        binary_normalized: list = []
        if isinstance(binary_raw, list):
            for item in binary_raw:
                if isinstance(item, dict):
                    binary_normalized.append({
                        "name": item.get("name", ""),
                        "nx": item.get("nx") or item.get("NX"),
                        "stack_canary": item.get("stack_canary") or item.get("Stack Canary"),
                        "relro": item.get("relro") or item.get("RELRO"),
                        "rpath": item.get("rpath") or item.get("RPATH"),
                        "runpath": item.get("runpath") or item.get("RUNPATH"),
                        "fortify": item.get("fortify"),
                        "stripped": item.get("stripped"),
                        "symbols": item.get("symbols", [])[:10],
                    })
        report["binary_analysis"] = binary_normalized

        # ── Code Analysis (security findings from source) ───────────────────────
        code_analysis = raw.get("code_analysis", {})
        code_findings = []
        if isinstance(code_analysis, dict):
            findings_dict = code_analysis.get("findings", {})
            if isinstance(findings_dict, dict) and findings_dict:
                for rule_id, detail in findings_dict.items():
                    if isinstance(detail, dict):
                        meta = detail.get("metadata", {})
                        files_dict = detail.get("files", {})
                        file_list = list(files_dict.keys())[:5] if isinstance(files_dict, dict) else []
                        code_findings.append({
                            "rule_id": rule_id,
                            "severity": meta.get("severity", "info"),
                            "title": meta.get("description", rule_id),
                            "description": meta.get("description", ""),
                            "masvs": meta.get("masvs", ""),
                            "cwe": meta.get("cwe", ""),
                            "owasp": meta.get("owasp-mobile", meta.get("owasp", "")),
                            "files": file_list
                        })
            elif isinstance(findings_dict, list):
                code_findings = findings_dict
            else:
                for severity in ("high", "warning", "info", "secure"):
                    section = code_analysis.get(severity, {})
                    if isinstance(section, dict):
                        for title, detail in section.items():
                            if isinstance(detail, dict):
                                code_findings.append({
                                    "severity": severity,
                                    "title": title,
                                    "description": detail.get("metadata", {}).get("description", ""),
                                    "files": list(detail.get("files", {}).keys())[:3]
                                })
        report["code_analysis"] = {"findings": code_findings}

        # ── Network Security ────────────────────────────────────────────────────
        # ── Network Security Config ─────────────────────────────────────────────
        netsec_raw = raw.get("network_security", {})
        if isinstance(netsec_raw, dict):
            report["network_security"] = netsec_raw
        else:
            report["network_security"] = {}

        # ── Trackers / Third-party SDKs ───────────────────────────────────────
        # MobSF's /api/v1/report_json includes a trackers field
        trackers_raw = raw.get("trackers", {})
        trackers_list: list = []
        if isinstance(trackers_raw, dict):
            # Format: {"tracker_name": {"categories": [], "website": ""}}
            for name, info in trackers_raw.items():
                if isinstance(info, dict):
                    trackers_list.append({
                        "name": name,
                        "categories": info.get("categories", []),
                        "website": info.get("website", ""),
                    })
                else:
                    trackers_list.append({"name": name, "categories": [], "website": ""})
        elif isinstance(trackers_raw, list):
            for item in trackers_raw:
                if isinstance(item, dict):
                    trackers_list.append({
                        "name": item.get("name", item.get("tracker_name", str(item))),
                        "categories": item.get("categories", []),
                        "website": item.get("website", ""),
                    })
                elif isinstance(item, str):
                    trackers_list.append({"name": item, "categories": [], "website": ""})
        report["trackers"] = trackers_list

        # ── AppSec Score ────────────────────────────────────────────────────────
        sec_score = None
        if isinstance(raw.get("appsec"), dict):
            sec_score = raw["appsec"].get("security_score")
        if sec_score is None and scorecard:
            sec_score = scorecard.get("security_score")
        if sec_score is None:
            sec_score = raw.get("security_score") or raw.get("appsec_score")

        report["appsec_score"] = sec_score
        report["security_score"] = sec_score

        logger.info(
            f"MobSF report parsed: pkg={report['package_name']} "
            f"perms={len(perms_raw)} urls={len(report['urls'])} "
            f"dangerous_perms={len(dangerous)}"
        )
        return report

    def extract_flags(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert parsed MobSF report → Sudarshan flag dict.
        Replaces / augments Androguard flags when MobSF is available.
        """
        perms = report.get("permissions", {})
        perm_names = list(perms.keys())

        def has_perm(*keywords: str) -> bool:
            return any(
                any(kw.upper() in p.upper() for kw in keywords)
                for p in perm_names
            )

        # URLs and IPs
        urls_raw = report.get("urls", [])
        hardcoded_urls = []
        for item in urls_raw:
            if isinstance(item, dict):
                url = item.get("url", item.get("link", ""))
            else:
                url = str(item)
            if url and len(url) < 256:
                hardcoded_urls.append(url)

        # Add Firebase URLs
        hardcoded_urls.extend(report.get("firebase_urls", []))

        # Domains
        domains = report.get("domains", {})
        for domain, info in domains.items():
            if isinstance(info, dict) and info.get("bad") == "yes":
                hardcoded_urls.append(f"http://{domain}")

        # Banking package detection
        banking_packages = [
            "com.boi", "com.sbi", "com.icici", "com.hdfc", "com.axis",
            "com.pnb", "com.kotak", "com.canara", "com.unionbank", "com.bankofindia",
            "in.org.npci.upiapp", "net.one97.paytm", "com.phonepe"
        ]
        code_str = json.dumps(report.get("code_analysis", {})).lower()
        targets_banks = any(pkg in code_str for pkg in banking_packages)
        bank_pkgs_found = [p for p in banking_packages if p in code_str]

        # Dangerous APIs from code analysis
        dangerous_api_keywords = [
            "addJavascriptInterface", "Runtime.exec", "ProcessBuilder",
            "DexClassLoader", "PathClassLoader", "System.loadLibrary"
        ]
        code_findings_str = json.dumps(report.get("code_analysis", {}).get("findings", []))
        found_apis = [api for api in dangerous_api_keywords if api in code_findings_str]

        return {
            "has_accessibility_abuse": has_perm("BIND_ACCESSIBILITY_SERVICE", "ACCESSIBILITY"),
            "has_sms_read_write": has_perm("READ_SMS", "RECEIVE_SMS", "SEND_SMS"),
            "has_system_alert_window": has_perm("SYSTEM_ALERT_WINDOW"),
            "dangerous_apis_found": found_apis,
            "hardcoded_urls_ips": list(set(hardcoded_urls))[:50],
            "targets_indian_banks": targets_banks,
            "indian_bank_packages_found": bank_pkgs_found,
        }

    def get_all_permissions(self, report: Dict[str, Any]) -> List[str]:
        """Return flat list of all permission names."""
        return list(report.get("permissions", {}).keys())

    def get_dynamic_summary(self, dynamic: Optional[Dict]) -> Optional[Dict]:
        """Parse dynamic analysis report if available."""
        if not dynamic:
            return None
        return {
            "available": True,
            "activities_triggered": dynamic.get("activities", []),
            "network_logs": dynamic.get("network_logs", [])[:20],
            "screenshots": dynamic.get("screenshots", []),
            "logcat": dynamic.get("logcat", "")[:2000],
            "api_calls": dynamic.get("api_calls", [])[:30],
            "files_accessed": dynamic.get("files_accessed", [])[:20],
        }
