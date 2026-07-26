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
  from app.services.mobsf_client import MobSFClient, MobSFNotAvailable

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
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── Configuration ───────────────────────────────────────────────────────────

MOBSF_HOST = os.getenv("MOBSF_HOST", "http://localhost:8008")
MOBSF_API_KEY = os.getenv("MOBSF_API_KEY", "")  # MobSF REST API key

# Default MobSF API key is shown on MobSF dashboard at http://localhost:8008/api_docs
# Also set via env: MOBSF_API_KEY=your_key

_HEADERS = {"Authorization": MOBSF_API_KEY}

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
        "dynamic": None,
        "appsec_score": None,
        "security_score": None,
    }

# ─── MobSF Client ─────────────────────────────────────────────────────────────

class MobSFClient:
    """REST client for MobSF Docker instance."""

    def __init__(self, host: str = MOBSF_HOST, api_key: str = MOBSF_API_KEY):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.headers = {"Authorization": self.api_key} if self.api_key else {}

    async def is_available(self) -> bool:
        """Quick health check — returns True if MobSF responds. Includes retries."""
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    r = await client.get(f"{self.host}/api_docs", headers=self.headers)
                    if r.status_code in (200, 302, 401, 403):
                        return True
                    logger.warning(f"MobSF health check unexpected status: {r.status_code}")
            except Exception as e:
                logger.warning(f"MobSF health check attempt {attempt + 1} failed: {e}")
            
            if attempt < 2:
                await asyncio.sleep(2)
        
        logger.error("MobSF is completely unavailable after retries.")
        return False

    async def upload(self, apk_path: str) -> str:
        """
        Upload APK to MobSF.
        Returns: scan_hash (used for all subsequent API calls)
        """
        file_name = os.path.basename(apk_path)

        with open(apk_path, "rb") as f:
            async with httpx.AsyncClient(timeout=300.0) as client:
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
        async with httpx.AsyncClient(timeout=300.0) as client:
            r = await client.post(
                f"{self.host}/api/v1/scan",
                headers=self.headers,
                data={"hash": scan_hash, "re_scan": 1 if rescan else 0},
            )
            r.raise_for_status()
        logger.info(f"MobSF scan triggered for hash={scan_hash}")

    async def get_report(self, scan_hash: str) -> Dict[str, Any]:
        """Fetch complete JSON report for a scan hash."""
        async with httpx.AsyncClient(timeout=60.0) as client:
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
        Falls back to empty_report on any failure.
        """
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                logger.info(f"MobSF analysis attempt {attempt + 1}/{max_retries} for {apk_path}")
                scan_hash = await self.upload(apk_path)
                await self.scan(scan_hash)

                # MobSF analysis typically takes 30–120 seconds
                # The scan endpoint is synchronous on the server side
                raw = await self.get_report(scan_hash)
                scorecard = await self.get_scorecard(scan_hash)

                return self._parse_report(raw, scorecard, scan_hash)

            except MobSFNotAvailable:
                raise
            except Exception as e:
                logger.error(f"MobSF analysis failed on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    raise MobSFAnalysisError(str(e))
                await asyncio.sleep(2.0 ** (attempt + 1))

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

        # Exported components (attack surface)
        exported_acts = []
        for act in raw.get("browsable_activities", {}).get("browsable", []):
            exported_acts.append(act)
        report["exported_activities"] = exported_acts

        exported_svcs = []
        for svc in report["services"]:
            if isinstance(svc, str) and "exported" in svc.lower():
                exported_svcs.append(svc)
        report["exported_services"] = exported_svcs

        # ── Network Indicators ──────────────────────────────────────────────────
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
        report["hardcoded_secrets"] = secrets[:20]

        # ── Certificate ─────────────────────────────────────────────────────────
        report["certificate"] = raw.get("certificate_analysis", {})

        # ── Manifest Analysis (security findings) ───────────────────────────────
        manifest_analysis = raw.get("manifest_analysis", {})
        if isinstance(manifest_analysis, dict):
            findings = []
            for severity in ("high", "warning", "info"):
                for item in manifest_analysis.get(severity, []):
                    findings.append({
                        "severity": severity,
                        "title": item.get("title", ""),
                        "description": item.get("description", item.get("desc", "")),
                        "component": item.get("component", "")
                    })
            report["manifest_analysis"] = findings
        elif isinstance(manifest_analysis, list):
            report["manifest_analysis"] = manifest_analysis

        # ── Binary Analysis ─────────────────────────────────────────────────────
        binary = raw.get("binary_analysis", [])
        if isinstance(binary, list):
            report["binary_analysis"] = binary

        # ── Code Analysis (security findings from source) ───────────────────────
        code_analysis = raw.get("code_analysis", {})
        if isinstance(code_analysis, dict):
            code_findings = []
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
        report["network_security"] = raw.get("network_security", {})

        # ── AppSec Score ────────────────────────────────────────────────────────
        report["appsec_score"] = raw.get("appsec_score")
        if scorecard:
            report["security_score"] = scorecard.get("security_score")

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
