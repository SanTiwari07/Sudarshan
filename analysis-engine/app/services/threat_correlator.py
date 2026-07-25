# backend/app/services/threat_correlator.py
"""
Sudarshan Threat Correlation Engine
=====================================
Queries public threat intelligence APIs to enrich IOCs extracted from APK analysis.

Supported sources:
  - VirusTotal (SHA256, URL, domain, IP)
  - AlienVault OTX (domain, IP, hash)
  - AbuseIPDB (IP reputation)

All queries are async and parallel.
Missing API keys cause graceful skip — never a failure.
Results are cached per-hash for the session.
"""

import asyncio
import hashlib
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── API Keys (from .env) ─────────────────────────────────────────────────────

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ─── Result Structure ─────────────────────────────────────────────────────────

def _empty_result() -> Dict[str, Any]:
    return {
        "available": False,
        "sha256_detections": 0,
        "sha256_total": 0,
        "vt_detection_ratio": 0.0,
        "vt_family": None,
        "vt_malicious_vendors": [],
        "ioc_reputation": [],
        "known_family": None,
        "campaign": None,
        "threat_score": 0.0,
        "threat_score_sources": [],
        "suspicious_domains": [],
        "malicious_ips": [],
        "otx_pulses": [],
        "correlation_confidence": 0.0,
        "sources_queried": [],
    }

# ─── VirusTotal ───────────────────────────────────────────────────────────────

async def _vt_check_hash(sha256: str) -> Dict[str, Any]:
    """Query VirusTotal for a SHA256 hash."""
    if not VT_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": VT_API_KEY},
            )
            if r.status_code == 404:
                return {"found": False}
            r.raise_for_status()
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            malicious_vendors = [
                vendor for vendor, result in results.items()
                if result.get("category") == "malicious"
            ]

            total = sum(stats.values()) or 1
            malicious = stats.get("malicious", 0)

            # Extract suggested family name
            family = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
            if not family:
                # Try extracting from names
                names = list(attrs.get("names", []))
                for name in names:
                    if "android" in name.lower():
                        family = name
                        break

            return {
                "found": True,
                "malicious": malicious,
                "total": total,
                "ratio": malicious / total,
                "family": family,
                "malicious_vendors": malicious_vendors[:5],
                "reputation": attrs.get("reputation", 0),
            }
    except Exception as e:
        logger.warning(f"VirusTotal hash query failed: {e}")
        return {}

async def _vt_check_url(url: str) -> Dict[str, Any]:
    """Query VirusTotal for a URL reputation."""
    if not VT_API_KEY:
        return {}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
            )
            if r.status_code == 404:
                return {"found": False, "url": url}
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            malicious = stats.get("malicious", 0)
            return {
                "found": True,
                "url": url,
                "malicious": malicious,
                "total": total,
                "ratio": malicious / total,
                "reputation": "malicious" if malicious > 2 else "suspicious" if malicious > 0 else "clean",
            }
    except Exception as e:
        logger.warning(f"VirusTotal URL query failed for {url[:50]}: {e}")
        return {"found": False, "url": url}

# ─── AlienVault OTX ──────────────────────────────────────────────────────────

async def _otx_check_hash(sha256: str) -> Dict[str, Any]:
    """Query AlienVault OTX for file hash."""
    if not OTX_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
            )
            if r.status_code == 404:
                return {"found": False}
            r.raise_for_status()
            data = r.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return {
                "found": True,
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name", ""),
                        "tags": p.get("tags", [])[:3],
                        "malware_families": p.get("malware_families", []),
                    }
                    for p in pulses[:3]
                ],
            }
    except Exception as e:
        logger.warning(f"OTX hash query failed: {e}")
        return {}

async def _otx_check_domain(domain: str) -> Dict[str, Any]:
    """Query AlienVault OTX for domain reputation."""
    if not OTX_API_KEY:
        return {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
            )
            if r.status_code == 404:
                return {"found": False, "domain": domain}
            r.raise_for_status()
            data = r.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            return {
                "found": True,
                "domain": domain,
                "pulse_count": len(pulses),
                "reputation": "malicious" if len(pulses) > 3 else "suspicious" if pulses else "unknown",
            }
    except Exception as e:
        logger.warning(f"OTX domain query failed for {domain}: {e}")
        return {"found": False, "domain": domain}

# ─── AbuseIPDB ────────────────────────────────────────────────────────────────

_IP_RE = __import__("re").compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

async def _abuseipdb_check_ip(ip: str) -> Dict[str, Any]:
    """Query AbuseIPDB for IP address reputation."""
    if not ABUSEIPDB_API_KEY or not _IP_RE.match(ip):
        return {}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            return {
                "ip": ip,
                "found": True,
                "abuse_score": score,
                "reputation": "malicious" if score > 50 else "suspicious" if score > 10 else "clean",
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "usage_type": d.get("usageType", ""),
            }
    except Exception as e:
        logger.warning(f"AbuseIPDB query failed for {ip}: {e}")
        return {}

# ─── Main Correlator ─────────────────────────────────────────────────────────

async def correlate(
    sha256: str,
    urls: List[str],
    package_name: str = "",
) -> Dict[str, Any]:
    """
    Run parallel threat correlation queries.

    Args:
        sha256: APK SHA256 hash
        urls: List of hardcoded URLs/IPs from static analysis
        package_name: APK package name for context

    Returns:
        Normalized correlation result dict
    """
    result = _empty_result()

    # Extract domains and IPs from URLs
    domains: List[str] = []
    ips: List[str] = []
    for url in urls[:10]:  # Cap to avoid rate limit
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url if url.startswith("http") else f"http://{url}")
            host = parsed.hostname or ""
            if _IP_RE.match(host):
                ips.append(host)
            elif host and "." in host:
                domains.append(host)
        except Exception:
            pass

    sources_queried: List[str] = []
    tasks = []

    # ── Launch parallel queries ────────────────────────────────────────────────
    hash_vt_task = asyncio.create_task(_vt_check_hash(sha256))
    hash_otx_task = asyncio.create_task(_otx_check_hash(sha256))

    # URL VT checks (cap at 3 to stay within free tier rate limits)
    url_vt_tasks = [asyncio.create_task(_vt_check_url(u)) for u in urls[:3]]

    # Domain OTX checks
    domain_otx_tasks = [asyncio.create_task(_otx_check_domain(d)) for d in domains[:5]]

    # IP AbuseIPDB checks
    ip_abuse_tasks = [asyncio.create_task(_abuseipdb_check_ip(ip)) for ip in ips[:5]]

    # ── Gather results ─────────────────────────────────────────────────────────
    vt_hash = await hash_vt_task
    otx_hash = await hash_otx_task
    url_results = await asyncio.gather(*url_vt_tasks, return_exceptions=True)
    domain_results = await asyncio.gather(*domain_otx_tasks, return_exceptions=True)
    ip_results = await asyncio.gather(*ip_abuse_tasks, return_exceptions=True)

    # ── Process VirusTotal hash ────────────────────────────────────────────────
    if vt_hash.get("found"):
        result["available"] = True
        result["sha256_detections"] = vt_hash.get("malicious", 0)
        result["sha256_total"] = vt_hash.get("total", 0)
        result["vt_detection_ratio"] = vt_hash.get("ratio", 0.0)
        result["vt_family"] = vt_hash.get("family")
        result["vt_malicious_vendors"] = vt_hash.get("malicious_vendors", [])
        if vt_hash.get("family"):
            result["known_family"] = vt_hash["family"]
        sources_queried.append("VirusTotal")

    # ── Process OTX hash ──────────────────────────────────────────────────────
    if otx_hash.get("found") and otx_hash.get("pulse_count", 0) > 0:
        result["available"] = True
        result["otx_pulses"] = otx_hash.get("pulses", [])
        sources_queried.append("AlienVault OTX")
        # Extract family from pulses
        for pulse in otx_hash.get("pulses", []):
            families = pulse.get("malware_families", [])
            if families and not result["known_family"]:
                result["known_family"] = families[0]
            for tag in pulse.get("tags", []):
                if any(f in tag.lower() for f in ["xenomorph", "cerberus", "anubis", "drinik", "joker", "spynote"]):
                    result["campaign"] = tag

    # ── Process URL reputation ─────────────────────────────────────────────────
    ioc_rep: List[Dict] = []
    for url_res in url_results:
        if isinstance(url_res, dict) and url_res.get("found"):
            ioc_rep.append({
                "indicator": url_res.get("url", ""),
                "type": "URL",
                "reputation": url_res.get("reputation", "unknown"),
                "vt_malicious": url_res.get("malicious", 0),
                "vt_total": url_res.get("total", 0),
                "source": "VirusTotal",
            })
            if url_res.get("malicious", 0) > 0:
                result["suspicious_domains"].append(url_res.get("url", ""))

    # ── Process domain reputation ──────────────────────────────────────────────
    for dom_res in domain_results:
        if isinstance(dom_res, dict) and dom_res.get("found") and dom_res.get("pulse_count", 0) > 0:
            ioc_rep.append({
                "indicator": dom_res.get("domain", ""),
                "type": "Domain",
                "reputation": dom_res.get("reputation", "unknown"),
                "otx_pulses": dom_res.get("pulse_count", 0),
                "source": "AlienVault OTX",
            })
            if dom_res.get("reputation") in ("malicious", "suspicious"):
                result["suspicious_domains"].append(dom_res.get("domain", ""))

    # ── Process IP reputation ──────────────────────────────────────────────────
    for ip_res in ip_results:
        if isinstance(ip_res, dict) and ip_res.get("found"):
            ioc_rep.append({
                "indicator": ip_res.get("ip", ""),
                "type": "IP",
                "reputation": ip_res.get("reputation", "unknown"),
                "abuse_score": ip_res.get("abuse_score", 0),
                "country": ip_res.get("country", ""),
                "isp": ip_res.get("isp", ""),
                "source": "AbuseIPDB",
            })
            if ip_res.get("reputation") == "malicious":
                result["malicious_ips"].append(ip_res.get("ip", ""))
            sources_queried.append("AbuseIPDB")

    result["ioc_reputation"] = ioc_rep

    # ── Threat Score Calculation ───────────────────────────────────────────────
    score_components: List[str] = []
    threat_score = 0.0

    if result["vt_detection_ratio"] > 0:
        vt_contribution = min(result["vt_detection_ratio"] * 40, 40.0)
        threat_score += vt_contribution
        score_components.append(f"VT detection: {result['vt_detection_ratio']:.0%} (+{vt_contribution:.1f})")

    if result["otx_pulses"]:
        otx_contribution = min(len(result["otx_pulses"]) * 5, 20.0)
        threat_score += otx_contribution
        score_components.append(f"OTX pulses: {len(result['otx_pulses'])} (+{otx_contribution:.1f})")

    malicious_urls = sum(1 for ioc in ioc_rep if ioc.get("reputation") == "malicious")
    if malicious_urls > 0:
        url_contribution = min(malicious_urls * 10, 20.0)
        threat_score += url_contribution
        score_components.append(f"Malicious URLs: {malicious_urls} (+{url_contribution:.1f})")

    result["threat_score"] = min(threat_score, 100.0)
    result["threat_score_sources"] = score_components
    result["correlation_confidence"] = min(len(sources_queried) / 3, 1.0)
    result["sources_queried"] = list(set(sources_queried))

    logger.info(
        f"Threat correlation complete: score={result['threat_score']:.1f} "
        f"sources={result['sources_queried']} family={result['known_family']}"
    )
    return result
