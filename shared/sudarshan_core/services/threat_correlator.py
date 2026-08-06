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

# ─── API Keys (from .env or environment) ──────────────────────────────────────

def _load_env_if_needed():
    """Ensure .env is loaded dynamically whenever API keys are requested."""
    try:
        from pathlib import Path
        from dotenv import load_dotenv
        candidate_paths = [
            Path("/app/.env"),
            Path("/opt/sudarshan-core/.env"),
            Path.cwd() / ".env",
            Path(__file__).resolve().parent / ".env",
            Path(__file__).resolve().parent.parent / ".env",
            Path(__file__).resolve().parent.parent.parent / ".env",
        ]
        for env_file in candidate_paths:
            if env_file.exists():
                load_dotenv(dotenv_path=env_file, override=True)
                break
    except Exception:
        pass

# The .env walk-up stats up to six paths and may re-parse the file with
# override=True. These getters are called INSIDE the per-URL, per-domain and
# per-IP task bodies, so a sample with a dozen extracted URLs performed dozens
# of redundant filesystem probes and environment mutations per analysis.
# Resolve once per process; an operator changing a key restarts the service.
_KEY_CACHE: Dict[str, str] = {}


def _cached_key(env_name: str) -> str:
    if env_name not in _KEY_CACHE:
        _load_env_if_needed()
        _KEY_CACHE[env_name] = os.getenv(env_name, "")
    return _KEY_CACHE[env_name]


def _get_vt_key() -> str:
    return _cached_key("VIRUSTOTAL_API_KEY")

def _get_otx_key() -> str:
    return _cached_key("OTX_API_KEY")

def _get_abuseipdb_key() -> str:
    return _cached_key("ABUSEIPDB_API_KEY")


# ─── IOC reputation cache ─────────────────────────────────────────────────────
#
# The `ioc_cache` table exists, is indexed (idx_ioc_expires) and has correct
# 24-hour TTL accessors in app.db.database — and NOTHING ever called them.
# Meanwhile this module issued up to 14 uncached outbound requests per analysis
# (1 VT hash + 1 OTX hash + 3 VT URLs + 5 OTX domains + 5 AbuseIPDB IPs) against
# a VirusTotal free tier of 4 requests/minute. A single analysis exceeded the
# quota, and GET /intelligence/{sha} re-fired the whole set on every request.
#
# The cache lives in the backend (app.db), which sudarshan_core must not import
# — the analysis engine has no such package. So it is injected: the backend
# passes its accessors in, and when they are absent (engine-side) correlation
# simply runs uncached exactly as before.
_cache_get = None   # async (indicator, ioc_type) -> Optional[dict]
_cache_put = None   # async (indicator, ioc_type, reputation, source, score, raw, ttl_hours)


def configure_ioc_cache(getter, setter) -> None:
    """Install the persistent IOC reputation cache. Called by the backend."""
    global _cache_get, _cache_put
    _cache_get, _cache_put = getter, setter
    logger.info("[Correlator] Persistent IOC cache enabled")


async def _cached_lookup(indicator: str, ioc_type: str):
    if _cache_get is None or not indicator:
        return None
    try:
        row = await _cache_get(indicator, ioc_type)
        if row:
            logger.debug(f"[Correlator] Cache hit: {ioc_type} {indicator[:60]}")
            return row.get("raw_data")
    except Exception as exc:
        logger.warning(f"[Correlator] IOC cache read failed: {exc}")
    return None


async def _cache_store(indicator: str, ioc_type: str, payload: Dict[str, Any]) -> None:
    if _cache_put is None or not indicator or not payload:
        return
    try:
        await _cache_put(
            indicator, ioc_type,
            payload.get("reputation", "unknown"),
            payload.get("source", ioc_type),
            float(payload.get("threat_score", 0.0) or 0.0),
            payload,
            24,
        )
    except Exception as exc:
        logger.warning(f"[Correlator] IOC cache write failed: {exc}")

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
        "vt_hash_in_database": None,
    }

# ─── VirusTotal ───────────────────────────────────────────────────────────────

async def _vt_check_hash(sha256: str) -> Dict[str, Any]:
    """Query VirusTotal for a SHA256 hash (24h cached)."""
    vt_key = _get_vt_key()
    if not vt_key:
        return {}
    cached = await _cached_lookup(sha256, "vt_hash")
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": vt_key},
            )
            if r.status_code == 404:
                return {"found": False, "in_database": False}
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

            # Malware family — VirusTotal's OWN classification, or nothing.
            #
            # There used to be a fallback here that scanned attrs["names"] — the
            # list of FILENAMES other people have submitted this file under — for
            # one containing "android", and used that string as the malware
            # family. `names` is uploader-supplied metadata, not analysis output.
            #
            # Observed live on a benign sample: Amaze File Manager is known to VT
            # with 0/75 detections, so it has no threat label, and the fallback
            # assigned it the family "Amaze File Manager 3.11.2 (Android 5.0+).apk".
            # That is not cosmetic — routes/upload.py adopts a correlation-derived
            # family when static classification says Unknown AND raises
            # ai_confidence to 1.15, a 15% multiplier on the final score. A clean
            # file manager was inflated because of a filename, and the report told
            # the analyst it belonged to a malware family.
            #
            # No label means no known family. Absence of classification is not a
            # classification.
            family = (
                attrs.get("popular_threat_classification", {})
                .get("suggested_threat_label")
            )

            result = {
                "found": True,
                "malicious": malicious,
                "total": total,
                "ratio": malicious / total,
                "family": family,
                "malicious_vendors": malicious_vendors[:5],
                "reputation": attrs.get("reputation", 0),
            }
            await _cache_store(sha256, "vt_hash", result)
            return result
    except Exception as e:
        logger.warning(f"VirusTotal hash query failed: {e}")
        return {}

async def _vt_check_url(url: str) -> Dict[str, Any]:
    """Query VirusTotal for a URL reputation (24h cached)."""
    vt_key = _get_vt_key()
    if not vt_key:
        return {}
    cached = await _cached_lookup(url, "vt_url")
    if cached is not None:
        return cached
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": vt_key},
            )
            if r.status_code == 404:
                return {"found": False, "url": url}
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            malicious = stats.get("malicious", 0)
            result = {
                "found": True,
                "url": url,
                "malicious": malicious,
                "total": total,
                "ratio": malicious / total,
                "reputation": "malicious" if malicious > 2 else "suspicious" if malicious > 0 else "clean",
            }
            await _cache_store(url, "vt_url", result)
            return result
    except Exception as e:
        logger.warning(f"VirusTotal URL query failed for {url[:50]}: {e}")
        return {"found": False, "url": url}

# ─── AlienVault OTX ──────────────────────────────────────────────────────────

async def _otx_check_hash(sha256: str) -> Dict[str, Any]:
    """Query AlienVault OTX for file hash."""
    otx_key = _get_otx_key()
    if not otx_key:
        return {}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                headers={"X-OTX-API-KEY": otx_key},
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
    """Query AlienVault OTX for domain reputation (24h cached)."""
    otx_key = _get_otx_key()
    if not otx_key:
        return {}
    cached = await _cached_lookup(domain, "otx_domain")
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": otx_key},
            )
            if r.status_code == 404:
                return {"found": False, "domain": domain}
            r.raise_for_status()
            data = r.json()
            pulses = data.get("pulse_info", {}).get("pulses", [])
            result = {
                "found": True,
                "domain": domain,
                "pulse_count": len(pulses),
                "reputation": "malicious" if len(pulses) > 3 else "suspicious" if pulses else "unknown",
            }
            await _cache_store(domain, "otx_domain", result)
            return result
    except Exception as e:
        logger.warning(f"OTX domain query failed for {domain}: {e}")
        return {"found": False, "domain": domain}

# ─── AbuseIPDB ────────────────────────────────────────────────────────────────

_IP_RE = __import__("re").compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

async def _abuseipdb_check_ip(ip: str) -> Dict[str, Any]:
    """Query AbuseIPDB for IP address reputation (24h cached)."""
    abuse_key = _get_abuseipdb_key()
    if not abuse_key or not _IP_RE.match(ip):
        return {}
    cached = await _cached_lookup(ip, "abuseipdb_ip")
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            result = {
                "ip": ip,
                "found": True,
                "abuse_score": score,
                "reputation": "malicious" if score > 50 else "suspicious" if score > 10 else "clean",
                "total_reports": d.get("totalReports", 0),
                "country": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "usage_type": d.get("usageType", ""),
            }
            await _cache_store(ip, "abuseipdb_ip", result)
            return result
    except Exception as e:
        logger.warning(f"AbuseIPDB query failed for {ip}: {e}")
        return {}

# ─── Main Correlator ─────────────────────────────────────────────────────────

async def correlate(
    sha256: str,
    urls: List[str],
    package_name: str = "",
    dynamic_urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run parallel threat correlation queries for static and live dynamic IOCs.

    Args:
        sha256: APK SHA256 hash
        urls: List of hardcoded URLs/IPs from static analysis
        package_name: APK package name for context
        dynamic_urls: Optional list of runtime-observed C2 URLs/IPs

    Returns:
        Normalized correlation result dict
    """
    result = _empty_result()

    # Combine static and dynamic URLs, tracking origin
    all_urls = list(urls)
    dyn_set = set(dynamic_urls or [])
    for d_url in dyn_set:
        if d_url not in all_urls:
            all_urls.append(d_url)

    # Extract domains and IPs from URLs
    domains: List[str] = []
    ips: List[str] = []
    for url in all_urls[:12]:  # Cap to avoid rate limit
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
        result["vt_hash_in_database"] = True
        result["sha256_detections"] = vt_hash.get("malicious", 0)
        result["sha256_total"] = vt_hash.get("total", 0)
        result["vt_detection_ratio"] = vt_hash.get("ratio", 0.0)
        result["vt_family"] = vt_hash.get("family")
        result["vt_malicious_vendors"] = vt_hash.get("malicious_vendors", [])
        if vt_hash.get("family"):
            result["known_family"] = vt_hash["family"]
        sources_queried.append("VirusTotal")
    elif vt_hash.get("found") is False and _get_vt_key():
        result["vt_hash_in_database"] = False
        sources_queried.append("VirusTotal")

    # ── Process OTX hash ──────────────────────────────────────────────────────
    if _get_otx_key():
        sources_queried.append("AlienVault OTX")
        result["available"] = True

    if otx_hash.get("found") and otx_hash.get("pulse_count", 0) > 0:
        result["otx_pulses"] = otx_hash.get("pulses", [])
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


class ThreatCorrelatorListener:
    """
    Subscribes to NETWORK_EVENT on RuntimeEventBus and correlates runtime URLs,
    publishing THREAT_DETECTED events back to the EventBus.
    """

    def __init__(self, event_bus: Any, package_name: str = "") -> None:
        self.event_bus = event_bus
        self.package_name = package_name
        self.seen_urls: set = set()
        if self.event_bus:
            self.event_bus.subscribe(self._on_event)
            logger.debug("[ThreatCorrelatorListener] Subscribed to RuntimeEventBus")

    def _on_event(self, event: Dict[str, Any]) -> None:
        etype = event.get("event_type", event.get("type", ""))
        if etype != "NETWORK_EVENT":
            return

        payload = event.get("payload", event.get("data", {}))
        url = payload.get("url") or payload.get("indicator")
        if not url or url in self.seen_urls:
            return

        self.seen_urls.add(url)

        def _bg_correlate():
            import time
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                res = loop.run_until_complete(
                    correlate(sha256="", urls=[url], package_name=self.package_name, dynamic_urls=[url])
                )
                loop.close()

                if res and (res.get("threat_score", 0) > 0 or res.get("suspicious_domains") or res.get("malicious_ips")):
                    from sudarshan_core.engines.event_bus import EventType, RuntimeEvent
                    self.event_bus.publish(RuntimeEvent(
                        event_type=EventType.THREAT_DETECTED,
                        timestamp=time.time(),
                        payload={
                            "indicator": url,
                            "threat_score": res.get("threat_score", 0),
                            "reputation": "malicious" if res.get("threat_score", 0) > 40 else "suspicious",
                            "source": ", ".join(res.get("sources_queried", ["ThreatIntel"])),
                            "family": res.get("known_family"),
                            "severity": "HIGH" if res.get("threat_score", 0) > 40 else "MED",
                        }
                    ))
            except Exception as e:
                logger.error("[ThreatCorrelatorListener] Background correlation failed for %s: %s", url, e)

        import threading
        threading.Thread(target=_bg_correlate, daemon=True).start()

