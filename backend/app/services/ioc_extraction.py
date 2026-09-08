"""
Extract queryable indicators from an analysis result.
=====================================================

`cases.raw_result` keeps the full forensic record and is not changed by any of
this. This module pulls the *indicators* out of it into `case_iocs` so the
platform can answer "which other samples contacted this host" - a question a
JSON blob cannot answer at any price.

Where indicators actually live in a result (verified against stored rows):

  threat_correlation.malicious_ips      - correlator, IPs with a reputation hit
  threat_correlation.suspicious_domains - correlator
  threat_correlation.ioc_reputation     - correlator, enriched {type,indicator,...}
  domains                               - static extraction (dict)
  hardcoded_urls_ips                    - static extraction (list)
  dynamic_result.network_logs           - observed at runtime

`hardcoded_urls_ips` needs care. Despite the name it is a raw string dump and
contains developer log messages, not just indicators - a real stored row holds
entries like "Analytics service at risk of not starting... See http://goo.gl/8Rd3yj
for instructions." Writing those in verbatim would fill the pivot table with
noise and produce false campaign links between unrelated samples, so each entry
is parsed for an embedded host rather than trusted as one.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)

# Hosts that say nothing about the sample. Any indicator resolving to one of
# these links every APK that ships an ad or analytics SDK, which is an
# anti-signal: it makes unrelated samples look like one campaign.
#
# Derived by running the extractor over the stored corpus and reading what came
# out - the first pass admitted www.google-analytics.com, doubleclick and
# twitter.com on samples that have nothing to do with each other.
#
# A denylist alone cannot be complete, which is why it is only half the defence.
# The other half is prevalence: see `shared_indicators` in app.db.intel, which
# ignores indicators that appear on too large a share of all cases.
_NOISE_SUFFIXES = (
    # Google / Android platform
    "goo.gl", "google.com", "googleapis.com", "gstatic.com", "android.com",
    "schemas.android.com", "google-analytics.com", "googletagmanager.com",
    "googleadservices.com", "googlesyndication.com", "doubleclick.net",
    "googleusercontent.com", "gvt1.com", "crashlytics.com", "firebaseio.com",
    "firebase.google.com", "app-measurement.com",
    # Standards / docs / tooling
    "w3.org", "apache.org", "github.com", "githubusercontent.com",
    "example.com", "example.org", "schema.org", "json-schema.org",
    "xmlpull.org", "slf4j.org", "oracle.com", "sun.com", "mozilla.org",
    # Mainstream consumer services - present in half of all APKs
    "facebook.com", "fbcdn.net", "twitter.com", "t.co", "instagram.com",
    "linkedin.com", "youtube.com", "microsoft.com", "live.com", "yahoo.com",
    "amazonaws.com", "cloudfront.net", "akamaized.net", "bit.ly",
    # Ad networks
    "flurry.com", "adjust.com", "appsflyer.com", "unity3d.com", "applovin.com",
    "inmobi.com", "mopub.com", "chartboost.com",
    "localhost",
)

_NOISE_EXACT = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "::1", "8.8.8.8", "1.1.1.1"}

# The correlator returns its own casing ("URL", "IP", "Domain"); static
# extraction returns lowercase. case_iocs is keyed on (sha256, indicator,
# ioc_type), so leaving both spellings in writes the same indicator twice and
# the pivot silently misses half its matches.
_TYPE_ALIASES = {
    "url": "url", "uri": "url", "link": "url",
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip_address": "ip",
    "domain": "domain", "hostname": "domain", "host": "domain", "fqdn": "domain",
    "email": "email", "e-mail": "email",
    "sha256": "sha256", "hash": "sha256", "file": "sha256",
    "package": "package", "package_name": "package",
}


def normalise_type(raw: Any) -> str:
    key = str(raw or "").strip().lower().replace(" ", "_")
    return _TYPE_ALIASES.get(key, key or "unknown")


def _is_noise(indicator: str) -> bool:
    low = indicator.lower().strip(".")
    if low in _NOISE_EXACT:
        return True
    return any(low == s or low.endswith("." + s) for s in _NOISE_SUFFIXES)


def _classify(indicator: str) -> Optional[str]:
    """Return 'ip', 'domain', 'url', or None when it is not an indicator."""
    value = indicator.strip()
    if not value:
        return None
    if value.lower().startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.fullmatch(value):
        return "domain"
    return None


def _host_of(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:  # noqa: BLE001
        return None


def _harvest_from_text(text: str) -> Set[str]:
    """
    Pull hosts out of a free-text string.

    This is what makes `hardcoded_urls_ips` usable: a log line mentioning a URL
    yields that URL's host, and a line mentioning nothing yields nothing.
    """
    found: Set[str] = set()
    for url in _URL_RE.findall(text):
        host = _host_of(url)
        if host:
            found.add(host)
    if not found:
        # Only fall back to bare-domain matching when the string is short
        # enough to plausibly *be* an indicator rather than prose containing one.
        stripped = text.strip()
        if len(stripped) <= 253 and " " not in stripped:
            for m in _DOMAIN_RE.findall(stripped):
                found.add(m.lower())
    return found


def _add(
    out: Dict[tuple, Dict[str, Any]],
    indicator: str,
    ioc_type: str,
    context: str,
    source: str,
    reputation: Optional[str] = None,
    confidence: Optional[float] = None,
) -> None:
    indicator = indicator.strip().rstrip(".")
    ioc_type = normalise_type(ioc_type)
    if not indicator or len(indicator) > 500 or _is_noise(indicator):
        return
    key = (indicator.lower(), ioc_type)
    existing = out.get(key)
    if existing is None:
        out[key] = {
            "indicator": indicator, "ioc_type": ioc_type, "context": context,
            "source": source, "reputation": reputation, "confidence": confidence,
        }
        return
    # A correlator hit outranks a static string sighting: keep the enrichment.
    if reputation and not existing.get("reputation"):
        existing["reputation"] = reputation
        existing["source"] = source
        existing["context"] = context
    if confidence is not None and existing.get("confidence") is None:
        existing["confidence"] = confidence


def _iter_strings(value: Any) -> Iterable[str]:
    """Yield strings from a str, list, or dict-keys - the three shapes seen."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, str):
                yield v
            elif isinstance(v, dict):
                for k in ("domain", "host", "url", "ip", "indicator", "value"):
                    if isinstance(v.get(k), str):
                        yield v[k]
                        break
    elif isinstance(value, dict):
        for k in value.keys():
            if isinstance(k, str):
                yield k


def extract_iocs(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return de-duplicated, noise-filtered indicators for `case_iocs`."""
    out: Dict[tuple, Dict[str, Any]] = {}

    if not isinstance(result, dict):
        return []

    # The sample itself is always an indicator, and it is the join key other
    # tools use when they receive an export.
    sha = result.get("sha256")
    if isinstance(sha, str) and len(sha) == 64:
        _add(out, sha, "sha256", "sample hash", "static", confidence=1.0)

    pkg = result.get("package_name")
    if isinstance(pkg, str) and pkg:
        _add(out, pkg, "package", "android package name", "static")

    tc = result.get("threat_correlation")
    if isinstance(tc, dict):
        for ip in _iter_strings(tc.get("malicious_ips")):
            if _classify(ip) == "ip":
                _add(out, ip, "ip", "correlator: malicious", "correlation",
                     reputation="malicious", confidence=0.9)
        for dom in _iter_strings(tc.get("suspicious_domains")):
            if _classify(dom) == "domain":
                _add(out, dom, "domain", "correlator: suspicious", "correlation",
                     reputation="suspicious", confidence=0.7)
        for entry in tc.get("ioc_reputation") or []:
            if not isinstance(entry, dict):
                continue
            ind = entry.get("indicator")
            if not isinstance(ind, str):
                continue
            kind = normalise_type(entry.get("type")) if entry.get("type") else (
                _classify(ind) or "unknown"
            )
            _add(out, ind, kind, "threat intelligence", "correlation",
                 reputation=entry.get("reputation"),
                 confidence=entry.get("confidence"))

    for dom in _iter_strings(result.get("domains")):
        if _classify(dom) == "domain":
            _add(out, dom, "domain", "static: extracted domain", "static")

    # The noisy one - parse, never trust.
    for raw in _iter_strings(result.get("hardcoded_urls_ips")):
        for host in _harvest_from_text(raw):
            kind = _classify(host)
            if kind in ("domain", "ip"):
                _add(out, host, kind, "static: hardcoded string", "static")

    for addr in _iter_strings(result.get("emails")):
        if "@" in addr and len(addr) < 320:
            _add(out, addr, "email", "static: extracted email", "static")

    dynamic = result.get("dynamic_result")
    if isinstance(dynamic, dict):
        for entry in dynamic.get("network_logs") or []:
            candidates: List[str] = []
            if isinstance(entry, str):
                candidates = list(_harvest_from_text(entry))
            elif isinstance(entry, dict):
                for k in ("host", "url", "domain", "remote_ip", "ip"):
                    v = entry.get(k)
                    if isinstance(v, str):
                        candidates.extend(
                            _harvest_from_text(v) if k == "url" else [v]
                        )
            for cand in candidates:
                kind = _classify(cand)
                if kind in ("domain", "ip"):
                    _add(out, cand, kind, "observed at runtime", "dynamic",
                         confidence=0.95)

    return list(out.values())
