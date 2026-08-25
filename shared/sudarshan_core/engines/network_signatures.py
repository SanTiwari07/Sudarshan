"""
Suricata and Snort signatures from a sample's network IOCs.

The export suite already offered YARA, STIX and IOC CSV. YARA matches the file;
none of them matched the sample's *traffic*, which is what a SOC actually
deploys at the perimeter. This module closes that gap.

Two failure modes drive almost every decision here, because a bad network rule
is worse than no rule:

  * A rule that does not compile is silently useless. Suricata and Snort take
    `content:"..."` strings in which `"` `\\` and `;` are structural, so any
    indicator carrying one produces a broken rule - the same class of defect
    that was already fixed once in the YARA exporter.

  * A rule that matches everything is worse than useless. A signature on
    10.0.0.5 or 127.0.0.1 fires on ordinary internal traffic and buries the
    analyst. Non-routable indicators are excluded, and the reason is recorded
    rather than silently dropped.

Nothing here is AI-generated. Signatures are a defensive artifact an operator
will deploy; they are derived deterministically from observed indicators so the
same report always yields the same rules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

#: Snort/Suricata reserve SIDs below 1,000,000 for distributed rulesets.
#: Local rules must start at or above this or they collide with vendor rules.
LOCAL_SID_START = 1_000_000

#: Cap the emitted rule count. A sample with thousands of extracted strings
#: would otherwise produce a ruleset nobody can deploy.
MAX_RULES = 200

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@dataclass
class Indicator:
    """One network indicator, and whether it can carry a signature."""

    value: str
    kind: str  # "domain" | "ip"
    usable: bool = True
    skip_reason: str = ""


@dataclass
class SignatureSet:
    """Generated rules plus an account of what was left out and why."""

    rules: List[str] = field(default_factory=list)
    skipped: List[Indicator] = field(default_factory=list)
    truncated: int = 0

    def text(self, header: str) -> str:
        lines = [header]
        for ind in self.skipped:
            lines.append(f"# skipped {ind.value}: {ind.skip_reason}")
        if self.truncated:
            lines.append(
                f"# {self.truncated} further indicator(s) omitted: "
                f"rule cap of {MAX_RULES} reached"
            )
        if self.skipped or self.truncated:
            lines.append("#")
        if not self.rules:
            lines.append("# No deployable network indicators were found.")
        lines.extend(self.rules)
        return "\n".join(lines) + "\n"


def _host_of(raw: str) -> str:
    """Reduce a URL or bare host to its hostname."""
    value = (raw or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        # Bare "host:port/path" - urlparse needs a scheme to find the host.
        value = value.split("/")[0]
        if value.count(":") == 1:
            value = value.split(":")[0]
    return value.strip().strip(".").lower()


def _classify(host: str) -> Optional[Indicator]:
    """Decide whether a host is a signable domain, a signable IP, or neither."""
    if not host:
        return None
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if not _DOMAIN_RE.match(host):
            return None
        if "." not in host:
            return None
        return Indicator(host, "domain")

    # An IP literal. Only globally routable addresses are worth alerting on.
    if addr.is_loopback:
        return Indicator(host, "ip", False, "loopback address")
    if addr.is_private:
        return Indicator(host, "ip", False, "RFC1918 / private address")
    if addr.is_link_local:
        return Indicator(host, "ip", False, "link-local address")
    if addr.is_multicast:
        return Indicator(host, "ip", False, "multicast address")
    if addr.is_unspecified or addr.is_reserved:
        return Indicator(host, "ip", False, "unspecified or reserved address")
    return Indicator(host, "ip")


def extract_indicators(report: Dict[str, Any]) -> List[Indicator]:
    """
    Collect network indicators from a report, deduplicated and classified.

    Reads both the static extraction and anything the sandbox actually
    contacted, because a host seen at runtime is the stronger indicator and
    must never be missed because static extraction did not also find it.
    """
    raw: List[str] = []
    for value in report.get("hardcoded_urls_ips") or []:
        if isinstance(value, str):
            raw.append(value)

    domains = report.get("domains")
    if isinstance(domains, dict):
        raw.extend(k for k in domains.keys() if isinstance(k, str))

    dynamic = report.get("dynamic_analysis")
    if isinstance(dynamic, dict):
        for log in dynamic.get("network_logs") or []:
            if not isinstance(log, dict):
                continue
            for key in ("url", "host", "destination", "ioc"):
                value = log.get(key)
                if isinstance(value, str) and value.strip():
                    raw.append(value)
                    break

    seen: Dict[str, Indicator] = {}
    for value in raw:
        indicator = _classify(_host_of(value))
        if indicator is None:
            continue
        # Keep the first classification; they are deterministic per host.
        seen.setdefault(indicator.value, indicator)
    return list(seen.values())


def escape_content(value: str) -> str:
    """
    Escape a value for a Suricata/Snort `content:"..."` string.

    `"` `\\` and `;` are structural in rule syntax; an unescaped one truncates
    or corrupts the rule. Bytes outside printable ASCII are emitted as a hex
    block, which both engines accept inside a content string.
    """
    out: List[str] = []
    for ch in str(value):
        if ch in ('"', "\\", ";"):
            out.append(f"\\{ch}")
        elif 0x20 <= ord(ch) <= 0x7E:
            out.append(ch)
        else:
            hex_bytes = " ".join(f"{b:02X}" for b in ch.encode("utf-8"))
            out.append(f"|{hex_bytes}|")
    return "".join(out)


def _msg(package: str, host: str, engine_note: str) -> str:
    """
    Build the alert message.

    The message is itself inside a quoted rule option, so it needs the same
    escaping as content - a package name with a quote in it would otherwise
    break every rule in the file.
    """
    pkg = escape_content(package or "unknown")[:80]
    return f"SUDARSHAN Android {pkg} {engine_note} {escape_content(host)[:120]}"


def _partition(
    indicators: Iterable[Indicator],
) -> Tuple[List[Indicator], List[Indicator], int]:
    usable: List[Indicator] = []
    skipped: List[Indicator] = []
    for ind in indicators:
        (usable if ind.usable else skipped).append(ind)
    truncated = max(0, len(usable) - MAX_RULES)
    return usable[:MAX_RULES], skipped, truncated


def build_suricata_rules(
    report: Dict[str, Any], sid_start: int = LOCAL_SID_START,
) -> SignatureSet:
    """Suricata rules: HTTP Host and TLS SNI for domains, IP match for hosts."""
    package = str(report.get("package_name") or "unknown")
    usable, skipped, truncated = _partition(extract_indicators(report))

    result = SignatureSet(skipped=skipped, truncated=truncated)
    sid = sid_start
    for ind in usable:
        content = escape_content(ind.value)
        if ind.kind == "domain":
            result.rules.append(
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"{_msg(package, ind.value, "HTTP contact to")}"; '
                f'flow:established,to_server; http.host; '
                f'content:"{content}"; nocase; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
            result.rules.append(
                f'alert tls $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"{_msg(package, ind.value, "TLS SNI for")}"; '
                f'tls.sni; content:"{content}"; nocase; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
        else:
            result.rules.append(
                f'alert ip $HOME_NET any -> {ind.value} any '
                f'(msg:"{_msg(package, ind.value, "traffic to")}"; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
    return result


def build_snort_rules(
    report: Dict[str, Any], sid_start: int = LOCAL_SID_START,
) -> SignatureSet:
    """
    Snort rules.

    Snort 2 has no `tls.sni` buffer, so a domain gets a single HTTP header rule
    rather than the HTTP + TLS pair Suricata gets. Emitting a `tls.sni` rule
    here would produce a file Snort refuses to load.
    """
    package = str(report.get("package_name") or "unknown")
    usable, skipped, truncated = _partition(extract_indicators(report))

    result = SignatureSet(skipped=skipped, truncated=truncated)
    sid = sid_start
    for ind in usable:
        content = escape_content(ind.value)
        if ind.kind == "domain":
            result.rules.append(
                f'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
                f'(msg:"{_msg(package, ind.value, "HTTP contact to")}"; '
                f'flow:established,to_server; '
                f'content:"{content}"; http_header; nocase; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
        else:
            result.rules.append(
                f'alert ip $HOME_NET any -> {ind.value} any '
                f'(msg:"{_msg(package, ind.value, "traffic to")}"; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
    return result


def suricata_text(report: Dict[str, Any], sha256: str = "") -> str:
    header = (
        f"# Suricata rules generated by Sudarshan\n"
        f"# Sample SHA-256: {sha256 or 'unknown'}\n"
        f"# Package: {report.get('package_name', 'unknown')}\n"
        f"# Derived deterministically from observed network indicators.\n"
        f"# Review before deploying: a domain may be shared with benign hosts.\n#"
    )
    return build_suricata_rules(report).text(header)


def snort_text(report: Dict[str, Any], sha256: str = "") -> str:
    header = (
        f"# Snort rules generated by Sudarshan\n"
        f"# Sample SHA-256: {sha256 or 'unknown'}\n"
        f"# Package: {report.get('package_name', 'unknown')}\n"
        f"# Derived deterministically from observed network indicators.\n"
        f"# Review before deploying: a domain may be shared with benign hosts.\n#"
    )
    return build_snort_rules(report).text(header)
