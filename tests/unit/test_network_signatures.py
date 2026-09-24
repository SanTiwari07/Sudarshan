"""
Suricata / Snort signature generation.

A network signature is deployed at a perimeter, so the two ways it can be
wrong are both expensive:

  * It does not compile - silently useless. `"` `\\` and `;` are structural in
    a content string, and the YARA exporter had exactly this defect before it
    was fixed, so it is pinned here from the start.
  * It matches everything - a rule on 10.0.0.5 or 127.0.0.1 fires on ordinary
    internal traffic and buries the analyst.

The exclusions are recorded in the output rather than dropped, because an
operator needs to know an indicator existed and was deliberately not signed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.network_signatures import (  # noqa: E402
    LOCAL_SID_START,
    MAX_RULES,
    build_snort_rules,
    build_suricata_rules,
    escape_content,
    extract_indicators,
    snort_text,
    suricata_text,
)


def _report(**kw):
    base = {"package_name": "com.evil.app", "hardcoded_urls_ips": [], "domains": {}}
    base.update(kw)
    return base


# ── indicator extraction ─────────────────────────────────────────────────────

def test_a_domain_is_extracted():
    inds = extract_indicators(_report(hardcoded_urls_ips=["evil.test"]))
    assert [i.value for i in inds] == ["evil.test"]
    assert inds[0].kind == "domain"


def test_a_url_is_reduced_to_its_host():
    inds = extract_indicators(
        _report(hardcoded_urls_ips=["https://evil.test/c2/beacon?x=1"])
    )
    assert [i.value for i in inds] == ["evil.test"]


def test_a_host_with_a_port_is_reduced():
    inds = extract_indicators(_report(hardcoded_urls_ips=["evil.test:8443/path"]))
    assert [i.value for i in inds] == ["evil.test"]


def test_a_public_ip_is_signable():
    inds = extract_indicators(_report(hardcoded_urls_ips=["104.21.5.9"]))
    assert inds[0].kind == "ip"
    assert inds[0].usable is True


@pytest.mark.parametrize("addr,reason", [
    ("127.0.0.1", "loopback"),
    ("10.0.0.5", "private"),
    ("192.168.1.1", "private"),
    ("172.16.0.9", "private"),
    ("169.254.1.1", "link-local"),
    ("0.0.0.0", "unspecified"),
])
def test_non_routable_addresses_are_excluded(addr, reason):
    """A rule on an internal address fires on everything."""
    inds = extract_indicators(_report(hardcoded_urls_ips=[addr]))
    assert len(inds) == 1
    assert inds[0].usable is False
    assert inds[0].skip_reason


def test_runtime_contacted_hosts_are_included():
    """A host seen at runtime is the stronger indicator; it must not be missed."""
    inds = extract_indicators(_report(
        dynamic_analysis={"network_logs": [{"url": "https://runtime.test/a"}]},
    ))
    assert [i.value for i in inds] == ["runtime.test"]


def test_the_same_host_from_several_sources_appears_once():
    inds = extract_indicators(_report(
        hardcoded_urls_ips=["evil.test", "https://evil.test/x"],
        domains={"evil.test": {}},
        dynamic_analysis={"network_logs": [{"host": "evil.test"}]},
    ))
    assert len(inds) == 1


def test_garbage_is_not_treated_as_an_indicator():
    inds = extract_indicators(_report(
        hardcoded_urls_ips=["", "not a host", "localhost", "....", "a b c"],
    ))
    assert inds == []


def test_non_string_entries_do_not_crash_extraction():
    assert extract_indicators(_report(hardcoded_urls_ips=[None, 5, {}])) == []


# ── escaping: the "does not compile" failure ─────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ('a"b', 'a\\"b'),
    ("a\\b", "a\\\\b"),
    ("a;b", "a\\;b"),
])
def test_structural_characters_are_escaped(raw, expected):
    assert escape_content(raw) == expected


def test_non_ascii_becomes_a_hex_block():
    # Both engines accept |XX| inside a content string; a raw byte does not
    # survive a rule file reliably.
    assert escape_content("é") == "|C3 A9|"


def test_a_quote_in_the_package_name_cannot_break_the_rule():
    rules = build_suricata_rules(
        _report(package_name='ev"il;pkg', hardcoded_urls_ips=["evil.test"])
    ).rules
    for rule in rules:
        # Every rule option is `name:"value";`, so the UNESCAPED quotes must
        # pair up. Escaped ones (\") are content and do not open or close an
        # option, so they have to be removed before counting - counting raw
        # quotes would fail on correctly escaped output.
        structural = re.sub(r"\\.", "", rule)
        assert structural.count('"') % 2 == 0
        assert '"' in rule
        # The escaping actually happened rather than the quote being dropped.
        assert '\\"' in rule
        assert "\\;" in rule


# ── Suricata ─────────────────────────────────────────────────────────────────

def test_a_domain_yields_both_http_and_tls_rules():
    rules = build_suricata_rules(_report(hardcoded_urls_ips=["evil.test"])).rules
    assert len(rules) == 2
    assert any("http.host" in r for r in rules)
    assert any("tls.sni" in r for r in rules)


def test_an_ip_yields_a_single_ip_rule():
    rules = build_suricata_rules(_report(hardcoded_urls_ips=["104.21.5.9"])).rules
    assert len(rules) == 1
    assert "104.21.5.9" in rules[0]
    assert "http.host" not in rules[0]


def test_sids_start_in_the_local_range_and_are_unique():
    """Below 1,000,000 collides with distributed vendor rulesets."""
    rules = build_suricata_rules(
        _report(hardcoded_urls_ips=["a.test", "b.test", "104.21.5.9"])
    ).rules
    sids = [int(r.split("sid:")[1].split(";")[0]) for r in rules]
    assert all(s >= LOCAL_SID_START for s in sids)
    assert len(set(sids)) == len(sids)


def test_every_rule_is_terminated_and_has_a_revision():
    rules = build_suricata_rules(_report(hardcoded_urls_ips=["evil.test"])).rules
    for rule in rules:
        assert rule.endswith(";)")
        assert "rev:1;" in rule
        assert rule.startswith("alert ")


# ── Snort ────────────────────────────────────────────────────────────────────

def test_snort_does_not_emit_a_tls_sni_rule():
    """Snort 2 has no tls.sni buffer; such a file fails to load."""
    rules = build_snort_rules(_report(hardcoded_urls_ips=["evil.test"])).rules
    assert len(rules) == 1
    assert "tls.sni" not in rules[0]
    assert "http_header" in rules[0]


def test_snort_and_suricata_agree_on_which_hosts_are_signable():
    report = _report(hardcoded_urls_ips=["evil.test", "10.0.0.5", "104.21.5.9"])
    suri = build_suricata_rules(report)
    snort = build_snort_rules(report)
    assert [i.value for i in suri.skipped] == [i.value for i in snort.skipped]


# ── output text ──────────────────────────────────────────────────────────────

def test_excluded_indicators_are_reported_not_silently_dropped():
    text = suricata_text(_report(hardcoded_urls_ips=["10.0.0.5"]), "a" * 64)
    assert "# skipped 10.0.0.5" in text
    assert "private" in text


def test_a_sample_with_no_indicators_says_so():
    text = suricata_text(_report(), "a" * 64)
    assert "No deployable network indicators" in text


def test_the_header_carries_the_sample_identity():
    text = snort_text(_report(hardcoded_urls_ips=["evil.test"]), "b" * 64)
    assert "b" * 64 in text
    assert "com.evil.app" in text


def test_output_is_deterministic():
    """Same report, same rules - an operator diffing two exports needs this."""
    report = _report(hardcoded_urls_ips=["evil.test", "104.21.5.9"])
    assert suricata_text(report, "c" * 64) == suricata_text(report, "c" * 64)


def test_the_rule_count_is_capped():
    report = _report(
        hardcoded_urls_ips=[f"host{i}.test" for i in range(MAX_RULES + 40)]
    )
    result = build_snort_rules(report)
    assert len(result.rules) == MAX_RULES
    assert result.truncated == 40
    assert "rule cap" in result.text("#")


# ── the endpoints must be wired ──────────────────────────────────────────────

def test_the_export_endpoints_are_registered(monkeypatch):
    """
    A generator nothing serves is the same dead-API defect as
    record_secondary_apk(): fully tested, never reachable.
    """
    # The backend refuses to import without a secret, by design.
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret_key")
    sys.path.insert(0, str(_ROOT / "backend"))
    from app.routes.report import router

    paths = {getattr(r, "path", "") for r in router.routes}
    assert "/report/suricata/{sha256}" in paths
    assert "/report/snort/{sha256}" in paths



