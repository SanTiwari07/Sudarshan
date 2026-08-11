"""Tests for threat-intel backfill on stored cases."""

import pytest

from app.services.case_intel_enrichment import should_recorrelate_threat_intel


def test_should_recorrelate_when_unavailable_and_never_queried():
    assert should_recorrelate_threat_intel({"available": False, "sources_queried": []}) is True


def test_should_not_recorrelate_when_available(monkeypatch):
    monkeypatch.setattr("app.services.case_intel_enrichment._get_vt_key", lambda: "vt")
    monkeypatch.setattr("app.services.case_intel_enrichment._get_otx_key", lambda: "otx")
    monkeypatch.setattr("app.services.case_intel_enrichment._get_abuseipdb_key", lambda: None)
    assert (
        should_recorrelate_threat_intel(
            {"available": True, "sources_queried": ["VirusTotal", "AlienVault OTX"]}
        )
        is False
    )


def test_enrich_case_backfills_correlation(monkeypatch):
    import asyncio
    from app.services import case_intel_enrichment as mod

    case = {
        "sha256": "a" * 64,
        "package_name": "com.test.app",
        "hardcoded_urls_ips": [],
        "threat_correlation": {"available": False, "sources_queried": []},
        "frs_breakdown": {"axes_excluded": ["correlation"], "correlation": 0.0},
        "has_accessibility_abuse": True,
        "all_permissions": [],
        "family_classification": "Unknown",
        "ai_confidence_multiplier": 1.0,
    }

    async def _fake_correlate(**_kwargs):
        return {
            "available": True,
            "threat_score": 42.0,
            "sources_queried": ["VirusTotal"],
            "threat_score_sources": ["VT detection: 50% (+20.0)"],
            "sha256_detections": 5,
            "sha256_total": 10,
            "vt_detection_ratio": 0.5,
        }

    monkeypatch.setattr(mod, "correlate", _fake_correlate)

    updated = asyncio.run(mod.enrich_case_threat_intel(case))
    assert updated["threat_correlation"]["available"] is True
    assert updated["threat_correlation"]["threat_score"] == 42.0
    assert "correlation" not in (updated["frs_breakdown"].get("axes_excluded") or [])
    assert updated["frs_breakdown"]["correlation"] == 42.0
