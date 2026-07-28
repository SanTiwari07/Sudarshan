"""
test_report_generator.py
========================
Tests for the Sudarshan report generator (v2).

Order:
  Case B  -- zero-dynamic state (no fabrication assertion -- the critical path)
  Case A  -- populated state (timeline renders, banner absent)
  Case C  -- no threat intel keys (dual-degraded state)

Do NOT skip these under time pressure.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[3] / "shared"))

from sudarshan_core.engines.report_generator import build_report


def _base() -> dict:
    return {
        "sha256": "a" * 64,
        "package_name": "com.test.malware",
        "app_name": "TestMalware",
        "analysis_mode": "androguard",
        "family_classification": "Unknown",
        "base_score": 75.0,
        "ai_confidence_multiplier": 1.0,
        "final_risk_score": 75.0,
        "risk_band": "High Risk",
        "confidence": 70.0,
        "recommended_action": "Quarantine immediately.",
        "frs_breakdown": {
            "stei": 75.0, "dynamic": 0.0, "correlation": 0.0, "banking_impact": 0.0,
            "formula_used": "static_only_frs", "dynamic_available": False,
            "stei_axes": {"CT": 80.0, "BT": 60.0, "PR": 50.0, "OB": 30.0, "IR": 20.0},
            "dynamic_ran": False, "dynamic_conclusive": False,
        },
        "all_permissions": [
            "android.permission.INTERNET",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "hardcoded_urls_ips": ["http://194.163.142.89/gate.php"],
        "hardcoded_secrets": [],
        "targets_indian_banks": True,
        "has_accessibility_abuse": True,
        "has_sms_read_write": True,
        "has_system_alert_window": True,
        "obfuscation_score": 0.55,
        "has_reflection": True,
        "threat_correlation": None,
        "dynamic_analysis": None,
        "dynamic_available": False,
        "manifest_findings": [],
        "code_findings": [],
        "activities": ["com.test.malware.MainActivity"],
        "services": ["com.test.malware.AccessibilityService"],
        "receivers": ["com.test.malware.SmsReceiver"],
        "certificate": {}, "domains": {},
        "executive_view": {
            "risk_badge": "HIGH",
            "plain_english_narrative": "Banking trojan indicators detected.",
            "recommended_actions": ["Block via MDM"],
            "customer_advisory_draft": "Do not install.",
        },
        "technical_view": {
            "permissions_fired": [], "strings_fired": [], "apis_fired": [],
            "matched_rule": "", "decoded_manifest_excerpts": [],
        },
        "threat_scenario_table": [],
        "intelligence_report": None,
        "fraud_workflow": None,
    }


# ===========================================================================
# Case B -- Zero-dynamic state (THE CRITICAL PATH -- test first)
# ===========================================================================

class TestCaseBZeroDynamic:

    def test_structural_completeness(self):
        html = build_report(_base())
        assert "Static Forensic Analysis" in html
        assert "Threat Intelligence" in html
        assert "Dynamic Analysis" in html
        assert "Recommendations" in html
        assert "Evidence Ledger" in html

    def test_dynamic_banner_renders(self):
        html = build_report(_base())
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" in html

    def test_no_fabricated_event_rows(self):
        """CRITICAL: no tl-event divs when evidence is absent."""
        html = build_report(_base())
        assert 'class="tl-event"' not in html, (
            "FABRICATION DETECTED: tl-event div attribute found despite zero dynamic evidence."
        )

    def test_no_fabricated_evid_ids(self):
        """EVID-NNN IDs must not appear when no dynamic evidence exists."""
        import re
        html = build_report(_base())
        evid = re.findall(r'\[EVID-\d{3}\]', html)
        assert len(evid) == 0, f"Fabricated EVID entries found: {evid}"

    def test_frs_score_renders(self):
        html = build_report(_base())
        assert "75" in html
        assert "High Risk" in html

    def test_static_permissions_render(self):
        html = build_report(_base())
        assert "BIND_ACCESSIBILITY_SERVICE" in html
        assert "READ_SMS" in html

    def test_stat_finding_ids_present(self):
        html = build_report(_base())
        assert "STAT-" in html

    def test_hardcoded_url_renders(self):
        html = build_report(_base())
        assert "194.163.142.89" in html

    def test_honest_state_message(self):
        html = build_report(_base())
        assert "honest system state" in html

    def test_print_stylesheet_present(self):
        html = build_report(_base())
        assert "@media print" in html

    def test_no_external_cdn(self):
        html = build_report(_base())
        for cdn in ["fonts.googleapis.com", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"]:
            assert cdn not in html, f"External CDN found: {cdn}"

    def test_no_javascript(self):
        html = build_report(_base())
        assert "<script" not in html.lower()

    def test_output_to_file(self, tmp_path):
        out = tmp_path / "report.html"
        build_report(_base(), output_path=out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert len(content) > 5000

    def test_sandbox_not_ran_cause_text(self):
        r = _base()
        r["frs_breakdown"]["dynamic_ran"] = False
        html = build_report(r)
        assert "SELinux" in html or "did not execute" in html

    def test_sandbox_ran_no_behavior_cause_text(self):
        r = _base()
        r["frs_breakdown"]["dynamic_ran"] = True
        html = build_report(r)
        assert "hook-triggering" in html or "goes dormant" in html or "Frida environment" in html


# ===========================================================================
# Case A -- Populated state
# ===========================================================================

class TestCaseAPopulated:

    def _setup(self, tmp_path: Path):
        ev = {
            "records": [
                {
                    "finding_id": "EVID-001",
                    "timestamp": 1700000000000,
                    "api": "SharedPreferences.getString",
                    "description": "Reading stored credentials",
                    "severity": "HIGH",
                    "mitre_technique_id": "T1409",
                },
                {
                    "finding_id": "EVID-002",
                    "timestamp": 1700000001000,
                    "api": "SmsManager.sendTextMessage",
                    "description": "Sending SMS to premium number",
                    "severity": "CRITICAL",
                    "mitre_technique_id": "T1412",
                },
            ]
        }
        (tmp_path / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
        r = _base()
        r["frs_breakdown"]["dynamic_ran"] = True
        r["frs_breakdown"]["dynamic_conclusive"] = True
        r["final_risk_score"] = 92.0
        r["risk_band"] = "CRITICAL"
        r["fraud_workflow"] = {
            "stages": [{
                "label": "Accessibility Service Activation",
                "technique_id": "T1418",
                "description": "App bound accessibility service.",
                "confidence": 0.9,
                "evidence_ids": ["EVID-001"],
            }],
            "fraud_sequence_detected": True,
            "sequence_label": "OTP_THEFT_CHAIN",
            "chain_confidence": 0.85,
        }
        return build_report(r, apk_dir=tmp_path)

    def test_timeline_renders(self, tmp_path):
        assert 'class="tl-event"' in self._setup(tmp_path)

    def test_evid_ids_present(self, tmp_path):
        html = self._setup(tmp_path)
        assert "EVID-001" in html
        assert "EVID-002" in html

    def test_api_names_rendered(self, tmp_path):
        html = self._setup(tmp_path)
        assert "SharedPreferences.getString" in html
        assert "SmsManager.sendTextMessage" in html

    def test_no_diagnostic_banner_when_evidence_present(self, tmp_path):
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" not in self._setup(tmp_path)

    def test_workflow_stages_render(self, tmp_path):
        assert "Accessibility Service Activation" in self._setup(tmp_path)

    def test_critical_score_renders(self, tmp_path):
        html = self._setup(tmp_path)
        assert "CRITICAL" in html
        assert "92" in html


# ===========================================================================
# Case C -- Dual-degraded: no intel + no dynamic simultaneously
# ===========================================================================

class TestCaseCDualDegraded:

    def _render(self) -> str:
        r = _base()
        r["threat_correlation"] = {"available": False, "sources_queried": []}
        r["frs_breakdown"]["dynamic_ran"] = False
        return build_report(r)

    def test_both_status_banners_present(self):
        html = self._render()
        assert "[INTEL-STATUS: API KEYS NOT CONFIGURED]" in html
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" in html

    def test_static_frs_formula_mentioned(self):
        assert "static-only formula" in self._render()

    def test_score_still_renders(self):
        assert "75" in self._render()

    def test_static_findings_still_render(self):
        html = self._render()
        assert "BIND_ACCESSIBILITY_SERVICE" in html
        assert "STAT-" in html

    def test_no_fabricated_events(self):
        assert 'class="tl-event"' not in self._render()

    def test_no_mitre_without_intel(self):
        assert "No MITRE techniques mapped" in self._render()

    def test_recommendations_render(self):
        assert "Recommendations" in self._render()

    def test_dynamic_banner_does_not_mention_api_keys(self):
        html = self._render()
        if "[DYNAMIC-STATUS:" in html:
            dyn_section = html.split("[DYNAMIC-STATUS:")[1][:600]
            assert "VT_API_KEY" not in dyn_section
            assert "OTX_API_KEY" not in dyn_section


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:

    def test_minimal_response_does_not_crash(self):
        r = {
            "sha256": "b" * 64,
            "package_name": "com.minimal",
            "family_classification": "Unknown",
            "base_score": 0.0,
            "ai_confidence_multiplier": 1.0,
            "final_risk_score": 0.0,
            "risk_band": "Safe",
            "executive_view": {
                "risk_badge": "SAFE",
                "plain_english_narrative": "",
                "recommended_actions": [],
                "customer_advisory_draft": "",
            },
            "technical_view": {
                "permissions_fired": [], "strings_fired": [], "apis_fired": [],
                "matched_rule": "", "decoded_manifest_excerpts": [],
            },
        }
        html = build_report(r)
        assert "<!DOCTYPE html>" in html
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" in html

    def test_html_escaping(self):
        r = _base()
        r["hardcoded_urls_ips"] = ['<script>alert("xss")</script>']
        html = build_report(r)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_safe_band_trust_verdict(self):
        r = _base()
        r["risk_band"] = "Safe"
        r["final_risk_score"] = 15.0
        html = build_report(r)
        assert "LIKELY SAFE" in html

    def test_evidence_json_empty_records(self, tmp_path):
        (tmp_path / "evidence.json").write_text(json.dumps({"records": []}), encoding="utf-8")
        html = build_report(_base(), apk_dir=tmp_path)
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" in html
        assert 'class="tl-event"' not in html

    def test_evidence_json_malformed(self, tmp_path):
        (tmp_path / "evidence.json").write_text("not valid json", encoding="utf-8")
        html = build_report(_base(), apk_dir=tmp_path)
        assert "<!DOCTYPE html>" in html
        assert "[DYNAMIC-STATUS: NO TELEMETRY CAPTURED]" in html

    def test_valid_html_structure(self):
        html = build_report(_base())
        for tag in ["<!DOCTYPE html>", "<html", "<head>", "<body>", "</html>"]:
            assert tag in html
