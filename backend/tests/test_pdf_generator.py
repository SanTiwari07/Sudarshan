"""
test_pdf_generator.py
=====================
Tests for the Sudarshan ReportLab Enterprise PDF Threat Investigation Report Generator.

Verifies:
  1. Data normalization into internal ReportData model with provenance & status tags.
  2. Report Consistency Gate (validate_report_data).
  3. PDF generation for fully populated cases.
  4. PDF generation for zero-dynamic degraded cases.
  5. Structural QA Pass (valid PDF header, page count > 0).
  6. Content QA Pass (extracted text matches authoritative case values).
  7. API route integration GET /api/v1/report/pdf/{sha256}.
  8. Score consistency (UI FRS == API FRS == PDF FRS == Risk Band).
  9. Edge cases: Empty evidence, VIDE unavailable, screenshots embedding.
"""

import io
import os
import sys
from pathlib import Path
import pytest
from pypdf import PdfReader

# Ensure shared, backend, and root directories are in sys.path
root_dir = str(Path(__file__).parents[2])
backend_dir = str(Path(__file__).parents[1])
shared_dir = str(Path(__file__).parents[2] / "shared")

for p in [root_dir, backend_dir, shared_dir]:
    if p not in sys.path:
        sys.path.insert(0, p)

from sudarshan_core.engines.pdf_generator import (
    build_report_data,
    validate_report_data,
    build_pdf_report,
    ReportData,
    ReportConsistencyError,
    Provenance,
    Status,
)

@pytest.fixture
def sample_case_data() -> dict:
    return {
        "case_id": "SDN-TEST-CASE-001",
        "sha256": "cacb75e2524dbeb0dba25c80a4cae8e5c2bf97c19297b33ecb3b467960837c9e",
        "sha1": "1ef6ec5b0f290f50522ba0cb2c760285f179402d",
        "md5": "b8ae663052708f06422817697b9704b9",
        "package_name": "com.sbi.lotusintouch.refund",
        "app_name": "TaxRefund_IncomeTax",
        "analysis_mode": "androguard",
        "analysis_status": "COMPLETED",
        "created_at": "2026-08-11 14:20:00 UTC",
        "base_score": 80.68,
        "ai_confidence_multiplier": 1.20,
        "final_risk_score": 96.8,
        "risk_band": "Critical",
        "recommended_action": "Quarantine device immediately and revoke banking tokens.",
        "family_classification": "Drinik",
        "matched_rule": "accessibility + sms + banking match",
        "all_permissions": [
            "android.permission.INTERNET",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "hardcoded_urls_ips": ["http://194.163.142.89/drinik/gate.php"],
        "targets_indian_banks": True,
        "has_accessibility_abuse": True,
        "has_sms_read_write": True,
        "has_system_alert_window": True,
        "frs_breakdown": {
            "stei": 79.12,
            "dynamic": 86.0,
            "correlation": 74.0,
            "banking_impact": 80.0,
            "formula_used": "full_frs",
            "dynamic_ran": True,
            "dynamic_conclusive": True,
            "stei_axes": {"CT": 100.0, "BT": 40.0, "PR": 71.0, "OB": 70.4, "IR": 10.0},
        },
        "dynamic_result": {
            "sandbox_provider": "Genymotion Desktop",
            "frida_version": "17.16.4",
            "analysis_duration": 30.0,
            "total_hooks_installed": 42,
            "total_events_captured": 18,
            "bfci": 86.0,
        },
        "threat_correlation": {
            "available": True,
            "vt_malicious_count": 38,
            "vt_total_engines": 70,
            "otx_pulse_count": 3,
            "abuseipdb_score": 71.0,
            "known_family": "Drinik",
        },
        "vide": {
            "analyzed": True,
            "visual_impersonation_detected": True,
            "matched_baseline": "SBI",
            "confidence": 0.74,
        },
        "executive_view": {
            "plain_english_narrative": "Tax refund trojan impersonating SBI. Captures credentials via accessibility service.",
            "fraud_objective": "Credential Theft & OTP Interception",
            "customer_impact": "Unauthorized access to bank accounts and keystroke logging.",
            "banking_impact": "Brand impersonation of State Bank of India.",
            "cert_in_recommendations": ["Block SHA-256 bank-wide."],
            "customer_advisory_draft": "Uninstall TaxRefund app immediately.",
        },
        "evidence_records": [
            {
                "finding_id": "EVID-001",
                "category": "Accessibility",
                "description": "Accessibility service bound and scraping UI text.",
                "severity": "CRITICAL",
                "mitreId": "T1628",
            }
        ],
        "fraud_workflow": {
            "stages": [
                {"stage_name": "Accessibility Service Enabled", "detail": "User persuaded to enable accessibility."},
                {"stage_name": "Overlay Phishing", "detail": "Fake SBI login window drawn over app."},
            ]
        },
    }

class TestPDFGeneratorUnit:

    def test_build_report_data_normalization(self, sample_case_data):
        report_data = build_report_data(sample_case_data)
        assert isinstance(report_data, ReportData)
        assert report_data.sha256.value == sample_case_data["sha256"]
        assert report_data.package_name.value == sample_case_data["package_name"]
        assert report_data.final_risk_score.value == 96.8
        assert report_data.risk_band.value == "Critical"
        assert report_data.stei_total.value == 79.12
        assert report_data.stei_ct.value == 100.0

    def test_validate_report_data_success(self, sample_case_data):
        report_data = build_report_data(sample_case_data)
        validate_report_data(report_data)  # Should not raise

    def test_validate_report_data_invalid_sha(self, sample_case_data):
        sample_case_data["sha256"] = ""
        report_data = build_report_data(sample_case_data)
        with pytest.raises(ReportConsistencyError, match="Invalid or missing SHA-256"):
            validate_report_data(report_data)

    def test_validate_report_data_invalid_frs(self, sample_case_data):
        sample_case_data["final_risk_score"] = 150.0
        report_data = build_report_data(sample_case_data)
        with pytest.raises(ReportConsistencyError, match="Invalid Fraud Risk Score"):
            validate_report_data(report_data)

    def test_build_pdf_report_bytes_populated(self, sample_case_data):
        pdf_bytes = build_pdf_report(sample_case_data)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-1.")

    def test_pdf_structural_qa_pass1(self, sample_case_data):
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        assert len(reader.pages) >= 2  # Multi-page layout

    def test_pdf_content_qa_pass2(self, sample_case_data):
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        full_text = " ".join([page.extract_text() for page in reader.pages])

        assert sample_case_data["package_name"] in full_text
        assert sample_case_data["sha256"][:12] in full_text
        assert "96.8" in full_text
        assert "Critical" in full_text or "CRITICAL" in full_text
        assert "EVID-001" in full_text

    def test_score_consistency_invariants(self, sample_case_data):
        """Verifies zero score drift: PDF FRS == API FRS == Risk Band."""
        report_data = build_report_data(sample_case_data)
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        page1_text = reader.pages[0].extract_text()

        # Final FRS score (96.8) and Risk Band (Critical) must match exactly
        assert f"{report_data.final_risk_score.value:.1f}" in page1_text
        assert report_data.risk_band.value.upper() in page1_text

    def test_build_pdf_report_zero_dynamic(self, sample_case_data):
        sample_case_data["dynamic_result"] = None
        sample_case_data["frs_breakdown"]["dynamic_ran"] = False
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        full_text = " ".join([page.extract_text() for page in reader.pages])

        assert "[DYNAMIC-STATUS: NO_TELEMETRY_CAPTURED]" in full_text or "NO_TELEMETRY_CAPTURED" in full_text

    def test_vide_unavailable_and_clean_handling(self, sample_case_data):
        # VIDE not analyzed
        sample_case_data["vide"] = {"analyzed": False}
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        full_text = " ".join([page.extract_text() for page in reader.pages])
        assert "NOT_AVAILABLE" in full_text

    def test_screenshots_handling(self, sample_case_data, tmp_path):
        sample_case_data["screenshots"] = [
            {
                "screenshot_id": "SCR-001",
                "filename": "scr1.png",
                "title": "Overlay Login Screen",
                "description": "Fake login form displayed over bank app.",
                "quality": "A",
            }
        ]
    def test_frs_canonical_consistency(self, sample_case_data):
        """Verifies canonical FRS consistency across all report sections."""
        sample_case_data["final_risk_score"] = 96.8
        sample_case_data["risk_band"] = "Critical"
        report_data = build_report_data(sample_case_data)
        pdf_bytes = build_pdf_report(sample_case_data)
        
        assert report_data.final_risk_score.value == 96.8
        assert report_data.risk_band.value == "Critical"
        
        reader = PdfReader(io.BytesIO(pdf_bytes))
        p1_text = reader.pages[0].extract_text()
        p3_text = reader.pages[2].extract_text()
        
        assert "96.8" in p1_text
        assert "96.8" in p3_text

    def test_threat_intel_unavailable_handling(self, sample_case_data):
        """Verifies report generation when threat intelligence API is unavailable."""
        sample_case_data["threat_correlation"] = {"available": False}
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        assert len(reader.pages) >= 12

    def test_empty_evidence_records_handling(self, sample_case_data):
        """Verifies report generation with empty evidence lists."""
        sample_case_data["evidence_records"] = []
        sample_case_data["mitre_techniques"] = []
        pdf_bytes = build_pdf_report(sample_case_data)
        reader = PdfReader(io.BytesIO(pdf_bytes))
        assert len(reader.pages) >= 12

from fastapi.testclient import TestClient

class TestPDFExportAPI:

    def test_export_pdf_endpoint(self, sample_case_data, monkeypatch):
        os.environ["JWT_SECRET_KEY"] = "test-secret-key-1234567890-super-secret-sudarshan"
        from app.main import app
        from app.routes.report import cache_report
        from app.auth.auth import create_access_token

        cache_report(sample_case_data["sha256"], sample_case_data)
        
        client = TestClient(app)
        valid_token = create_access_token(1, "testanalyst", "analyst")
        headers = {"Authorization": f"Bearer {valid_token}"}

        response = client.get(f"/api/v1/report/pdf/{sample_case_data['sha256']}", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-1.")

