"""
scripts/qa_pdf_visual.py
========================
Generates a full-scale PDF Threat Investigation Report for QA,
renders all pages to PNG images using pypdfium2, and saves them
in the artifact directory for visual inspection.
"""

import json
import sys
from pathlib import Path

# Add project root and shared directory
root_dir = Path(__file__).parents[1]
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "shared"))

try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None

from sudarshan_core.engines.pdf_generator import build_pdf_report

def run_visual_qa():
    # 1. Artifact output directory
    artifact_dir = Path(__file__).parents[1] / "artifacts_qa"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    
    pdf_path = artifact_dir / "sudarshan_investigation_report_qa.pdf"

    # 2. Rich Test Case Payload
    case_data = {
        "case_id": "SDN-2026-08-0091-REAL",
        "sha256": "cacb75e2524dbeb0dba25c80a4cae8e5c2bf97c19297b33ecb3b467960837c9e",
        "sha1": "1ef6ec5b0f290f50522ba0cb2c760285f179402d",
        "md5": "b8ae663052708f06422817697b9704b9",
        "package_name": "com.sbi.lotusintouch.refund",
        "app_name": "TaxRefund_IncomeTax",
        "analysis_mode": "androguard",
        "analysis_status": "COMPLETED",
        "created_at": "2026-08-12 14:20:00 UTC",
        "base_score": 80.68,
        "ai_confidence_multiplier": 1.20,
        "final_risk_score": 96.8,
        "risk_band": "Critical",
        "recommended_action": "Quarantine immediately, revoke active banking session tokens, and file CSIRT-Fin advisory.",
        "family_classification": "Drinik",
        "matched_rule": "has_accessibility_abuse + has_sms_read_write + targets_indian_banks",
        "all_permissions": [
            "android.permission.INTERNET",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.READ_CONTACTS",
            "android.permission.CALL_PHONE",
        ],
        "hardcoded_urls_ips": ["http://194.163.142.89/drinik/gate.php"],
        "targets_indian_banks": True,
        "has_accessibility_abuse": True,
        "has_sms_read_write": True,
        "has_system_alert_window": True,
        "obfuscation_score": 0.68,
        "has_reflection": True,
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
            "sandbox_provider": "Genymotion Desktop (Android 11, x86_64)",
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
            "matched_baseline": "SBI (State Bank of India)",
            "confidence": 0.74,
        },
        "executive_view": {
            "plain_english_narrative": "This application presents itself as an income-tax refund utility from the State Bank of India but is a repackaged Drinik-family banking trojan. Once installed, it asks the victim to enable an accessibility service to read on-screen text and simulate taps inside real banking apps. It separately registers to receive incoming SMS messages for OTP interception.",
            "fraud_objective": "On-screen Credential Capture & Silent OTP Interception for Account Takeover",
            "customer_impact": "Unauthorized fund transfers, account takeover, and complete credential/keystroke compromise.",
            "banking_impact": "Brand impersonation of SBI and ICICI Bank, customer support escalation, and fraud loss.",
            "cert_in_recommendations": [
                "Block SHA-256 hash cacb75e2524dbeb0dba2... and package name at enterprise app layer.",
                "File incident report with CSIRT-Fin referencing campaign cluster Drinik-2026-H1.",
                "Force step-up hardware token authentication for impacted accounts."
            ],
            "customer_advisory_draft": "We have identified a fraudulent application impersonating an income-tax refund service from your bank. If you have installed an app named TaxRefund_IncomeTax.apk, please uninstall it immediately.",
        },
        "evidence_records": [
            {"finding_id": "EVID-001", "category": "Accessibility", "description": "AccessibilityService bound to com.sbi.lotusintouch. UI scraping observed on login fields.", "severity": "CRITICAL", "mitreId": "T1628"},
            {"finding_id": "EVID-002", "category": "SMS Intercept", "description": "BroadcastReceiver registered for android.provider.Telephony.SMS_RECEIVED. Inbound OTP intercepted.", "severity": "CRITICAL", "mitreId": "T1643"},
            {"finding_id": "EVID-003", "category": "Overlay Phishing", "description": "SYSTEM_ALERT_WINDOW active. Fake login overlay drawn over banking foreground activity.", "severity": "HIGH", "mitreId": "T1637"},
            {"finding_id": "EVID-004", "category": "C2 Network", "description": "HTTP POST beacon sent to http://194.163.142.89/drinik/gate.php with stolen credentials.", "severity": "HIGH", "mitreId": "T1437"},
            {"finding_id": "EVID-005", "category": "Dynamic Code", "description": "DexClassLoader invoked with reflection Class.forName(). Staged payload execution.", "severity": "MEDIUM", "mitreId": "T1407"},
        ],
        "fraud_workflow": {
            "stages": [
                {"stage_name": "Accessibility Service Enabled", "detail": "User prompted to enable accessibility service for refund processing."},
                {"stage_name": "Overlay Phishing Active", "detail": "Phishing window displayed when target banking app opens."},
                {"stage_name": "SMS OTP Interception", "detail": "Inbound banking SMS intercepted silently before victim notification."},
                {"stage_name": "C2 Exfiltration", "detail": "Credentials and OTP exfiltrated via HTTP POST to remote C2 server."},
            ]
        },
        "mitre_techniques": [
            {"id": "T1628", "name": "Input Capture via Accessibility Service", "evidence": "Static declaration + Frida hook event count x42"},
            {"id": "T1637", "name": "App Overlay Attack", "evidence": "SYSTEM_ALERT_WINDOW reference + overlay hook x9"},
            {"id": "T1643", "name": "Capture SMS Messages", "evidence": "SMS_RECEIVED receiver + SmsManager hook x18"},
            {"id": "T1437", "name": "Application Layer C2", "evidence": "Hardcoded endpoint http://194.163.142.89/drinik/gate.php"},
            {"id": "T1407", "name": "Download New Code at Runtime", "evidence": "DexClassLoader + Class.forName reflection invocation"},
        ],
    }

    print(f"[QA] Generating ReportLab PDF for SHA256={case_data['sha256'][:12]}...")
    pdf_bytes = build_pdf_report(case_data)
    pdf_path.write_bytes(pdf_bytes)
    print(f"[QA] PDF generated successfully! Saved to {pdf_path} ({len(pdf_bytes)} bytes)")

    image_paths = []
    # 3. Render every page to PNG using pypdfium2 if available
    if pdfium is not None:
        pdf_doc = pdfium.PdfDocument(pdf_path)
        page_count = len(pdf_doc)
        print(f"[QA] Total Pages in PDF: {page_count}")

        for idx in range(page_count):
            page = pdf_doc[idx]
            image = page.render(scale=2.0).to_pil()  # High DPI rendering
            img_filename = f"qa_page_{idx+1:02d}.png"
            img_path = artifact_dir / img_filename
            image.save(img_path)
            image_paths.append(img_path)
            print(f"[QA] Rendered Page {idx+1}/{page_count} -> {img_path}")
    else:
        # Use reportlab PyPDF or pypdf reader if pypdfium2 not installed
        try:
            from pypdf import PdfReader
            reader = PdfReader(pdf_path)
            page_count = len(reader.pages)
            print(f"[QA] Total Pages in PDF (via pypdf): {page_count}")
        except Exception:
            print(f"[QA] Generated PDF at {pdf_path}")

    print("[QA] Visual QA generation complete!")
    return image_paths

if __name__ == "__main__":
    run_visual_qa()
