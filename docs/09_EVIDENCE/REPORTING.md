# SUDARSHAN — Forensic Reporting & Export Subsystem

> **Classification:** AUTHORITATIVE  
> **Source Modules:** `backend/app/services/report_service.py`, `backend/app/routes/report.py`  

---

SUDARSHAN generates 4 primary report formats:
1. **Executive Fraud Summary PDF:** High-level overview designed for non-technical executives, outlining financial loss risk, targeted institution, and containment actions.
2. **Technical SOC PDF:** Comprehensive forensic report with full permissions breakdown, disassembled manifest, and timeline.
3. **Standalone Interactive HTML:** Self-contained single-page report with embedded visual assets and interactive timeline.
4. **STIX 2.1 JSON Bundle:** Machine-readable threat intelligence bundle formatted for SIEM ingestion.
