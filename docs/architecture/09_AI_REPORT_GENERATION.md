# 09 - AI Report Generation & Export Specification

```yaml
Module Title:        AI Report Generation & Export Engine
Version:             3.0.0
Primary Files:       shared/sudarshan_core/engines/pdf_generator.py
                     shared/sudarshan_core/engines/report_generator.py
                     backend/app/routes/report.py
Test Suite:          backend/tests/test_pdf_generator.py, backend/tests/test_report_generator.py
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Real-Data Pipeline & Data Provenance](#2-real-data-pipeline--data-provenance)
- [3. Report Consistency Gate](#3-report-consistency-gate)
- [4. ReportLab PDF Generation Engine](#4-reportlab-pdf-generation-engine)
- [5. API Endpoints & Export Routes](#5-api-endpoints--export-routes)

---

## 1. Executive Overview

The **ReportLab Enterprise PDF Threat Investigation Report Generator** ([`pdf_generator.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/pdf_generator.py)) provides server-side PDF generation for Sudarshan. It converts authoritative case objects and disk artifacts into multi-page security reports.

---

## 2. Real-Data Pipeline & Data Provenance

```
load_report(sha256)
        ↓
load associated case artifacts (evidence.json, screenshots, manifest, workflow, etc.)
        ↓
build_report_data(case, artifacts) -> ReportData model
        ↓
validate_report_data(report_data) -> ReportConsistencyGate
        ↓
ReportLabPDFGenerator -> pure visual rendering
        ↓
PDF bytes
```

- **Zero Hardcoded Data**: Production PDF generation contains zero synthetic or hardcoded case attributes.
- **Data Provenance Tags**: `STATIC`, `DYNAMIC`, `THREAT_INTEL`, `DERIVED`, `AI`, `SYSTEM`.
- **Status Tags**: `OBSERVED`, `DERIVED`, `CORRELATED`, `NOT_OBSERVED`, `NOT_AVAILABLE`, `NOT_PERFORMED`, `ERROR`.

---

## 3. Report Consistency Gate

Before rendering, `validate_report_data()` asserts:
- `report_data.sha256 == case.sha256`
- `report_data.package_name == case.package_name`
- `report_data.final_risk_score == case.final_risk_score`
- `report_data.risk_band == case.risk_band`

If any core value conflicts, `ReportConsistencyError` is raised.

---

## 4. ReportLab PDF Generation Engine

- **Pure Visual Rendering**: No score calculation, family classification, or telemetry invention inside the renderer.
- **Multi-Page Layout**: Parts A through W including Executive Cover, Score Ledger, Forensic APK Metadata, Coverage Matrix, STEI 5-Axis Chart, Dynamic Behavioral Telemetry, Evidence Registry, Fraud Workflow, Threat Intelligence, VIDE, MITRE ATT&CK Mobile, SOC Recommendations, CERT-In Advisory, Chain of Custody, and Screenshots Gallery.
- **Two-Pass Page Numbering**: `NumberedCanvas` renders "Page X of Y" and running headers/footers with SHA-256 and platform version.

---

## 5. API Endpoints & Export Routes

- `GET /api/v1/report/pdf/{sha256}`: Serves native ReportLab PDF stream (`application/pdf`). Requires analyst Bearer token.
- `GET /api/v1/report/html/{sha256}`: Serves standalone single-file HTML report.
- `GET /api/v1/report/stix/{sha256}`: Serves STIX 2.1 JSON bundle.
- `GET /api/v1/report/iocs/{sha256}`: Serves IOC CSV export.
