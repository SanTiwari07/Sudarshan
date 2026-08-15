# 09 - AI Report Generation & Export Specification

```yaml
Module Title:        AI Report Generation & Export Engine
Version:             2.1.0
Primary Files:       shared/sudarshan_core/engines/pdf_generator.py
                     shared/sudarshan_core/engines/report_generator.py
                     backend/app/routes/report.py
Test Suite:          backend/tests/test_pdf_generator.py, backend/tests/test_report_generator.py
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Real-Data Pipeline & Data Provenance](#2-real-data-pipeline--data-provenance)
- [3. Report Consistency Gate & FRS Alignment](#3-report-consistency-gate--frs-alignment)
- [4. ReportLab PDF Generation Engine](#4-reportlab-pdf-generation-engine)
- [5. Master Reference Replication (12 Core Sections)](#5-master-reference-replication-12-core-sections)
- [6. API Endpoints & Export Routes](#6-api-endpoints--export-routes)

---

## 1. Executive Overview

The **ReportLab Enterprise PDF Threat Investigation Report Generator** ([`pdf_generator.py`](file:///c:/Projects/Sudarshan/shared/sudarshan_core/engines/pdf_generator.py)) provides server-side PDF generation for Sudarshan. It converts authoritative case objects and disk artifacts into multi-page security reports strictly matching the visual structure, layout, typography, gauges, and information density of the master reference specification (`sudarshan pdf.pdf`).

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

- **Zero Fabricated Data**: PDF generation contains zero synthetic or hardcoded case attributes. All values come from the actual case payload or persisted evidence.
- **Data Provenance Tags**: `STATIC`, `DYNAMIC`, `THREAT_INTEL`, `DERIVED`, `AI`, `SYSTEM`.
- **Status Tags**: `OBSERVED`, `DERIVED`, `CORRELATED`, `NOT_OBSERVED`, `NOT_AVAILABLE`, `NOT_PERFORMED`, `ERROR`.

---

## 3. Report Consistency Gate & FRS Alignment

Before rendering, `validate_report_data()` asserts zero score drift:
- `report_data.sha256 == case.sha256`
- `report_data.package_name == case.package_name`
- `report_data.final_risk_score == case.final_risk_score` (Deterministic Risk Engine FRS)
- `report_data.risk_band == case.risk_band`

Canonical FRS Invariant: `UI FRS == API FRS == PDF FRS == Assessment FRS == Risk Band`.

---

## 4. ReportLab PDF Generation Engine

- **Pure Visual Rendering**: No score calculation or telemetry invention inside the renderer.
- **Vector Flowables**:
  - `FRSDialGauge`: 180° semi-circle dial gauge chart.
  - `FRSBarMeter`: Horizontal bar chart for 4-axis FRS breakdown.
  - `STEIBarMeter`: 5-axis STEI progress bar chart.
  - `VIDEBarMeter`: Horizontal progress bar chart with 0.72 detection threshold line.
  - `BFCIBarMeter`: Vertical bar chart for behavioral category breakdown.
- **Two-Pass Page Numbering**: `NumberedCanvas` renders "Page X of Y" and running headers/footers with black "S" logo box, SHA-256, Case ID, and timestamp.

---

## 5. Master Reference Replication (12 Core Sections)

1. **Page 1: PART A · EXECUTIVE — VERDICT SUMMARY**: About Box, Verdict Summary Dial, Family Attribution Confidence Card, Executive Conclusion Box, 4 Key Findings Cards, Sample Reputation Table, Analysis Coverage Badges, Risk Contributors Table.
2. **Page 2: PART A · EXECUTIVE — NARRATIVE & RESPONSE**: Plain-English Summary with evidence tags `[STAT-NNN]`, Recommended SOC Actions Table, Customer Advisory Draft Box, CERT-In Recommendations List.
3. **Page 3: PART B · TECHNICAL — DETERMINISTIC SCORE LEDGER**: Determinism Invariant Box, FRS Breakdown Bar Chart, Axis Breakdown Table, Formula Block, Static-Only vs Confirmed Comparison Table.
4. **Page 4: STEI — 5-AXIS BREAKDOWN**: STEI 5-axis progress meter, CT/BT/PR/OB/IR breakdown table & formula.
5. **Page 5: PART B · TECHNICAL — FORENSIC EVIDENCE (STATIC)**: APK Identity Table, Static Findings Table, Dangerous Permissions 2-Column Grid.
6. **Page 6: EVIDENCE → TECHNIQUE → FRAUD IMPACT**: Static Evidence to MITRE to Fraud Impact Mapping Table.
7. **Page 7: PART B · TECHNICAL — ATTACK & BEHAVIOR ANALYSIS (DYNAMIC)**: Sandbox Info Table, Reconstructed Causal Workflow Diagram, BFCI v2 Category Breakdown Bar Chart.
8. **Page 8: HOOK BUNDLE INVENTORY**: Monitored Classes/APIs, Event counts, Fraud signature table.
9. **Page 9: PART B · TECHNICAL — VISUAL IMPERSONATION DETECTION (VIDE)**: VIDE UI Fingerprint comparison horizontal bar chart, VIDE metrics table, lab-baseline caveat box.
10. **Page 10: PART B · TECHNICAL — THREAT INTELLIGENCE & SCENARIO CORRELATION**: External Threat Intelligence Table, Threat Scenario Correlation Matrix, MITRE ATT&CK Mobile Techniques Table.
11. **Page 11: PART C · AUDIT & TRACEABILITY — COVERAGE, LIMITATIONS & EVIDENCE LEDGER**: Analysis Coverage & Limitations Matrix Table, Evidence Ledger Table.
12. **Page 12: PART C · AUDIT & TRACEABILITY — INDICATORS, CHAIN OF CUSTODY & GOVERNANCE**: IOC File & Network Split Table, Chain of Custody Table, Sign-Off Table, Methodology & Glossary, 3 Principle Cards.
13. **Appendix**: Runtime Screenshots Gallery with timestamps, triggers, descriptions, quality grades, and embedded images.

---

## 6. API Endpoints & Export Routes

- `GET /api/v1/report/pdf/{sha256}`: Serves native ReportLab PDF stream (`application/pdf`). Requires analyst Bearer token.
- `GET /api/v1/report/html/{sha256}`: Serves standalone single-file HTML report.
- `GET /api/v1/report/stix/{sha256}`: Serves STIX 2.1 JSON bundle.
- `GET /api/v1/report/iocs/{sha256}`: Serves IOC CSV export.
