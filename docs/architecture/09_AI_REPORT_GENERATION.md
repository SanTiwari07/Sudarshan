# 09 - AI Report Generation & Export Specification

```yaml
Module Title:        AI Report Generation & Export Engine
Version:             2.1.0
Primary Files:       shared/sudarshan_core/engines/report_generator.py
                     backend/app/routes/report.py
Test Suite:          backend/tests/test_report_generator.py, backend/tests/test_artifact_persistence.py
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Report Cache & Persistence (`report.py`)](#2-report-cache--persistence-reportpy)
- [3. PDF & JSON Report Export](#3-pdf--json-report-export)
- [4. HTML Security Report Generation](#4-html-security-report-generation)

---

## 1. Executive Overview

The **AI Report Generation Engine** exports structured case findings into standardized security formats: PDF executive security reports for CISO/SOC briefing, JSON report feeds for API integrations, and HTML executive security reports ([`report_generator.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/report_generator.py)).

---

## 2. Report Cache & Persistence (`report.py`)

Case reports are queried and served via [`report.py`](file:///d:/Projects/Sudarshan%20BOI/backend/app/routes/report.py):

- `GET /api/v1/report/pdf/{sha256}`: Exports full PDF report. Requires Bearer auth.
- `GET /api/v1/report/json/{sha256}`: Exports complete JSON analysis payload. Requires Bearer auth.
- `POST /api/v1/report/chat`: Interacts with RAG-grounded AI assistant for case inquiry.

---

## 3. PDF & JSON Report Export

Generates comprehensive reports containing:
- Executive Fraud Card & FRS breakdown meter.
- 5-axis STEI scores and BFCI v2 behavioral timeline.
- Dynamic Frida hook event summary and network traffic breakdown.
- Threat Scenario correlation matrix.
- CERT-In regulatory advisory drafts.

---

## 4. HTML Security Report Generation

[`report_generator.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/report_generator.py) compiles:
- Executive Risk Summary.
- Technical SOC Evidence Tables.
- Interactive Causal Fraud Workflow stages.
- Threat Scenario correlation matrix.
- CERT-In regulatory advisory drafts.
