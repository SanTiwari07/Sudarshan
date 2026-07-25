# 09 — AI Report Generation & Export Specification

```yaml
Module Title:        AI Report Generation & STIX 2.1 Exporter
Version:             2.2.0-STABLE
Primary Files:       backend/app/engines/report_generator.py
                     backend/app/routes/report.py
Test Suite:          tests/test_gemini_rag.py
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Report Cache & Persistence (`report.py`)](#2-report-cache--persistence-reportpy)
- [3. STIX 2.1 JSON Export](#3-stix-21-json-export)
- [4. CSV IOC Export](#4-csv-ioc-export)
- [5. HTML Security Report Generation](#5-html-security-report-generation)

---

## 1. Executive Overview

The **AI Report Generation Engine** exports structured case findings into standardized security formats: STIX 2.1 JSON bundles for SIEM/SOAR ingestion, CSV IOC feeds for firewall/gateway blocking, and standalone HTML executive security reports.

---

## 2. Report Cache & Persistence (`report.py`)

Case reports are cached in memory and SQLite upon analysis completion:

- `GET /api/v1/report/export/json/{sha256}`: Returns STIX 2.1 JSON bundle.
- `GET /api/v1/report/export/csv/{sha256}`: Returns CSV IOC feed (`indicator,type,severity,source`).

---

## 3. STIX 2.1 JSON Export

Generates STIX 2.1 `bundle` objects containing:
- `malware` SDOs with family classification.
- `indicator` SDOs for extracted C2 URLs, IP addresses, and domain names.
- `relationship` SDOs linking indicators to malware families (`indicates`).
- `attack-pattern` SDOs for matched MITRE ATT&CK for Mobile technique IDs.

---

## 4. CSV IOC Export

Formatted for direct ingestion into Palo Alto, Fortinet, or Cisco firewalls:

```csv
indicator,type,severity,description
https://c2-server.top/gate.php,URL,CRITICAL,Extracted C2 Endpoint
192.168.1.100,IP,HIGH,Hardcoded Socket Host
com.sbi.lotus.fake,PACKAGE,CRITICAL,Malicious Target App
```

---

## 5. HTML Security Report Generation

`report_generator.py` uses Jinja2 templates to compile:
- Executive Fraud Card & FRS breakdown meter.
- 5-axis STEI scores and BFCI v2 behavioral timeline.
- Interactive Causal Fraud Workflow stages.
- Threat Scenario correlation matrix.
- CERT-In regulatory advisory drafts.
