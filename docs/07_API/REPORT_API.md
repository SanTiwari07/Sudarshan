# SUDARSHAN — Report & Export API

> **Classification:** AUTHORITATIVE  
> **Prefix:** `/api/v1/report`  

---

## Endpoints

- `GET /api/v1/report/pdf/{sha256}`: Download executive PDF report.
- `GET /api/v1/report/technical-pdf/{sha256}`: Download granular technical SOC report.
- `GET /api/v1/report/html/{sha256}`: Render standalone interactive HTML report.
- `GET /api/v1/report/stix/{sha256}`: Export standardized STIX 2.1 JSON bundle.
- `GET /api/v1/report/iocs/{sha256}`: Export structured JSON indicators.
- `GET /api/v1/report/iocs-txt/{sha256}`: Export plain-text indicator list for firewall ingestion.
- `GET /api/v1/report/yara/{sha256}`: Export tailored YARA detection rule.
- `GET /api/v1/report/snort/{sha256}`: Export network Snort rule.
- `GET /api/v1/report/suricata/{sha256}`: Export network Suricata rule.
