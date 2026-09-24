# SUDARSHAN — Case Management API

> **Classification:** AUTHORITATIVE  
> **Prefix:** `/api/v1/cases`  

---

## Endpoints

- `GET /api/v1/cases`: List investigations. Filter by `status`, `verdict`, `risk_band`, or search query.
- `GET /api/v1/cases/{sha256}`: Retrieve comprehensive investigation record.
- `PATCH /api/v1/cases/{sha256}/status`: Update case status (`open`, `investigating`, `closed`, `false_positive`).
- `PATCH /api/v1/cases/{sha256}/verdict`: Update analyst verdict override with required justification.
- `PATCH /api/v1/cases/{sha256}/assign`: Assign case to an analyst.
- `GET /api/v1/cases/{sha256}/evidence`: Retrieve raw normalized evidence events.
- `GET /api/v1/cases/{sha256}/iocs`: Return extracted IOCs (IPs, domains, hashes, package names).
- `GET, POST /api/v1/cases/{sha256}/notes`: Retrieve or append analyst notes.
