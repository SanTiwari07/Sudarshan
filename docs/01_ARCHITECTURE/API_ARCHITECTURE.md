# SUDARSHAN — API Architecture & Design

> **Classification:** AUTHORITATIVE  
> **Last Verified:** 2026-09-25  

---

## 1. REST Architecture Principles

SUDARSHAN exposes an OpenAPI 3.0-compliant RESTful interface designed for both web dashboard consumption and headless SIEM/SOAR pipeline automation:

1. **Versioning:** All primary business routes are prefixed under `/api/v1`.
2. **Authentication:** Bearer token authentication using JSON Web Tokens (JWT) signed with HMAC-SHA256.
3. **Role-Based Access Control (RBAC):** Three distinct privilege tiers enforced via FastAPI dependencies:
   - `analyst`: Upload samples, view assigned cases, execute RAG queries, download reports.
   - `soc_lead`: View all tenant cases, manage batch priorities, view audit trails.
   - `admin`: User administration, key configuration, revoke active sessions, system maintenance.
4. **Service-to-Service Security:** Communication between the Gateway and Analysis Engine is gated by the `X-Internal-Service-Token` header.

---

## 2. Router Organization

In `backend/app/main.py`, routers are mounted modularly:

| Prefix | Router Module | Responsibilities |
| :--- | :--- | :--- |
| `/api/v1/auth` | `backend/app/routes/auth.py` | Login, registration, token refresh, logout, session revocation |
| `/api/v1` | `backend/app/routes/upload.py` | Sync/async APK upload, job status polling, job cancellation |
| `/api/v1` | `backend/app/routes/cases.py` | Case list, filtering, case detail retrieval, analyst tags/notes |
| `/api/v1` | `backend/app/routes/batch.py` | Batch job submission, pause, resume, cancel, status |
| `/api/v1` | `backend/app/routes/discovery.py`| URL crawling, candidate APK discovery, automatic ingestion |
| `/api/v1` | `backend/app/routes/report.py` | Executive PDF generation, STIX 2.1 JSON export |
| `/api/v1` | `backend/app/routes/intelligence.py`| Live threat intel queries, domain reputation |
| `/api/v1` | `backend/app/routes/resilience.py` | Guest time-warp, seed-persona, anti-evasion triggers |
| `/api/v1` | `backend/app/routes/audit.py` | Security audit log queries |
| `/api` | `backend/app/routes/runtime_api.py`| Real-time Frida event streaming and telemetry sinks |

---

## 3. Response Contract Consistency

All API endpoints return JSON payloads conforming to standard schemas:
- **Success:** Returns HTTP 200/201 with structured data models.
- **Validation Failure:** Returns HTTP 422 with FastAPI validation details.
- **Unauthorized:** Returns HTTP 401 with standard `{ "detail": "..." }`.
- **Forbidden:** Returns HTTP 403 when RBAC role is insufficient.
- **Timeout:** Returns HTTP 408 when an analysis job exceeds execution budgets.
