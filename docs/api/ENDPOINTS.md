# SUDARSHAN — API Endpoints Documentation

> **Authoritative REST API Reference**  
> **Source Repository**: `SanTiwari07/Sudarshan`  
> **Last Verified Against Active Codebase**: 2026-08-25  

This document provides a comprehensive specification of all active REST API endpoints across the **FastAPI Gateway (Port 8000)** and the **Analysis Engine Microservice (Port 8001)**.

---

## 1. Gateway Routing Architecture

* **Prefix `/api/v1`**: Core business endpoints (Authentication, APK Analysis, Batch Scanning, Case Management, Threat Intelligence, Reports, VIDE Baselines, and APK Discovery).
* **Prefix `/api`**: Low-level runtime telemetry and sink endpoints registered in `backend/app/main.py:98`.
* **Root Routes**: Platform metadata and health status.

---

## 2. Authentication (`/api/v1` — `backend/app/auth/auth.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/auth/login` | None | Authenticate user credentials and issue JWT | `OAuth2PasswordRequestForm` (`username`, `password`) | `{"access_token": "...", "token_type": "bearer", "role": "analyst"}` |
| `POST /api/v1/auth/register` | None (dev) / Admin (prod) | Register new user account | `UserRegisterRequest` (`username`, `password`, `role`) | `UserResponse` (`id`, `username`, `role`, `created_at`) |
| `GET /api/v1/auth/me` | Bearer Token | Return current authenticated user profile | None | `UserResponse` (`id`, `username`, `role`, `created_at`) |
| `GET /api/v1/auth/registration-policy` | None | Check if public registration is enabled | None | `{"allow_registration": true/false}` |
| `PATCH /api/v1/auth/users/{user_id}/role`| Admin only | Update user role | `RoleUpdateRequest` (`role`: `analyst`/`soc_lead`/`admin`) | `UserResponse` |

---

## 3. APK Analysis (`/api/v1` — `backend/app/routes/upload.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/analyze` | Bearer Token (`require_analyst`) | Synchronous APK analysis (returns full results immediately) | `multipart/form-data`: `file: UploadFile` | `AnalysisResponse` (full static, dynamic, correlation, and FRS breakdown) |
| `POST /api/v1/analyze/async` | Bearer Token (`require_analyst`) | Asynchronous APK analysis (enqueues job) | `multipart/form-data`: `file: UploadFile` | `{"job_id": "...", "status": "queued", "sha256": "..."}` |
| `GET /api/v1/status/{job_id}` | Bearer Token (`require_analyst`) | Poll async job status & progress | None | `JobStatusResponse` (`job_id`, `status`, `progress_pct`, `current_stage`, `result`) |
| `GET /api/v1/sandbox/status` | Bearer Token (`require_analyst`) | Check dynamic Android sandbox availability | None | `{"available": true/false, "device": "...", "frida": "..."}` |
| `GET /api/v1/sandbox/debug/{case_id}` | Bearer Token (`require_analyst`) | Return sandbox diagnostics for a case | None | `{"case_id": "...", "device_serial": "...", "logs": [...]}` |

---

## 4. Enterprise Batch Scanning (`/api/v1` — `backend/app/routes/batch.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/batches` | Bearer Token (`require_analyst`) | Create batch and upload multiple APKs | `multipart/form-data`: `files: List[UploadFile]` | `BatchSummary` (`batch_id`, `total_jobs`, `status`, `created_at`) |
| `GET /api/v1/batches` | Bearer Token (`require_analyst`) | List batches (paginated; scoped to user unless admin/soc_lead) | `limit: int = 20, offset: int = 0` | `{"batches": [BatchSummary], "total": int}` |
| `GET /api/v1/batches/{batch_id}` | Bearer Token (`require_analyst`) | Get batch summary and progress metrics | None | `BatchSummary` with completion counts and percentage |
| `GET /api/v1/batches/{batch_id}/jobs` | Bearer Token (`require_analyst`) | Get lightweight status list of all jobs in batch | None | `List[BatchJobSummary]` (`job_id`, `filename`, `status`, `progress_pct`) |
| `POST /api/v1/batches/{batch_id}/pause` | Bearer Token (`require_analyst`) | Pause batch queue processing | None | `{"status": "paused", "batch_id": "..."}` |
| `POST /api/v1/batches/{batch_id}/resume`| Bearer Token (`require_analyst`) | Resume paused batch queue | None | `{"status": "processing", "batch_id": "..."}` |
| `POST /api/v1/batches/{batch_id}/cancel`| Bearer Token (`require_analyst`) | Cancel all queued jobs in batch | None | `{"status": "cancelled", "cancelled_jobs": int}` |
| `POST /api/v1/batch-jobs/{job_id}/retry`| Bearer Token (`require_analyst`) | Retry a failed batch job | None | `BatchJobSummary` (status reset to `queued`) |

---

## 5. Case History & Investigation (`/api/v1` — `backend/app/routes/cases.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `GET /api/v1/cases` | Bearer Token (`require_analyst`) | List analyzed cases with search & filter | `q`, `family`, `risk_band`, `page`, `page_size` | `{"cases": [CaseSummary], "total": int, "page": int}` |
| `GET /api/v1/cases/{sha256}` | Bearer Token (`require_analyst`) | Retrieve complete analysis dossier for a case | None | Full `FraudCardData` / `AnalysisResponse` |
| `DELETE /api/v1/cases/{sha256}` | Admin only | Delete an analysis case | None | `{"status": "deleted", "sha256": "..."}` |
| `GET /api/v1/cases/{sha256}/evidence` | Bearer Token (`require_analyst`) | Retrieve raw evidence records for a case | None | `{"evidence": [EvidenceRecord]}` |
| `GET /api/v1/cases/{sha256}/notes` | Bearer Token (`require_analyst`) | List analyst notes on a case | None | `{"notes": [CaseNote]}` |
| `POST /api/v1/cases/{sha256}/notes` | Bearer Token (`require_analyst`) | Add an analyst note | `{"text": "..."}` | `CaseNote` (`id`, `sha256`, `text`, `author`, `created_at`) |
| `POST /api/v1/cases/{sha256}/chat` | Bearer Token (`require_analyst`) | Conversational Q&A on case findings via Gemini RAG | `{"message": "...", "history": [...]}` | `{"response": "...", "sources": [...]}` |

---

## 6. Reports & Threat Export (`/api/v1` — `backend/app/routes/report.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `GET /api/v1/report/{sha256}/pdf` | Bearer Token (`require_analyst`) | Download ReportLab investigation report (PDF) | None | `application/pdf` binary stream |
| `GET /api/v1/report/{sha256}/html` | Bearer Token (`require_analyst`) | View standalone HTML security report | None | `text/html` document |
| `GET /api/v1/report/{sha256}/stix` | Bearer Token (`require_analyst`) | Export case IOCs as STIX 2.1 JSON bundle | None | `application/json` (STIX 2.1 bundle) |
| `GET /api/v1/report/{sha256}/iocs` | Bearer Token (`require_analyst`) | Export high-confidence IOCs as CSV | None | `text/csv` (indicator, type, confidence, malware_family) |
| `GET /api/v1/report/{sha256}/json` | Bearer Token (`require_analyst`) | Return raw cached analysis JSON | None | `application/json` |

---

## 7. Threat Intelligence (`/api/v1` — `backend/app/routes/intelligence.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/intel/correlate` | Bearer Token (`require_analyst`) | Correlate indicators with VT/OTX/AbuseIPDB | `{"sha256": "...", "urls": [...], "ips": [...]}` | `ThreatCorrelationResult` |
| `POST /api/v1/intel/enrich` | Bearer Token (`require_analyst`) | Enrich case findings with external intel | `{"sha256": "..."}` | Updated case intelligence profile |
| `GET /api/v1/intel/cache/stats` | Bearer Token (`require_analyst`) | Query IOC 24h reputation cache statistics | None | `{"total_cached": int, "active": int, "expired": int}` |
| `POST /api/v1/intel/cache/clear` | Admin only | Flush expired IOC cache entries | None | `{"cleared_count": int}` |
| `GET /api/v1/intel/live-threats` | Bearer Token (`require_analyst`) | Stream active threat feed signals | None | `{"threats": [...]}` |

---

## 8. APK URL Discovery (`/api/v1` — `backend/app/routes/discovery.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/discovery/crawl` | Bearer Token (`require_analyst`) | Start web crawler looking for APK URLs | `{"target_url": "...", "max_pages": 10}` | `{"session_id": "...", "status": "crawling"}` |
| `GET /api/v1/discovery/sessions` | Bearer Token (`require_analyst`) | List recent discovery sessions | None | `List[DiscoverySession]` |
| `GET /api/v1/discovery/sessions/{session_id}` | Bearer Token (`require_analyst`) | Get discovered APK candidates | None | `{"session": DiscoverySession, "candidates": [...]}` |
| `POST /api/v1/discovery/ingest/{candidate_id}` | Bearer Token (`require_analyst`) | Download discovered APK & start analysis | None | `{"status": "ingesting", "job_id": "..."}` |

---

## 9. Screenshots & Visual Assets (`/api/v1` — `backend/app/routes/screenshots.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `GET /api/v1/screenshots/{sha256}/{filename}` | Bearer Token (`require_analyst`) | Serve captured runtime screenshot image | None | `image/png` or `image/jpeg` binary |
| `GET /api/v1/screenshots/{sha256}/manifest` | Bearer Token (`require_analyst`) | Get timeline metadata for all screenshots | None | `{"screenshots": [{"filename": "...", "timestamp": "...", "caption": "..."}]}` |

---

## 10. VIDE Baselines (`/api/v1` — `backend/app/routes/baselines.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `GET /api/v1/baselines` | Bearer Token (`require_analyst`) | List official Indian bank visual baselines | None | `List[InstitutionBaselineSummary]` |
| `GET /api/v1/baselines/{institution_id}`| Bearer Token (`require_analyst`) | Get layout and color baseline details | None | `InstitutionBaselineDetail` |
| `POST /api/v1/baselines/refresh` | Admin only | Trigger in-process baseline corpus reload | None | `{"status": "reloaded", "institutions_loaded": int}` |

---

## 11. Runtime Telemetry (`/api` — `backend/app/routes/runtime_api.py`)

*Note: These endpoints use the prefix `/api` (not `/api/v1`).*

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `GET /api/runtime/health` | Bearer Token (Analyst scoped) | Runtime telemetry API health check | Bearer Token (Analyst scoped) | `{"status": "ok"}` |
| `GET /api/runtime/status` | Bearer Token (Analyst scoped) | Pipeline health and active stage status | Bearer Token (Analyst scoped) | `{"active_stages": [...], "device_connected": bool}` |
| `GET /api/runtime/hooks` | Bearer Token (Analyst scoped) | Frida hook installation & hit counters | Bearer Token (Analyst scoped) | `{"hooks": [{"name": "...", "hits": int, "errors": int}]}` |
| `GET /api/runtime/events` | Bearer Token (Analyst scoped) | Ring buffer of recent telemetry events | Bearer Token (Analyst scoped) | `{"events": [...]}` (max 500 events) |
| `GET /api/runtime/pipeline` | Bearer Token (Analyst scoped) | State machine transition history | Bearer Token (Analyst scoped) | `{"transitions": [...]}` |
| `GET /api/runtime/metrics` | Bearer Token (Analyst scoped) | Event throughput and processing metrics | Bearer Token (Analyst scoped) | `{"events_per_second": float, "dropped_events": int}` |
| `GET /api/runtime/evidence` | Bearer Token (Analyst scoped) | Real-time snapshots of dynamic evidence | Bearer Token (Analyst scoped) | `{"evidence": [...]}` |
| `GET /api/runtime/diagnostics` | Bearer Token (Analyst scoped) | Combined system diagnostics | Bearer Token (Analyst scoped) | Memory, queue, and ADB socket status |
| `POST /api/events` | Internal secret | Ingest runtime events from external sink | `RuntimeEvent` payload | `{"status": "recorded"}` |

---

## 12. Root & Service Health

| Method & Path | Auth Required | Purpose | Response Summary |
| :--- | :--- | :--- | :--- |
| `GET /` | None | Root platform metadata & formulas | `{"status": "...", "version": "2.1.0", "engines": [...], "scoring": [...]}` |
| `GET /health` | None | Simple readiness probe | `{"status": "ok"}` |

---

## 13. Analysis Engine Microservice (`Port 8001` — `analysis-engine/app/main.py`)

| Method & Path | Auth Required | Purpose | Request Body / Params | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| `POST /api/v1/analyze` | Internal Token (`HEADER_NAME`) | Primary synchronous analysis route | `AnalyzePathRequest` (`file_path`, `sha256`, `timeout_seconds`) | Full analysis payload (static, dynamic, scoring, manifest) |
| `POST /api/v1/analyze-path` | Internal Token (`HEADER_NAME`) | Async analysis initiation on shared volume | `AnalyzePathRequest` | `{"job_id": "...", "status": "queued"}` |
| `GET /api/v1/job/{job_id}` | Internal Token (`HEADER_NAME`) | Poll microservice job execution status | None | `JobStatusResponse` (`job_id`, `status`, `result`) |
| `GET /health` | None | Microservice health check | None | `{"status": "ok", "service": "analysis-engine"}` |
| `GET /status` | None | Subprocess tool readiness probe | None | `{"tools": {"apktool": bool, "jadx": bool, "androguard": bool, "adb_connected": bool}}` |
