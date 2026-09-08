# API reference

Complete index of the routes registered by the SUDARSHAN backend gateway and the analysis-engine microservice.

Generated from the route decorators in `backend/app/routes/`, `backend/app/auth/auth.py` and `analysis-engine/app/main.py`. Verified against the codebase on **2026-08-27**.

- Interactive reference: `http://localhost:8000/docs`
- Platform overview: [`../../README.md`](../../README.md)
- Backend service notes: [`../../backend/README.md`](../../backend/README.md)

---

## Conventions

**Base URL.** `http://localhost:8000` by default. Routers are mounted at `/api/v1`, except runtime telemetry which is mounted at `/api`.

**Authentication.** All authenticated routes take a bearer token:

```http
Authorization: Bearer <access_token>
```

**Roles.** Enforced by FastAPI dependencies in `backend/app/auth/auth.py`:

| Dependency | Accepts |
| :--- | :--- |
| `get_current_user` | Any authenticated user |
| `require_analyst` | `analyst`, `soc_lead`, `admin` |
| `require_soc_lead` | `soc_lead`, `admin` |
| `require_admin` | `admin` |

**Case scoping.** For `role=analyst`, case and batch listings are filtered to that analyst's own records, and single-case reads are checked by `assert_case_visible`. `soc_lead` and `admin` see everything.

**Rate limits.** Applied by `slowapi`: `POST /auth/register` 10/hour, `POST /auth/login` 30/minute, `POST /analyze` and `POST /analyze/async` 10/minute each.

**Export auditing.** Every response from a report, IOC or rule export route is recorded by `ExportLedgerMiddleware` into `export_events`.

---

## Root

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
| `GET` | `/` | None | Platform metadata: name, version, available engines and scoring model |
| `GET` | `/health` | None | Liveness probe |

---

## Authentication

Router: `backend/app/auth/auth.py`, mounted at `/api/v1/auth`.

| Method | Path | Auth | Request body | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | None | `RegisterRequest` — `username`, `password` | `UserInfo` (201) |
| `POST` | `/api/v1/auth/login` | None | `LoginRequest` — `username`, `password` (JSON) | `TokenResponse` |
| `GET` | `/api/v1/auth/me` | Any user | — | `UserInfo` |
| `POST` | `/api/v1/auth/logout` | Any user | — | `{"status": ...}` — revokes the current session `jti` |
| `POST` | `/api/v1/auth/logout-all` | Any user | — | Revokes every session for the caller |
| `GET` | `/api/v1/auth/sessions` | Any user | — | The caller's active sessions |
| `PATCH` | `/api/v1/auth/users/{user_id}/role` | `admin` | `RoleChangeRequest` — `role` ∈ `analyst` \| `soc_lead` \| `admin` | `UserInfo` |
| `PATCH` | `/api/v1/auth/users/{user_id}/active` | `admin` | `ActiveChangeRequest` — `is_active` | `UserInfo` |
| `POST` | `/api/v1/auth/users/{user_id}/revoke-sessions` | `admin` | — | Revokes all sessions for that user |

`RegisterRequest` deliberately has **no** `role` field. Self-registration always produces an `analyst`; elevation is an admin operation. Registration returns 403 when `SUDARSHAN_ALLOW_REGISTRATION` disables public sign-up, 409 on a taken username, and rejects passwords shorter than 8 characters.

`TokenResponse` fields: `access_token`, `token_type` (`"bearer"`), `username`, `role`, `expires_in_hours`.

> `POST /api/v1/auth/login` takes a **JSON body**, not an OAuth2 form. There is no `/api/v1/auth/registration-policy` route.

---

## Analysis

Router: `backend/app/routes/upload.py`, mounted at `/api/v1`.

| Method | Path | Auth | Request | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/analyze` | `require_analyst` | `multipart/form-data` — `file` | `AnalysisResponse` — the complete case payload |
| `POST` | `/api/v1/analyze/async` | `require_analyst` | `multipart/form-data` — `file` | `AsyncJobResponse` — `job_id`, `status`, `message` (202) |
| `GET` | `/api/v1/status/{job_id}` | `require_analyst` | — | Job status, progress and, when finished, the result |
| `POST` | `/api/v1/analyze/cancel/{job_id}` | `require_analyst` | — | Cancels a queued or running job |
| `GET` | `/api/v1/sandbox/status` | `require_analyst` | — | Sandbox provider, device and Frida availability |
| `GET` | `/api/v1/sandbox/debug/{case_id}` | `require_analyst` | — | Sandbox diagnostics for one case |

Uploads are validated on ZIP magic (`PK\x03\x04`) and extension, and the SHA-256 is computed server-side — a client-supplied hash is never trusted.

---

## Enterprise batch scan

Router: `backend/app/routes/batch.py`, mounted at `/api/v1`.

| Method | Path | Auth | Request | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/batches` | `require_analyst` | `multipart/form-data` — `files` (2–50 `.apk`) | `BatchCreateResponse` (202) |
| `GET` | `/api/v1/batches` | `require_analyst` | `limit` (1–100, default 20), `offset` | `BatchListResponse` |
| `GET` | `/api/v1/batches/{batch_id}` | `require_analyst` | — | `BatchDetailResponse` |
| `GET` | `/api/v1/batches/{batch_id}/jobs` | `require_analyst` | — | `List[BatchJobSummary]` |
| `POST` | `/api/v1/batches/{batch_id}/pause` | `require_analyst` | — | `BatchControlResponse` |
| `POST` | `/api/v1/batches/{batch_id}/resume` | `require_analyst` | — | `BatchControlResponse` |
| `POST` | `/api/v1/batches/{batch_id}/cancel` | `require_analyst` | — | `BatchControlResponse` |
| `POST` | `/api/v1/batch-jobs/{job_id}/retry` | `require_analyst` | — | `BatchJobSummary` reset to `QUEUED` |

Fewer than 2 files returns 400 with a pointer to `/analyze/async`; more than 50 returns 400. Batch states: `QUEUED`, `RUNNING`, `PAUSED`, `COMPLETED`, `PARTIAL`, `FAILED`, `CANCELLED`. Job states: `QUEUED`, `SCANNING`, `COMPLETED`, `FAILED`, `CANCELLED`. A completed job carries `case_sha256`, which deep-links to the full case.

---

## Case history

Router: `backend/app/routes/cases.py`, mounted at `/api/v1/cases`.

| Method | Path | Auth | Request | Response |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/cases` | `require_analyst` | `limit` (1–100, default 20), `offset`, `q`, `band` | `CaseListResponse` |
| `GET` | `/api/v1/cases/{sha256}` | `require_analyst` | — | Full case payload |
| `GET` | `/api/v1/cases/{sha256}/evidence` | `require_analyst` | `limit` (1–2000, default 500), `severity` | Structured runtime evidence records |
| `GET` | `/api/v1/cases/{sha256}/iocs` | `require_analyst` | — | Indicators extracted for the case |
| `GET` | `/api/v1/cases/{sha256}/notes` | `require_analyst` | — | Analyst notes |
| `POST` | `/api/v1/cases/{sha256}/notes` | `require_analyst` | `NoteCreateRequest` — `text`, optional `author` | The created note |
| `PATCH` | `/api/v1/cases/{sha256}/status` | `require_analyst` | `StatusChangeRequest` — `status` | Updated case status |
| `PATCH` | `/api/v1/cases/{sha256}/verdict` | `require_soc_lead` | `VerdictRequest` — `verdict`, `reason` (3–2000 chars) | Updated analyst verdict |
| `PATCH` | `/api/v1/cases/{sha256}/assign` | `require_soc_lead` | `AssignRequest` — `assigned_to` (user id, or `null` to unassign) | Updated assignment |

`q` matches SHA-256, package name, application name or family, and `band` filters on the exact risk band (or `all`). Both are applied in SQL, so they search the whole registry rather than the current page.

Overriding a verdict requires a written reason and is recorded in the audit log. The engine-computed score is never mutated by an override.

> There is no `DELETE /api/v1/cases/{sha256}` and no `POST /api/v1/cases/{sha256}/chat`. Analyst chat lives at `/api/v1/chat` — see [Reports, exports and AI](#reports-exports-and-ai).

---

## Reports, exports and AI

Router: `backend/app/routes/report.py`, mounted at `/api/v1`. Every route requires `require_analyst`.

### Exports

| Method | Path | Media type | Contents |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/report/pdf/{sha256}` | `application/pdf` | ReportLab investigation dossier, attachment-dispositioned as `sudarshan_report_<sha12>.pdf` |
| `GET` | `/api/v1/report/technical-pdf/{sha256}` | `application/pdf` | Alias that delegates to the PDF route and returns the same bytes |
| `GET` | `/api/v1/report/html/{sha256}` | `text/html` | Self-contained single-file report |
| `GET` | `/api/v1/report/stix/{sha256}` | `application/json` | STIX 2.1 bundle with deterministic UUIDv5 identifiers |
| `GET` | `/api/v1/report/iocs/{sha256}` | `text/csv` | Indicator, type, confidence, family; downloads as `sudarshan_iocs_<sha12>.csv` |
| `GET` | `/api/v1/report/iocs-txt/{sha256}` | `text/plain` | One indicator per line; downloads as `sudarshan_iocs_<sha12>.txt` |
| `GET` | `/api/v1/report/yara/{sha256}` | `text/plain` | Generated YARA rule; downloads as `sudarshan_rule_<sha12>.yar`. Rule name and string values are sanitised so the output compiles |
| `GET` | `/api/v1/report/suricata/{sha256}` | `text/plain` | Suricata rules from observed network indicators |
| `GET` | `/api/v1/report/snort/{sha256}` | `text/plain` | The same indicators in Snort syntax |
| `GET` | `/api/v1/report/mitre/{sha256}` | `application/json` | MITRE ATT&CK for Mobile technique mapping |

All return 404 with `"Report not found. Analyze the APK first."` when no case exists for the hash.

> **Known inconsistency.** `/api/v1/report/technical-pdf/{sha256}` is declared with `response_class=HTMLResponse` and a docstring describing print-ready HTML, but its body delegates to `export_pdf_report`, which returns an explicit `Response` with `media_type="application/pdf"`. The declared response class does not match what the route emits. Documented as observed; the code is unchanged.

> There is no `/api/v1/report/json/{sha256}`. Retrieve the full case object from `GET /api/v1/cases/{sha256}`. Path order is `/report/<format>/{sha256}`, not `/report/{sha256}/<format>`.

### AI investigation

| Method | Path | Request | Response |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/chat/stream` | `ChatRequest` — `sha256`, `question` | Server-sent events; tokens streamed as they are produced |
| `POST` | `/api/v1/chat` | `ChatRequest` | `ChatResponse` — `answer`, `sections_used`, `source` |
| `GET` | `/api/v1/chat/history/{sha256}` | — | Stored conversation for the case |
| `DELETE` | `/api/v1/chat/history/{sha256}` | — | Clears the stored conversation |
| `POST` | `/api/v1/explain/artifact` | `ExplainArtifactRequest` — `value`, `kind` (`api` \| `string`) | Plain-language explanation of one technical artifact |

`ChatRequest` still accepts a `history` field for backward compatibility, but it is **ignored**. Conversation history is read server-side from `chat_messages` and capped at 20 turns, so a caller cannot fabricate a prior assistant turn to steer the answer.

`DELETE` must remain in the CORS allow-list for the history route to work from a browser.

---

## Threat intelligence

Router: `backend/app/routes/intelligence.py`, mounted at `/api/v1/intelligence`.

| Method | Path | Auth | Response |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/intelligence/{sha256}` | `require_analyst` | `IntelligenceResponse` |

`IntelligenceResponse` carries per-source status (`SourceStatus`), VirusTotal, AlienVault OTX and AbuseIPDB detail objects, the indicator list (`IOCItem`) and a correlation timeline (`TimelineStep`). Sources with no configured API key are reported as unavailable and the correlation axis is excluded from scoring rather than counted as zero.

> There are no `/api/v1/intel/*` routes. `correlate`, `enrich`, `cache/stats`, `cache/clear` and `live-threats` do not exist; correlation runs inside the analysis pipeline and is read back through this single route.

---

## Screenshots

Router: `backend/app/routes/screenshots.py`, mounted at `/api/v1`.

| Method | Path | Auth | Request | Response |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/screenshots/{sha256}/manifest` | `require_analyst` | `order` (`newest` default) | Screenshot timeline with captions and metadata |
| `GET` | `/api/v1/screenshots/{sha256}/{filename}` | `require_analyst` | — | The image bytes |

Both routes validate `sha256` against a strict hex pattern and reject any `filename` containing a path separator, so the image route cannot be walked outside the case artifact directory.

---

## VIDE baselines

Router: `backend/app/routes/baselines.py`, mounted at `/api/v1/baselines`.

| Method | Path | Auth | Response |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/baselines` | `require_analyst` | `{cache, count, baselines[]}` — the loaded corpus as served to the analysis engine |
| `GET` | `/api/v1/baselines/{institution_id}` | `require_analyst` | Full design schema for one institution; backs the visual diff viewer |
| `POST` | `/api/v1/baselines/refresh` | `admin` | Re-ingests the corpus from disk and invalidates the cache |

A background worker also re-ingests the corpus every `VIDE_BASELINE_REFRESH_SECONDS` (default 1 hour; `0` disables it).

---

## APK discovery

Router: `backend/app/routes/discovery.py`, mounted at `/api/v1/discovery`.

| Method | Path | Auth | Request | Response |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/discovery/start` | `require_analyst` | `StartDiscoveryRequest` — `url` | `session_id` and initial status; crawling runs as a background task |
| `GET` | `/api/v1/discovery/{session_id}/status` | `require_analyst` | — | Crawl progress |
| `GET` | `/api/v1/discovery/{session_id}/results` | `require_analyst` | — | Discovered and validated APK candidates |
| `POST` | `/api/v1/discovery/{session_id}/analyze` | `require_analyst` | `AnalyzeCandidateRequest` — `candidate_id` | Enqueues the candidate for analysis |

URL fetching passes through `backend/app/services/discovery/security.py` before any request is issued.

---

## Investigation resilience

Router: `backend/app/routes/resilience.py`, mounted at `/api/v1/analysis`. All HTTP routes require `require_analyst`.

| Method | Path | Request | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/analysis/personas` | — | Available synthetic victim personas |
| `POST` | `/api/v1/analysis/{session_id}/assertions` | — | Execution Assertion Matrix for the session |
| `GET` | `/api/v1/analysis/{session_id}/suggestions` | — | Suggested triggers for an unexercised run |
| `POST` | `/api/v1/analysis/{session_id}/suggestions` | `SuggestionsRequest` — `execution_assertions`, `unfulfilled_goals`, `target_bank_packages` | Suggestions computed from a supplied assertion set |
| `POST` | `/api/v1/analysis/{session_id}/time-warp` | `TimeWarpRequest` — `hours` (0 < h ≤ 2160, default 24), `force_jobs`, `package_name`, `device_serial` | Advances the guest clock and forces scheduled jobs |
| `POST` | `/api/v1/analysis/{session_id}/seed-persona` | `SeedPersonaRequest` — `persona_id`, `device_serial`, `include` | Seeds contacts, messages, calls and photos onto the guest |
| `POST` | `/api/v1/analysis/{session_id}/autonomous-anti-evasion` | `AntiEvasionRequest` — persona and volume knobs, `battery_level`, `observation_seconds`, `warp_schedule` | Runs the anti-evasion sequence and reports the behavioural delta |
| `GET` | `/api/v1/analysis/{session_id}/checkpoint` | — | Current session checkpoint |
| `POST` | `/api/v1/analysis/{session_id}/checkpoint/restore` | `CheckpointRestoreRequest` — `package_name`, `device_serial` | Restores a session from its checkpoint |
| `GET` | `/api/v1/analysis/{session_id}/events` | — | Replay buffer, for clients that cannot hold a WebSocket |
| `WS` | `/api/v1/analysis/{session_id}/events/ws` | `token` query parameter | Live resilience event stream |

The WebSocket authenticates with a `token` **query parameter** rather than an `Authorization` header, because the browser WebSocket API cannot set headers. `GET /{session_id}/events` is the fallback when a proxy in front of the backend does not upgrade connections.

Seeding a full persona is slow — content inserts cost roughly one second per row — so the anti-evasion sequence seeds a slice and skips what is already present.

---

## Runtime telemetry

Router: `backend/app/routes/runtime_api.py`, mounted at `/api`. Every route requires `get_current_user`.

| Method | Path | Query | Returns |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/runtime/health` | — | Pipeline diagnostics across all stages |
| `GET` | `/api/runtime/status` | — | Frida server status, ADB connectivity, hook counts, event rates |
| `GET` | `/api/runtime/hooks` | `case_id` | Hook inventory with fire and error counts |
| `GET` | `/api/runtime/events` | `limit` (1–500, default 50), `category`, `severity` | Recent events from the in-process ring buffer |
| `GET` | `/api/runtime/pipeline` | `case_id` | DAE state machine and transition history for active sessions |
| `GET` | `/api/runtime/metrics` | — | Throughput, drop rate, error rate |
| `GET` | `/api/runtime/evidence` | `limit` (1–1000, default 100), `severity`, `case_id` | Evidence store snapshot |
| `GET` | `/api/runtime/diagnostics` | `case_id` | Combined operational diagnostics |

`/api/runtime/health` is authenticated deliberately: it discloses the host ADB path, connection mode, emulator serials, the exact Frida version and per-hook error detail.

> There is no `POST /api/events` ingest route. Runtime events reach the database through the in-process flusher started with the app lifecycle.

---

## Audit

Router: `backend/app/routes/audit.py`, mounted at `/api/v1/audit`. Every route requires `require_soc_lead`.

| Method | Path | Query | Returns |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/audit/events` | `actor_user_id`, `action`, `target_type` (`user` \| `case` \| `session`), `target_id`, `since` (ISO-8601), `limit` (1–500, default 100), `offset` | Filtered audit events |
| `GET` | `/api/v1/audit/case/{sha256}` | — | Audit trail for one case |
| `GET` | `/api/v1/audit/actions` | — | The action vocabulary, so a UI filter does not hardcode it |

---

## Analysis engine microservice

`analysis-engine/app/main.py`, version 2.3.0, internal port 8001. **Not published** in `docker-compose.yml` and has no user authentication of its own; the backend reaches it over the Compose network at `http://analysis-engine:8001`.

| Method | Path | Request | Response |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | — | Liveness probe |
| `GET` | `/status` | — | Toolchain readiness, ADB connectivity, concurrency settings |
| `POST` | `/api/v1/analyze` | `AnalyzePathRequest` — path to a file on the shared uploads volume | Full analysis payload |
| `POST` | `/api/v1/analyze/upload` | `multipart/form-data` — `file` | Full analysis payload |
| `POST` | `/api/v1/analyze/async` | Same as `/analyze` | `job_id` |
| `GET` | `/api/v1/status/{job_id}` | — | `JobStatusResponse` |

`ANALYSIS_ENGINE_INTERNAL_TOKEN` is the shared secret between the two services (`shared/sudarshan_core/security/internal_auth.py`).

Job state is held in an in-process dict with TTL eviction (`JOB_RETENTION_SECONDS`, default 3600; `MAX_RETAINED_JOBS`, default 200). It is **not durable** — a container restart loses in-flight jobs, and the gateway's `analysis_jobs` table is the authoritative record. The service is pinned to `--workers 1` for the same reason: a second worker would return 404 for a job created in the other process.

> There is no `/api/v1/analyze-path` and no `/api/v1/job/{job_id}`.

---

## Error responses

| Status | Meaning |
| :--- | :--- |
| 400 | Malformed input — bad SHA-256, invalid filename, batch size out of range, unknown role or status value |
| 401 | Missing, malformed or expired bearer token |
| 403 | Authenticated but insufficient role, or public registration disabled |
| 404 | No case, job, batch or session for the given identifier |
| 409 | Username already taken |
| 429 | Rate limit exceeded |
| 500 | Pipeline or renderer failure; the detail carries the underlying error |
| 503 | Dependency unavailable — for example, dynamic analysis requested while the analysis engine is down and `SUDARSHAN_ALLOW_GATEWAY_DYNAMIC` is unset |

FastAPI returns errors as `{"detail": ...}`, where `detail` is a string or an object depending on the raising site.
