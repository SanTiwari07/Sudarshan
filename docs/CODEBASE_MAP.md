# SUDARSHAN — Codebase Map & Source Reference

> **Authoritative Technical Map of the Codebase**  
> **Source Repository**: `SanTiwari07/Sudarshan`  
> **Last Verified Against Active Codebase**: 2026-08-25  

This document serves as an exhaustive directory-by-directory, class-by-class, and function-by-function index of the **SUDARSHAN** codebase. Use this map to navigate the repository and trace functionality to its source.

---

## Repository Directory Overview

```text
Sudarshan/
├── backend/                  # Gateway & Orchestration API (Port 8000)
│   ├── app/                  # FastAPI application modules
│   │   ├── ai/               # Gemini client & RAG core
│   │   ├── auth/             # JWT auth & RBAC
│   │   ├── db/               # SQLite database layer & DDL
│   │   ├── rag/              # Domain knowledge base
│   │   ├── routes/           # REST API route handlers
│   │   ├── services/         # Background services & enrichment
│   │   └── workers/          # Async job & batch workers
│   └── tests/                # Backend pytest test suite (53 files)
│
├── analysis-engine/          # Containerized Microservice (Port 8001)
│   ├── app/                  # FastAPI microservice entrypoint & routing
│   │   └── main.py           # Core microservice execution engine
│   └── Dockerfile            # Container definition with APKTool & JADX
│
├── shared/sudarshan_core/    # Shared Core Python Library
│   ├── ai/                   # Resilient Gemini Provider & Failover
│   ├── analyzers/            # Native bytecode analyzer (Androguard)
│   ├── engines/              # Scoring, dynamic sandbox, repair, decompilers
│   │   ├── agentic/          # Deep UI exploration subsystem
│   │   ├── vide/             # Visual Impersonation Detection Engine
│   │   └── frida_hooks/      # Compiled Frida JS hook bundles
│   ├── models/               # Pydantic schemas & Manifest contracts
│   ├── sandbox/              # SandboxProvider (Genymotion / AVD abstraction)
│   ├── security/             # Containment policies & token authentication
│   ├── services/             # ThreatCorrelator & MobSFClient
│   ├── validation/           # Corpus validation & stress testing
│   └── visual_evidence/      # Screenshot linking & claim validation
│
├── frontend/                 # React 18 SPA Frontend (Port 5173)
│   └── src/                  # TypeScript / React source
│       ├── components/       # Reusable UI, layout & chart components
│       ├── context/          # AuthContext & AnalysisContext
│       ├── pages/            # View pages (Upload, FraudCard, Tech, Batch, Chat)
│       └── types/            # TypeScript interfaces
│
├── scripts/                  # Operations, preflight & validation scripts
└── tests/                    # Core pytest test suite (57 files)
```

---

## 1. Backend Gateway (`backend/app/`)

The backend gateway handles user requests, session authentication, case persistence, job queuing, STIX/PDF report generation, and coordinates with the analysis microservice.

### `backend/app/main.py`
* **Purpose**: Primary FastAPI gateway entrypoint (Port 8000).
* **Key Components**:
  * `app = FastAPI(...)`: Initializes application, sets up CORS allow-list (`CORS_ALLOW_ORIGINS`), and registers rate limiter.
  * `@app.on_event("startup")`: Initializes SQLite database (`init_db`), seeds administrator account (`seed_demo_users`), wires the 24h IOC reputation cache, registers the runtime telemetry sink on `EventBus`, starts the VIDE baseline refresh worker, and spins up `analysis_queue` and `batch_worker` pools.
  * `@app.on_event("shutdown")`: Gracefully stops background workers.
  * `read_root()` (`GET /`): Returns platform metadata, active engines, and scoring formulas.
  * `health()` (`GET /health`): Simple health check endpoint.

### `backend/app/routes/`
* **`upload.py`**:
  * `POST /api/v1/analyze`: Synchronous APK analysis. Receives upload, calculates SHA-256, streams to `/app/uploads/`, attempts delegated execution to `analysis-engine:8001`, falls back to local execution if engine is offline, runs RAG synthesis, and saves the case.
  * `POST /api/v1/analyze/async`: Asynchronous APK analysis. Creates an `analysis_job` record, writes binary to shared volume, and enqueues to the worker pool.
  * `GET /api/v1/status/{job_id}`: Polls async job progress (`0%` to `100%`) and returns full analysis when complete.
  * `GET /api/v1/sandbox/status`: Probes sandbox availability.
* **`batch.py`**:
  * `POST /api/v1/batches`: Uploads multiple APKs, validates ZIP magic bytes, creates `analysis_batches` and `analysis_batch_jobs` records, and enqueues the batch.
  * `GET /api/v1/batches`: Lists batches with pagination and role-based filtering (`analyst` vs `soc_lead`/`admin`).
  * `GET /api/v1/batches/{batch_id}`: Retrieves batch summary, job counts, and completion percentage.
  * `GET /api/v1/batches/{batch_id}/jobs`: Retrieves lightweight job status rows for a batch.
  * `POST /api/v1/batches/{batch_id}/pause`, `/resume`, `/cancel`: Controls queue processing.
  * `POST /api/v1/batch-jobs/{job_id}/retry`: Re-queues a failed batch job.
* **`cases.py`**:
  * `GET /api/v1/cases`: Lists historical cases with search (`q`), family filter, risk band filter, and pagination.
  * `GET /api/v1/cases/{sha256}`: Retrieves full saved case analysis.
  * `DELETE /api/v1/cases/{sha256}`: Deletes a case (admin only).
  * `GET` & `POST /api/v1/cases/{sha256}/notes`: Retrieves and adds analyst notes to a case.
  * `POST /api/v1/cases/{sha256}/chat`: Grounded interactive chat on the case findings via Gemini vector RAG.
* **`report.py`**:
  * `GET /api/v1/report/{sha256}/pdf`: Generates and serves a ReportLab PDF investigation report.
  * `GET /api/v1/report/{sha256}/html`: Serves standalone HTML security report.
  * `GET /api/v1/report/{sha256}/stix`: Exports case IOCs as a STIX 2.1 JSON bundle.
  * `GET /api/v1/report/{sha256}/iocs`: Exports high-confidence IOCs as CSV.
  * `GET /api/v1/report/{sha256}/json`: Returns raw cached JSON report.
* **`intelligence.py`**:
  * `POST /api/v1/intel/correlate`: On-demand threat correlation for indicators against VirusTotal/OTX/AbuseIPDB.
  * `GET /api/v1/intel/cache/stats`: Statistics on cached IOC reputation items.
  * `POST /api/v1/intel/cache/clear`: Flushes expired IOC cache entries.
  * `GET /api/v1/intel/live-threats`: Feeds active threat signals.
* **`discovery.py`**:
  * `POST /api/v1/discovery/crawl`: Crawls a target domain or URL for direct APK download links.
  * `GET /api/v1/discovery/sessions` & `/{session_id}`: Retrieves discovery session progress.
  * `POST /api/v1/discovery/ingest/{candidate_id}`: Automatically downloads and enqueues a discovered APK.
* **`screenshots.py`**:
  * `GET /api/v1/screenshots/{sha256}/{filename}`: Serves authenticated screenshot image files.
* **`baselines.py`**:
  * `GET /api/v1/baselines`: Lists registered official Indian banking baselines for VIDE.
  * `POST /api/v1/baselines/refresh`: Triggers in-process baseline corpus reload.
* **`resilience.py`**:
  * Endpoints for investigation assertions, time-warp simulations, persona seeding, and checkpoint management.
* **`runtime_api.py`**:
  * Registered at prefix `/api`.
  * `GET /api/runtime/status`: Pipeline health and active stage status.
  * `GET /api/runtime/events`: Telemetry ring buffer (max 500 events).
  * `GET /api/runtime/hooks`: Hook hit counters and error metrics.
  * `POST /api/events`: Ingests runtime events into the telemetry sink.

### `backend/app/auth/`
* **`auth.py`**:
  * `hash_password()`, `verify_password()`: Passlib bcrypt password hashing.
  * `create_access_token()`, `decode_access_token()`: PyJWT token creation and verification with expiration (`JWT_EXPIRE_HOURS`).
  * `get_current_user()`: FastAPI dependency validating `Authorization: Bearer <token>`.
  * `require_analyst()`, `require_soc_lead()`, `require_admin()`: Role-based authorization gates.

### `backend/app/db/`
* **`database.py`**:
  * `init_db()`: Creates SQLite tables (`users`, `cases`, `ioc_cache`, `case_notes`, `analysis_jobs`, `discovery_sessions`, `discovery_candidates`, `analysis_batches`, `analysis_batch_jobs`) and indexes.
  * `save_case(sha256, result, analyst_id)`: Persists complete analysis JSON and indexed metadata.
  * `get_case(sha256)`: Retrieves complete case result.
  * `list_cases(...)`: Paginated search and filtering over historical cases.
  * `get_cached_ioc(indicator, ioc_type)`, `save_ioc_cache(...)`: 24-hour TTL IOC reputation store.

### `backend/app/workers/`
* **`analysis_queue.py`**:
  * Background asyncio worker pool executing queued single-APK analysis jobs.
* **`batch_worker.py`**:
  * Background worker managing enterprise batch scanning, serializing job execution per batch to prevent device contention.
* **`baseline_refresh.py`**:
  * Periodic worker that warms and invalidates the in-memory VIDE baseline corpus.

### `backend/app/ai/`
* **`gemini_client.py`**:
  * `analyze_with_llm(...)`: Orchestrates AI analysis using `GeminiProviderManager` to generate Executive View, Technical Narrative, Attack Graph, Mitigations, and Customer Advisories.
* **`gemini_rag.py`**:
  * Vector embedding, cosine similarity search, and RAG document indexing for cases.
  * `InvestigationRAG`: In-memory vector store indexing finding claims, permissions, and network IOCs for chat Q&A.

---

## 2. Analysis Engine Microservice (`analysis-engine/app/`)

Standalone containerized microservice (Port 8001) executing resource-intensive decompilation, APK repair, native static analysis, and dynamic sandbox execution.

### `analysis-engine/app/main.py`
* **`_execute_analysis_pipeline(apk_path, sha256_hash, timeout_seconds)`**:
  1. Runs native Androguard analysis (`analyze_apk`).
  2. Runs APK repair engine (`ApkRepairEngine`) if AXML corruption is detected.
  3. Decompiles resources via `ApktoolEngine` and source via `JadxEngine`.
  4. Executes VIDE visual impersonation detection (`run_vide_analysis`).
  5. Optionally executes MobSF analysis if configured.
  6. Executes dynamic analysis via `run_frida_analysis` if sandbox is reachable.
  7. Queries threat correlation (`correlate`).
  8. Computes deterministic risk score (`compute_fraud_risk_score`).
  9. Classifies family (`classify_family`).
  10. Generates Investigation Manifest (`build_manifest`).
* **Endpoints**:
  * `POST /api/v1/analyze`: Primary synchronous microservice analysis route.
  * `POST /api/v1/analyze-path`: Asynchronous microservice analysis route taking an internal volume path.
  * `GET /api/v1/job/{job_id}`: Polls microservice job status.
  * `GET /health` & `GET /status`: Probes availability of ADB, APKTool, JADX, and disk limits.

---

## 3. Shared Core Library (`shared/sudarshan_core/`)

Core reusable algorithms, scoring math, dynamic exploration, and sandbox drivers.

### `shared/sudarshan_core/engines/`
* **`risk_engine.py`**:
  * `calculate_risk_score(...)`: Authoritative Fraud Risk Score (FRS) engine.
  * `_axis_ct()`, `_axis_bt()`, `_axis_pr()`, `_axis_ob()`, `_axis_ir()`: Computes the 5 STEI axes.
  * `_calculate_stei()`: Evaluates STEI formula ($0.60\text{CT} + 0.20\text{BT} + 0.10\text{PR} + 0.05\text{OB} + 0.05\text{IR}$).
  * `_calculate_dynamic_score()`: Evaluates BFCI from Frida sandbox telemetry.
  * `_calculate_correlation_score()`: Normalizes VirusTotal/OTX/AbuseIPDB results.
  * `_calculate_banking_impact()`: Evaluates target bank package matches and regulatory risk.
  * *Floors & Escalations*: Implements Visibility Floor, Static Evidence Floor, Evasion Floor, `INCOMPLETE_EXERCISE` assertion floor, and CH27 triad escalation.
* **`bfci_scorer.py`**:
  * `calculate_bfci_v2(...)`: Logarithmic volume-aware behavioral formula.
* **`frida_sandbox.py`**:
  * `run_frida_analysis(...)`: Primary dynamic analysis controller.
  * `start_session()`: Manages device connection, exact PID resolution, attach retry loop, and script injection.
  * `_select_hooks_script()`: Resolves the compiled `banking_trojan.bundle.js`.
* **`apk_repair.py`**:
  * `ApkRepairEngine`: Detects and fixes AXML corruption (repaired string pool offsets, UTF-8 string table bounds, and manifest chunk headers).
* **`apktool_engine.py`**:
  * `ApktoolEngine`: Subprocess wrapper for APKTool 2.10.0 extracting resource XMLs and smali.
* **`jadx_engine.py`**:
  * `JadxEngine`: Subprocess wrapper for JADX 1.5.1 decompiling Java sources and scanning for embedded secrets.
* **`classification_engine.py`**:
  * `classify_family(...)`: Deterministic rule-based malware family classifier (Drinik, Xenomorph, Cerberus, Anubis, SOVA, Hydra, SpyNote, Joker, FluBot).
* **`pdf_generator.py`**:
  * `generate_investigation_pdf(...)`: ReportLab deterministic PDF report compiler creating multi-page executive and technical dossiers.
* **`report_generator.py`**:
  * Generates standalone HTML investigation reports.
* **`evidence_store.py`**:
  * `EvidenceStore`: Central repository of hashed and tagged runtime evidence items.
* **`screenshot_manager.py`**:
  * `ScreenshotManager`: Handles automated device screen captures, image deduplication, and captions.
* **`workflow_reconstructor.py`**:
  * `WorkflowReconstructor`: Analyzes temporal sequences of events to build execution kill chains.
* **`event_bus.py`**:
  * `RuntimeEventBus`: Pub/sub event broker for runtime telemetry.
* **`network_capture.py`**:
  * Captures and filters HTTP/HTTPS network indicators and sockets.

### `shared/sudarshan_core/engines/agentic/` (Deep UI Explorer)
* **`exploration_engine.py`**:
  * `AgenticExplorer`: Main exploration coordinator managing budgets (`ExplorationBudget`), state transitions, backtrack stack, and stopping reasons (`StopReason`).
* **`perception.py`**:
  * `PerceptionPipeline`: Implements the 5-level priority perception hierarchy (UI XML $\rightarrow$ Activity $\rightarrow$ Frida events $\rightarrow$ Logcat $\rightarrow$ Vision).
* **`screen_classifier.py`**:
  * `ScreenClassifier`: Rule-based semantic classification of 17 screen types (`ScreenType`) and package ownership contexts (`classify_screen_with_ownership`).
* **`screen_graph.py`**:
  * `ScreenGraphBuilder`: Calculates stable SHA-256 screen hashes $H(activity, topology)$ and tracks navigation edges.
* **`action_dispatch.py`**:
  * `ActionDispatcher`: Canonical translator converting semantic goals into executable coordinates and tool payloads (`ExecutableAction`).
* **`action_verifier.py`**:
  * `ActionVerifier`: Compares pre- and post-action observations to verify progress and detect state transitions.
* **`tool_executor.py`**:
  * `ToolExecutor`: Executes interactions via ADB (`input tap`, `input text`, `keyevent`, `grant_permission`).
* **`sanitizer.py`**:
  * Filters and sanitizes text inputs and UI labels to prevent prompt injection.

### `shared/sudarshan_core/engines/vide/` (Visual Impersonation Engine)
* **`pipeline.py`**:
  * `run_vide_analysis(...)`: Orchestrates visual comparison against official banking baselines.
* **`baseline_store.py`**:
  * Loads and caches visual profiles for protected financial institutions.
* **`color_match.py`**:
  * Delta-E CIE76 color difference calculator comparing dominant UI palettes.
* **`fuzzy.py`**:
  * Levenshtein-based fuzzy string and keyword matcher.
* **`signer_registry.py`**:
  * Verifies APK signing certificates against official bank developer certificate fingerprints.

### `shared/sudarshan_core/ai/`
* **`gemini_provider.py`**:
  * `GeminiProviderManager`: Central resilient AI client managing circuit-breaker states (`AVAILABLE`, `DEGRADED`, `OPEN`), primary-to-fallback failover, cooldowns, and retries.
* **`gemini_settings.py`**:
  * `load_gemini_settings()`: Parses environment variables for primary/fallback models and keys.
* **`gemini_errors.py`**:
  * Classifies Gemini errors (rate limits, auth failures, thinking token budget errors) and redacts secrets from logs.

### `shared/sudarshan_core/sandbox/`
* **`provider.py`**:
  * `SandboxProvider`: Base class for device interaction, ADB discovery, package management, and port forwarding.
* **`auto.py`**:
  * Auto-discovers whether Genymotion Desktop VM, Android Studio AVD, or a physical device is online.
* **`genymotion.py`** & **`android_studio.py`**:
  * Backend providers tailored to Genymotion (VirtualBox host-only networking) and Android Studio AVD.

### `shared/sudarshan_core/security/`
* **`sandbox_containment.py`**:
  * Audits and enforces network containment policies to prevent the dynamic sandbox from bridging private host subnets.
* **`internal_auth.py`**:
  * Validates internal microservice shared-secret tokens (`ANALYSIS_ENGINE_INTERNAL_TOKEN`).

---

## 4. Frontend Application (`frontend/src/`)

React 18 SPA built with Vite, TypeScript, and TailwindCSS.

### `frontend/src/pages/`
* **`Upload.tsx`**: APK upload portal with drag-and-drop zone, file validation, and real-time step progress animation.
* **`FraudCard.tsx`**: Executive overview presenting the FRS dial, Risk Band, Verdict status, plain-English summary, and CERT-In recommendations.
* **`TechnicalView.tsx`**: Deep technical SOC analyst view with tabs for Manifest, Code Findings, VIDE Impersonation, Behavioral Timeline, Frida Hooks, and Screenshot Gallery.
* **`ThreatIntelView.tsx`**: Threat actor attribution, IOC reputation table (VirusTotal, OTX, AbuseIPDB), and STIX 2.1 / CSV export downloads.
* **`InvestigationChat.tsx`**: Interactive chat interface querying the case findings using Gemini RAG.
* **`History.tsx`**: Paginated, filterable table of all analyzed cases.
* **`BatchScan.tsx`**: Enterprise batch scanning interface for multi-APK upload and queue management.
* **`BatchDetail.tsx`**: Real-time batch progress monitor with per-job status, retry, and cancellation controls.
* **`Login.tsx`**: JWT authentication login page.

### `frontend/src/context/`
* **`AuthContext.tsx`**: Manages user login state, JWT storage in `localStorage`, and token expiration.
* **`AnalysisContext.tsx`**: Holds current active case data and provides global state for investigation views.

---

## 5. Scripts & Automation (`scripts/`)

* **`scripts/validate_corpus.py`**: Benchmarks static-only scoring against the 17-sample labelled ground-truth corpus.
* **`scripts/preflight.py`**: Comprehensive preflight diagnostic verifying host environment, ADB, Frida server, Python packages, and API keys.
* **`scripts/health_check.py`**: End-to-end operational verification script probing backend and analysis-engine endpoints.
* **`scripts/setup_dynamic_analysis.py`**: Automated helper to push frida-server to an emulator and verify root access.
* **`scripts/virustotal_crosscheck.py`**: Cross-checks corpus samples against live VirusTotal detections within rate limits.
