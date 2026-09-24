# Codebase map

Directory, module and responsibility index for the SUDARSHAN repository. Use it to find where something lives and what owns it.

Verified against the active codebase on **2026-08-27**.

> This document maps **structure**, not API surface. Route signatures live in [`api/ENDPOINTS.md`](api/ENDPOINTS.md) and are not duplicated here — two copies of a route table guarantee one of them is wrong.

- Platform overview: [`../README.md`](../README.md)
- Component READMEs: [backend](../backend/README.md) · [analysis-engine](../analysis-engine/README.md) · [shared](../shared/README.md) · [frontend](../frontend/README.md) · [scripts](../scripts/README.md) · [tests](../tests/README.md)

---

## Top level

```text
Sudarshan/
├── backend/                  Gateway and case store (FastAPI 2.1.0, port 8000)
├── analysis-engine/          Analysis microservice (FastAPI 2.3.0, internal port 8001)
├── shared/sudarshan_core/    Domain layer consumed by both services
├── frontend/                 React 18 analyst dashboard (port 5173)
├── tests/                    Engine-level pytest suite
├── scripts/                  Operational and validation tooling
├── deploy/security/          seccomp profile for the analysis engine
├── docs/                     This documentation portal
├── CyberSecurity Bible/      Standalone reference material, not platform documentation
├── docker-compose.yml        frontend, backend, analysis-engine, mitmproxy, mobsf
├── docker-compose.hardened.yml
├── start.ps1                 Windows bootstrap
└── .env.example              Annotated configuration reference
```

Both service images install `shared/sudarshan_core` editable at `/opt/sudarshan-core` and bind-mount `./shared` over it in development, so the two services cannot drift.

---

## 1. Backend gateway — `backend/`

```text
backend/
├── app/
│   ├── main.py                 App construction, CORS, router registration, lifecycle
│   ├── rate_limit.py           slowapi limiter
│   ├── startup_validation.py   Production fail-closed checks
│   ├── registration_policy.py  Public self-registration policy
│   ├── case_access.py          Role-based case visibility
│   ├── artifact_resolve.py     Artifact path resolution for a case
│   ├── evidence_loader.py      Evidence record loading from artifacts
│   ├── demo_seed.py            Optional demo account seeding
│   ├── ai/
│   │   ├── gemini_client.py    Thin client over the shared provider manager
│   │   └── gemini_rag.py       Investigation graph, retrieval, streaming answers
│   ├── auth/auth.py            JWT issue and verify, RBAC dependencies, sessions
│   ├── db/
│   │   ├── database.py         aiosqlite connection, schema, case and job accessors
│   │   ├── intel.py            IOCs, runs, chat, exports, runtime events
│   │   ├── security.py         Sessions, login attempts
│   │   ├── migrations.py       Additive schema migrations
│   │   └── paths.py            Database path resolution
│   ├── middleware/
│   │   └── export_ledger.py    Records every report, IOC and rule export
│   ├── rag/knowledge_base.py   MITRE / RBI / CERT-In / NPCI reference context
│   ├── routes/                 See the table below
│   ├── services/
│   │   ├── audit_service.py           Audit action vocabulary and writer
│   │   ├── case_intel_enrichment.py   Re-correlation and case merge
│   │   ├── ioc_extraction.py          Indicator extraction into case_iocs
│   │   ├── resilience_events.py       Resilience event hub
│   │   ├── resilience_summary.py      Session summary for the UI
│   │   ├── run_recorder.py            Per-run history records
│   │   └── discovery/                 Crawler, downloader, resolver, validator, security
│   └── workers/
│       ├── analysis_queue.py   ANALYSIS_WORKERS coroutines (default 2)
│       ├── batch_worker.py     Single FIFO batch task
│       ├── baseline_refresh.py Periodic VIDE corpus re-ingest
│       └── retention.py        Operational-state sweeper
├── tests/                      61 test modules plus fixture helpers
├── Dockerfile                  python:3.11-slim
├── requirements.txt
└── README_FRIDA.md
```

### Routers

| Module | Mount | Owns |
| :--- | :--- | :--- |
| `auth/auth.py` | `/api/v1/auth` | Login, registration, `/me`, sessions, role and account administration |
| `routes/upload.py` | `/api/v1` | Synchronous and async analysis, job status and cancel, sandbox status and debug |
| `routes/batch.py` | `/api/v1` | Batch lifecycle and per-job retry |
| `routes/cases.py` | `/api/v1/cases` | Case list and detail, evidence, IOCs, notes, status, verdict, assignment |
| `routes/report.py` | `/api/v1` | All exports, analyst chat, chat history, artifact explanation |
| `routes/intelligence.py` | `/api/v1/intelligence` | Per-case correlation result |
| `routes/screenshots.py` | `/api/v1` | Screenshot manifest and image serving |
| `routes/baselines.py` | `/api/v1/baselines` | VIDE baseline listing and admin refresh |
| `routes/discovery.py` | `/api/v1/discovery` | Crawl start, status, results, candidate analysis |
| `routes/resilience.py` | `/api/v1/analysis` | Personas, assertions, suggestions, time warp, anti-evasion, checkpoints, event stream and WebSocket |
| `routes/runtime_api.py` | `/api/runtime` | Health, status, hooks, events, pipeline, metrics, evidence, diagnostics |
| `routes/audit.py` | `/api/v1/audit` | Audit event query |

81 route decorators in total. Signatures: [`api/ENDPOINTS.md`](api/ENDPOINTS.md).

### Persistence

SQLite through `aiosqlite` with direct SQL — no ORM, and SQLAlchemy is not a dependency. Tables: `users`, `sessions`, `login_attempts`, `cases`, `case_notes`, `case_iocs`, `analysis_jobs`, `analysis_runs`, `analysis_batches`, `analysis_batch_jobs`, `ioc_cache`, `runtime_events`, `chat_messages`, `export_events`, `audit_events`, `discovery_sessions`, `discovery_candidates`. Schema detail: [`DATABASE.md`](operations/DATABASE.md).

---

## 2. Analysis engine — `analysis-engine/`

```text
analysis-engine/
├── app/
│   ├── main.py            FastAPI app, analysis pipeline, in-process job store
│   └── adb_bootstrap.py   Policy-validated ADB warm-up at container start
├── entrypoint.sh          Toolchain verification, ADB bootstrap, uvicorn --workers 1
├── Dockerfile             ubuntu:24.04, JDK 17, Python 3.12, APKTool 2.10.0, JADX 1.5.1
├── requirements.txt
└── test_frida*.py, restart_frida*.py   Hand-run diagnostic probes, not tests
```

`_execute_analysis_pipeline(apk_path, sha256_hash, timeout_seconds)` is the whole service in one function, instrumented by `PipelineTimer`:

1. Validate the file — ZIP magic, extension, size cap.
2. Run Androguard (`analyze_apk`), APKTool, JADX and MobSF as concurrent tasks where safe.
3. Repair the APK (`ApkRepairEngine`) when AXML is malformed, and re-analyse.
4. Build the investigation manifest (`build_manifest`).
5. Run the dynamic sandbox (`run_frida_analysis`) when reachable, which drives the agentic explorer.
6. Run VIDE (`run_vide_analysis`).
7. Correlate threat intelligence (`correlate`).
8. Classify the family (`classify_family`).
9. Compute the deterministic score (`compute_fraud_risk_score`).
10. Return the case payload to the gateway.

Concurrency: `asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)`, default 2, plus a per-device-serial lock in the sandbox controller. Job state is an in-process dict with TTL eviction — the service is pinned to `--workers 1` for that reason.

---

## 3. Shared core — `shared/sudarshan_core/`

### `engines/` — analysis, scoring and reporting

| Module | Owns |
| :--- | :--- |
| `risk_engine.py` | STEI, FRS, axis exclusion and renormalisation, bands, escalation rules, four safety floors, confidence |
| `bfci_scorer.py` | BFCI v2 — seven weighted categories, logarithmic volume scoring, fraud sequence detection |
| `execution_assertions.py` | Execution Assertion Matrix, `INCOMPLETE_EXERCISE` verdict |
| `classification_engine.py` | Deterministic malware-family classifier |
| `frida_sandbox.py` | Sandbox controller: install, launch ladder, PID attach, ART deopt, hooks, event collection |
| `dae_pipeline.py` | 16-state pipeline machine with logged transitions |
| `agentic_explorer.py` | Deep UI exploration driver |
| `ui_explorer.py` | Model-assisted exploration path |
| `apk_repair.py` | AXML and string-table repair, resign, SHA-256 |
| `apktool_engine.py`, `jadx_engine.py` | Decompiler wrappers |
| `event_bus.py`, `evidence_store.py` | Runtime events and normalised evidence records |
| `screenshot_manager.py` | Capture, dedup policy, storage layout |
| `workflow_reconstructor.py`, `behavior_graph.py` | Causal chains and behaviour relationships |
| `mitre_mapper.py` | ATT&CK for Mobile technique mapping |
| `ioc_collector.py` | Indicator extraction and normalisation |
| `network_capture.py`, `network_signatures.py` | HAR ingest and C2 signature matching |
| `anti_evasion.py`, `anti_analysis_detector.py` | Evasion probing and detection |
| `device_state_simulator.py`, `time_warp.py`, `persona.py` | Synthetic guest state, clock advancement, victim seeding |
| `permission_orchestrator.py`, `permission_investigator.py` | Pre-grant policy and grant-dialog investigation |
| `multi_stage_engine.py` | Second-stage payload observation |
| `capability_profile.py` | Declared-capability summary bridging static to runtime |
| `session_manager.py`, `runtime_lifecycle.py`, `pipeline_state.py`, `pipeline_timing.py` | Session, lifecycle and timing state |
| `replay_engine.py` | Deterministic replay for the determinism invariant |
| `analysis_history.py` | Per-package run history and deltas |
| `batch_runner.py` | Batch orchestration helpers |
| `yara_scanner.py`, `yara_rules/` | Runtime-string YARA scanning; 8 rules across 2 files |
| `pdf_generator.py`, `report_generator.py`, `report_theme.py` | PDF, HTML and shared visual tokens |
| `frida_hooks/` | Frida agent sources and compiled bundles |

### `engines/agentic/` — deep UI exploration

`perception.py` (five-level observation), `screen_classifier.py`, `screen_graph.py`, `planner.py`, `goal_planner.py`, `goal_tracker.py` (15-stage fraud goal graph), `progress_tracker.py`, `adaptive_budget.py`, `action_dispatch.py`, `semantic_action.py`, `action_verifier.py`, `tool_registry.py`, `tool_executor.py`, `world_model.py`, `coverage_tracker.py`, `agent_memory.py`, `audit_log.py`, `crash_classifier.py`, `remediation.py`, `form_recovery.py`, `field_classifier.py`, `field_taxonomy.py`, `field_constraints.py`, `credentials.py`, `auth_state.py`, `victim_profile.py`, `victim_policy.py`, `visual_grounding.py`, `caption_generator.py`, `screenshot_policy.py`, `device_properties.py`, `ui_observation.py`, `secondary_payload.py`, `sanitizer.py`, `benchmark.py`.

`sanitizer.py` is the single choke point for untrusted content heading into a prompt. Nothing else escapes at a call site.

### `engines/vide/` — visual impersonation

`pipeline.py` orchestrates. `view_ast.py` and `ast_builders.py` normalise hierarchies from layout XML, uiautomator and HTML. `compare.py` and `corpus_compare.py` score against baselines (detection threshold 0.20). `color_match.py` does CIEDE2000 ΔE. `fuzzy.py` does the string axis (threshold 82.0). `discriminative.py` finds exclusive features for attribution. `signer_registry.py` is fail-closed. `baseline_store.py` and `corpus_loader.py` load baselines. `forensics.py` builds the breakdown both the card and the PDF render. `semantic_matcher.py` is advisory only and never the verdict.

### Other packages

| Package | Owns |
| :--- | :--- |
| `ai/` | `gemini_provider.py` (slots, circuit breaker, cooldown, retries), `gemini_settings.py`, `gemini_errors.py`, `artifact_explainer.py` |
| `analyzers/` | `apk_analyzer.py` — Androguard manifest and DEX analysis, entropy, concealed payload |
| `sandbox/` | `provider.py`, `factory.py`, `auto.py`, `genymotion.py`, `android_studio.py`, `future.py`, `config.py`, `device.py`, `device_channel.py`, `frida_assets.py`, `types.py`, `exceptions.py` |
| `security/` | `adb_gateway.py`, `sandbox_containment.py`, `internal_auth.py` |
| `services/` | `threat_correlator.py`, `mobsf_client.py` |
| `models/` | `schemas.py`, `manifest.py` |
| `ingest/` | `apk_record.py` |
| `validation/` | `labelled_corpus.py`, `static_scoring.py`, `corpus.py`, `runner.py`, `coverage.py`, `screenshot_audit.py`, `recovery.py`, `stress.py`, `virustotal_crosscheck.py`, `engineering_report.py` |
| `visual_evidence/` | `linker.py`, `claim_templates.py`, `enrich.py`, `quality.py`, `api_merge.py`, `report_sections.py`, `static_sources.py`, `models.py`, `constants.py` |
| `brand/` | Brand marks used by the PDF and HTML renderers |
| root | `preflight.py`, `runtime_paths.py` |

---

## 4. Frontend — `frontend/src/`

```text
src/
├── App.tsx                  Route table, auth guards, shared case types
├── main.tsx                 Entry point
├── config.ts                API_BASE, auth headers, 401 interceptor, authed download
├── components/
│   ├── batch/               BatchScanPage, BatchDetailPage, fleet summary, job rows, progress hook
│   ├── discovery/           UrlDiscoveryArea
│   ├── investigation/       Verdict, findings registry, evidence drawers, score ledger,
│   │   │                    screenshots, VIDE panels, attack story, MITRE matrix, notes
│   │   └── scoreInfluence/  Per-axis influence detail views
│   ├── layout/              AppShell, AppHeader, AppSidebar
│   ├── motion/              Reduced-motion-aware animation primitives
│   ├── threatIntel/         Intel overview, attribution, IOC registry, similarity, sources
│   ├── ui/                  Badge, Card, DrawerShell, EvidenceSection, primitives
│   └── upload/              Drop zone, pipeline stepper, stage definitions
├── context/                 AuthContext, AnalysisContext, InvestigationUIContext
├── hooks/                   useInvestigationModel, useIntelPayload, useResilience,
│                            useRuntimeScreenshots, useCaseLinks, useDialogBehavior, useReducedMotion
├── layout/navItems.ts       Workspace navigation
├── lib/                     View models, evidence mappers, routing and copy helpers
├── pages/                   Login, Upload, FraudCard, TechnicalView, ThreatIntelView,
│                            History, InvestigationChat, BatchScan, BatchDetail
├── theme/                   colors, severity, riskTone, typography
├── types/                   batch, investigation
└── utils/derive.ts
```

Routes and their components: [`../frontend/README.md`](../frontend/README.md).

---

## 5. Tests

| Path | Modules | Collected |
| :--- | ---: | ---: |
| `tests/unit/` | 88 | 1,813 |
| `tests/integration/` | 2 | 12 |
| `backend/tests/` | 61 (including fixture helpers) | 797 |

**2,622 collected** on 2026-08-27, no collection errors. Inventory: [`../tests/README.md`](../tests/README.md).

---

## 6. Where to look first

| Question | Start at |
| :--- | :--- |
| Why did this sample get this score? | `shared/sudarshan_core/engines/risk_engine.py` |
| Why was the dynamic axis excluded? | `risk_engine.dynamic_exclusion_reason`, `engines/execution_assertions.py` |
| Why did the sandbox stop where it did? | `engines/dae_pipeline.py` transitions, `GET /api/runtime/pipeline` |
| Why did the explorer take that action? | `engines/agentic/planner.py`, `action_verifier.py`, `agent_memory.py` |
| Why was this flagged as an impersonation? | `engines/vide/corpus_compare.py`, `forensics.py` |
| Why is there no threat-intel data? | `services/threat_correlator.py`, and whether the API keys are set |
| Why did the model not answer? | `ai/gemini_provider.py` circuit state, `GET /api/runtime/status` |
| Where is this route defined? | [`api/ENDPOINTS.md`](api/ENDPOINTS.md), then the named router |
