# Changelog - Sudarshan Enterprise Platform

All notable changes to this project are documented in this file.

## 2026-08-24

### Added
- **Screenshot hardening (second-phase)**: Central `ScreenshotPolicy` (`shared/sudarshan_core/engines/agentic/screenshot_policy.py`) with state/event-aware deduplication — separate from event and evidence deduplication. Decisions: CAPTURE, DEDUPLICATED, SUPPRESSED, BLOCKED, REUSE with auditable reasons.
- **Screen ownership classification**: `HOME_LAUNCHER`, `EXTERNAL_APP`, `CRASH_STATE`, `SYSTEM_INSTALLER`, etc. via package/activity context (`classify_screen_with_ownership`). Home launcher is not explored as target-app UI; Gemini planner skipped for non-explorable states.
- **External application graph**: External/system screens stored in `ExplorationGraph.external_states`, linked from target states via transition edges.
- **Crash handling**: One crash-context screenshot per crash transition; `APP_CRASH` events in exploration graph; recovery without home screenshot spam.
- **20 regression tests** (`tests/unit/test_screenshot_hardening.py`): Home spam, external dedup, permission dedup, same-screen reuse, crash handling, long-run bounded captures.

### Changed
- **ScreenshotManager** routes all captures through `ScreenshotPolicy` before adb screencap. Manifest includes `policy_statistics`, `suppressed_count`, semantic filenames, and ownership metadata.
- **AgenticExplorer** per-action screenshots no longer use `force=True`; policy evaluates each capture. Home/crash states handled by dedicated async handlers without normal exploration.
- **PerceptionPipeline** skips Level-5 vision for `HOME_LAUNCHER` foreground.
- **Deep Dynamic Exploration Engine** (`shared/sudarshan_core/engines/agentic/exploration_engine.py`): Per-analysis state/action graph with `ApplicationProfile`, `EvidenceMoment`, victim journey reconstruction, deterministic action prioritization, scroll/menu/backtrack support, and exploration coverage metrics. Integrated into `AgenticExplorer` with post-action re-observe, causal screenshot linking, and explicit stop reasons.
- **27 new unit tests** (`tests/unit/test_deep_exploration.py`): State graph, deduplication, evidence moments, mock RTO multi-branch exploration, permission investigation, secondary APK boundary, prompt injection defense.
- **Gemini primary/fallback manager**: `shared/sudarshan_core/ai/gemini_provider.py` routes every Gemini call through Gemini 3.x Flash first, then Gemini 2.5 Flash on quota, rate-limit, 5xx, timeout, or primary-key auth failure, with a configurable primary cooldown. Legacy `GEMINI_API_KEY` / `GEMINI_MODEL` remain primary aliases.

### Changed
- **AgenticExplorer** no longer stops when all 15 fraud goals complete; goals are threat-intelligence prioritization only. Exploration stops on graph exhaustion, budget, or safety boundary.
- Default action budget raised to 120 (`SUDARSHAN_AGENT_ACTION_BUDGET`). Frida silence threshold raised to 8 and requires no unexplored graph branches.
- **Screen classifier** extended with `UPDATE_PROMPT`, `VPN_REQUEST`, `EXTERNAL_APK`, `DOWNLOAD_PROMPT`, `WEBVIEW`, `DIALOG`, `HOME_LAUNCHER`, `EXTERNAL_APP`, `CRASH_STATE` types and ownership resolution.
- **ScreenshotManager** gains causal linking fields (`state_id`, `action_id`, `evidence_id`, `evidence_moment_id`, `ownership`, `deduplication_status`) and suppression statistics.

## 2026-08-12

### Added / Upgraded
- **Reference-Replication ReportLab PDF Engine**: Redesigned server-side ReportLab PDF threat investigation generator (`shared/sudarshan_core/engines/pdf_generator.py`) to strictly replicate the visual structure, 12-section technical organization, typography, color scheme, headers/footers, and information density of master reference specification `sudarshan pdf.pdf`.
- **Vector Drawing Flowables**: Custom ReportLab `FRSDialGauge` (180° arc dial), `FRSBarMeter` (4-axis FRS breakdown), `STEIBarMeter` (5-axis STEI breakdown), `VIDEBarMeter` (UI comparison chart with 0.72 detection threshold line), `BFCIBarMeter` (vertical behavioral category bar chart), `WorkflowDiagram` (horizontal attack step flow), and `NumberedCanvas` running headers/footers.
- **Canonical FRS Consistency Fix**: Resolved FRS score drift bug in `FraudRiskHero.tsx` and PDF generation pipeline. All UI cards, API responses, PDF pages, executive summaries, and assessment blocks now consume the single canonical `final_risk_score` from `risk_engine.py`.
- **Real-Data Pipeline & Provenance Grounding**: Fully grounded report data model in real case payloads and disk evidence artifacts (`evidence.json`, screenshots manifest) with zero synthetic/fake data fabrication.
- **Enhanced Test Suite**: Added comprehensive unit, API, and edge-case tests in `backend/tests/test_pdf_generator.py` covering score consistency, empty evidence, missing dynamic analysis, VIDE states, and screenshot embedding.

## 2026-08-11

### Documentation
- **Full Documentation Audit**: Complete codebase-verified documentation pass across all files in `docs/` and root `README.md`. Codebase treated as sole source of truth.
- **Version corrected**: All docs and `README.md` now state `v2.1.0` (from `backend/app/main.py`); prior docs incorrectly stated `v2.5.0-STABLE`.
- **Test count corrected**: Verified **583 tests collected** (2026-08-11 live run, 42.63s) via `pytest tests/ backend/tests --collect-only`. Prior `README.md` stated 526; prior `docs/` stated 519.
- **Indian bank package count corrected**: `08_DETERMINISTIC_RISK_ENGINE.md` and `README.md` updated to state 21 package prefixes (from 47/various); verified against `apk_analyzer.py::INDIAN_BANK_PACKAGES`.
- **Demo credentials sanitized**: `docs/BOI_DEMO_CREDENTIALS.md` no longer contains plaintext passwords; replaced with `.env` placeholder guidance.
- **CASE_STUDIES.md annotated**: Summary table notes FRS/STEI distinction; Drinik/Xenomorph FRS scores marked "Not re-verified".
- **BENCHMARKS.md annotated**: Warning added — metrics not re-measured in this audit pass.

## [2.5.0-STABLE] - 2026-08-05

### Documentation
- **Master Documentation Audit & Zero-Drift Synchronization**: Comprehensive synchronization across all 24 documentation files in `/docs`, root `README.md`, `CHANGELOG.md`, and `DOCUMENTATION_AUDIT_REPORT.md` against active codebase implementation (`SanTiwari07/Sudarshan`).
- **Verified Test Metrics**: Standardized test execution metrics across documentation to **457 total tests collected & verified** across `tests/` and `backend/tests/`.
- **System Architecture Alignment**: Verified microservices topology (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`), 24h SQLite IOC reputation cache, Frida 17 Java bridge sub-probes, and runtime telemetry endpoints.
- **Second-pass drift remediation (same date)**: Corrected gateway paths (`POST /api/v1/analyze`, `/analyze/async`, `GET /intelligence/{sha256}`), dashboard routes (`/fraud-card`, `/threat-intel`), removed unreferenced model references not present in code, documented `validate_dynamic_pipeline.py` / `shared/sudarshan_core/validation/`, and recorded Technical View screenshot URL gap.

## [2.5.0-STABLE] - 2026-08-03

### Added
- **Persistent IOC Reputation Cache (24h TTL)**: SQLite-backed caching (`ioc_cache` table) in `backend/app/main.py` and `shared/sudarshan_core/services/threat_correlator.py` preventing API rate limit exhaustion across VirusTotal, OTX, and AbuseIPDB.
- **Frida 17 Java-Bridge Sub-Probes**: Added `bisect_sec`, `bisect_temp`, and `java_probe` preflight hooks (`shared/sudarshan_core/engines/frida_hooks/`) for deep ART deoptimization and Java bridge validation.

### Changed
- **Automated Test Suite Expansion**: Expanded verified automated test suite from 388 to **421 passing tests** across `tests/` and `backend/tests/`.
- **Analysis Engine Container Entrypoint**: Refactored `analysis-engine/entrypoint.sh` and Docker compose healthcheck to validate Java 17, ADB host connectivity, and Frida server port binding (`SUDARSHAN_FRIDA_PORT=27055`).
- **Frontend Vite File Watching Stability**: Configured `CHOKIDAR_USEPOLLING=true` and `CHOKIDAR_INTERVAL=300` in `docker-compose.yml` for Windows bind mount file watcher stability.

### Fixed
- **Admin Password Seeding**: Updated `backend/app/main.py` startup handler to generate a secure random password if `ADMIN_PASSWORD` is unconfigured, avoiding published default credentials.

### Documentation
- **Zero-Drift Master Audit**: Updated all 24 portal documentation files in `/docs`, root `README.md`, `CHANGELOG.md`, and `DOCUMENTATION_AUDIT_REPORT.md` to achieve 100% synchronization with codebase.

---

## [2.4.0-STABLE] - 2026-07-29

### Runtime Telemetry API & Frida 17 Banking Malware Instrumentation Suite
- **Runtime Telemetry REST Endpoints**: Implemented `/api/runtime/*` route suite (`backend/app/routes/runtime_api.py`) exposing live pipeline health, Frida hook inventory/metrics, ring-buffered telemetry stream (max 500 events), pipeline state machine status, and evidence snapshots.
- **Frida 17 Banking Malware Instrumentation**: Upgraded dynamic instrumentation hooks suite (`shared/sudarshan_core/engines/frida_hooks/banking_trojan.js`) targeting overlay attacks, SMS interception, keylogging, accessibility abuse, C2 communications, and system anti-analysis evasion bypasses.
- **Agentic UI Exploration Engine**: Enhanced Gemini-driven UI navigation planner (`shared/sudarshan_core/engines/agentic_explorer.py`, `planner.py`) with activity trigger testing, launch ladder execution, and automated goal progression.
- **APK Manifest Repair Engine**: Implemented `shared/sudarshan_core/engines/apk_repair.py` for automated AXML manifest repair, zipalign recovery, and re-signing of corrupt or protected banking APKs.
- **FraudCard Executive Dashboard Component**: Built `frontend/src/pages/FraudCard.tsx` providing executive threat visualization, 5-axis STEI threat scoring breakdown, FRS metrics, and actionable risk highlights.
- **Runtime Verification Test Suite**: Added `scripts/verify_runtime_pipeline.py` and `tests/unit/test_frida_pipeline_full.py` to continuously validate live telemetry endpoints, Frida session lifecycle, and event bus message passing.
- **Comprehensive Documentation Audit**: Completed full 24-document zero-drift documentation audit across `/docs` and root project files.

---

## [2.3.0-STABLE] - 2026-07-29

### Enterprise Documentation Portal Zero-Drift Audit & Release Synchronization
- **Zero-Drift Synchronization**: Comprehensive audit and update of all 24 markdown documentation files in `/docs` and root repository files (`README.md`, `CHANGELOG.md`) to reflect active codebase implementation (`SanTiwari07/Sudarshan`).
- **Standardized Microservice Topology**: Documented 5-container architecture (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`).
- **Verified Test Metrics**: Updated test execution metrics to **388 / 388 unit and integration tests passing** across `backend/tests/`.
- **PowerShell Test Invocation**: Standardized test command:
  ```powershell
  $env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests
  ```
- **Shared Core Module Pathing**: Updated all architectural module references to `shared/sudarshan_core/...` mounted to `/opt/sudarshan-core`.
- **Dynamic Sandbox Operational State**: Updated DAE current state documentation to reflect SELinux preflight execution (`adb root` + `setenforce 0`), Frida 17.16.4 attachment via PID, and `Java.deoptimizeEverything()` ART deoptimization.

---

## [2.3.0-STABLE] - 2026-07-27

### Frida 17.16.4 Project-Wide Migration & Standardization
- **Full Frida Upgrade (17.16.0 → 17.16.4)**: Standardized Frida client, server, and tooling across the entire repository on Frida `17.16.4`.
- **Binary Assets & Setup Scripts**: Downloaded and verified official `frida-server-17.16.4-android-x86_64` (SHA256: `7f7b69d5e33b0a3753bbe152369c7a00173636e92d9e4351e96495c3f885d6f9`) in `frida-server-17.16.4-android-x86_64/`. Updated `scripts/setup_dynamic_analysis.py` to push Frida 17.16.4 server binary. Purged obsolete `frida-server-17.16.0-android-x86_64` assets.
- **Python Dependencies & Docker Images**: Confirmed `frida==17.16.4` and `frida-tools==14.10.4` pinning in `backend/requirements.txt` and `analysis-engine/requirements.txt`.
- **Documentation Alignment**: Synchronized `README.md`, `docs/PROJECT_CONTEXT.md`, `docs/MIGRATION.md`, `docs/HOW_TO_RUN.md`, `docs/DOCUMENTATION_AUDIT_REPORT.md`, and `docs/02_SYSTEM_OVERVIEW.md`.

---

## [RC-2] - 2026-07-25

### Key Updates & Infrastructure Alignment

#### GitHub Repository Rename
- Updated remote repository configuration to [https://github.com/SanTiwari07/Sudarshan.git](https://github.com/SanTiwari07/Sudarshan.git).

#### Frida Attach by PID Fix
- **File:** `backend/app/engines/frida_sandbox.py`
- **Problem:** Dynamic analysis attempted to attach to applications by package name (`com.android.insecurebankv2`). On Android, Frida reports running processes by their display label (`InsecureBankv2`), causing attach-by-name to fail across retries.
- **Fix:** Resolved PID via `adb shell pidof`, enabling immediate attach on attempt 1.

#### Frida 17 Java Bridge Bundling
- **File:** `backend/app/engines/frida_hooks/banking_trojan.bundle.js`
- **Fix:** Bundled `frida-java-bridge` via `frida-compile` into `banking_trojan.bundle.js` to ensure compatibility with Frida 17.16.4 on 16 KB page-size Android 13+ AVDs (`google_apis_ps16k`).

#### Gemini Model Upgrade
- Upgraded default model configuration from retired `gemini-1.5-flash` to `gemini-2.5-flash`.

#### Windows Sandbox Cwd Support
- Added `powershell.cmd` wrapper to support sandbox `run_command` Cwd execution under Windows PowerShell.

#### Comprehensive Test Suite
- Expanded test coverage to passing tests spanning risk engines, prompt injection defenses, goal DAG progression, and determinism replay baselines.

---

## [RC-1] - 2026-07-19

### Bug Fixes

#### frida-server Startup Failure (Critical)
- **File:** `backend/app/engines/frida_sandbox.py`
- **Problem:** The backend used `adb shell su -c '/data/local/tmp/frida-server &'`
  to automatically start `frida-server` on the Android emulator. On emulators
  where the `su` binary does not support the `-c` argument (`su: invalid uid/gid '-c'`),
  this command silently failed - meaning `frida-server` was never running and all
  dynamic analysis was skipped without any visible error in the UI.
- **Fix:** Replaced `su -c` with `nohup /data/local/tmp/frida-server > /dev/null 2>&1 &`.
  Since `adbd` is already running as root (`adb root`), direct execution is portable
  and works on all AVD emulator configurations.

#### Missing Dynamic Analysis in Dashboard (Critical)
- **File:** `frontend/src/App.tsx`
- **Problem:** The `FraudCardData` TypeScript interface was missing the `dynamic_analysis`
  field. The backend API correctly returned the full `DynamicAnalysisResult` payload,
  but the frontend type system silently dropped it. As a result, the `DynamicAnalysisPanel`
  in `TechnicalView.tsx` always rendered "Dynamic analysis data unavailable".
- **Fix:** Added the `DynamicAnalysis` TypeScript type and mapped it to `FraudCardData`.
  The panel now correctly displays runtime API call hooks, network traffic, attack
  timelines, coverage metrics, and screenshots captured during Frida instrumentation.

### New Features

#### One-Command Startup Script (start.ps1)
- **File:** `start.ps1` (project root)
- **Description:** A PowerShell script that replaces the multi-step manual startup
  process. Previously, starting the platform required 5+ separate commands
  (`adb kill-server`, `adb tcpip 5555`, `adb root`, `frida-server` launch,
  `docker compose up`) run in the right order.
- **Now:** Run `.\start.ps1` and everything starts automatically with status feedback.

### Documentation

#### README.md (New)
- Created comprehensive project-level README with architecture diagram, API reference,
  configuration table, project structure, and quick start guide.

---

## [Beta] - 2026-07-18

### Features Implemented

#### Full Analysis Pipeline
- APK upload with static analysis (native parser / MobSF primary)
- Frida dynamic sandbox with multi-stage engine and UI Explorer
- Threat correlation (VirusTotal, AbuseIPDB, OTX)
- FRS scoring engine with 5-axis STEI breakdown
- AI intelligence report (Gemini API)
- SQLite case persistence

#### React Frontend
- Upload page - drag-and-drop APK upload with real-time progress
- Fraud Analyst Card - executive risk summary with BFCI gauge
- SOC / Technical View - full static and dynamic evidence panels
- Threat Intel View - IOC reputation, MITRE ATT&CK mapping
- Case History - paginated list of all past analyses
- JWT Authentication - role-based (analyst / soc_lead / admin)
