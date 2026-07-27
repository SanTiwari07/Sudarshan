# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 2026-07-27 (later revision)

### Fixed
- **Frida SMS/OTP hooks had never fired.** `banking_trojan.js` called `.length()` on a
  `java.lang.String`, which frida-java-bridge unboxes to a JS primitive, so the hook threw before
  `emit()`. The 0.25-weight SMS component could not score on any sample. Fixed at three sites in
  both the source and the compiled bundle. (`AccessibilityNodeInfo.getText` legitimately is a
  `CharSequence` and was left unchanged.)
- **`Activity.onResume` inflated the banking score for every app.** It emitted into the scored
  `banking` category (cap 3), so three screen transitions produced `banking: 100` for a benign app.
  Since UI exploration navigates screens, this fired on 100% of runs. Moved to an unscored
  `activity` category; verified 50-79 to 0.0.
- **Total hook-initialisation failure was invisible.** `_on_message` had no branch for the agent's
  `{type:'error'}` payload, so a run where every hook died reported `available: true`,
  `bfci: 0.0`, `hook_errors: []` — indistinguishable from a dormant sample. Both the
  initialisation and runtime error envelopes are now recorded in `hook_errors`.
- **`ui_explorer.py` referenced `self.model`, which is never assigned** (`self.client` is the real
  attribute), so the fallback explorer raised `AttributeError` on every iteration and the OCR path
  was unreachable.
- **`frida_sandbox.py` used `logger` 44 lines before defining it**, turning every optional-import
  fallback into a `NameError` rather than graceful degradation.
- **Delegated analyses fed the LLM the wrong object.** `upload.py` passed `frs_breakdown` where
  `_build_evidence_dict` expects `final_risk_score` / `risk_band` / `confidence` / `evidence`, so
  every narrative was generated from `score=0, band="Unknown"` and contradicted the verdict shown
  beside it.
- **`analysis-engine/Dockerfile` was missing `unzip`**, which the JADX install step invokes. The
  image build failed with exit code 127 and no containers started.

### Added
- **SELinux preflight in `run_frida_analysis`** (`adb root` + `getenforce` + `setenforce 0`),
  executed before the `frida-server` check. This took dynamic instrumentation from 0 of 8 corpus
  trojans to 4 of 8.
- **`GEMINI_API_KEY`, `GEMINI_MODEL` and `SUDARSHAN_EXPLORER_MODE` on the analysis-engine service.**
  Without them `ui_explorer` and the agentic planner imported successfully but disabled themselves,
  and `SUDARSHAN_EXPLORER_MODE=ai` silently degraded to `monkey`.
- **`env_file: .env`** on backend and analysis-engine. Compose interpolates `${VAR}` into the YAML
  but does not inject `.env` into containers, so configured values never reached the services.

### Changed
- **Failure reporting no longer names the wrong component.** Two call sites asserted a fixed
  "Ensure frida-server is running on emulator" string, and the outer wrapper discarded the
  session's real exception to substitute it. Failures now propagate the actual cause via
  `FridaSession.last_error`, including SELinux state and whether the process was running.

### Documentation
- Corrected the dynamic-analysis root cause across `02_SYSTEM_OVERVIEW.md`,
  `04_DYNAMIC_ANALYSIS_ENGINE.md` and `DAE_CURRENT_STATE.md`. The previous diagnosis
  ("Frida 17 / ART inlining") was wrong; `Java.deoptimizeEverything()` was working.
- `DAE_CURRENT_STATE.md`: withdrew the "all silent failures fully resolved" claim, corrected the
  test count from 299 to **320**, and added a Part 3 enumerating five open defects.
- Corrected phantom endpoints: `/api/v1/chat/investigation` to `/api/v1/chat` +
  `/api/v1/chat/stream`; `/api/v1/report/export/json/{sha256}` to `/api/v1/report/stix/{sha256}`;
  `/api/v1/report/export/csv/{sha256}` to `/api/v1/report/iocs/{sha256}`.
- Documented four previously undocumented endpoints: `GET /api/v1/auth/me`,
  `PATCH /api/v1/auth/users/{user_id}/role`, `GET`/`POST /api/v1/cases/{sha256}/notes`.
- Corrected the AVD Android version from 13 to 17 (`sdk_gphone16k_x86_64`).

---

## [2.3.0-STABLE] — 2026-07-27
### Documentation
- **Complete Portal Zero-Drift Audit**: Verified and updated all 24 markdown documentation files in `/docs/` and root `README.md`/`CHANGELOG.md` to achieve 100% codebase alignment.
- **Service Topology Alignment**: Standardized port tables across all docs (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`).
- **Shared Core Module Paths**: Updated module paths to `shared/sudarshan_core/` mounted via `PYTHONPATH`.
- **Test Suite Pathing**: Updated all test commands to `pytest backend/tests`.

### Added
- **Containerized Analysis Engine Microservice** (`analysis-engine/`): Created dedicated Ubuntu 24.04 microservice container housing Java 17, Python 3.12, pinned APKTool v2.10.0 (`/usr/local/bin/apktool`), pinned JADX CLI v1.5.1 (`/usr/local/bin/jadx`), PyPI verified Frida 17.16.4, Androguard, and ADB.
- **Analysis Engine REST API** (`analysis-engine/app/main.py`): Exposes REST endpoints on port `8001` (`POST /api/v1/analyze`, `POST /api/v1/analyze/async`, `GET /api/v1/status/{job_id}`, `GET /health`, `GET /status`).
- **Network ADB Connection & Retry Loop** (`entrypoint.sh`): Implemented idempotent 10-attempt connection retry loop to Android Studio AVD via `host.docker.internal:5555` with lazy runtime reconnect logic in `frida_sandbox.py`.
- **Zero-Copy Shared Volume Architecture**: Mounted `uploads` Docker volume shared between `backend` and `analysis-engine` containers for instant, zero-network-copy file access.
- **Container Hardening & Resource Bounds**: Applied `mem_limit: 4g`, `cpus: 2.0`, `no-new-privileges:true`, healthcheck endpoints, and configurable 300-second execution hard timeout.
- **Backend Orchestrator Gateway Refactor** (`backend/app/routes/upload.py`): Completely eliminated local host binary subprocess calls (`apktool`, `jadx`, `java`, `frida`, `adb`) from the backend container; refactored backend to act strictly as a thin gateway orchestrator querying `http://analysis-engine:8001`.
- **Orchestrator Client Test Suite** (`backend/tests/test_analysis_client.py`): Added unit test suite validating gateway client integration and offline fallback handling.


## [2.2.0-STABLE] — 2026-07-25
### Added
- **Formal `InvestigationManifest` Pydantic Model** (`backend/app/models/manifest.py`): Serializes static findings to `manifest.json` before sandbox launch; derives dynamic hook profiles and goal priorities.
- **APKTool & JADX CLI Static Engines** (`apktool_engine.py`, `jadx_engine.py`): Standalone resource decompilation and DEX-to-Java source pattern scanning for 10 fraud-relevant signatures with graceful fallback.
- **mitmproxy Decryption Sidecar Integration** (`docker-compose.yml`, `network_capture.py`): Intercepts transparent HTTPS traffic, exports HAR dumps, and merges HTTP headers, status codes, and body sizes with Frida hook events.
- **Visual Fraud Workflow Reconstruction Component** (`WorkflowDiagram.tsx`): Interactive MITRE ATT&CK technique stage rendering, confidence bars, and expandable hook details in Technical View.
- **BFCI Scoring Engine v2** (`bfci_scorer.py`): Volume-aware logarithmic scaling and 30-second temporal sequence bonus scoring.
- **Behavioral Fraud Workflow Reconstructor** (`workflow_reconstructor.py`): Causal chain engine generating MITRE ATT&CK stage mappings from raw Frida events.
- **Unconditional ART Deoptimization Hook** (`banking_trojan.js`): Added `Java.deoptimizeEverything()` to eliminate ART JIT inlining silent hook suppression.
- **Integration & Verification Test Suite** (`tests/test_remaining_features.py`): Expanded test suite to 299/299 passing unit tests (100% pass rate).

## [RC-2] — 2026-07-25
### Added
- Remote repository update to [https://github.com/SanTiwari07/Sudarshan.git](https://github.com/SanTiwari07/Sudarshan.git).
- PID-based Frida process attach (`adb shell pidof`) replacing package name attach retries.
- Frida 17.16.4 bundling with `frida-java-bridge` (`banking_trojan.bundle.js`).
- Upgraded Gemini model configuration to `gemini-2.5-flash`.
- Sandbox Cwd compatibility wrapper (`powershell.cmd`).
- 285 passing unit and determinism replay tests.

## [RC-1] — 2026-07-19
### Added
- One-command bootstrapper script (`start.ps1`).
- `nohup` execution for `frida-server` on Android emulators.
- Dynamic analysis TypeScript interfaces in React dashboard.

## [Beta] — 2026-07-18
### Added
- Complete repository refactoring into a flattened enterprise structure.
- Comprehensive technical documentation (`ARCHITECTURE.md`, `HOW_TO_RUN.md`, `PROJECT_CONTEXT.md`).
- Multi-stage Docker setup with MobSF (port 8001), FastAPI backend, and React frontend.
