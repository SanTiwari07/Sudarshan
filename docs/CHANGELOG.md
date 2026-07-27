# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
