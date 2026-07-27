# Changelog — Sudarshan Enterprise Platform

All notable changes to this project are documented in this file.

## [2.3.0-STABLE] — 2026-07-27

### Documentation Synchronization & Zero-Drift Audit
- **Full Portal Audit (`/docs`)**: Verified and updated all 24 markdown documentation files to ensure 100% synchronization with the active codebase (`SanTiwari07/Sudarshan`).
- **Microservices Topology Alignment**: Standardized port tables across all docs (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`).
- **Shared Core Package Pathing**: Corrected all module import references from `backend/app/engines/...` to `shared/sudarshan_core/engines/...` and `shared/sudarshan_core/models/...`.
- **Test Suite Pathing**: Updated all test execution commands from `pytest tests/` to `pytest backend/tests` (or `cd backend && pytest tests/`).
- **DAE & Risk Engine Status**: Aligned DAE capabilities, 5-axis STEI, 6-component BFCI v2, and 4-axis FRS formulas with active source code.

## [RC-2] — 2026-07-25

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
- Expanded test coverage to 285 passing tests spanning risk engines, prompt injection defenses, goal DAG progression, and determinism replay baselines.

---

## [RC-1] — 2026-07-19

### Bug Fixes

#### frida-server Startup Failure (Critical)
- **File:** `backend/app/engines/frida_sandbox.py`
- **Problem:** The backend used `adb shell su -c '/data/local/tmp/frida-server &'`
  to automatically start `frida-server` on the Android emulator. On emulators
  where the `su` binary does not support the `-c` argument (`su: invalid uid/gid '-c'`),
  this command silently failed — meaning `frida-server` was never running and all
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
- **What it does:**
  - Kills stale ADB server and restarts fresh
  - Enables ADB TCP mode on the emulator
  - Restarts `adbd` as root
  - Kills any stale `frida-server` process and launches a fresh instance
  - Verifies `frida-server` is actually running before proceeding
  - Launches `docker compose up`
  - Prints URLs for frontend, backend, and MobSF

### Documentation

#### README.md (New)
- Created comprehensive project-level README with architecture diagram, API reference,
  configuration table, project structure, and quick start guide.

#### backend/README_FRIDA.md (Updated)
- Added Quick Start section referencing `start.ps1`.
- Updated `frida-server` version references from `17.15.3` to `17.16.1`.
- Updated startup command from `su -c` to `nohup` method with explanation.
- Added Known Limitations section covering emulator reboot requirements and Git file size constraints.
- Added `start.ps1` to the Files Reference table.

---

## [Beta] — 2026-07-18

### Features Implemented

#### Full Analysis Pipeline
- APK upload with static analysis (Androguard fallback / MobSF primary)
- Frida dynamic sandbox with multi-stage engine and UI Explorer
- Threat correlation (VirusTotal, AbuseIPDB, OTX)
- FRS scoring engine with 5-axis STEI breakdown
- AI intelligence report (Gemini API / Ollama)
- SQLite case persistence

#### React Frontend
- Upload page — drag-and-drop APK upload with real-time progress
- Fraud Analyst Card — executive risk summary with BFCI gauge
- SOC / Technical View — full static and dynamic evidence panels
  - Explainability Engine
  - APK Metadata
  - Threat Indicators Checklist
  - Permission Analysis Table
  - Dangerous API Table
  - Network Intelligence
  - IOC Reputation Panel
  - Dynamic Sandbox Execution Panel (multi-stage summary, attack timeline,
    coverage metrics, screenshots)
  - Risk Scoring Breakdown (5-axis STEI)
- Threat Intel View — IOC reputation, MITRE ATT&CK mapping
- Case History — paginated list of all past analyses
- JWT Authentication — role-based (analyst / soc_lead / admin)

#### Docker Stack
- backend — FastAPI + Uvicorn
- frontend — Vite + React (dev server)
- mobsf — Mobile Security Framework v4.5.1

#### ADB / Frida Networking
- Backend connects to host emulator via `host.docker.internal:5555` (Docker Desktop)
- `ADB_HOST` / `ADB_PORT` configurable via `.env`
- Graceful fallback to static-only analysis if sandbox unreachable

### Bug Fixes (During Beta)

- **Docker ADB Connection Silent Failure:** `get_sandbox_status()` now actively
  probes ADB TCP connection instead of assuming connectivity from env variables.
- **Missing Dynamic Intelligence in API Payload:** Expanded `AnalysisResponse`
  Pydantic schema and updated `/analyze` route to extract full `UIExplorer`
  outputs (attack timeline, coverage metrics, screenshots, anti-analysis events)
  into the API response.
- **STEI Score Redistribution:** When dynamic analysis is unavailable, STEI
  weight increases from 25% to 50% in the FRS formula automatically.

---

## Known Issues (Open)

| Issue | Impact | Workaround |
|-------|--------|------------|
| `frida-server` not persistent across emulator reboots | Dynamic analysis fails after emulator restart | Run `.\start.ps1` which re-launches `frida-server` automatically |
| `frida-server` binary not in Git (>100 MB) | New developers must set it up manually | Follow Step 2 in `backend/README_FRIDA.md` |
| Ollama AI reports require local Ollama installation | AI narrative defaults to static template | Install Ollama locally or set `GEMINI_API_KEY` in `.env` |
| MobSF "username already taken" warning on restart | Cosmetic warning, no functional impact | Safe to ignore |
