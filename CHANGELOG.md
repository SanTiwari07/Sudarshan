# Changelog — Sudarshan Enterprise Platform

All notable changes to this project are documented in this file.

## [2.3.0-STABLE] — 2026-07-29

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

## [2.3.0-STABLE] — 2026-07-27

### Frida 17.16.4 Project-Wide Migration & Standardization
- **Full Frida Upgrade (17.16.0 → 17.16.4)**: Standardized Frida client, server, and tooling across the entire repository on Frida `17.16.4`.
- **Binary Assets & Setup Scripts**: Downloaded and verified official `frida-server-17.16.4-android-x86_64` (SHA256: `7f7b69d5e33b0a3753bbe152369c7a00173636e92d9e4351e96495c3f885d6f9`) in `frida-server-17.16.4-android-x86_64/`. Updated `scripts/setup_dynamic_analysis.py` to push Frida 17.16.4 server binary. Purged obsolete `frida-server-17.16.0-android-x86_64` assets.
- **Python Dependencies & Docker Images**: Confirmed `frida==17.16.4` and `frida-tools==14.10.4` pinning in `backend/requirements.txt` and `analysis-engine/requirements.txt`.
- **Documentation Alignment**: Synchronized `README.md`, `docs/PROJECT_CONTEXT.md`, `docs/MIGRATION.md`, `docs/HOW_TO_RUN.md`, `docs/DOCUMENTATION_AUDIT_REPORT.md`, and `docs/02_SYSTEM_OVERVIEW.md`.

---

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
- Expanded test coverage to passing tests spanning risk engines, prompt injection defenses, goal DAG progression, and determinism replay baselines.

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

### Documentation

#### README.md (New)
- Created comprehensive project-level README with architecture diagram, API reference,
  configuration table, project structure, and quick start guide.

---

## [Beta] — 2026-07-18

### Features Implemented

#### Full Analysis Pipeline
- APK upload with static analysis (native parser / MobSF primary)
- Frida dynamic sandbox with multi-stage engine and UI Explorer
- Threat correlation (VirusTotal, AbuseIPDB, OTX)
- FRS scoring engine with 5-axis STEI breakdown
- AI intelligence report (Gemini API / Ollama)
- SQLite case persistence

#### React Frontend
- Upload page — drag-and-drop APK upload with real-time progress
- Fraud Analyst Card — executive risk summary with BFCI gauge
- SOC / Technical View — full static and dynamic evidence panels
- Threat Intel View — IOC reputation, MITRE ATT&CK mapping
- Case History — paginated list of all past analyses
- JWT Authentication — role-based (analyst / soc_lead / admin)
