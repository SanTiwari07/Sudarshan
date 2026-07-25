# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
