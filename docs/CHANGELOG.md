# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

