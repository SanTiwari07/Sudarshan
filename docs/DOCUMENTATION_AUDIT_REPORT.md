# Sudarshan Platform Master Documentation Audit Report

```yaml
Audit Date:          2026-08-06
Platform Version:    v2.5.0-STABLE (CONTAINERIZED MICROSERVICES, SANDBOX CONTAINMENT P0)
Target Repository:   SanTiwari07/Sudarshan (d:/Projects/Sudarshan BOI)
Test Suite Command:  $env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
Audit Scope:         Full Repository, Security Containment, Engines, Microservices, REST APIs, Docker Compose, Documentation Portal
```

---

## Executive Summary

A full zero-drift documentation pass was executed on **2026-08-06** against the active codebase. Portal documents in `/docs` were compared to implementation files, with emphasis on the P0 sandbox containment work (`shared/sudarshan_core/security/`, `docker-compose.hardened.yml`, gateway dynamic-analysis gate in `upload.py`).

**Empirical verification:** `pytest tests/ backend/tests --collect-only` reports **486 tests collected** (`.pytest_cache/v/cache/nodeids`, 2026-08-06).

---

# Documentation Update Report

## Files Updated

- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — §12 security/containment; FRS weights; repo tree (`security/`, hardened compose); test metric **486**; Genymotion ADB wording.
- [`docs/02_SYSTEM_OVERVIEW.md`](02_SYSTEM_OVERVIEW.md) — FRS renormalization; containment subsystem row; test metric **486**.
- [`docs/01_INTRODUCTION.md`](01_INTRODUCTION.md) — FRS formulation and risk bands aligned to `risk_engine.py`.
- [`docs/PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) — FRS §4.3–4.4; test metric **486**.
- [`docs/architecture/08_DETERMINISTIC_RISK_ENGINE.md`](architecture/08_DETERMINISTIC_RISK_ENGINE.md) — Full FRS section rewrite (axis exclusion, bands, visibility floor).
- [`docs/architecture/04_DYNAMIC_ANALYSIS_ENGINE.md`](architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) — §2c sandbox containment and ADB policy.
- [`docs/DAE_CURRENT_STATE.md`](DAE_CURRENT_STATE.md) — Containment capabilities, remediation rows, limitations; test metric **486**.
- [`docs/HOW_TO_RUN.md`](HOW_TO_RUN.md) — `.env.example`-aligned security vars; §5.1 hardened compose; admin password behavior.
- [`docs/MIGRATION.md`](MIGRATION.md) — Internal token and gateway dynamic-analysis policy.
- [`docs/README.md`](README.md) — Index entries for security runbooks; test metric **486**; containment test modules.
- [`docs/CONTRIBUTING.md`](CONTRIBUTING.md), [`docs/VALIDATION.md`](VALIDATION.md), [`docs/evaluation/11_EVALUATION.md`](evaluation/11_EVALUATION.md) — Test metric **486**; containment test modules in 11.
- [`docs/dashboard/10_DASHBOARD.md`](dashboard/10_DASHBOARD.md) — Risk band labels from API.
- [`docs/CHANGELOG.md`](CHANGELOG.md) — **2026-08-06** release notes.
- [`README.md`](../README.md) — FRS summary and test metric **486** (root entry point).

## Files Created

- None.

## Files Deleted

- None.

## Sections Rewritten

- **FRS / risk bands** across `01_INTRODUCTION`, `02_SYSTEM_OVERVIEW`, `08_DETERMINISTIC_RISK_ENGINE`, `PROJECT_CONTEXT`, `ARCHITECTURE`, root `README.md` (removed obsolete 0.40/0.30 fixed-weight and legacy five-band table).
- **Security & isolation** — `ARCHITECTURE.md` §12, `04_DYNAMIC_ANALYSIS_ENGINE.md` §2c, `HOW_TO_RUN.md` §5.1.
- **DAE operational state** — containment remediation scorecard and known artifact-root limitation.

## Architecture Changes

- Documented **two-layer containment** (guest compromise assumption + control-plane ADB/Frida policy).
- Documented **analysis-engine internal auth** and **production fail-closed** behavior.
- Documented **gateway dynamic analysis disabled by default** (`SUDARSHAN_ALLOW_GATEWAY_DYNAMIC`).
- Documented **hardened compose overlay** and loopback-only MobSF/mitmproxy in base compose.

## New Features Documented

- `adb_gateway.run_adb` centralized choke point.
- `validate_backend_production_config()` on gateway startup.
- Analysis-engine `_InternalServiceAuthMiddleware`.
- Security regression tests under `tests/unit/` and `backend/tests/test_gateway_dynamic_blocker.py`.

## Documentation Drift Fixed

| Drift | Resolution |
| :--- | :--- |
| FRS fixed 0.40/0.30/0.15/0.15 weights | Replaced with nominal 0.25/0.35/0.20/0.20 + renormalization per `risk_engine.py` |
| Legacy CRITICAL at ≥80 / five-band LOW–CRITICAL table | Replaced with Safe / Suspicious / High Risk / Critical thresholds from code |
| Test count **457** | Updated to **486** collected tests |
| Genymotion ADB always `host.docker.internal` | Clarified VM IP / `ADB_HOST` vs AVD exception |
| `ADMIN_PASSWORD=sudarshan_admin_2024` in HOW_TO_RUN | Removed; documented random bootstrap password |
| DAE “screenshot gallery gap” | Removed; UI uses JWT blob fetch (already in `10_DASHBOARD.md`) |

## Remaining TODOs

- [`docs/evaluation/CASE_STUDIES.md`](evaluation/CASE_STUDIES.md) and [`docs/VALIDATION.md`](VALIDATION.md) ground-truth tables still reference legacy `CRITICAL` score ranges (≥85 / ≥80); re-baseline against current `risk_engine.py` bands when corpus scores are re-measured.
- Per-session ephemeral artifact roots — partial mitigation only; see [`security/P0_RED_TEAM_PENETRATION_REPORT.md`](security/P0_RED_TEAM_PENETRATION_REPORT.md).

## Warnings

- Default **dev** `docker-compose.yml` bind-mounts source trees; not equivalent to hardened production posture.
- Enabling `SUDARSHAN_ALLOW_GATEWAY_DYNAMIC=true` runs dynamic analysis in the gateway container and is unsafe for production.

## Suggestions

- Run `pytest tests/ backend/tests` on CI after each release and pin the collected count in `DOCUMENTATION_AUDIT_REPORT.md`.
- Add a short cross-link from [`08_DETERMINISTIC_RISK_ENGINE.md`](architecture/08_DETERMINISTIC_RISK_ENGINE.md) to `backend/tests/test_risk_engine.py` for band threshold regression tests.
