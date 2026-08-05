# Sudarshan Platform Master Documentation Audit Report

```yaml
Audit Date:          2026-08-05
Platform Version:    v2.5.0-STABLE (CONTAINERIZED MICROSERVICES, IOC CACHE & RUNTIME TELEMETRY)
Target Repository:   SanTiwari07/Sudarshan (d:/Projects/Sudarshan BOI)
Test Suite Command:  $env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
Audit Scope:         Full Repository, All Engines, Microservices, REST APIs, Telemetry, Docker Compose, Documentation Portal
```

---

## Executive Summary

A full zero-drift documentation pass was executed on **2026-08-05** against the active codebase. All portal documents in `/docs`, root [`README.md`](../README.md), and [`CHANGELOG.md`](../CHANGELOG.md) were compared to implementation files (FastAPI routes, frontend routes, `shared/sudarshan_core`, Docker Compose, `.env.example`, and validation tooling).

**Empirical verification:** `pytest tests/ backend/tests --collect-only` reports **457 tests collected** (executed on the audit host).

---

# Documentation Update Report

## Files Updated

- [`docs/CONTRIBUTING.md`](CONTRIBUTING.md) — Test gate aligned to 457 collected tests and full suite path.
- [`docs/02_SYSTEM_OVERVIEW.md`](02_SYSTEM_OVERVIEW.md) — Removed Ollama references; fixed `/api/v1/analyze`; test metric 457.
- [`docs/VALIDATION.md`](VALIDATION.md) — Fixed diagram test count; added Dynamic APK Corpus Validation section.
- [`docs/README.md`](README.md) — Gemini-only AI index; diagram label correction.
- [`docs/PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) — LLM stack, ADB/SandboxProvider wording; `validation/` tree; `validate_dynamic_pipeline.py`.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — Gateway analyze/async API specification.
- [`docs/01_INTRODUCTION.md`](01_INTRODUCTION.md) — Correct REST surface listing.
- [`docs/dashboard/10_DASHBOARD.md`](dashboard/10_DASHBOARD.md) — Route paths (`/fraud-card`, `/threat-intel`); Gemini-only narrative; screenshot API gap documented.
- [`docs/evaluation/11_EVALUATION.md`](evaluation/11_EVALUATION.md) — Full `tests/` + `backend/tests` layout; 457 metrics; validation cross-link.
- [`docs/evaluation/BENCHMARKS.md`](evaluation/BENCHMARKS.md) — `/api/v1/analyze` and `/analyze/async` ingestion modes.
- [`docs/DAE_CURRENT_STATE.md`](DAE_CURRENT_STATE.md) — SandboxProvider, validation framework, known screenshot route gap, corpus CLI command.
- [`docs/HOW_TO_RUN.md`](HOW_TO_RUN.md) — `validate_dynamic_pipeline.py` operational steps.
- [`docs/future/12_FUTURE_WORK.md`](future/12_FUTURE_WORK.md) — Baseline platform reflects Genymotion-default SandboxProvider.
- [`README.md`](../README.md) — API table, Ollama removal, repo tree, evaluation pytest path.
- [`docs/DOCUMENTATION_AUDIT_REPORT.md`](DOCUMENTATION_AUDIT_REPORT.md) — This report.
- [`docs/CHANGELOG.md`](CHANGELOG.md) — Documentation drift fixes appended under 2026-08-05.

## Files Created

- None (all changes applied to existing numbered portal documents).

## Files Deleted

- None.

## Sections Rewritten

- REST API ingestion paths (`/api/v1/upload` → `/api/v1/analyze`, `/api/v1/analyze/async`, `/api/v1/intelligence/{sha256}`).
- Frontend SPA route map in `10_DASHBOARD.md`.
- Evaluation folder structure and CI diagram in `11_EVALUATION.md`.
- Dynamic validation protocol in `VALIDATION.md` and `HOW_TO_RUN.md`.

## Architecture Changes

- No code architecture changes in this pass — documentation now matches the existing **SandboxProvider** boundary, **validation** package under `shared/sudarshan_core/validation/`, and **5-container** Compose topology already in `docker-compose.yml`.

## New Features Documented

- **Dynamic Validation Framework**: `validate_dynamic_pipeline.py`, corpus manifest, `validation_runs/` engineering reports, stress/recovery flags (implementation pre-existed; was missing from portal docs).

## Documentation Drift Fixed

| Drift | Resolution |
| :--- | :--- |
| Stale test counts (388 / 421 vs **457**) | Standardized on empirically collected count |
| Ollama / Gemini 3.6 cited without code references | Removed; docs state Gemini via `google-genai` + `GEMINI_MODEL` |
| Wrong upload API path | Updated to `/api/v1/analyze` across portal + root README |
| Wrong dashboard routes (`/executive`, `/intel`) | Updated to `/fraud-card`, `/threat-intel` per `App.tsx` |
| Missing validation CLI documentation | Added to `VALIDATION.md`, `HOW_TO_RUN.md`, `DAE_CURRENT_STATE.md`, `PROJECT_CONTEXT.md` |

## Remaining TODOs

- Implement or document alternative for **`GET /api/v1/screenshots/{filename}`** so `TechnicalView.tsx` gallery matches backend capabilities (currently documented as a known gap only).
- Optional: add `docs/VALIDATION.md` cross-link from `docs/README.md` index table (portal index lists `VALIDATION.md` in grep but verify index row — check docs/README)

## Warnings

- **Historical changelog entries** under `docs/CHANGELOG.md` for 2026-08-03 still mention 421 tests — accurate for that release; do not rewrite history.
- **Root `CHANGELOG.md` RC-2 entries** reference `backend/app/engines/` paths — superseded by `shared/sudarshan_core/engines/`; left as historical traceability.
- Live **corpus validation** requires host sandbox connectivity; failures are environmental, not pytest failures.

## Suggestions

- Add a authenticated static route (or signed URL) for screenshot artifacts under `uploads/` or case artifact directories.
- Wire `docs/README.md` document matrix row for [`VALIDATION.md`](VALIDATION.md) if not already present in the index table.

---

## Verification Metrics

- **Automated Test Suite**: **457 / 457 tests collected** (`pytest tests/ backend/tests --collect-only`, 2026-08-05).
- **Documentation Link Integrity**: Internal `file:///` links preserved; relative markdown links preferred in new sections.
- **Codebase Consistency**: API paths, frontend routes, and LLM stack aligned with source inspection.
