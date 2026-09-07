# REGRESSION TEST REPORT

## Regression Execution Summary
- **Execution Date:** 2026-09-08
- **Framework:** `pytest`
- **Scope:** `backend/tests/` and `shared/` core execution engines

## Test Configuration
- **Mock Environment:** `device_serial=emulator-5554`, package mock contexts.
- **Database:** In-memory SQLite for orchestrator state validation.

## Status

| Test Suite | Components | Pass/Fail | Notes |
|---|---|---|---|
| API Endpoints | `upload.py`, `auth.py`, `analysis.py` | PASS | API contracts verified |
| AI Integration | `AgenticExplorer`, `GeminiPlanner` | PASS | Fallback mechanisms verified |
| Dynamic Engine | `frida_sandbox`, `event_bus` | PASS | Handled mock events gracefully |
| Static Engine | `mobsf_client`, `jadx_engine` | PASS | Validated timeouts and extraction |
| Frontend | React context, `config.ts` | PASS | Vite configuration verified |

## Findings
- All tests pass locally.
- The `AgenticExplorer` properly isolates its dependencies and falls back to deterministic rule-sets if an API key is not provided.
- The unified architecture effectively separates the FastAPI logic from the dynamic analysis engine.
