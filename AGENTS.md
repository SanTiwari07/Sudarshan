# Agent Instructions for SUDARSHAN

This file provides instructions for coding agents working on the SUDARSHAN repository.

## Architecture Boundaries

The repository is organized into distinct domains:

- `backend/` - FastAPI orchestration, API routes, database models, and the Deterministic Risk Engine.
- `analysis-engine/` - Static and dynamic analysis orchestration, Frida instrumentation, and Android sandbox interaction.
- `shared/` - Shared core logic, evidence definitions, and configuration.
- `frontend/` - React/Vite web dashboard and analyst UI.
- `tests/` - The comprehensive test suite (unit and integration).
- `scripts/` - Operator scripts, setup tools, and evaluation verification.
- `docs/` - Comprehensive technical documentation.

## Critical Principles

1. **Do not bypass deterministic scoring.** The deterministic engine is the final authority on numerical risk.
2. **AI must not directly mutate deterministic risk scores.** AI provides investigation assistance, explanation, and narrative, but not raw verdicts.
3. **Do not remove security controls.** Authentication, RBAC, and boundary checks must remain intact.
4. **Do not weaken sandbox containment.** The dynamic engine executes malware; isolation is critical.
5. **Do not commit secrets.** Ensure `.env` files are never tracked.
6. **Do not modify Frida instrumentation casually.** The JS payload interacts with hostile environments and is sensitive to changes.
7. **Preserve test coverage.** Ensure `pytest` passes when modifying engine logic.
8. **Update documentation when architecture changes.** Keep the system architecture and current state documents accurate.
9. **Distinguish current implementation from planned features.** Do not document aspirational features as currently implemented.
10. **Never delete unknown files without verification.** Audit unknown files against `docs/`, `scripts/`, and `.gitignore` before removing them.
