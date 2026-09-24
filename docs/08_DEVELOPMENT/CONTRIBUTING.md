# SUDARSHAN — Contributing Guidelines & Architecture Boundaries

> **Classification:** AUTHORITATIVE  
> **Reference:** `AGENTS.md`  

---

## 1. Architectural Boundaries

- `backend/`: FastAPI orchestration, API routes, database models, RAG chat.
- `analysis-engine/`: Containerized static/dynamic pipelines, Frida orchestration, and Android sandbox interaction.
- `shared/`: Shared core logic (`sudarshan_core`), risk engine, VIDE algorithms, evidence definitions.
- `frontend/`: React 18 / Vite web dashboard.
- `tests/`: Automated unit and integration test suite.

---

## 2. Mandatory Rules

1. **Do not bypass deterministic scoring.** The Deterministic Risk Engine (`risk_engine.py`) is the sole authority on numerical risk.
2. **AI must not mutate deterministic risk scores.** AI provides explanation and narrative, but never raw scores.
3. **Do not weaken sandbox containment.** Dynamic analysis executes live malware; isolation is critical.
4. **Never commit secrets.** `.env` files must never be tracked.
5. **Preserve test coverage.** Ensure `pytest` passes before opening pull requests.
