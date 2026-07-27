# Developer Guidelines & Contribution Manual

```yaml
Document Title:      Sudarshan Developer & Contribution Guide
Version:             2.2.0-STABLE
Target Audience:     Core Contributors, Module Developers, Security Researchers
```

---

## Table of Contents
- [1. Code Standards & Guidelines](#1-code-standards--guidelines)
- [2. Development Workflow](#2-development-workflow)
- [3. Testing & Determinism Baselines](#3-testing--determinism-baselines)
- [4. Logging & Debugging Standards](#4-logging--debugging-standards)
- [5. Submitting Pull Requests](#5-submitting-pull-requests)

---

## 1. Code Standards & Guidelines

### Python (Backend & Shared Core)
- **Runtime**: Python 3.12+
- **Shared Library**: Core logic, models, and engines belong in `shared/sudarshan_core/` so both gateway and analysis engine can consume them.
- **Type Hints**: Mandatory for all function signatures.
- **Formatting**: PEP-8 compliant.
- **Validation**: Use Pydantic v2 schemas (`BaseModel`) for all API parameters and internal domain contracts.

### TypeScript / React (Frontend)
- **Framework**: React 18 with TypeScript and Vite.
- **Styling**: Tailwind CSS with utility class patterns. Avoid inline CSS.
- **Icons**: Lucide React (`lucide-react`).

---

## 2. Development Workflow

1. **Clone & Branch**:
   ```bash
   git clone https://github.com/SanTiwari07/Sudarshan.git
   cd Sudarshan
   git checkout -b feature/your-feature-name
   ```
2. **Environment Setup**:
   - Install backend dependencies (`pip install -r backend/requirements.txt`).
   - Install frontend dependencies (`cd frontend && npm install`).
3. **Local Hot-Reload Execution**:
   - Backend Gateway: `uvicorn backend.app.main:app --reload --port 8000`
   - Frontend: `cd frontend && npm run dev`

---

## 3. Testing & Determinism Baselines

All PRs must maintain 100% test suite compliance. Never break existing test assertions or compromise the **Determinism Invariant**.

### Running Automated Tests
```bash
cd backend
pytest tests/
```

### Key Test File Inventory (in `backend/tests/`)
- `tests/test_remaining_features.py`: Tests `InvestigationManifest`, `ApktoolEngine`, `JadxEngine`, and `mitmproxy` HAR parsing.
- `tests/test_bfci_scorer.py`: Tests logarithmic volume scoring and sequence bonuses.
- `tests/test_workflow_reconstructor.py`: Tests causal chain workflow reconstruction.
- `tests/test_risk_engine.py`: Tests 5-axis STEI, static fallback, and 4-axis FRS formula.
- `tests/test_prompt_injection.py`: Tests input sanitization against prompt injection attacks.
- `tests/test_determinism_replay.py`: Validates byte-for-byte verdict stability against pre-refactor recorded baselines.

---

## 4. Logging & Debugging Standards

- Use structured logging via standard Python `logging`.
- Log entries must include contextual identifiers (e.g., `[Manifest]`, `[Frida]`, `[APKTool]`, `[JADX]`).
- Do NOT log raw sensitive API keys or user passwords.
- Always catch and handle non-critical sub-engine errors gracefully without crashing the upload router.

---

## 5. Submitting Pull Requests

1. Run formatting and lint checks.
2. Ensure all automated pytest test cases pass (`cd backend && pytest tests/`).
3. Push to your branch and submit a Pull Request against `main`. Include a clear summary of changes and reference updated documentation.

