# Developer Guidelines & Contribution Manual

```yaml
Document Title:      Sudarshan Developer & Contribution Guide
Version:             2.1.0
Last Revision:       2026-08-03
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
- **Runtime**: Python 3.12+ / 3.13+
- **Shared Package**: Core logic, models, services, and engines belong in [`shared/sudarshan_core/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/) so both backend gateway and analysis engine can consume them cleanly.
- **Type Hints**: Mandatory for all function signatures.
- **Formatting**: PEP-8 compliant.
- **Validation**: Use Pydantic v2 schemas (`BaseModel`) for all API parameters and internal domain contracts ([`schemas.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/schemas.py)).

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
3. **Local Execution**:
   - Launch full container stack: `docker compose up --build -d` (or `.\start.ps1`)
   - Or run locally:
     - Backend Gateway: `python -m uvicorn app.main:app --reload --port 8000` (from `backend/`)
     - Frontend: `npm run dev` (from `frontend/`)

---

## 3. Testing & Determinism Baselines

All PRs must maintain 100% test suite compliance (**923 tests collected** across `tests/` and `backend/tests`). Never break existing test assertions or compromise the **Determinism Invariant**.

### Running Automated Tests
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

### Key Test File Inventory (in [`tests/`](file:///d:/Projects/Sudarshan%20BOI/tests/) and [`backend/tests/`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/))
- `tests/test_remaining_features.py`: Tests `InvestigationManifest`, `ApktoolEngine`, `JadxEngine`, and `mitmproxy` HAR parsing.
- `tests/test_bfci_scorer.py`: Tests logarithmic volume scoring and sequence bonuses.
- `tests/test_workflow_reconstructor.py`: Tests causal chain workflow reconstruction.
- `tests/test_risk_engine.py`: Tests 5-axis STEI, static fallback, and 4-axis FRS formula.
- `tests/test_manifest_repair.py`: Tests automated AXML manifest repair and fallback XML decoding.
- `tests/test_prompt_injection.py`: Tests input sanitization against prompt injection attacks.
- `tests/test_determinism_replay.py`: Validates byte-for-byte verdict stability against pre-refactor recorded baselines.
- `tests/test_detection_regressions.py`: Tests detection regression assertions across malware patterns.
- `tests/test_frida_preflight.py`: Verifies Frida attach SELinux preflight execution.

---

## 4. Logging & Debugging Standards

- Use structured logging via standard Python `logging`.
- Log entries must include contextual identifiers (e.g., `[Manifest]`, `[Frida]`, `[APKTool]`, `[JADX]`).
- Do NOT log raw sensitive API keys or user passwords.
- Always catch and handle non-critical sub-engine errors gracefully without crashing the upload router.

---

## 5. Submitting Pull Requests

1. Run formatting and lint checks.
2. Ensure all automated pytest test cases pass (`pytest tests/ backend/tests` - **923 tests collected**).
3. Push to your branch and submit a Pull Request against `main`. Include a clear summary of changes and reference updated documentation.
