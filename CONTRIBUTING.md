# Contributing

Development setup, standards and review expectations for SUDARSHAN.

```yaml
Backend app version:     2.1.0
Analysis engine version: 2.3.0
Last verified:           2026-08-27
Audience:                Core contributors, module developers, security researchers
```

---

## Contents

- [1. Repository layout](#1-repository-layout)
- [2. Development setup](#2-development-setup)
- [3. Code standards](#3-code-standards)
- [4. Testing](#4-testing)
- [5. Changes that need corpus evidence](#5-changes-that-need-corpus-evidence)
- [6. Logging and debugging](#6-logging-and-debugging)
- [7. Documentation](#7-documentation)
- [8. Pull requests](#8-pull-requests)

---

## 1. Repository layout

| Path | Contents | README |
| :--- | :--- | :--- |
| `backend/` | FastAPI gateway, auth, persistence, workers, AI layer | [`../backend/README.md`](../backend/README.md) |
| `analysis-engine/` | Analysis microservice and its container | [`../analysis-engine/README.md`](../analysis-engine/README.md) |
| `shared/sudarshan_core/` | Domain layer both services consume | [`../shared/README.md`](../shared/README.md) |
| `frontend/` | React 18 analyst dashboard | [`../frontend/README.md`](../frontend/README.md) |
| `tests/` | Engine-level pytest suite | [`../tests/README.md`](../tests/README.md) |
| `backend/tests/` | Gateway pytest suite | [`../backend/README.md`](../backend/README.md) |
| `scripts/` | Operational and validation tooling | [`../scripts/README.md`](../scripts/README.md) |
| `docs/` | This documentation portal | [`README.md`](README.md) |

Anything that decides something — what a sample is, what it did, what it scores — belongs in `shared/sudarshan_core/`, not in a service. That is the whole reason the package exists: the gateway and the engine must not be able to disagree.

---

## 2. Development setup

```bash
git clone https://github.com/SanTiwari07/Sudarshan.git
cd Sudarshan
git checkout -b feature/your-feature-name

cp .env.example .env          # set JWT_SECRET_KEY at minimum
```

### Full stack in Docker

```bash
docker compose up --build -d
docker compose logs -f backend
```

`./backend`, `./analysis-engine`, `./shared` and `./frontend` are bind-mounted, so edits take effect without a rebuild.

### One service on the host

```bash
# Backend
export PYTHONPATH="$PWD/backend:$PWD/shared"
export JWT_SECRET_KEY=... ANALYSIS_ENGINE_URL=http://localhost:8001
cd backend && python -m uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend && npm ci && npm run dev
```

Full setup guide, including the sandbox: [`HOW_TO_RUN.md`](getting-started/HOW_TO_RUN.md).

### Git hooks

```bash
powershell -File scripts/enable-githooks.ps1     # or: git config core.hooksPath .githooks
```

`.githooks/pre-push` blocks pushes that would reintroduce Cursor Agent attribution into history. It does **not** run tests.

---

## 3. Code standards

### Python

- **Runtime.** The backend image is Python 3.11-slim; the analysis-engine image is Python 3.12. `shared/pyproject.toml` declares `requires-python = ">=3.11"`. Do not use syntax newer than 3.11.
- **Type hints** on every function signature.
- **PEP 8** formatting. No formatter is configured in this repository, so match the surrounding file rather than reformatting it.
- **Pydantic v2** (`BaseModel`) for API parameters and internal domain contracts — see [`schemas.py`](../shared/sudarshan_core/models/schemas.py).
- **Dependencies** are pinned per service in `backend/requirements.txt` and `analysis-engine/requirements.txt`. `shared/pyproject.toml` deliberately declares none; duplicating them would reintroduce the drift the shared package exists to remove.

### TypeScript and React

- React 18 with TypeScript 5 and Vite 5.
- Tailwind utility classes; no inline CSS.
- Icons from `lucide-react`.
- Severity, risk tone and typography come from `frontend/src/theme/`. Do not hardcode a risk colour in a component.
- Analyst-facing wording lives in `src/lib/analystCopy.ts`, `verdictCopy.ts` and `findingExplanations.ts`, so the same finding reads identically wherever it appears.
- Build case links with `caseRoutes` / `caseSectionPath` from `src/lib/caseRoutes.ts`, never by string concatenation.

ESLint is configured (`npm run lint`). There is no Prettier configuration.

### Invariants that are not negotiable

| Rule | Why |
| :--- | :--- |
| The risk engine is the sole authority on `base_score`, `final_risk_score`, `risk_band` and `verdict` | Model output must never reach a scoring function. A determinism test asserts identical evidence yields an identical verdict |
| All ADB invocation goes through `sudarshan_core.security.adb_gateway.run_adb` | A parallel subprocess wrapper bypasses the containment policy |
| All untrusted strings go through `sudarshan_core.engines.agentic.sanitizer` | Per-site escaping guarantees one site will forget |
| An unavailable axis is **excluded**, never scored zero | Scoring a missing measurement as 0.0 pushed real banking trojans into the `Safe` band |
| "Not observed" and "not present" are different states everywhere they surface | This is the product's core claim about its own evidence |

---

## 4. Testing

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=test_secret \
  python -m pytest tests/ backend/tests -q
```

```powershell
$env:PYTHONPATH="backend;shared"
$env:JWT_SECRET_KEY="test_secret_key_for_pytest"
python -m pytest tests/ backend/tests -q
```

**2,622 tests collected** on 2026-08-27 with no collection errors — 1,813 in `tests/unit`, 12 in `tests/integration`, 797 in `backend/tests`.

**There is no CI workflow in this repository.** No `.github/` directory exists. Running the suite locally before pushing is the only gate there is.

Frontend: `cd frontend && npm test` (Vitest).

### Collection requirements

- `PYTHONPATH` must include both `backend` and `shared`; `sudarshan_core` is not installed into the host interpreter.
- `requests` and a working `bcrypt` backend for `passlib` must be present. One import error during collection aborts the whole session.
- Async tests use `asyncio.run(...)`. `pytest-asyncio` is not installed, so `@pytest.mark.asyncio` is silently a no-op.
- Optional dependencies (`google.genai`, `yara-python`, `chromadb`) may be absent; guard with `pytest.importorskip`.

### Where tests live

| Area | Suite |
| :--- | :--- |
| Risk, BFCI, floors, determinism | `backend/tests/test_risk_engine.py`, `test_bfci_scorer.py`, `test_determinism_replay.py`, `tests/unit/test_risk_engine_nothing_happened.py` |
| Static analysis and repair | `backend/tests/test_manifest_repair.py`, `test_detection_regressions.py`, `test_activity_parser.py` |
| Sandbox and Frida | `tests/unit/test_sandbox_*.py`, `test_frida_pipeline_full.py`, `backend/tests/test_launch_ladder.py`, `test_frida_preflight.py` |
| Agentic exploration | `tests/unit/test_deep_exploration.py`, `test_action_*.py`, `backend/tests/test_agentic_explorer.py`, `test_goal_progression.py` |
| VIDE | `tests/unit/test_vide_*.py` (20 files) |
| Evidence and workflow | `tests/unit/test_evidence_*.py`, `backend/tests/test_workflow_reconstructor.py` |
| API and auth | `backend/tests/test_boundaries.py`, `test_hackathon_security_hardening.py`, `test_batch.py`, `test_prompt_injection.py` |
| Reporting | `backend/tests/test_report_generator.py`, `test_pdf_generator.py` |

Full inventory: [`../tests/README.md`](../tests/README.md).

---

## 5. Changes that need corpus evidence

Some changes are **model changes**: they move existing verdicts on samples that have already been classified. These require validation against the labelled corpus before merge, not a tuned expectation in a test.

Treat a change as a model change if it touches:

- an FRS axis weight, or the set of axes;
- a STEI axis weight;
- a BFCI category weight, category cap, or the set of scored categories (`UNSCORED_CATEGORIES` exists so that behaviour worth recording but not worth scoring has somewhere to go);
- the sequence window or sequence multiplier;
- a safety-floor threshold (`_STEI_STRONG`, `_BFCI_SUBSTANTIVE`) or the conditions under which a floor fires;
- a risk band boundary or a VIDE escalation rule.

Validate with:

```bash
docker run --rm \
  -v "$PWD/shared:/opt/sudarshan-core" -v "$PWD/scripts:/scripts" \
  -v "/path/to/corpus:/corpus:ro" \
  -e PYTHONPATH=/opt/sudarshan-core -e SUDARSHAN_LABELLED_CORPUS_DIR=/corpus \
  --entrypoint python sudarshan-analysis-engine:latest /scripts/validate_corpus.py --check
```

The corpus is gitignored — it contains live banking trojans — so this cannot be automated. Exit code 2 means "could not run" and must never be read as a pass.

---

## 6. Logging and debugging

- Structured logging via the standard `logging` module.
- Prefix entries with a contextual identifier: `[Manifest]`, `[Frida]`, `[APKTool]`, `[JADX]`, `[RiskEngine]`, `[Correlator]`, `[Gemini]`.
- Never log API keys, passwords or tokens.
- Handle sub-engine failures without failing the request. Every optional stage in the pipeline degrades and logs; none of them abort the analysis.
- Do not lower the Androguard log level. `backend/app/main.py` pins those loggers to `WARNING` because `DEBUG` emits tens of thousands of records per analysis holding DEX parse-tree references, which pushes memory to 2–3 GB and invites an OOM kill.
- A silent degradation is a bug. If a feature disables itself because a dependency or key is missing, it must say so at the point of degradation — several soft dependencies here are wrapped in `try/except ImportError`, and a service that starts "healthy" with a feature switched off is the hardest failure mode to diagnose.

---

## 7. Documentation

Documentation is part of the change, not a follow-up.

- Update the affected document in the same pull request.
- **The code is the source of truth.** If a document and the code disagree, the document is the defect.
- Cite the file that implements a claim. A claim with no source is not verifiable and will be asked about in review.
- Measurements carry a date and, where they came from a run, a commit. A number without provenance is not a measurement.
- No credentials, ever — placeholders only.
- No emoji.

Documents that must be updated when behaviour changes:

| Change | Also update |
| :--- | :--- |
| A route added, removed or re-signatured | [`api/ENDPOINTS.md`](api/ENDPOINTS.md) |
| A feature reaching or leaving working state | [`FEATURE_STATUS.md`](features/FEATURE_STATUS.md) |
| A new operational constraint | [`KNOWN_LIMITATIONS.md`](features/KNOWN_LIMITATIONS.md) |
| A scoring formula, weight or floor | [`architecture/08_DETERMINISTIC_RISK_ENGINE.md`](architecture/08_DETERMINISTIC_RISK_ENGINE.md) and the README risk section |
| A new environment variable | `.env.example` and [`HOW_TO_RUN.md`](getting-started/HOW_TO_RUN.md) |
| A directory or module moved | [`CODEBASE_MAP.md`](reference/CODEBASE_MAP.md) and the relevant component README |

---

## 8. Pull requests

1. Run `npm run lint` for frontend changes.
2. Run the full suite: `PYTHONPATH="backend:shared" JWT_SECRET_KEY=test python -m pytest tests/ backend/tests -q`.
3. For a model change, attach the corpus validation output (§5).
4. Update the documentation the change affects (§7).
5. Push the branch and open a pull request against `main` with a summary of what changed and why.

In the description, state explicitly whether the change moves any existing verdict. That is the single question a reviewer of this codebase most needs answered.
