# Backend — API gateway and case store

FastAPI service that fronts the whole platform. It authenticates analysts, accepts APKs, delegates analysis to the analysis-engine microservice, persists cases and evidence, serves reports and exports, and runs the AI investigation layer.

The app is declared in [`app/main.py`](app/main.py) as `Sudarshan Enterprise Banking Threat Intelligence Platform`, version **2.1.0**, and listens on port **8000**.

- Platform overview: [`../README.md`](../README.md)
- Full route reference: [`../docs/07_API/API_REFERENCE.md`](../docs/07_API/API_REFERENCE.md)
- Frida setup notes for this service: [`README_FRIDA.md`](README_FRIDA.md)

---

## Layout

```text
backend/
├── app/
│   ├── main.py                   # App construction, CORS, routers, startup/shutdown
│   ├── ai/
│   │   ├── gemini_client.py      # Thin client over the shared provider manager
│   │   └── gemini_rag.py         # Investigation graph, retrieval, streaming answers
│   ├── auth/auth.py              # JWT issue/verify, RBAC dependencies, sessions
│   ├── db/
│   │   ├── database.py           # aiosqlite connection, schema, case/job accessors
│   │   ├── intel.py              # IOCs, runs, chat, exports, runtime events
│   │   ├── security.py           # Sessions and login-attempt tracking
│   │   ├── migrations.py         # Additive schema migrations
│   │   └── paths.py              # Database path resolution
│   ├── middleware/export_ledger.py  # Records every report/IOC/rule export
│   ├── rag/knowledge_base.py     # MITRE / RBI / CERT-In / NPCI reference context
│   ├── routes/                   # See the router table below
│   ├── services/                 # Audit, IOC extraction, discovery, resilience, run recorder
│   └── workers/                  # Background asyncio tasks
├── tests/                        # Gateway pytest suite (conftest adds this dir for fixture modules)
├── Dockerfile
├── requirements.txt
├── README_FRIDA.md
└── reset_admin.py                # Local admin password reset helper
```

`shared/sudarshan_core` is installed into the image at `/opt/sudarshan-core` and bind-mounted in development, so engine changes are live without a rebuild.

---

## Routers

Registered in [`app/main.py`](app/main.py). Everything is under `/api/v1` except runtime telemetry.

| Module | Mounted at | Responsibility |
| :--- | :--- | :--- |
| [`auth/auth.py`](app/auth/auth.py) | `/api/v1/auth` | Login, registration, `/me`, sessions, logout, role and account administration |
| [`routes/upload.py`](app/routes/upload.py) | `/api/v1` | `/analyze`, `/analyze/async`, `/status/{job_id}`, `/analyze/cancel/{job_id}`, `/sandbox/status`, `/sandbox/debug/{case_id}` |
| [`routes/batch.py`](app/routes/batch.py) | `/api/v1` | `/batches` lifecycle and `/batch-jobs/{job_id}/retry` |
| [`routes/discovery.py`](app/routes/discovery.py) | `/api/v1/discovery` | Crawl start, status, results, candidate analysis |
| [`routes/report.py`](app/routes/report.py) | `/api/v1` | Report and rule exports, analyst chat, chat history, artifact explanation |
| [`routes/cases.py`](app/routes/cases.py) | `/api/v1/cases` | Case list and detail, evidence, IOCs, notes, status, verdict, assignment |
| [`routes/intelligence.py`](app/routes/intelligence.py) | `/api/v1/intelligence` | Per-case threat correlation |
| [`routes/screenshots.py`](app/routes/screenshots.py) | `/api/v1` | Screenshot manifest and image serving |
| [`routes/baselines.py`](app/routes/baselines.py) | `/api/v1/baselines` | VIDE baseline listing and admin refresh |
| [`routes/resilience.py`](app/routes/resilience.py) | `/api/v1/analysis` | Personas, assertions, suggestions, time warp, anti-evasion, checkpoints, event stream and WebSocket |
| [`routes/runtime_api.py`](app/routes/runtime_api.py) | `/api/runtime` | Health, status, hooks, events, pipeline, metrics, evidence, diagnostics |
| [`routes/audit.py`](app/routes/audit.py) | `/api/v1/audit` | Audit event query — `soc_lead` and above |

---

## Authentication and authorisation

`JWT_SECRET_KEY` is mandatory. The service refuses to start without it rather than falling back to a generated value, which would let anyone forge a token for any role.

| Role | Grants |
| :--- | :--- |
| `analyst` | Analysis, own cases, reports, chat, batches |
| `soc_lead` | All cases, verdict override, case assignment, audit log |
| `admin` | Everything, plus role changes, account activation, session revocation, baseline refresh |

Dependencies: `require_analyst`, `require_soc_lead`, `require_admin` (from `require_role`). Self-registration always produces an `analyst`; elevation is admin-only via `PATCH /api/v1/auth/users/{user_id}/role`.

Case visibility is scoped in [`app/case_access.py`](app/case_access.py): an `analyst` sees only cases with their own `analyst_id`; `soc_lead` and `admin` see all.

Rate limits (`slowapi`): 10/minute on `/analyze` and `/analyze/async`, 30/minute on `/auth/login`, 10/hour on `/auth/register`.

---

## Database

SQLite through `aiosqlite` with direct SQL. There is no ORM — SQLAlchemy is not a dependency of this service.

Path resolution is [`app/db/paths.py`](app/db/paths.py); in Compose it is set explicitly to `SUDARSHAN_DB_PATH=/app/data/sudarshan.db` on the `dbdata` volume, so the database survives `docker compose down`, image rebuilds and the hardened overlay.

Tables: `users`, `sessions`, `login_attempts`, `cases`, `case_notes`, `case_iocs`, `analysis_jobs`, `analysis_runs`, `analysis_batches`, `analysis_batch_jobs`, `ioc_cache`, `runtime_events`, `chat_messages`, `export_events`, `audit_events`, `discovery_sessions`, `discovery_candidates`.

Schema details: [`../docs/99_HISTORY/legacy_docs/operations/DATABASE.md`](../docs/99_HISTORY/legacy_docs/operations/DATABASE.md).

Adopting a database from an older install:

```bash
docker compose run --rm backend \
  python /opt/sudarshan-scripts/db_admin.py adopt /app/sudarshan.db
```

---

## Background workers

Started and stopped with the app lifecycle in [`app/main.py`](app/main.py).

| Worker | Module | Behaviour |
| :--- | :--- | :--- |
| Analysis queue | [`workers/analysis_queue.py`](app/workers/analysis_queue.py) | `ANALYSIS_WORKERS` coroutines (default 2) consuming queued analysis jobs |
| Batch worker | [`workers/batch_worker.py`](app/workers/batch_worker.py) | One task; strict FIFO per batch, one `SCANNING` job at a time |
| Baseline refresh | [`workers/baseline_refresh.py`](app/workers/baseline_refresh.py) | Re-ingests the VIDE baseline corpus every `VIDE_BASELINE_REFRESH_SECONDS` (default 1 h; `0` disables) |
| Retention sweeper | [`workers/retention.py`](app/workers/retention.py) | Every `RETENTION_INTERVAL_HOURS` (default 24), purges expired sessions, old login attempts, expired IOC cache rows and old jobs. Disable with `RETENTION_ENABLED=false` |
| Runtime event flusher | [`routes/runtime_api.py`](app/routes/runtime_api.py) | Batches in-memory runtime events into `runtime_events` |

The retention sweeper never deletes forensic records: `cases`, `case_notes`, `case_iocs`, `analysis_runs`, `chat_messages`, `audit_events` and `export_events` are retained indefinitely.

---

## AI layer

[`ai/gemini_rag.py`](app/ai/gemini_rag.py) builds a per-SHA-256 evidence index, classifies question intent, retrieves relevant sections, and streams a structured answer. It calls the shared provider manager in `sudarshan_core.ai.gemini_provider`, so failover, cooldown and retry policy are identical to the analysis engine.

Constraints enforced here:

- The model receives indexed evidence chunks, never the raw APK or a whole report.
- The model never computes risk; it explains what the risk engine already decided.
- Conversation history is read from `chat_messages` server-side and capped at 20 turns — client-supplied history is accepted for compatibility but ignored, so a caller cannot fabricate a prior assistant turn.
- Every APK-derived string passes `sudarshan_core.engines.agentic.sanitizer` before entering a prompt.

---

## Local development

Run against the rest of the stack in Docker, with this service on the host:

```bash
export PYTHONPATH="$PWD/backend:$PWD/shared"
export JWT_SECRET_KEY=... ADMIN_USERNAME=admin ADMIN_PASSWORD=...
export ANALYSIS_ENGINE_URL=http://localhost:8001
cd backend && uvicorn app.main:app --reload --port 8000
```

Or run everything in Compose and edit in place — `./backend` is bind-mounted to `/app`:

```bash
docker compose up -d backend
docker compose logs -f backend
```

Reset the admin password:

```bash
docker compose exec backend python reset_admin.py
```

---

## Tests

From the repository root. `PYTHONPATH` must carry both `backend` and `shared`; `sudarshan_core` is not installed into the host interpreter, and without it collection fails with `ModuleNotFoundError`:

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=test_secret \
  python -m pytest tests/ backend/tests -q
```

`backend/tests` contributes **797** of the **2,622** tests collected on 2026-08-27, with no collection errors. `backend/tests/conftest.py` is the only conftest in the tree; it adds `backend/tests` to `sys.path` so the fixture modules beside the tests (`auth_helpers.py`, `case_study_fixtures.py`, `determinism_fixtures.py`) import cleanly.

There is no CI workflow in this repository, so the suite is developer-run.

---

## Configuration

Read from the root `.env`. Variables that matter most to this service:

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `JWT_SECRET_KEY` | — | Mandatory; startup aborts if unset |
| `JWT_EXPIRE_HOURS` | see `.env.example` | Access token lifetime |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | — | Bootstrap admin, seeded at startup |
| `SUDARSHAN_DB_PATH` | `/app/data/sudarshan.db` | Absolute database path |
| `ANALYSIS_ENGINE_URL` | `http://analysis-engine:8001` | Microservice endpoint |
| `ANALYSIS_ENGINE_INTERNAL_TOKEN` | — | Shared secret for engine calls |
| `ANALYSIS_WORKERS` | `2` | Analysis queue concurrency |
| `ANALYSIS_TIMEOUT_SECONDS` | `600` in code, `1200` in Compose | The gateway's HTTP timeout to the engine is this value **+ 60 s**, so it must exceed the engine's own ceiling |
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Explicit allow-list |
| `SUDARSHAN_ENV` | — | `production` enables fail-closed startup validation |
| `SUDARSHAN_ALLOW_GATEWAY_DYNAMIC` | unset | Must stay unset in production — the gateway must not drive the device |
| `SUDARSHAN_RATE_LIMIT_DISABLED` | unset | Local development only |
| `AUTH_ACCOUNT_LOCK_THRESHOLD`, `AUTH_IP_LOCK_THRESHOLD`, `AUTH_LOCKOUT_WINDOW_MINUTES` | see `.env.example` | Lockout policy |
| `RETENTION_ENABLED`, `RETENTION_INTERVAL_HOURS`, `RETENTION_*_DAYS` | see `workers/retention.py` | Retention sweeper |
| `GEMINI_*` | see `.env.example` | Provider keys, models, cooldown, retries |
| `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY` | — | Correlation is skipped and the axis excluded when unset |

Full annotated reference: [`../.env.example`](../.env.example).

---

## Operational notes

- Androguard at `DEBUG` emits tens of thousands of records per analysis and holds DEX parse-tree references, which pushes memory to 2–3 GB and invites an OOM kill. `main.py` pins those loggers to `WARNING` at import time; do not lower it in a deployed service.
- The `analysis-engine` service has no authentication of its own and is deliberately not published. Reach it only over the Compose network.
- `POST /api/v1/chat/stream` uses SSE. `DELETE` is included in the CORS method list because `DELETE /api/v1/chat/history/{sha256}` uses it; removing it makes the browser preflight fail and clearing a conversation looks like a network error.
- `routes/report.py`, `routes/runtime_api.py`, `routes/screenshots.py`, `routes/batch.py` and `routes/upload.py` declare their routers without a prefix, so their paths are spelled in full at the decorator (`/report/pdf/{sha256}`, `/chat/stream`, `/batches`, `/analyze`, …) and the mount adds only `/api/v1` or `/api`.
