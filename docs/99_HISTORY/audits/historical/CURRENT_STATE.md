# Current state

Snapshot of what works, what is constrained, and what is absent.

Original report **2026-08-14**. Re-verified against the active codebase on **2026-08-27**.

> The original version of this document carried a "Project Health Score of 7.75 / 10" and a twelve-point breakdown of numeric component scores. Those numbers had no method behind them and nothing regenerated them, so they have been removed rather than carried forward. What follows is limited to statements that can be checked against the repository.

Maintained views: [docs/features/FEATURE_STATUS.md](docs/features/FEATURE_STATUS.md) · [docs/features/KNOWN_LIMITATIONS.md](docs/features/KNOWN_LIMITATIONS.md) · [BUGS_AND_IMPROVEMENTS.md](future/BUGS_AND_IMPROVEMENTS.md)

---

## Verified facts

| Property | Value | How to check |
| :--- | :--- | :--- |
| Backend app version | 2.1.0 | `backend/app/main.py` |
| Analysis engine app version | 2.3.0 | `analysis-engine/app/main.py` |
| Backend route decorators | 81 | `grep -c` over `backend/app/routes/` and `backend/app/auth/auth.py` |
| Analysis engine routes | 6 | `analysis-engine/app/main.py` |
| Tests collected | 2,622 | `PYTHONPATH="backend:shared" JWT_SECRET_KEY=t pytest tests/ backend/tests --collect-only` (2026-08-27, no collection errors) |
| CI workflows | none | No `.github/` directory exists |
| Persistence | SQLite via `aiosqlite`, WAL, no ORM | `backend/app/db/` |
| Frida | 17.16.4 pinned host and guest | both `requirements.txt`, both Dockerfiles |
| Decompilers | APKTool 2.10.0, JADX 1.5.1 | `analysis-engine/Dockerfile` |
| Fraud goal graph | 15 stages | `shared/sudarshan_core/engines/agentic/goal_tracker.py` |
| Launch ladder | 5 steps | `shared/sudarshan_core/engines/frida_sandbox.py` |
| YARA rules | 8 across 2 files | `shared/sudarshan_core/engines/yara_rules/` |
| VIDE lab baselines | 10 | `shared/sudarshan_core/data/ui_baselines/` |
| Signer registry entries | 12 packages, empty allowlists (fail-closed) | `shared/sudarshan_core/data/bank_signer_registry.json` |
| Corpus detection result | 8/8 flagged, 0/9 false positives, static-only | `docs/evaluation/corpus_static_validation.json`, measured 2026-08-15 at commit `ce30610` |

---

## Component state

| Component | State | Notes |
| :--- | :--- | :--- |
| Frontend | Working | React 18 SPA; case-addressed routes with legacy redirects. The bundled image runs the Vite dev server, not a production build |
| Backend gateway | Working | 81 routes, all documented in [docs/api/ENDPOINTS.md](docs/api/ENDPOINTS.md). Earlier reports called 18 of them undocumented; that is resolved |
| Database | Working | Direct async SQL, on a dedicated `dbdata` volume so it survives `docker compose down` and the hardened overlay |
| Analysis engine | Working | Concurrent static stages bounded by a semaphore; every optional stage degrades rather than failing the request. Job state is in-process and not durable |
| Risk engine | Working | Deterministic. Axis exclusion and renormalisation, four safety floors, VIDE escalation. A determinism replay test asserts identical evidence yields an identical verdict |
| Dynamic sandbox | Working, environment-dependent | Requires a rooted host-side emulator with matching frida-server. Degrades to static-only when unreachable, and says so in the verdict |
| Agentic explorer | Working | 15-stage goal graph. Falls back to a deterministic planner without a Gemini key |
| Threat intelligence | Constrained | Correlation works; caching is incomplete — OTX hash lookups bypass the cache and 404s are not negatively cached. See [BUGS_AND_IMPROVEMENTS.md](future/BUGS_AND_IMPROVEMENTS.md) §1.2 and §1.3 |
| Reporting | Working | PDF, HTML, STIX 2.1, IOC CSV/TXT, YARA, Suricata, Snort, MITRE JSON. The PDF `TypeError` reported in the original audit is fixed |
| Security and infrastructure | Working, with a documented fail-open | Containment policy, ADB choke point, hardened overlay. Internal service auth is fail-open outside `SUDARSHAN_ENV=production` |
| Test suite | Large, unenforced | 2,622 tests, no CI. Nothing prevents a regression from being pushed |

---

## What is absent

- **Continuous integration.** No workflow, no automated gate.
- **Horizontal scale.** One SQLite file and an in-process queue.
- **A production frontend build.** `npm run build` works; nothing serves the output.
- **Durable job state in the analysis engine.** In-process dict with TTL eviction, pinned to one worker for that reason.
- **Negative caching for threat intelligence.** Unknown indicators are re-queried on every run.
- **Discriminative VIDE baseline fingerprints.** All ten shipped baselines carry identical fingerprints and colliding palettes, so attribution rests on the bank name alone.

---

The active codebase is the source of truth. Where this document and the code disagree, the code is correct.
