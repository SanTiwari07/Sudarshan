# Documentation audit log

Record of documentation synchronization passes against the SUDARSHAN codebase. Newest first. Earlier entries are kept as history and are not rewritten.

---

## 2026-08-27 — Full documentation synchronization

```yaml
Scope:                   Every Markdown file outside node_modules and the CyberSecurity Bible
Backend app version:     2.1.0   (backend/app/main.py)
Analysis engine version: 2.3.0   (analysis-engine/app/main.py)
Test suite metric:       2,622 collected, no collection errors
                         (PYTHONPATH="backend;shared" pytest tests/ backend/tests --collect-only)
Continuous integration:  none - no .github/ directory exists in this repository
Method:                  Route decorators, engine constants, Compose definitions and
                         package manifests read directly; every claim traced to a file
```

### Corrected

| Area | Was | Is |
| :--- | :--- | :--- |
| Test count | 920 collected, 525 enforced by CI | 2,622 collected, none enforced — there is no CI workflow |
| CI pipeline | `.github/workflows/ci.yml` gating `backend/tests` | No `.github/` directory exists. Only `.githooks/pre-push`, which checks commit attribution |
| Backend route count | 51 routes, 18 undocumented | 81 route decorators, all documented |
| Report export paths | `/api/v1/report/{sha256}/pdf` | `/api/v1/report/pdf/{sha256}` — format precedes the hash |
| Threat intelligence routes | `/api/v1/intel/correlate`, `/cache/stats`, `/cache/clear`, `/live-threats` | None of these exist. One route: `GET /api/v1/intelligence/{sha256}` |
| Discovery routes | `/discovery/crawl`, `/discovery/sessions`, `/discovery/ingest/{id}` | `/discovery/start`, `/discovery/{session_id}/status`, `/{session_id}/results`, `/{session_id}/analyze` |
| Analyst chat | `POST /api/v1/cases/{sha256}/chat` | `POST /api/v1/chat` and `/chat/stream` |
| Login | `OAuth2PasswordRequestForm` | JSON body (`LoginRequest`) |
| Engine routes | `/api/v1/analyze-path`, `/api/v1/job/{job_id}` | `/api/v1/analyze`, `/analyze/upload`, `/analyze/async`, `/status/{job_id}` |
| Non-existent routes removed | `/auth/registration-policy`, `DELETE /cases/{sha256}`, `/report/{sha256}/json`, `POST /api/events` | Removed from documentation |
| Registration policy variable | `ALLOW_PUBLIC_REGISTRATION` | `SUDARSHAN_ALLOW_REGISTRATION` |
| BFCI model | Six categories | Seven — `code_execution` at 0.10, the original six scaled by 0.90 |
| Sequence bonus | `+15` points | `×1.25` multiplier within a 30-second window |
| VIDE colour metric | Delta-E CIE76 | CIEDE2000 (`delta_e_2000` in `color_match.py`) |
| Screen classifier | 17 semantic types | 21 |
| Launch ladder | 7 steps | 5 (`launch_method_used` in `frida_sandbox.py`) |
| YARA | "Zero rules deployed, silent no-op" | 8 rules across 2 files in `engines/yara_rules/` |
| VIDE signer registry | 3 sample banks | 12 packages with deliberately empty, fail-closed allowlists |
| VIDE baselines | 3 demo baselines | 10 lab baselines in-repo, plus an external corpus via `BANKING_BASELINE_CORPUS_DIR` |
| mitmproxy port | `127.0.0.1:8080` | `127.0.0.1:${MITMPROXY_PORT:-8085}` → container `8080` |
| `FRIDA_ANALYSIS_DURATION` | 30 s, later 300 s | 240 s in `docker-compose.yml` |
| Frontend component | `WorkflowDiagram.tsx` | Removed; the timeline is `investigation/AttackStory.tsx` |
| Absolute filesystem links | 149 `file:///d:/Projects/Sudarshan%20BOI/...` links across 13 files | Repository-relative paths |

### Rewritten

Root `README.md`; `docs/README.md` portal; `docs/api/ENDPOINTS.md`; `docs/FEATURE_STATUS.md`; `docs/KNOWN_LIMITATIONS.md`; `docs/CODEBASE_MAP.md`; `docs/HOW_TO_RUN.md`; `docs/CONTRIBUTING.md`; `docs/FEATURE_AUDIT.md`; `docs/BOI_DEMO_CREDENTIALS.md`; `backend/README_FRIDA.md`; `tests/apks/README.md`; and the root audit set — `ARCHITECTURE_DRIFT_REPORT.md`, `CURRENT_STATE.md`, `VERIFICATION_STATUS.md`, `BUGS_AND_IMPROVEMENTS.md`.

### Created

Component READMEs that did not previously exist: `backend/README.md`, `analysis-engine/README.md`, `shared/README.md`, `frontend/README.md`, `scripts/README.md`, `tests/README.md`.

### Removed

- Invented metrics: the "Project Health Score 7.75 / 10" and its twelve unmethodised component scores in `CURRENT_STATE.md`.
- Emoji: status glyphs in `docs/DAE_CURRENT_STATE.md`, `docs/01_INTRODUCTION.md` and `researchcompetition.md`.
- Duplicated route tables in `docs/CODEBASE_MAP.md`, which had drifted from both the code and `api/ENDPOINTS.md`.

### Documented, not fixed

Code issues found during the audit and recorded rather than changed — see [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) §7 and [`../BUGS_AND_IMPROVEMENTS.md`](../BUGS_AND_IMPROVEMENTS.md):

- `/api/v1/report/technical-pdf/{sha256}` declares `response_class=HTMLResponse` but returns `application/pdf`.
- `ANALYSIS_TIMEOUT_SECONDS` defaults to 600 in the gateway and 300 in the engine, with Compose setting 1200 for both.
- `demo_seed.py` falls back to hardcoded default passwords when `DEMO_*_PASSWORD` is unset.
- `_otx_check_hash` bypasses the IOC cache that every other lookup in that module uses.
- `sources_queried.append("AbuseIPDB")` sits inside the per-IP loop, so a configured key with no IPs triggers endless re-correlation.
- `SSRFSafeAsyncClient.send` validates the resolved address then hands the hostname to the transport, which re-resolves it.
- Runtime telemetry routes authenticate but do not scope to the requesting analyst.
- `ScreenshotManager` decrements its ID counter on duplicate suppression and reuses a millisecond-stamped device path.
- `scripts/validate_corpus.py` emits references to `audit/DETECTION_VALIDATION.md` into `docs/evaluation/CORPUS_STATIC_VALIDATION.md`; that directory does not exist in this repository. The generated file is marked "do not edit", so it was left untouched and the defect recorded against the generator.

### Not modified

No application source, test, configuration, Dockerfile, Compose file, shell or PowerShell script, dependency manifest or `.env` file was changed in this pass.

---

## 2026-08-25 — Portal construction

```yaml
Auditor:          Antigravity AI codebase auditor
Platform version: v2.1.0
Method:           Multi-layer codebase audit across backend, analysis engine, core, frontend, tests, database, configuration
```

Created four foundational documents — `CURRENT_ARCHITECTURE.md`, `CODEBASE_MAP.md`, `FEATURE_STATUS.md` and `KNOWN_LIMITATIONS.md` — refreshed the eight subsystem architecture documents and `VIDE.md`, updated `api/ENDPOINTS.md`, and rebuilt portal navigation across `README.md`, `01_INTRODUCTION.md`, `02_SYSTEM_OVERVIEW.md`, `HOW_TO_RUN.md` and `dashboard/10_DASHBOARD.md`.

The 2026-08-27 pass superseded several claims from this one; they are listed in the correction table above.

### Architectural reality recorded at that time

| Subsystem | Recorded state |
| :--- | :--- |
| Gateway and microservice | Gateway on port 8000; analysis engine on 8001 with `MAX_CONCURRENT_ANALYSES=2`, sharing `/app/uploads` |
| Persistence | Direct async SQL via `aiosqlite`, WAL mode, no SQLAlchemy; raw payloads in `cases.raw_result` |
| Authentication | JWT bearer with `analyst`, `soc_lead`, `admin` |
| Static decompilation | `apk_analyzer.py`, `apk_repair.py`, APKTool 2.10.0, JADX 1.5.1, optional MobSF |
| Dynamic sandbox | `SandboxProvider` over Genymotion or AVD; exact PID attach; compiled `banking_trojan.bundle.js`; ART deoptimization |
| UI exploration | Five-level perception priority, semantic screen classification, action dispatch, post-action verification |
| Scoring | Five-axis STEI, logarithmic BFCI v2, four-axis FRS with renormalisation, CH27 triad, four safety floors |
| VIDE | Structural AST 0.35, brand string containment 0.40, colour 0.25, plus signer registry |
| AI | `GeminiProviderManager` with `AVAILABLE` / `DEGRADED` / `OPEN` circuit states, primary-to-fallback failover, 60 s cooldown, 2048-token budget |
| Batch scanning | FIFO `batch_worker.py` with pause, resume, cancel and retry |
| Reporting | ReportLab PDF, standalone HTML, STIX 2.1, CSV IOC feeds |
| Frontend | React 18 SPA with Vite and Tailwind |
