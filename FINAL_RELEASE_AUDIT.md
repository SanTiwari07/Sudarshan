# SUDARSHAN — Final Release Audit

Audit date: 2026-09-26 · Branch: `main` (base commit `6d3e943`) · Method: source, configuration, test suites, a live Docker stack and a live Android emulator (`emulator-5554`, API 37, x86_64) were treated as ground truth. Earlier audit documents were not trusted.

## 1. Executive Summary

**Final status: NOT PRODUCTION READY** (see §16).

The application builds, starts, authenticates, analyses APKs end-to-end (static + live Frida dynamic run on an emulator + threat intel + VIDE + reports) and the full test suites pass. The audit found and fixed **24 defects**, including five security issues (SSRF via redirect, WebSocket auth bypass for revoked sessions, a hardened Compose overlay that silently kept writable host bind-mounts, hardcoded credentials, Postgres published to the LAN with a default password), a crash that killed UI exploration on the first screen of every dynamic run, a Postgres-only 500 on a case endpoint, broken HTTPS URL discovery, and UI panels that displayed fabricated risk percentages.

Blocking items that remain: a real admin password is in public Git history (must be rotated), the VIDE engine still produces a High-Risk false positive on at least one benign app, the CH06 signer registry has zero provisioned fingerprints (so a genuine bank app would score ≥ 92), and there is no GCP deployment artefact at all.

**Major cleanup:** 466 files removed from version control (41 dead scripts/probes/ad-hoc tests, 342 tracked validation-run outputs, 82 Gradle build-cache files, an AI chat transcript in `frontend/src`); 69 broken documentation links repaired; corrupt encodings repaired in `.env.example`, `sudarshan_core/config/__init__.py` and three UI components.

**Deployment status:** local Docker deployment verified working. GCP: not deployable as-is (no manifests; dynamic analysis requires nested-virtualisation / external device infrastructure).

## 2. Repository Cleanup

| File/Directory | Action | Reason |
|---|---|---|
| `analysis-engine/restart_frida.py`, `restart_frida_no_l.py` | Deleted | Hand-run `os.system("adb shell …")` probes; zero references except a README note (updated). Shipped into the engine image. |
| `analysis-engine/corpus_report.py`, `corpus_run.sh` | Deleted | One-off corpus harness; zero references. |
| `backend/test_{dedup,dyn,idempotency,perf,pool_load,postgres_regression,sqlite_regression,transaction,vide_all}.py` | Deleted | Ad-hoc scripts outside `testpaths` (never collected, never in CI), hardcoded `d:/Sudarshan` paths. |
| `backend/dynamic_result.json` | Deleted | Captured run output; only mentioned in a code comment. |
| `backend/app/engines/frida_hooks/package-lock.json` | Deleted | Orphan: `backend/app/engines/` contains nothing else. |
| `frontend/update_surfaces.cjs`, `.py` | Deleted | One-off codemods with an absolute `c:\Projects` path. |
| `frontend/src/REDESIGN_SUMMARY.md` | Deleted | AI chat transcript ("I have completely redesigned…") inside the source tree. |
| `scripts/` — `bisect_sections`, `bisect_spawn_hooks`, `test_bridge_spawn`, `test_frida_stages`, `test_hypothesis`, `test_inithooks_blocks`, `test_native_vs_java`, `test_no_spawn_run`, `test_schedule_main`, `test_spawn_loadurl`, `test_webview_trigger`, `extract_apk`, `extract_axml`, `get_axml_strings`, `get_dex_strings`, `list_hooks`, `scan`, `generate_audit` | Deleted | Device-bisection experiments / string dumps with hardcoded `emulator-5554` + `com.baseline.sbi`; zero references in code, docs, CI, Docker or `scripts/README.md`. |
| `scripts/run_e2e_pipeline.py`, `scripts/test_api_vide.py` | Deleted | Contained the **real admin password** in plain text; also pointed at wrong ports/paths. |
| `shared/sudarshan_core/engines/frida_hooks/bisect_sec*.js`, `bisect_temp*.js` | Deleted | Bisection copies of the agent used only by the deleted bisect scripts; the runtime loads `banking_trojan.bundle.js`. |
| `banking-baseline-corpus-main/` (82 files) | Untracked + ignored | 100 % Gradle `.gradle/` caches; the corpus loader looks for `banking-baseline-corpus/` (no `-main`). |
| `*/validation_runs/` (342 files across `Test APK/`, `tests/apks/`, `tests/fixtures/apks/`) | Untracked + ignored | Timestamped run logs/JSON; `.gitignore` already listed one copy; no code reference. Local copies kept. |
| `.dockerignore` | Rewritten | Old file used lowercase `test apk/` (case-sensitive miss) and let `backend/sudarshan.db`, uploads, artifacts and APKs be baked into the backend image. |
| `frontend/.dockerignore` | Added | `COPY . .` copied host (Windows) `node_modules` over the Linux install. |
| `.gitignore` | Updated | `**/validation_runs/`, `**/.gradle/`. |

Kept deliberately: `Test APK/`, `tests/apks/`, `tests/fixtures/` (the three trees share identical Git blobs, so they cost no repository size; tests and scripts resolve all three), `docs/99_HISTORY/` (clearly historical), `scripts/verify_*` harnesses (feature verification tools).

## 3. Bugs Found and Fixed

| Bug | Root Cause | File | Fix | Test |
|---|---|---|---|---|
| UI exploration died on the first screen of every dynamic run with screenshots (`Fatal loop error: 'str' object has no attribute 'value'`) — observed live | `ScreenType` is a plain str-constants class; code called `ScreenType.UNKNOWN.value` | `shared/…/engines/agentic_explorer.py` | Pass `ScreenType.UNKNOWN`; log traceback on fatal loop errors | `tests/unit/test_plain_constant_value_access.py` (AST guard over whole codebase) + live emulator run |
| **SSRF**: URL discovery followed a public 302 to `127.0.0.1` / `169.254.169.254` (verified live) | Check lived in `AsyncClient.send()`, which httpx does not re-enter for redirects | `backend/app/services/discovery/security.py` | Validation + IP pinning moved into a transport, so every hop is checked | `backend/tests/test_discovery_ssrf_redirect.py` |
| URL discovery failed for every HTTPS site (`SSLV3_ALERT_HANDSHAKE_FAILURE`, verified live) | Host rewritten to the pinned IP, so SNI/cert check used the IP | same | `sni_hostname` extension keeps the real hostname for TLS | same |
| Revoked/logged-out/disabled tokens could still open the live-events WebSocket | Handshake only verified the JWT signature | `backend/app/auth/auth.py`, `routes/resilience.py` | Extracted `authenticate_token()` (session, revocation, active checks) and used it for the WebSocket | `backend/tests/test_ws_session_auth.py` |
| Hardened overlay kept `./backend:/app`, `./analysis-engine:/app`, `./shared` **writable** and mounted host `~/.android` into the malware container | Compose merges volume lists by target; overlay could not remove them | `docker-compose.hardened.yml` | `volumes: !override`; re-added VIDE read-only; named volume for Frida cache | `docker compose … config` inspected |
| Hardened overlay was invalid (`security_opt items at 0 and 1 are equal`) | `no-new-privileges` duplicated across base + overlay | same | Removed duplicate | `docker compose -f … -f docker-compose.hardened.yml config -q` passes |
| Postgres published on `0.0.0.0:5432` with password `sudarshan`; backend could race Postgres at startup | Hardcoded compose values; missing `depends_on` | `docker-compose.yml` | `POSTGRES_PASSWORD` required, loopback bind, `depends_on: service_healthy` | Stack restarted; port now `127.0.0.1:5432` |
| MobSF key had a published default in Compose | `${MOBSF_API_KEY:-sudarshan_mobsf_api_key_2026}` | `docker-compose.yml` | Now required (`:?`) | compose config |
| Demo accounts seeded with published default passwords (incl. an admin alias) | Defaults in `demo_seed.py` | `backend/app/demo_seed.py`, `.env.example` | No defaults; refused when `SUDARSHAN_ENV=production` | `backend/tests/test_demo_seed.py` (2 new tests) |
| Hardcoded passwords in scripts | Literal credentials | `scripts/e2e_visual_evidence_validate.py` (+2 deleted scripts) | Read from env | — |
| `GET /cases/{sha}/iocs` → 500 on PostgreSQL (verified live) | `HAVING case_count …` alias is SQLite-only | `backend/app/db/intel.py` | Repeat the aggregate | Live endpoint 200 after fix |
| `.env` overrode Compose/CI/test environment at runtime | `load_dotenv(override=True)` on first API-key lookup | `shared/…/services/threat_correlator.py` | `override=False` | `tests/unit/test_correlator_env_precedence.py` |
| Every analysis re-queried VT/OTX/AbuseIPDB (incl. cached-404s) | Persistent IOC cache is only injected in the backend; correlation actually runs in the engine | same | In-process 24 h TTL cache fallback | `tests/unit/test_correlator_memory_cache.py` |
| Whole sentences sent to VirusTotal as "URLs" (observed in engine logs) | Analyzer stores the full string containing a URL | same | Extract the URL/IP token before any lookup (scoring input unchanged) | same file |
| Benign calculator scored 64 "High Risk" — part 1: Android `#AARRGGBB` colours parsed as CSS `#RRGGBBAA` (`#FF6200EE` purple → orange) | Wrong channel order | `shared/…/vide/layout_extractor.py` | `android_color_to_rgb_hex()` at the Android source | `tests/unit/test_vide_false_positive_regressions.py` |
| Same false positive — part 2: a bare `"6"` "reproduced" `"Enter 6-Digit MPIN"` at ratio 100 | Token-set ratio scores subsets at 100 | `shared/…/vide/fuzzy.py` | Candidates without a word cannot match a label | same |
| Threat-correlation panel showed invented risk contributions (+12.5/15/25/30 %) and a synthetic `EV-VIDE-01` record as "deterministic" | Hardcoded fallbacks in the UI | `frontend/…/ThreatCorrelationPanel.tsx` | Show only engine-attributed contributions; "Not scored" otherwise | `ThreatCorrelationPanel.test.tsx` |
| React crash risk ("Rendered more hooks…") in the AI investigation page | Hooks called after an early return (13 lint errors) | `frontend/src/pages/InvestigationChat.tsx` | Null check moved to a wrapper component | eslint `rules-of-hooks` clean |
| Logout could leave the browser signed in | `fetch(...).catch` ran before local state was cleared | `frontend/src/context/AuthContext.tsx` | Clear first, then best-effort revoke | `AuthFlowMatrix` tests 13/14/20 |
| U+FFFD mojibake rendered in the UI (`3 � 1 dangerous`, lost `…`, `Δ`, quotes) | Encoding corruption | `VerdictBlock.tsx`, `OverlayEvidenceViewer.tsx`, `VisualDiffViewer.tsx` | Restored from commit `34300a1` | `VerdictBlock.test.tsx` |
| `sudarshan_core.config` unimportable | `__init__.py` saved as UTF-16 | `shared/sudarshan_core/config/__init__.py` | Empty UTF-8 file | AST/UTF-8 guard test |
| `.env.example` tail unreadable (`ARTIFACT_STORAGE` section) | Appended as UTF-16 | `.env.example` | Re-encoded; documented new variables | — |
| Batch tasks could be garbage-collected mid-run and were not cancelled on shutdown | Bare `asyncio.create_task` | `backend/app/workers/batch_worker.py` | Strong task set + cancel on shutdown | batch tests (9) |
| Test suite wrote into the developer DB (`data/sudarshan.db`), used real API keys, and left `test_artifact_pytest.apk` in the repo root; 4 tests were order/device dependent | No isolation | `conftest.py` (new), `test_url_ingestion.py`, `test_device_channel.py`, `test_blocker_fixes.py`, `test_vide_semantic_matcher.py`, `test_multinode_*` | Temp DB per session, blanked provider keys, in-memory fixture, hermetic patches | Full suite 0 failures |
| Misleading startup log "Initialized SQLite" while running on Postgres | Log ignored `is_postgres()` | `backend/app/db/database.py` | Correct label | live logs |
| Silent detection-signal failures | `except Exception: pass` | `apk_analyzer.py` (accessibility), `upload.py` (dropped MobSF findings) | Logged | — |
| Internal token compared with `!=` | Non-constant-time | `analysis-engine/app/main.py` | `hmac.compare_digest` | — |
| `ARTIFACT_STORAGE=gcs` would crash with a bare ImportError | `google-cloud-storage` not in any requirements | `shared/…/storage/artifact_storage.py` | Clear RuntimeError explaining the missing dependency | — |
| 21 stale/broken frontend tests (wrong `App` import, mojibake placeholder, old aria-label, stale kind list) | Test drift | `frontend/src/test/AuthFlowMatrix.test.tsx`, `caseQuestions.test.ts` | Updated | 250/250 pass |
| CI never ran frontend lint or the 250 vitest tests | Workflow drift | `.github/workflows/static_ci.yml` | Added `npm run lint`, `npm test` | — |

## 4. Bugs Found but Not Fixed

| Issue | Severity | Reason | Required Follow-up |
|---|---|---|---|
| Real admin password committed in 4 historical commits (public GitHub remote) | **Critical** | Removed from the working tree; history rewrite on a shared remote is destructive and needs owner coordination | **Rotate the admin password now.** Then optionally purge with `git filter-repo --replace-text` and force-push after all collaborators agree. |
| CH06 signer registry has 0 fingerprints for all 12 protected packages → any APK with a bank package name (incl. the genuine app) is "impersonation" and floored to FRS ≥ 92 | High | Explicit, tested team decision ("an empty allowlist is a decision"); changing it alters deterministic scoring | Provision real release-certificate SHA-256s from Play Store builds, or decide to treat unprovisioned entries as "undetermined". |
| VIDE still flags benign Fossify Calculator at moderate confidence (0.38) from colour palette + generic structure with **0/19** text labels; the risk engine floors any VIDE detection at FRS 55 | High | Calibration/threshold change to a deterministic escalation; needs a labelled benign corpus to tune safely | Require text corroboration (or a higher threshold) for palette-only detections; re-validate on benign corpus. |
| Spawn-gated Frida launch fails for legacy-targetSdk samples on the API 37 AVD (InsecureBankv2) → honest `INSTRUMENTED_TOO_LATE`, dynamic axis excluded | Medium | Frida instrumentation changes need device work (AGENTS.md rule 6) | Investigate permission-review screen during spawn on API ≥ 34. |
| `backend/tests/test_agentic_explorer.py:201` skipped as "Broken by frida_hooks changes" | Medium | Pre-existing known-broken test | Repair or delete with justification. |
| STIX / IOC-CSV / YARA / Snort / Suricata / MITRE exports have no frontend entry point (backend endpoints work) | Low | Feature gap, not a defect | Add export buttons if analysts need them. |
| `frontend` container runs the Vite **dev server**; no production static build/serve image | Medium | Deployment design gap | Add a multi-stage build (nginx) for production. |
| `laya` optional profile image builds PyTorch from the network; not built/verified | Low | Optional profile | Verify before enabling. |
| 97 ESLint `no-explicit-any` warnings; main JS chunk > 500 kB | Low | Cosmetic | Code-split and type progressively. |
| 160 environment variables are read by the code but not in `.env.example` | Low | Nearly all are tuning knobs with safe defaults | Generate a reference table. |

## 5. Feature Verification

| Feature | Backend | Frontend | Test | Runtime | Status |
|---|---|---|---|---|---|
| Authentication / JWT sessions / logout revocation | PASS | PASS | PASS | PASS (login 200, `/me` 401 after logout) | PASS |
| RBAC (analyst / soc_lead / admin) | PASS | PASS | PASS | PASS (unauthenticated `/cases` → 401) | PASS |
| APK upload + async job queue | PASS | PASS | PASS | PASS (202 → `done`) | PASS |
| Static analysis (Androguard/APKTool/JADX/MobSF) | PASS | PASS | PASS | PASS | PASS |
| Dynamic analysis (ADB, Frida 17.16.4, hooks, canary, explorer) | PASS | PASS | PASS | PASS on emulator (`EVENTS_CAPTURED` for Fossify; honest `INSTRUMENTED_TOO_LATE`/`CRASHED_BEFORE_EXPLORATION` elsewhere) | PARTIAL (spawn-gating limitation) |
| Dynamic failure semantics (no events ≠ safe) | PASS | PASS | PASS | PASS | PASS |
| Threat intelligence (VT/OTX/AbuseIPDB + cache) | PASS | PASS | PASS | PASS (live 404s cached) | PASS |
| VIDE visual impersonation | PARTIAL | PASS | PASS | FAIL (benign app flagged) | PARTIAL |
| CH06 signer check | PARTIAL | PASS | PASS | not run on a genuine bank APK | PARTIAL (no fingerprints) |
| Risk engine (STEI/BFCI/FRS, floors) | PASS | PASS | PASS | PASS | PASS |
| AI / Gemini (RAG chat, failover, sanitisation) | PASS | PASS | PASS (mocked) | RAG index built live; chat not exercised with a live key | PARTIAL |
| Reports: HTML, PDF, STIX, IOC CSV, MITRE, YARA | PASS | PDF only | PASS | PASS (all 200) | PASS |
| Case history / notes / evidence / IOCs | PASS | PASS | PASS | PASS (after Postgres fix) | PASS |
| Screenshots manifest/images | PASS | PASS | PASS | PASS | PASS |
| Batch scanning | PASS | PASS | PASS | not run live | PARTIAL |
| URL discovery | PASS | PASS | PASS | PASS (HTTPS now works, SSRF blocked) | PASS |
| Runtime telemetry API | PASS | PASS | PASS | PASS | PASS |
| Resilience (time-warp, personas, WS stream) | PASS | PASS | PASS | not run live | PARTIAL |

## 6. API Verification

All 80 routes were enumerated from the live FastAPI app. Every route except `GET /`, `GET /health`, `POST /api/v1/auth/login`, `POST /api/v1/auth/register` requires a session-backed bearer token; 70 of them additionally enforce a role. The WebSocket requires a valid session (fixed). Registration is closed by default in production.

| Endpoint | Method | Auth | Tested | Result |
|---|---|---|---|---|
| `/health`, `/` | GET | none | live | 200 |
| `/api/v1/auth/login`, `/logout`, `/me` | POST/POST/GET | none / bearer | live | 200 / 200 / 200→401 after logout |
| `/api/v1/auth/register`, `/users/*`, `/sessions`, `/logout-all` | various | none (policy) / admin / bearer | pytest | PASS |
| `/api/v1/analyze`, `/analyze/async`, `/status/{job}`, `/analyze/cancel/{job}` | POST/POST/GET/POST | analyst | live + pytest | 202 / done |
| `/api/v1/sandbox/status`, `/sandbox/debug/{id}` | GET | analyst | pytest | PASS |
| `/api/v1/cases`, `/cases/{sha}`, `/notes`, `/status`, `/verdict`, `/assign` | GET/PATCH/POST | analyst+ | live + pytest | 200 |
| `/api/v1/cases/{sha}/iocs` | GET | analyst | live | **500 on Postgres → fixed → 200** |
| `/api/v1/cases/{sha}/evidence` | GET | analyst | live | 200 |
| `/api/v1/report/{html,pdf,stix,iocs,iocs-txt,yara,suricata,snort,mitre,technical-pdf}/{sha}` | GET | analyst | live (6) + pytest | 200 |
| `/api/v1/intelligence/{sha}` | GET | analyst | live | 200 |
| `/api/v1/chat`, `/chat/stream`, `/chat/history/{sha}`, `/explain/artifact` | POST/GET/DELETE | analyst | pytest (mocked AI) | PASS |
| `/api/v1/screenshots/{sha}/manifest`, `/{filename}` | GET | analyst | live + pytest (traversal) | 200 |
| `/api/v1/batches*`, `/batch-jobs/{id}/retry` | various | analyst/soc_lead | pytest | PASS |
| `/api/v1/discovery/*` | various | analyst | pytest + live SSRF probe | PASS |
| `/api/v1/baselines*` | GET/POST | analyst/admin | pytest | PASS |
| `/api/v1/analysis/{session}/*` (+ `/events/ws`) | various | analyst | pytest | PASS |
| `/api/runtime/*` (8 routes) | GET | bearer | live (`/health`) + pytest | 200 |
| `/api/v1/audit/*` | GET | soc_lead/admin | pytest | PASS |
| Analysis engine `/api/v1/analyze` (internal) | POST | internal token (mandatory in production) | live via backend | 200 |

## 7. Security Audit

| Finding | Severity | Status |
|---|---|---|
| Real admin password in Git history (public remote) | Critical | Working tree cleaned; **rotation required** |
| SSRF through redirects in URL discovery | High | Fixed + tests |
| Hardened overlay kept writable host bind-mounts and host `~/.android` in the malware container | High | Fixed |
| WebSocket accepted revoked/disabled sessions | Medium | Fixed + tests |
| Postgres on `0.0.0.0:5432` with default password | Medium | Fixed (loopback + required secret) |
| Published default MobSF key and demo passwords | Medium | Removed |
| `.env` silently overriding runtime environment (could undo `SUDARSHAN_ENV=production` etc.) | Medium | Fixed |
| Non-constant-time internal token compare | Low | Fixed |
| Path traversal on screenshots | — | Verified safe (name check, resolve containment, case authorisation) |
| `shell=True` / `os.system` in runtime code | — | None remain (two occurrences were in deleted scripts) |
| CORS | — | Explicit allow-list, no wildcard with credentials |
| AI boundary | — | APK strings sanitised before prompts; AI output never feeds FRS/BFCI/STEI (`ai_confidence` is a deterministic family multiplier despite its name) |
| Registration | — | Closed by default in production |
| Backend port 8000 / frontend 5173 bound to all interfaces in the dev compose file | Low | Acceptable for dev; production needs a reverse proxy/TLS |

## 8. Hardcoded Configuration Audit

Remaining intentional hardcoded values:

- **Frida 17.16.4 / frida-tools 14.10.4, APKTool 2.10.0, JADX 1.5.1** — pinned in Dockerfiles for reproducibility; Frida must match the device-side server.
- **Ports 8000 / 8001 / 5173 / 27055 / 8085 / 8008 / 5432** — service contract inside Compose; host bindings are overridable (`MITMPROXY_PORT`) or loopback-only.
- **Service DNS names** (`analysis-engine`, `mobsf`, `postgres`) — Compose network names; `ANALYSIS_ENGINE_URL`, `MOBSF_HOST`, `DATABASE_URL` override them.
- **`http://localhost:8000/api/v1` frontend fallback** — used only when `VITE_API_URL` is unset (Compose sets it).
- **Default CORS origins `localhost:5173`** — dev default; `CORS_ALLOW_ORIGINS` overrides.
- **Scoring weights** (STEI 0.60/0.20/0.10/0.05/0.05, FRS 0.25/0.35/0.20/0.20, VIDE 0.40/0.35/0.25, IOC TTL 24 h) — algorithmic constants of the deterministic engine; the UI labels were verified to match.
- **Gemini model defaults** (`gemini-2.5-flash`) — overridable via `GEMINI_*_MODEL`.
- **Postgres user/db name `sudarshan`** — non-secret identifiers; the password is now required config.
- **`ADMIN_USERNAME` default `admin`** — username only; password is random-generated if unset.

## 9. Secrets Audit

- `.env` and `.sudarshan_sandbox.env` have **never** been committed.
- Every secret value in the local `.env` was searched in all commits (values never printed): JWT secret, Gemini keys, VT/OTX/AbuseIPDB keys — **not found**. The **admin password was found in 2 tracked files and 4 historical commits** → files removed; **rotation required**. The MobSF key in `.env` equals the formerly published Compose default → **change it**.
- An older admin password (`scripts/e2e_visual_evidence_validate.py`) and demo passwords were removed from the tree; they remain in history — do not reuse them.
- Pattern scans (Google API keys, private keys, GitHub tokens, `sk-` keys) found only a fake key in a unit test.
- `POSTGRES_PASSWORD=sudarshan` was appended to the **local, untracked** `.env` only so the existing `sudarshan_pgdata` volume keeps working; rotate it with `ALTER USER`.

## 10. Git Audit

- Branch `main`, remote `origin` = `github.com/SanTiwari07/Sudarshan`; other remote branches: `development`, `db/persistence-layer`, `feature/genymotion-migration`, `harden-dynamic-analysis`.
- **AI attribution:** no `Co-authored-by` AI identities or "Generated with…" trailers in any commit; the Cursor co-author was already remapped via `.mailmap`. One AI chat transcript file was found in the tree and removed.
- Commit hygiene: several vague messages exist (`made changes`, `Repo cleanup`, `fixed UI and Pdf`); cosmetic, **no history rewrite recommended** for them.
- **History rewrite is required only for the leaked admin password**, and only after rotation and team agreement (force-push affects all clones). Not performed.
- Working tree: this audit's changes are committed locally in one commit; **not pushed**.

## 11. Test Results

Measured on this machine (Python 3.11.9, Node 24):

| Suite | Collected | Passed | Failed | Skipped | Errors | Duration |
|---|---|---|---|---|---|---|
| pytest — baseline before audit | 2841 | 2809 | **5** | 27 | 0 | 345 s |
| pytest — final (incl. live-emulator integration test) | 2860 | 2833 | 0 | 27 | 0 | 650 s |
| vitest — baseline | 248 | 225 | **23** | 0 | 0 | 5 s |
| vitest — final | 250 | 250 | 0 | 0 | 0 | ~6 s |

- Frontend `npm run build`: PASS (chunk-size warning only). `tsc --noEmit`: PASS. `npm run lint`: 0 errors (was 17), 97 warnings.
- Skips: 13 `rapidfuzz` not installed in the local venv (it is installed in the images), 13 reference bank APKs not present, 1 missing script, 1 known-broken explorer test (see §4), 1 missing fixture.
- CI drift: CI runs `tests/unit` + `backend/tests` (not `tests/integration`, which needs a device) and — before this audit — no frontend lint or unit tests.

## 12. Docker Verification

- `docker compose config`: PASS. Hardened overlay (`-f docker-compose.yml -f docker-compose.hardened.yml config`): **was FAIL**, now PASS; merged volumes verified to contain no host source mounts.
- Fresh-clone check with an empty `.env`: Compose stops with a clear message (`POSTGRES_PASSWORD must be set…`), as for `JWT_SECRET_KEY`.
- `docker compose build`: backend, analysis-engine, frontend built. `laya` (optional profile) not built.
- `docker compose up -d`: all 6 services up; `analysis-engine` and `postgres`, `mobsf` healthy; backend waits for Postgres now.
- Health: backend `/health` 200, engine `/health` 200, frontend 200.

## 13. Local Deployment Verification

Tested against the running Compose stack (PostgreSQL backend) with the host emulator reachable over ADB:

1. Frontend served (200); backend and engine health 200.
2. Login with the configured admin (200); unauthenticated `/cases` 401.
3. Upload of *Fossify Calculator* via `/analyze/async` → job `done`; case stored in Postgres.
4. Pipeline: static (APKTool/Androguard/MobSF) → live Frida dynamic run (`EVENTS_CAPTURED`, BFCI 6.3) → VT/OTX correlation → VIDE → risk engine → RAG index.
5. Reports: HTML, PDF, STIX, IOC CSV, MITRE, YARA — all 200 with content; intel, IOCs, evidence, screenshot manifest, runtime health — 200.
6. Logout revoked the session (`/me` 401).
7. A malware sample (Cerberus) returned from a prior analysis: verdict *Suspicious*, dynamic `CRASHED_BEFORE_EXPLORATION` (correctly inconclusive).

Not tested live: batch scanning UI, Gemini chat with a live key, Genymotion provider, the hardened overlay at runtime (config only).

## 14. GCP Deployment Readiness

No GCP artefact exists in the repository (no Cloud Build, Cloud Run, GKE, Terraform). The only GCP code is an optional GCS artifact store whose dependency is not installed.

| Subsystem | Status | Requirement |
|---|---|---|
| Frontend | GCP READY WITH CONFIGURATION | Replace Vite dev server with a static build (Cloud Storage/CDN or nginx on Cloud Run); set `VITE_API_URL` at build time |
| Backend API | GCP READY WITH CONFIGURATION | Cloud Run/GKE; secrets in Secret Manager; `CORS_ALLOW_ORIGINS`; HTTPS LB; WebSocket timeout ≥ analysis length; in-process workers need min-instances ≥ 1 (no scale-to-zero) |
| Database | GCP READY WITH CONFIGURATION | Cloud SQL for PostgreSQL via `DATABASE_URL`; do **not** use SQLite on Cloud Run (ephemeral FS) |
| Artifact storage | GCP REQUIRES INFRASTRUCTURE | Add `google-cloud-storage` to both images, create bucket, `ARTIFACT_STORAGE=gcs`; shared `uploads` volume has no Cloud Run equivalent |
| Analysis engine (static) | GCP READY WITH CONFIGURATION | GKE or Compute Engine (2 vCPU / ≥4 GB, Java 17); single worker (`--workers 1`, in-memory job table) |
| Dynamic sandbox (AVD/Genymotion + ADB + Frida) | GCP REQUIRES INFRASTRUCTURE | Compute Engine VM with nested virtualisation (or Genymotion Cloud / physical device farm), rooted image, private network only; ADB is reached via `ADB_SERVER_SOCKET` — cannot run on Cloud Run |
| MobSF | GCP REQUIRES INFRASTRUCTURE | Separate VM/GKE service with persistent disk (3.5 GB image) |
| mitmproxy | GCP REQUIRES INFRASTRUCTURE | Must sit on the sandbox's network path; co-locate with the emulator host |
| AI (Gemini) / threat intel | GCP READY | Keys via Secret Manager |

## 15. Known Limitations

- VIDE can flag benign apps with bank-like palettes; any VIDE detection floors FRS at 55.
- CH06 cannot verify any genuine bank app until fingerprints are provisioned; genuine apps would be scored critical.
- Dynamic analysis requires a rooted emulator/device and host ADB; spawn-gating fails for some legacy apps on API 37, in which case the dynamic axis is excluded (reported as `INSTRUMENTED_TOO_LATE`, never as clean).
- The analysis engine keeps its job table in memory — one worker, one node.
- The Compose frontend is a development server.
- `ai_confidence` is a deterministic multiplier, not an AI output — the name is misleading.
- `Test APK/`, `tests/apks/` and `tests/fixtures/` hold duplicate copies of the corpus (same blobs).
- Several code paths reference `test apk/` (lowercase), which only resolves on case-insensitive filesystems.

## 16. Final Release Decision

**NOT PRODUCTION READY**

Evidence: the code builds, the Docker stack runs, the full backend (2833 passed / 0 failed / 27 skipped) and frontend (250/250) suites pass, and an end-to-end analysis with a live Frida run and all report exports worked. Security defects found in this audit are fixed and covered by tests.

It is not production ready because critical gates still fail:
1. **Secrets gate** — a real admin password is in public Git history and has not been rotated.
2. **Correctness gate** — VIDE produced a High-Risk verdict for a benign app, and CH06 would mark every genuine protected bank app as impersonation (FRS ≥ 92). For a fraud-intelligence product these are false certainties.
3. **Deployment gate** — there is no production frontend image and no GCP deployment definition; the dynamic sandbox needs dedicated VM/device infrastructure.

Once the password is rotated, fingerprints are provisioned (or CH06 treats unprovisioned entries as undetermined), and VIDE palette-only detections are recalibrated, the system would qualify for **PRODUCTION READY WITH DOCUMENTED LIMITATIONS** for local/VM deployment.
