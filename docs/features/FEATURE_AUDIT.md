# Feature audit — documentation vs. code

Verified discrepancies between what documentation stated and what the source code implements.

Original audit: **2026-08-15**. Re-verified against the active codebase on **2026-08-27**; each finding below carries its current status. Findings that no longer hold are kept with their resolution rather than deleted, because the claim they corrected still appears in older material.

For the maintained view of what exists and what does not, use [FEATURE_STATUS.md](features/FEATURE_STATUS.md) and [KNOWN_LIMITATIONS.md](features/KNOWN_LIMITATIONS.md).

---

## 1. Test suite accounting

**Original finding (2026-08-15).** Documentation claimed 730 automated tests. An AST count of `tests/` and `backend/tests/` yielded 725 across 90 files, and the CI configuration executed only 202 of them.

**Status: superseded, and the CI half was already wrong.** Measured 2026-08-27 with `pytest tests/ backend/tests --collect-only`: **2,622 tests collected**, no collection errors — 1,813 in `tests/unit`, 12 in `tests/integration`, 797 in `backend/tests`.

The more important correction is that **no CI workflow exists in this repository**. There is no `.github/` directory. Successive revisions of this and other documents described a `ci.yml` gating first 202 and later 525 tests; that file is not present and is not in the git history for this repository. The only automated git-side gate is `.githooks/pre-push`, which checks commit attribution, not tests.

## 2. Threat intelligence caching and 404 responses

**Original finding.** The 24-hour IOC cache stored positive hits but dropped 404 responses, so benign or novel indicators burned API quota on every re-scan.

**Status: partially addressed.** The cache is real and injected by the backend (`configure_ioc_cache` in `shared/sudarshan_core/services/threat_correlator.py`, backed by the `ioc_cache` table with a 24-hour TTL). `_cache_store` writes only when a lookup returned a payload, so an indicator that VirusTotal has never seen is still re-queried on the next run.

Two secondary facts worth stating: the analysis engine runs **uncached** when it correlates directly, because `sudarshan_core` must not import `app.db`; and rate pressure can be bounded with `VIRUSTOTAL_RATE_LIMIT_PER_MIN`. See [KNOWN_LIMITATIONS.md §4.1](features/KNOWN_LIMITATIONS.md).

## 3. YARA scanner had no rules

**Original finding.** The YARA execution logic existed but no `.yar` files were deployed, so every scan returned empty.

**Status: resolved.** `shared/sudarshan_core/engines/yara_rules/` now ships two rule files carrying eight rules — `banking_trojan_behaviour.yar` (6) and `apk_dropper_packaging.yar` (2). `frida_sandbox.py` resolves the directory absolutely (overridable with `SUDARSHAN_YARA_RULES_DIR`) rather than relative to the working directory, and logs whether rules loaded, so "no matches" is distinguishable from "never ran".

The rules deliberately target strings decrypted at runtime rather than the packed APK. Measured on the labelled corpus, `AccessibilityNodeInfo` appeared in 2 of 8 trojans and 8 of 9 benign apps — a conventional static string rule would have flagged the clean apps and missed the malware. See [YARA_RULES.md](reference/YARA_RULES.md).

## 4. No ORM in the persistence layer

**Original finding.** Documentation implied SQLAlchemy; the code uses direct async SQL.

**Status: confirmed, and it is the intended design.** `backend/app/db/` uses `aiosqlite` with direct SQL against a WAL-mode database. SQLAlchemy is not a dependency of any service. Documentation that implies an ORM is wrong; the direct-SQL layer is not a defect.

## 5. Internal service authentication is fail-open outside production

**Original finding.** The internal auth middleware fails open in development and relies on environment-variable validation.

**Status: confirmed, with the behaviour now precisely documented.** `_InternalServiceAuthMiddleware` in `analysis-engine/app/main.py`:

- `/health`, `/status`, `/openapi.json`, `/docs` and `/redoc` are always public.
- With `ANALYSIS_ENGINE_INTERNAL_TOKEN` **unset** and `SUDARSHAN_ENV=production`, every other request is refused with 503.
- With the token unset and any other environment, requests pass through unauthenticated.
- With the token set, a request whose `X-Sudarshan-Internal-Token` header does not match is refused with 401.

The compensating control is that the service is **not published** in `docker-compose.yml` — it is reachable only on the internal Compose network. The risk the original finding names remains real: a deployment that fails to set `SUDARSHAN_ENV=production` gets no authentication on an unauthenticated service.

## 6. Undocumented API surface

**Original finding.** The router registered 51 endpoints, 18 of them undocumented.

**Status: resolved by documentation, and the count has grown.** The backend now registers **81** route decorators across `backend/app/routes/` and `backend/app/auth/auth.py`. All of them, plus the six analysis-engine routes, are enumerated in [api/ENDPOINTS.md](api/ENDPOINTS.md) with method, path, required role, request body and response shape.

That rewrite also removed a set of endpoints that documentation described but the code never had — `/api/v1/auth/registration-policy`, `DELETE /api/v1/cases/{sha256}`, `POST /api/v1/cases/{sha256}/chat`, the whole `/api/v1/intel/*` group, `/api/v1/report/{sha256}/json`, `POST /api/events`, and the engine's `/api/v1/analyze-path` and `/api/v1/job/{job_id}`.

## 7. VIDE signer registry is demonstration scope

**Original finding.** The registry contained only three sample banks.

**Status: partially addressed, and the framing was wrong.** `shared/sudarshan_core/data/bank_signer_registry.json` now lists **twelve** Indian banking packages, and `shared/sudarshan_core/data/ui_baselines/` carries **ten** lab baselines.

The registry entries deliberately carry **empty** fingerprint allowlists. That is a fail-closed state, not missing data: a package with no provisioned certificate has its identity claim rejected rather than trusted. Provisioning real fingerprints turns rejection into verification; it does not switch the control on.

The real limitation is elsewhere. In the shipped baseline set all ten fingerprints are identical and the palettes collide at ΔE 0, so only the bank *name* distinguishes one baseline from another and attribution rests almost entirely on the string axis. The wider corpus is external, resolved through `BANKING_BASELINE_CORPUS_DIR`; without it roughly thirty attribution tests skip silently. See [KNOWN_LIMITATIONS.md §5.3](features/KNOWN_LIMITATIONS.md).

---

*Original audit 2026-08-15. Re-verified against the codebase 2026-08-27.*
