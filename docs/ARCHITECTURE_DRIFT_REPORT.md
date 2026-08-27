# Architecture drift report

Deviations between what earlier documentation described and what the code actually does.

Original audit **2026-08-14**. Every item re-verified against the active codebase on **2026-08-27**; findings that no longer hold are marked resolved rather than deleted, because the claim each one corrects still appears in older material.

Maintained views: [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md) · [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) · [docs/CURRENT_ARCHITECTURE.md](docs/CURRENT_ARCHITECTURE.md)

---

## 1. Persistence layer uses no ORM

**Documented.** SQLAlchemy with synchronous connections.

**Actual.** `backend/app/db/` uses `aiosqlite` with direct SQL against a WAL-mode database. SQLAlchemy appears in no `requirements.txt` and is imported nowhere.

**Status: confirmed, still current.** This is the intended design, not an accident. Documentation implying an ORM is wrong.

**Severity.** High — a reader looking for models and sessions will not find them.

## 2. Static analysis runs concurrently, not sequentially

**Documented.** "Sequential triaged gating", where each stage waits for the previous one.

**Actual.** `_execute_analysis_pipeline` in `analysis-engine/app/main.py` launches Androguard, APKTool, JADX and MobSF as concurrent tasks, bounded by `asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)` (default 2) and, for anything touching the device, a per-device-serial lock.

**Status: confirmed, still current.**

**Severity.** Medium — the concurrency model determines the failure modes, so describing it wrongly makes timeouts hard to reason about.

## 3. Fuzzing removed; the explorer is a 15-stage goal graph

**Documented.** A random input fuzzer, a hybrid mode, and an 11-stage explorer graph.

**Actual.** The fuzzer and hybrid mode were deleted — random input corrupted evidence and contended for the ADB socket. Exploration runs against a **15-stage fraud goal graph** built by `_build_default_goals()` in `shared/sudarshan_core/engines/agentic/goal_tracker.py`: launch, permission grant, accessibility abuse, overlay, login flow, SMS/OTP interception, banking app detection, network/C2, persistence, dynamic code loading, reflection, deep links, broadcast receivers, exported components, background services.

**Status: confirmed, still current.**

**Correction to the original report.** It described a "7-step launch fallback ladder". The code calls it a **five-step** ladder in `frida_sandbox.py`, and records the rung that succeeded as `launch_method_used` (`"failed"` when all five fail). Documentation stating seven steps is wrong.

**Severity.** Medium.

## 4. Threat-intelligence caching is incomplete

**Documented.** Broad VirusTotal fallback and cached OTX hash lookups.

**Actual.** Two distinct gaps remain:

- **OTX hash lookups bypass the cache entirely.** `_otx_check_hash` in `shared/sudarshan_core/services/threat_correlator.py` calls neither `_cached_lookup` nor `_cache_store`, unlike `_otx_check_domain`, `_vt_check_hash`, `_vt_check_url` and the AbuseIPDB path, which all use both.
- **404 responses are not negatively cached.** `_cache_store` writes only when a lookup produced a payload, so an indicator VirusTotal has never seen is re-queried on every run — the exact case where quota is cheapest to waste.

**Status: confirmed, still current.** See [docs/KNOWN_LIMITATIONS.md §4.1](docs/KNOWN_LIMITATIONS.md).

**Severity.** High against a free-tier VirusTotal key (4 requests/minute).

## 5. Security posture is ahead of the documentation

**Documented.** `P0_SANDBOX_ESCAPE_INCIDENT` described unmitigated container exposure.

**Actual.** `docker-compose.hardened.yml` applies a read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, and a seccomp profile to the analysis engine; dev bind-mounts and the `~/.android` mount are removed. `FRIDA_LISTEN_HOST` defaults to loopback. All ADB invocation is funnelled through `adb_gateway.run_adb`, which blocks `tcpip`, `usb`, `pair`, `unpair`, `kill-server` and `start-server`. The analysis engine is not published at all; MobSF and mitmproxy bind to loopback.

**Status: confirmed as improvement.** The incident documents record the remediation; they should be read as history, not as current exposure.

**Severity.** Positive drift.

## 6. No CI pipeline exists

**Not in the original report; found during the 2026-08-27 re-verification.**

**Documented.** Several documents described `.github/workflows/ci.yml` running a subset of the suite (variously 202 or 525 tests) and treated that subset as an enforced quality gate.

**Actual.** There is no `.github/` directory in this repository and no CI workflow. The only automated git-side gate is `.githooks/pre-push`, which checks commit attribution rather than running tests. The suite — **2,622 tests collected** on 2026-08-27 — is entirely developer-run.

**Status: documentation corrected 2026-08-27.**

**Severity.** High — an enforced gate that does not exist is a worse error than a missing one, because it stops anyone from adding it.

---

## Conclusion

The codebase is more concurrent, more instrumented and more locked down than older documentation describes, and its weakest points are in the integration layers — threat-intelligence caching and the absence of automated enforcement — rather than in the analysis engines.

The active codebase is the source of truth. Where a design document and the code disagree, the document is the defect.
