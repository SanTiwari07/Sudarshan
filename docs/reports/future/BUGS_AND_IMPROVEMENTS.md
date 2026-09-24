# Bugs and improvements

Open defects and improvement candidates, each verified against the active codebase.

Original register **2026-08-14**. Re-verified **2026-08-27**; items fixed since are recorded as closed with the change that closed them, so the register also serves as a record of what has been dealt with.

Reproduction detail: [VERIFICATION_STATUS.md](operations/VERIFICATION_STATUS.md). Operational boundaries that are deliberate rather than defects: [docs/features/KNOWN_LIMITATIONS.md](docs/features/KNOWN_LIMITATIONS.md).

---

## 1. Open

### 1.1 SSRF time-of-check / time-of-use via DNS rebinding — P1

**Location.** `backend/app/services/discovery/security.py` — `SSRFSafeAsyncClient.send`

**Issue.** `send` calls `resolve_and_check_url(str(request.url))`, which resolves the hostname and checks the resulting address against the denylist, and then calls `super().send(request, ...)` with the **hostname** still in the request. httpx resolves it again when it opens the connection. A DNS server under attacker control can answer with a public address for the check and a private one — `127.0.0.1`, link-local, RFC1918 — for the connection.

**Reach.** The URL discovery crawler, which fetches analyst-supplied URLs.

**Remediation.** Pin the connection to the address that passed the check: connect to the verified IP and carry the original hostname in the `Host` header and TLS SNI, rather than handing the hostname to the transport.

### 1.2 Threat-intelligence cache does not store negative results — P1

**Location.** `shared/sudarshan_core/services/threat_correlator.py` — `_cache_store`

**Issue.** The cache writes only when a lookup produced a payload. An indicator that VirusTotal has never seen returns nothing, is not cached, and is re-queried on every subsequent run. On a free-tier key (4 requests/minute) this is the cheapest possible way to exhaust quota, and it happens on exactly the benign and novel samples that generate the most unknown indicators.

**Remediation.** Negative caching: store a "checked, not found" marker with its own TTL, so a recently-checked unknown is not re-queried.

### 1.3 OTX hash lookups bypass the cache entirely — P1

**Location.** `shared/sudarshan_core/services/threat_correlator.py` — `_otx_check_hash`

**Issue.** Every other lookup in the module — `_vt_check_hash`, `_vt_check_url`, `_otx_check_domain`, the AbuseIPDB path — calls `_cached_lookup` before the request and `_cache_store` after it. `_otx_check_hash` calls neither, so one uncached outbound request is issued per analysis regardless of what the cache holds.

**Remediation.** Add the same `_cached_lookup` / `_cache_store` pair, keyed `otx_hash`.

### 1.4 AbuseIPDB is never marked as queried when the case has no IPs — P2

**Location.** `shared/sudarshan_core/services/threat_correlator.py` (the `sources_queried.append("AbuseIPDB")` call sits inside the per-IP result loop) and `backend/app/services/case_intel_enrichment.py` — `should_recorrelate_threat_intel`

**Issue.** With an AbuseIPDB key configured and a case containing zero IP indicators, the loop never runs, so `"AbuseIPDB"` never enters `sources_queried`. `should_recorrelate_threat_intel` returns true for a configured source that is absent from that set, so every read of the case triggers another full correlation pass.

**Effect.** Repeated correlation work and outbound requests for the VirusTotal and OTX sources, on every read of an affected case.

**Remediation.** Record the source as queried when it is configured and the query ran, independent of whether it produced rows — a "checked, empty" state distinct from "not checked".

### 1.5 Screenshot counter decrement and remote-path reuse — P2

**Location.** `shared/sudarshan_core/engines/screenshot_manager.py`

**Issue.** Two separate collision risks remain. `self._counter -= 1` runs when a capture is suppressed as a duplicate, so a later capture can be issued an ID (`SCR-003`) that a previous image already used. Separately, the device-side path is `sudarshan_screen_<timestamp_ms>.png` with no unique component, so two captures within the same millisecond overwrite each other.

**Mitigating factor.** Each capture now carries a `scr_uuid`, so evidence records themselves are uniquely identified even when the display ID repeats.

**Remediation.** Never decrement the counter — a suppressed capture should consume its ID. Append the UUID to the device-side path.

### 1.6 Runtime telemetry is not scoped to the requesting analyst — P2

**Location.** `backend/app/routes/runtime_api.py`

**Issue.** Every route in this module depends on `get_current_user`, which authenticates but does not scope. `case_id` is accepted as a plain filter, so an `analyst` can read hooks, events, evidence and diagnostics for a case owned by another analyst — unlike `/api/v1/cases/*`, which runs through `assert_case_visible`.

**Remediation.** Apply the same ownership check the case routes use before returning case-scoped telemetry.

### 1.7 `technical-pdf` advertises HTML and returns PDF — P3

**Location.** `backend/app/routes/report.py`

**Issue.** `/api/v1/report/technical-pdf/{sha256}` is declared `response_class=HTMLResponse` with a docstring describing print-ready HTML, but its body returns `await export_pdf_report(...)`, which is an explicit `Response` with `media_type="application/pdf"`. The OpenAPI schema therefore describes something the route does not emit.

**Remediation.** Either declare the correct response class, or make the route emit the print-ready HTML the docstring describes.

### 1.8 `ANALYSIS_TIMEOUT_SECONDS` has two different defaults — P3

**Location.** `backend/app/routes/upload.py` (default `600`), `analysis-engine/app/main.py` (default `300`), `docker-compose.yml` (sets `1200` for both)

**Issue.** The gateway's HTTP timeout to the engine is the value it reads **plus 60 s**, and it is required to exceed the engine's own pipeline ceiling. Inside Compose both read 1200 and the invariant holds. Outside Compose the defaults disagree — the gateway would wait 660 s for an engine that gives up at 300 s.

**Remediation.** One default, read from one place.

---

## 2. Closed since the original register

### 2.1 PDF generator `TypeError` — closed

**Was.** `banking_impact` was a narrative string; the FRS bar meter multiplied it by a float and raised `TypeError: can't multiply sequence by non-int of type 'float'`, returning 500 from every PDF export.

**Now.** `shared/sudarshan_core/engines/pdf_generator.py` carries `banking_impact_score: FieldValue[float]` alongside the narrative `banking_impact: FieldValue[str]`, and the meter reads the numeric field. Covered by `backend/tests/test_pdf_generator.py`.

### 2.2 Explorer crash-fallback `AttributeError` — closed

**Was.** After three consecutive crashes, the recovery path read `self.main_activity`, which was never initialised, raising `AttributeError` and bypassing the intended fallback.

**Now.** `self.main_activity` is set in `AgenticExplorer.__init__`. Covered by `tests/unit/test_crash_and_loop_recovery.py`.

### 2.3 Undocumented API surface — closed

**Was.** 18 endpoints registered by the router and absent from the endpoint documentation.

**Now.** All 81 backend route decorators and all 6 analysis-engine routes are enumerated in [docs/api/ENDPOINTS.md](docs/api/ENDPOINTS.md) with method, path, required role, request body and response shape. The same rewrite removed a set of endpoints the documentation described but the code never had.

### 2.4 YARA scanner had no rules — closed

**Was.** The scanner existed with zero `.yar` files deployed, returning empty on every scan.

**Now.** Eight rules across `shared/sudarshan_core/engines/yara_rules/`, resolved by absolute path and overridable with `SUDARSHAN_YARA_RULES_DIR`. The scanner logs whether rules loaded, so "no matches" is distinguishable from "never ran".

---

## 3. Improvements

### 3.1 Add a CI workflow

There is none. No `.github/` directory exists, and 2,622 tests are collected but nothing runs them automatically. Several documents previously described a `ci.yml` that does not exist, which is worse than no CI at all — it discourages anyone from adding one.

A first workflow would run `PYTHONPATH="backend:shared" JWT_SECRET_KEY=test python -m pytest tests/ backend/tests -q`, which needs only `requests` and a working `bcrypt` backend beyond the declared dependencies.

### 3.2 Unify environment configuration

`validate_backend_production_config` and the analysis engine's internal-auth middleware both branch on `SUDARSHAN_ENV`, and both fail open outside `production`. A single environment profile that sets containment strictness, registration policy and internal auth together would make "we are running in development mode" a visible state rather than an inferred one.

### 3.3 Provision discriminative VIDE baseline fingerprints

All ten shipped baselines carry identical fingerprints and palettes that collide at ΔE 0, so only the bank name distinguishes them and attribution rests almost entirely on the string axis. `scripts/regenerate_fingerprints.py` exists for this; it needs a corpus with genuine per-institution artwork.

### 3.4 Externalise analysis-engine job state

`JOBS` is an in-process dict, which is why the service is pinned to `--workers 1` and why an engine restart loses in-flight work. Moving it to shared storage removes both constraints at once.

### 3.5 Build the frontend for production

The bundled image runs the Vite dev server against a bind-mounted tree. `npm run build` produces `dist/`, but nothing serves it. A multi-stage build behind the same proxy that terminates TLS would make the stack deployable rather than demonstrable.
