# Known limitations

Operational boundaries of SUDARSHAN as the code stands. Every entry names the component that imposes the limit, what the engine does about it, what it costs the analyst, and what can be done.

Verified against the active codebase on **2026-08-27**.

- Platform overview: [`../README.md`](../README.md)
- Feature status: [`FEATURE_STATUS.md`](FEATURE_STATUS.md)

---

## How to read an entry

| Field | Meaning |
| :--- | :--- |
| **Limitation** | What the system cannot do, stated plainly |
| **Engine response** | What the code does when it hits the limit |
| **Impact** | What the analyst loses |
| **Workaround** | What an operator can do today |
| **Remediation** | What would actually remove the limit |

A limitation with an engine response is a managed boundary. A limitation without one is a gap.

---

## 1. Dynamic analysis and the sandbox

### 1.1 Dormant and trigger-gated malware

**Component.** `shared/sudarshan_core/engines/frida_sandbox.py`, `shared/sudarshan_core/engines/execution_assertions.py`

**Limitation.** Evasion-first banking trojans — Anatsa, Xenomorph, SOVA, Anubis, Cerberus, Octo — do nothing under observation. They stall behind `WorkManager` and `AlarmManager` timers, wait for a targeted banking app to reach the foreground, wait for an OTP SMS, or wait for an accessibility grant that a sterile sandbox never produces. Inside the analysis window the sandbox can capture zero weighted behavioural events.

**Engine response.** The run is marked `dynamic_conclusive = false` and the dynamic axis is **excluded** from the FRS rather than scored 0.0; the remaining weights are renormalised. `dynamic_exclusion_reason` records why. The Execution Assertion Matrix then records which trigger conditions were actually reached; when none were, the verdict becomes `INCOMPLETE_EXERCISE` and reported confidence is halved. If the band would otherwise have been `Safe`, the visibility, static-evidence or incomplete-exercise floor raises it to `Suspicious` — without touching the score.

**Impact.** A dormant sample produces a case that says "we could not see this run", not a clean bill of health. Confirming a second-stage payload still needs a longer window or a manual trigger.

**Workaround.** Raise `FRIDA_ANALYSIS_DURATION` (Compose default 240 s). Use the resilience endpoints — `POST /api/v1/analysis/{session_id}/time-warp` to advance the guest clock, `seed-persona` to populate contacts and messages, `autonomous-anti-evasion` to run the full sequence. `GET /api/v1/analysis/{session_id}/suggestions` returns the triggers the run did not reach.

**Remediation.** Longer soak windows on a dedicated device pool, and per-family trigger playbooks driven from the investigation manifest.

### 1.2 Sandbox evasion

**Component.** `shared/sudarshan_core/engines/anti_analysis_detector.py`, `shared/sudarshan_core/engines/risk_engine.py`

**Limitation.** A sample that fingerprints the emulator and stops has defeated observation. Anti-analysis carries no BFCI weight, so an evasion-only run contributes exactly 0.0 to the score.

**Engine response.** The evasion floor refuses a `Safe` verdict when sample-attributed anti-analysis events are present and the run was inconclusive. Harness-attributed evasion — checks that fire because of the instrumentation rather than because of the sample — is filtered out first, so the floor cannot be tripped by the sandbox observing itself.

**Impact.** The verdict says the sample resisted analysis. It does not say what the sample would have done.

**Workaround.** Run the anti-evasion sequence, which seeds device state and warps the clock, then compare the before/after behavioural delta.

**Remediation.** A less detectable guest: physical hardware, or a hypervisor-level introspection path instead of in-process instrumentation.

### 1.3 Incomplete exercise of the UI

**Component.** `shared/sudarshan_core/engines/agentic_explorer.py`, `engines/agentic/adaptive_budget.py`

**Limitation.** The explorer reaches a bounded number of screens per run, governed by `FRIDA_ANALYSIS_DURATION`, `SUDARSHAN_AGENT_ACTION_BUDGET` and per-iteration latency. Flows behind real authentication, a payment step, or device-specific state may never be reached.

**Engine response.** Coverage is tracked and reported; unreached goals appear in the assertions and suggestions payloads. Screen-hash loop detection stops the explorer burning budget in a cycle.

**Impact.** Coverage is partial and stated as partial. "Not observed" is not "not present".

**Workaround.** Raise the duration and action budget. Raise `SUDARSHAN_ACTION_DELAY_SCALE` on a slow sandbox — actions that fire before the UI settles are wasted budget. Install `uiautomator2` (already declared in both `requirements.txt`); without it every device interaction becomes a separate ADB subprocess and the same budget buys a fraction of the actions.

**Remediation.** Faster perception cycles and a persistent device channel across the whole session.

### 1.4 Single-device concurrency

**Component.** `shared/sudarshan_core/engines/frida_sandbox.py` (per-serial lock), `analysis-engine/app/main.py` (`MAX_CONCURRENT_ANALYSES`, default 2)

**Limitation.** Analyses targeting the same device serial serialise behind an in-process lock. Two samples never drive one emulator at once.

**Engine response.** Jobs queue rather than colliding. The batch worker enforces one `SCANNING` job per batch for the same reason.

**Impact.** Dynamic throughput is bounded by the number of emulators, not by CPU.

**Workaround.** Run several emulators and pin `DEVICE_SERIAL` per instance, or accept serialisation and use batch scanning, which is designed for it.

**Remediation.** A device pool with a scheduler that assigns free serials to queued jobs.

### 1.5 Pre-granted permissions hide the grant interaction

**Component.** `shared/sudarshan_core/engines/permission_orchestrator.py`, `SUDARSHAN_PREGRANT_PERMISSIONS` (default `1`)

**Limitation.** Manifest-declared runtime permissions are granted with `pm grant` before launch, because legacy `targetSdk` apps cold-start into `ReviewPermissionsActivity` and block process launch otherwise. Android therefore never shows a runtime permission dialog, and the explorer cannot observe the sample asking.

**Impact.** Evidence of *how* a sample social-engineers a permission grant is absent, even though the resulting capability is fully observed.

**Workaround.** Set `SUDARSHAN_PREGRANT_PERMISSIONS=0` when the grant interaction itself is the object of study, and accept that some samples will fail to launch.

**Remediation.** Selective pre-grant — grant only what is needed for launch and leave the fraud-relevant permissions to be requested.

### 1.6 Frida version and bundle constraints

**Component.** `shared/sudarshan_core/engines/frida_hooks/`

**Limitation.** Frida 17 removed the built-in `Java` global, so a raw `Java.perform` script fails with `ReferenceError: 'Java' is not defined`. Only the pre-compiled bundle — built with `frida-compile` against `frida-java-bridge` — runs. Frida 16 is not a fallback: it cannot link on 16 KB page-size devices. Host `frida` and guest `frida-server` must be the same version (17.16.4).

**Engine response.** The controller loads `banking_trojan.bundle.js` and refuses the uncompiled source. Version mismatch is caught by preflight.

**Impact.** A hook change requires a rebuild of the bundle, not just an edit to the `.js` file.

**Workaround.** Edit the `.js` source, recompile to `.bundle.js`, and keep both in the repository. Run `python scripts/preflight.py --container` after any version change.

**Remediation.** None needed; this is the supported Frida 17 model.

### 1.7 Timers and `rpc` are unreliable inside the agent

**Component.** `shared/sudarshan_core/engines/frida_hooks/banking_trojan.bundle.js`

**Limitation.** The JavaScript runtime inside the agent does not reliably service `setInterval`/`setTimeout` or `rpc` exports in this configuration, so recurring agent-side work cannot be driven from the JS event loop.

**Engine response.** Recurring work is driven from Java hooks instead, which fire on real application activity.

**Impact.** Anything that needs a wall-clock tick inside the agent has to be restructured around a hook.

**Workaround.** Hang periodic logic off a frequently-called framework method rather than a timer.

### 1.8 Screenshot capture is conditional

**Component.** `engines/agentic/perception.py`, `engines/agentic/screenshot_policy.py`

**Limitation.** Screenshots are perception level 5 and fire only when the UI XML is empty or unparseable, contains no clickable nodes, has a labelled-node fraction below threshold, when the activity is a known WebView or browser class, or when the previous action failed for lack of UI understanding.

**Rationale.** Capturing every frame is slow and produces near-identical images that bury the interesting one.

**Impact.** A visually significant screen that parsed cleanly may have no screenshot.

**Workaround.** None exposed as a per-run setting. `SUDARSHAN_DISABLE_SCREENSHOTS` only turns capture off entirely.

---

## 2. Network and topology

### 2.1 TLS interception is defeated by certificate pinning

**Component.** `shared/sudarshan_core/engines/network_capture.py`, mitmproxy sidecar

**Limitation.** HAR evidence requires the mitmproxy CA in the guest **system** store and a sample that does not pin its certificates. A pinned client sees the interception and fails closed.

**Engine response.** Network evidence is simply absent; the network BFCI component scores 0 and contributes nothing. The remaining axes are unaffected.

**Impact.** C2 traffic from a pinning sample is invisible to the HAR path.

**Workaround.** Rely on the Frida socket and HTTP hooks, which observe below the TLS layer, and on the hardcoded indicators recovered statically.

**Remediation.** Per-sample pinning bypass hooks, which are sample-specific and not general.

### 2.2 Genymotion host-only networking is not reachable through `host.docker.internal`

**Component.** `shared/sudarshan_core/sandbox/genymotion.py`, `docker-compose.yml`

**Limitation.** On Windows and macOS, Docker Desktop maps `host.docker.internal` to the host loopback. Genymotion VMs live on a VirtualBox host-only adapter (for example `192.168.56.101`), which loopback does not reach. Setting `ADB_HOST=host.docker.internal` for Genymotion does not work.

**Engine response.** The auto-detect provider resolves the VM endpoint directly from `adb devices -l`. The containment policy rejects a control-plane route that would bridge the guest onto the host LAN or through the Docker host ADB multiplexer.

**Impact.** A misconfigured `ADB_HOST` produces a sandbox that appears absent rather than one that misbehaves.

**Workaround.** Leave `ADB_HOST` empty on Docker Desktop and let `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037` proxy the host ADB server. On Linux Docker, set `ADB_HOST` to the VM IP — route B in `.env.example`.

### 2.3 Analysis-engine job state is not durable

**Component.** `analysis-engine/app/main.py` (`JOBS`)

**Limitation.** The microservice holds async job state in an in-process dict with TTL eviction (`JOB_RETENTION_SECONDS` 3600, `MAX_RETAINED_JOBS` 200). A container restart loses in-flight jobs. The service is pinned to `--workers 1` because a second worker would return 404 for a job created in the other process.

**Engine response.** The gateway keeps the authoritative record in `analysis_jobs`, so a lost engine job surfaces as a failed gateway job rather than a silent hang.

**Impact.** An engine restart during analysis costs that run.

**Remediation.** Externalise the job store, which is also what would allow more than one worker.

### 2.4 Batch recovery after a process exit is not durable

**Component.** `backend/app/workers/batch_worker.py`

**Limitation.** A job left in `SCANNING` by a process exit had its asyncio task cancelled with the process. At startup the worker marks such jobs `FAILED` and moves on.

**Impact.** A restart mid-batch costs one job, not the batch.

**Workaround.** Retry the job with `POST /api/v1/batch-jobs/{job_id}/retry`.

**Remediation.** A persistent queue with visibility timeouts.

### 2.5 Batch jobs are not deduplicated

**Component.** `backend/app/workers/batch_worker.py`

**Limitation.** Every member of a batch runs the full pipeline. A hash already analysed is analysed again.

**Impact.** Wasted sandbox time on a batch containing duplicates or previously seen samples.

**Workaround.** Screen the batch against `GET /api/v1/cases` before uploading.

---

## 3. AI and language models

### 3.1 Thinking models consume the output budget

**Component.** `shared/sudarshan_core/ai/gemini_provider.py`, `engines/agentic/planner.py`

**Limitation.** Gemini 3.x Flash spends part of its output budget on internal reasoning before emitting any JSON. Measured on `gemini-3.6-flash`, 358 of 512 tokens went to thinking, truncating the planner action mid-string so the planner fell back to the deterministic path on every call. Thinking cannot be disabled on that model — `thinking_budget=0` returns HTTP 400.

**Engine response.** `SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS` defaults to 2048, and incompatible `thinking_config` knobs are stripped automatically when failing over to `gemini-2.5-flash`.

**Impact.** With a lower budget, exploration silently degrades to the fallback planner and looks like a shallow run rather than a configuration error.

**Workaround.** Do not lower `SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS` below 2048 on a thinking model.

### 3.2 Provider quota opens the circuit

**Component.** `shared/sudarshan_core/ai/gemini_provider.py`

**Limitation.** A failing provider slot opens its circuit for `GEMINI_PRIMARY_COOLDOWN_SECONDS` (default 60) before it is probed again. With both slots open, `GeminiAllProvidersFailed` is raised.

**Engine response.** Callers fall back to deterministic output: the explorer uses `FallbackPlanner`, reporting uses a template narrative. The score and verdict are unaffected because they never depended on the model.

**Impact.** Narrative quality and exploration depth degrade. Nothing fails.

**Workaround.** Configure a distinct `GEMINI_FALLBACK_API_KEY`. An identical key and model is dropped at load time — the manager will not fail over to itself.

### 3.3 Running with no key at all

**Limitation.** Without `GEMINI_PRIMARY_API_KEY` (or the legacy `GEMINI_API_KEY`), the agentic planner disables itself at import time.

**Impact.** The analysis completes, but exploration is shallower and the case narrative is templated. The failure is silent — the service starts healthy.

**Workaround.** Check `GET /api/runtime/status` and the startup logs; a run using the fallback planner says so.

### 3.4 The knowledge base runs in a reduced mode without ChromaDB

**Component.** `backend/app/rag/knowledge_base.py`

**Limitation.** With `chromadb` installed the knowledge base does semantic similarity search; without it, it falls back to keyword lookup.

**Impact.** Reference context is less precise. Evidence grounding, which comes from the per-case investigation graph rather than the knowledge base, is unaffected.

**Workaround.** `pip install chromadb` in the backend image if semantic retrieval matters.

---

## 4. Threat intelligence

### 4.1 External API rate limits

**Component.** `shared/sudarshan_core/services/threat_correlator.py`

**Limitation.** The VirusTotal free tier allows 4 requests per minute. One analysis can issue up to 14 outbound lookups (1 VT hash, 1 OTX hash, 3 VT URLs, 5 OTX domains, 5 AbuseIPDB IPs), which exceeds the quota on its own.

**Engine response.** A 24-hour TTL cache in the `ioc_cache` table serves repeats. The cache is **injected by the backend**: `sudarshan_core` must not import `app.db`, so the analysis engine runs uncached when it correlates directly.

**Impact.** A burst of distinct samples still hits the quota, and correlation for those samples is unavailable — which excludes the correlation axis rather than scoring it zero.

**Workaround.** Bound the rate with `VIRUSTOTAL_RATE_LIMIT_PER_MIN`, or use a paid key.

### 4.2 Missing keys exclude the axis

**Limitation.** With `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` and `ABUSEIPDB_API_KEY` unset, correlation is skipped entirely.

**Engine response.** `correlation_available = false`; the 0.20 correlation weight is removed and the remaining axes renormalise. This is deliberate — scoring the axis 0.0 pinned a fifth of every score at zero and pushed real banking trojans into the `Safe` band.

**Impact.** Verdicts rest on static and dynamic evidence alone. `axes_excluded` on the case records it.

### 4.3 Family classification confirms, it does not discover

**Component.** `shared/sudarshan_core/engines/classification_engine.py`

**Limitation.** The classifier is rule-based over known signatures. On the labelled corpus run of 2026-08-15, five of eight banking trojans classified as `Unknown` and three were attributed to the wrong family (FluBot, Octo and Teabot all read as Anubis; SharkBot read as Hydra).

**Impact.** `family_classification` is a hint, not attribution. The `FAMILY_BANKING_WEIGHT` term in the banking-impact axis defaults to 0.5 for an unknown family, so a missed family lowers that axis rather than distorting it.

**Workaround.** Treat VirusTotal's family labels as the attribution source and this field as corroboration.

---

## 5. Decompilation and binary recovery

### 5.1 Packed and native-only samples

**Component.** `shared/sudarshan_core/analyzers/apk_analyzer.py`, `engines/jadx_engine.py`

**Limitation.** Samples that keep their logic in native `.so` libraries or ship under a commercial packer (SecNeo, Qihoo, Bangcle) decompile to a stub. The Java surface JADX recovers says almost nothing about behaviour.

**Engine response.** The analyser flags `System.loadLibrary`, scores `classes.dex` entropy on the obfuscation axis, sets `has_concealed_payload`, and defers to runtime hooks. The visibility floor then blocks a `Safe` verdict when the payload was never observed.

**Impact.** Static evidence for these samples is thin by construction, and the case depends on the dynamic run succeeding.

**Workaround.** Prioritise dynamic analysis for flagged samples and extend the window.

### 5.2 YARA is scoped to runtime strings

**Component.** `shared/sudarshan_core/engines/yara_scanner.py`, `engines/yara_rules/`

**Limitation.** Eight rules across two files. They target strings decrypted in memory, not the packed APK, because measurement on the labelled corpus showed a conventional static string rule would flag the clean apps and miss the trojans — `AccessibilityNodeInfo` appeared in 2 of 8 malware samples and 8 of 9 benign ones.

**Engine response.** The rules directory is resolved absolutely (overridable with `SUDARSHAN_YARA_RULES_DIR`) and the scanner logs whether rules loaded, so "no matches" can be distinguished from "never ran". `yara-python` is a soft dependency; absent, the scanner logs that it is disabled.

**Impact.** YARA contributes corroboration on unpacked runtime strings, not primary detection.

### 5.3 VIDE baselines are lab-scope

**Component.** `shared/sudarshan_core/data/ui_baselines/`, `engines/vide/corpus_loader.py`

**Limitation.** Ten demonstration baselines ship in the repository. The wider banking baseline corpus lives outside it and is resolved through `BANKING_BASELINE_CORPUS_DIR` (legacy alias `VIDE_CORPUS_DIR`). Without that variable, roughly thirty attribution tests **skip silently** rather than fail.

**A known weakness in the shipped corpus.** All ten baseline fingerprints are identical and the palettes collide at ΔE 0. Only the bank *name* actually distinguishes one baseline from another, so attribution on this corpus rests almost entirely on the string axis.

**Engine response.** Attribution requires at least one exclusive feature and reports `ambiguous` with a reason (`margin` or `no_exclusive_evidence`) when no baseline separates. The signer registry is fail-closed: twelve banking packages with deliberately empty fingerprint allowlists, so an unprovisioned package has its identity claim rejected rather than trusted.

**Impact.** VIDE detection is sound; VIDE *attribution* to a specific bank should not be relied on until the corpus carries discriminative fingerprints.

**Workaround.** Point `BANKING_BASELINE_CORPUS_DIR` at a corpus with genuine per-institution fingerprints, and regenerate with `scripts/regenerate_fingerprints.py`.

---

## 6. Platform and deployment

### 6.1 Single node

**Component.** `backend/app/db/`, `backend/app/workers/analysis_queue.py`

**Limitation.** Persistence is one SQLite file in WAL mode; the analysis queue is an in-process `asyncio` queue with `ANALYSIS_WORKERS` coroutines (default 2). There is no second node and no shared broker.

**Impact.** Throughput and availability are bounded by one process. A restart drains the queue.

**Remediation.** Postgres and an external broker. Both would be substantial changes to the persistence layer, which uses direct SQL rather than an ORM.

### 6.2 No continuous integration

**Limitation.** The repository has no `.github/` directory and no CI workflow. The test suite is developer-run.

**Engine response.** The only automated git-side gate is `.githooks/pre-push`, which blocks pushes carrying Cursor Agent attribution. It does not run tests.

**Impact.** Nothing prevents a regression from being pushed. Documentation that claims a CI-enforced subset of tests is wrong.

**Workaround.** Run `PYTHONPATH="backend:shared" JWT_SECRET_KEY=test python -m pytest tests/ backend/tests -q` before pushing. 2,622 tests collected on 2026-08-27.

### 6.3 Corpus validation cannot run in CI

**Component.** `scripts/validate_corpus.py`

**Limitation.** The labelled corpus contains live banking trojans and is gitignored, so the detection-accuracy artifact can never be regenerated automatically.

**Engine response.** Exit code 2 means "could not run" and is deliberately distinct from exit code 1, "something regressed", so an absent corpus is never reported as a pass or as a failure.

**Impact.** The published accuracy figures are a dated snapshot (2026-08-15, commit `ce30610`), not a continuously verified property.

### 6.4 The frontend container runs a dev server

**Component.** `frontend/Dockerfile`

**Limitation.** The bundled frontend image runs `npm run dev -- --host` against a bind-mounted source tree. `npm run build` produces `dist/`, but no production static server is configured in this repository.

**Impact.** The published stack is suitable for development and demonstration, not for an internet-facing deployment.

**Remediation.** A multi-stage build serving `dist/` from a static server, behind the same reverse proxy that terminates TLS.

### 6.5 Development-mode auth relaxations

**Component.** `backend/app/startup_validation.py`, `backend/app/registration_policy.py`

**Limitation.** Several checks — containment strictness, gateway dynamic-analysis gating, registration policy — behave differently outside `SUDARSHAN_ENV=production`.

**Impact.** A stack running with development defaults is materially less restrictive than the same stack in production mode, and it does not say so loudly.

**Workaround.** Set `SUDARSHAN_ENV=production` and `SANDBOX_CONTAINMENT_STRICT=true`, and deploy with `docker-compose.hardened.yml`. Startup validation then fails closed on a non-compliant configuration.

---

## 7. Known code inconsistencies

Recorded here because documentation should not paper over them. None is fixed by this document.

| Issue | Location | Effect |
| :--- | :--- | :--- |
| `/api/v1/report/technical-pdf/{sha256}` is declared `response_class=HTMLResponse` with a docstring describing print-ready HTML, but delegates to `export_pdf_report`, which returns `media_type="application/pdf"` | `backend/app/routes/report.py` | The OpenAPI schema advertises HTML; the route emits a PDF. Clients that trust the schema will mislabel the download |
| `ANALYSIS_TIMEOUT_SECONDS` defaults to 600 where the gateway reads it and 300 where the engine reads it, while Compose sets 1200 for both | `backend/app/routes/upload.py`, `analysis-engine/app/main.py`, `docker-compose.yml` | Outside Compose the gateway's client timeout (value + 60 s) and the engine's pipeline ceiling disagree |
| Frida diagnostic probes sit beside service code | `analysis-engine/test_frida*.py`, `restart_frida*.py` | These are hand-run debugging scripts, not tests. They are not collected by pytest and are not maintained |
| `scripts/validate_corpus.py` writes references to `audit/DETECTION_VALIDATION.md` into its generated output | `scripts/validate_corpus.py`, `docs/evaluation/CORPUS_STATIC_VALIDATION.md` | The `audit/` directory is not in this repository, so the generated validation document points at a file a reader cannot open. The generated file is marked "do not edit", so the fix belongs in the generator |
