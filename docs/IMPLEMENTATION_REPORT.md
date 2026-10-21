# SUDARSHAN — Reliability Implementation Report

> **Date:** 2026-10-11 · **Branch:** see the pull request / branch carrying commits `3258e1d`…
> **Audit:** [`RELIABILITY_AUDIT.md`](RELIABILITY_AUDIT.md) — defect IDs (L*, D*) refer to it.

## 1. Summary

The deterministic engine remains the only source of scores; no AI component reads or writes any value changed here. Weights, caps, windows and multipliers are unchanged; BFCI changes restore intended semantics (count distinct observations; correlate only timestamped events) and are versioned `bfci-v2.1`.

**Not done:** no test ran against an Android device or emulator (none available: no `/dev/kvm`, no `adb`). The zero-event behaviour on the problematic Android environment is therefore **instrumented but not root-caused**. No device-level fix is claimed.

## 2. Defects fixed and files changed

| Defects | Files | Change |
| :--- | :--- | :--- |
| L2, L3, L4, L12 | `shared/sudarshan_core/engines/telemetry_diagnostics.py` (new), `frida_sandbox.py` | Stage recorder + 7-way classification; `_dispatch_message` counts every message and never raises; `_on_detached`; `_load_primary_agent` (single primary load path, registers `detached`, records failures); agent `diag` milestones recorded; companion messages kept non-primary; `telemetry_diagnostics` on success and failure results |
| L6, L7, L8 | `event_bus.py`, `frida_sandbox.py` | Bounded queue (`SUDARSHAN_EVENT_BUS_MAX_QUEUE`, default 20000) with publisher backpressure (`SUDARSHAN_EVENT_BUS_PUBLISH_TIMEOUT`, 2 s) and counted drops; non-blocking publish from the worker thread; `task_done()` in `finally`; `metrics()`; `close()`; unbounded `Queue.join()` replaced by `drain()`; bus closed per session |
| L9, D11 | `evidence_store.py`, `runtime_event.py` | `event_fingerprint` (shared with BFCI); `evidence_key`, `provenance`; de-duplication; synthetic-event refusal (`allow_synthetic` for tests only); EVID allocated only on store; tolerant parsing; `metrics()` |
| D8, D9, D10 | `bfci_scorer.py`, `frida_sandbox.py` | `dedupe_events`; unstamped events excluded from sequence detection; all axes labelled; `explain_bfci()` → `bfci_explanation` in results; `BFCI_RULESET_VERSION` |
| D5, D6, D7 | `multi_stage_engine.py`, `batch_runner.py`, `sandbox/genymotion.py`, `sandbox/android_studio.py`, `frida_sandbox.py` (`stage_name` kwarg) | Per-stage `stage_id`, timestamps, derived status, `profile_applied`, limitations, structured error; reset in `finally`; primary chosen among usable stages; skipped stages recorded; static findings and stage name forwarded; arguments by name; `banking_apps` reports real success |
| D1, D2, D3 | `backend/app/routes/upload.py` | Removed shadowing `import os`; `_receive_apk_for_job` releases reserved slot on rejection; `_dynamic_failure_result`; multi-stage receives static findings |
| D4, D12 | `analysis-engine/app/main.py` | Dynamic exception → structured FAILED result; no unbounded HAR re-ingest |
| D12, D13 | `network_capture.py`, `frida_sandbox.py` | Session-window HAR attribution; `TCP_CONNECT` labelling; ip/port/first/last seen; header redaction; `collection_report()` → `network_collection`; `network_logs_total` |
| L12 | `shared/sudarshan_core/models/schemas.py`, `upload.py` | Additive optional API fields: `error`, `runtime_attempted`, `telemetry_diagnostics`, `bfci_explanation`, `network_flows`, `network_collection`, `network_logs_total` |
| D14, D15, D16 | `pdf_generator.py`, `risk_engine.py` | Metadata rows from recorded values ("Not recorded" otherwise); explicit `dynamic_ran`; exclusion reason reported for every excluded run (score unchanged) |
| D17 | `frontend/src/lib/telemetryStatus.ts` (new), `RuntimeStatus.tsx`, `types/case.ts` | Recorded failure reason, telemetry classification, hooks installed, TLS-inspection disclosure; zero events never described as benign |
| D18 | `frida_sandbox.py::_apply_agent_config` | Package name restricted to `[A-Za-z0-9._]` |
| D19 | `docs/03_RISK/BFCI.md`, `docs/02_ANALYSIS/NETWORK_ANALYSIS.md`, `FRIDA_INSTRUMENTATION.md`, `09_EVIDENCE/EVIDENCE_MODEL.md`, `10_VALIDATION/FEATURE_STATUS.md` | Corrected and extended |

Test files changed: `tests/unit/test_launch_handoff_instrumentation.py` (observes `_handle_message`; companion messages are now dispatched as non-primary), `tests/unit/test_static_dynamic_bridge.py` (source window widened: the findings dict is built just above the call). Both keep their original assertions.

## 3. Tests added

| File | Kind | Covers |
| :--- | :--- | :--- |
| `tests/unit/test_telemetry_diagnostics.py` | Unit, **mocked** Frida transport | All 7 classifications, processing-loss accounting, malformed messages, handler exceptions, detach, agent load failure, companion isolation, concurrency |
| `tests/unit/test_event_bus_reliability.py` | Unit | Subscriber isolation, worker-error drain regression, bounded queue drops, worker self-publish without deadlock, `close()`, typed subscriptions |
| `tests/unit/test_evidence_integrity.py` | Unit + bus→store integration | Duplicate delivery, shared native event ids, stable keys, provenance, synthetic refusal, EVID continuity, recovery; BFCI duplicates, empty evidence, unstamped sequences, cited sequences, attribution, reproducibility, unscored/harness categories |
| `tests/unit/test_multi_stage_truthful.py` | Unit, **mocked** device + Frida | Status derivation, primary selection, profile not applied, profile exception + reset, disconnect, all-failed, forwarding, batch-runner arguments |
| `tests/unit/test_network_and_report_disclosure.py` | Unit + real PDF render | HAR window attribution, legacy behaviour, TCP_CONNECT, redaction, TLS disclosure, report rows, no fabricated PDF metadata, API model fields, engine guards |
| `tests/unit/test_agent_deopt_gate.py` (+1) | Unit | Hostile package name sanitised; package header size correct |
| `backend/tests/test_upload_slot_release.py` | API (real route + SQLite) | Slot release for bad extension / magic / empty / oversize on both endpoints; structured dynamic failure |
| `backend/tests/test_e2e_upload_no_sandbox.py` | **End-to-end API**, real benign APK (`tests/apks/BASE-07-BOI.apk`), real Androguard, persistence and PDF; analysis-engine reported unreachable; **no device** | 200 response, `EMULATOR_UNAVAILABLE` with error, axis excluded with reason, identical score on resubmission, PDF discloses missing telemetry and does not claim a run |
| `tests/integration/test_frida_local_agent.py` | **Real Frida 17.16.4 against a local Linux child process — not Android** | Bundle loads; missing Java bridge classified `AGENT_INIT_FAILED`; a real native `connect()` hook event propagates to EvidenceStore (`frida_native` provenance) and to a BFCI contribution citing stored evidence keys; process death recorded as `process-terminated`; hostile package name still loads |
| `frontend/src/lib/telemetryStatus.test.ts` | Frontend unit | "Not recorded" defaults, failure reason, TLS disclosure, non-benign phrasing |

Regression proof against the original code (run by stashing only the source changes): bus `drain()` after a worker error → `False`; three unstamped events → `['OTP_THEFT_CHAIN']`; BFCI once vs twice-delivered SMS event → `14.2` vs `22.5`; EvidenceStore records for one event delivered twice → `2`; `data: None` event → dropped with an error.

## 4. Results

Environment: Linux 6.18 container, Python 3.13.16, frida 17.16.4 / frida-tools 14.10.4 (pip), Node 22.22.0. **No adb, no KVM, no emulator.** Yama `ptrace_scope` not present; local Frida attach to a child process works on this host.

| Suite | Before | After |
| :--- | :--- | :--- |
| `pytest tests backend/tests` | 2857 passed, 2 failed, 7 skipped | **2940 passed**, 7 skipped, the same 2 environmental tests deselected (`test_pipeline.py::test_dynamic_analysis` needs adb; `test_resolve_and_check_url_valid` needs DNS) |
| `tests/integration/test_frida_local_agent.py` (real Frida, local Linux) | — | 4 passed |
| Frontend `npx tsc --noEmit` | — | passes |
| Frontend `npm run lint` | — | 0 errors (warnings pre-existing style) |
| Frontend `npm test` (vitest) | 250 passed | **254 passed** |
| Frontend `npx vite build` | — | succeeds |

**Device / live tests: none were run.** Every dynamic-path test above is either mocked or runs on the local Linux host.

## 5. Commands to reproduce

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt -r analysis-engine/requirements.txt pytest-asyncio pypdf
pip install -e shared/ --no-deps
mkdir -p /tmp/uploads
PYTHONPATH=backend:shared JWT_SECRET_KEY=ci UPLOADS_DIR=/tmp/uploads \
  pytest tests backend/tests -q \
  --deselect tests/integration/test_pipeline.py::test_dynamic_analysis \
  --deselect backend/tests/test_discovery_security.py::test_resolve_and_check_url_valid

# Real Frida against a local process (skips itself if the host forbids attach)
PYTHONPATH=backend:shared pytest tests/integration/test_frida_local_agent.py -v

cd frontend && npm ci && npx tsc --noEmit && npm run lint && npm test && npx vite build
```

## 6. Known limitations and remaining blockers

1. **Zero-event root cause on Android is open.** Next step on a device: run a benign app (e.g. one of `tests/apks/BASE-*.apk`) on Genymotion and on an Android Studio AVD, once with spawn gating and once with `SUDARSHAN_SPAWN_GATING=0`, and read `telemetry_diagnostics` from the result. The classification separates the remaining hypotheses (L10 JS-thread wedge: canary but no `ping`/`event` messages; L11 ART/timing: hooks installed, attached for the whole window, `HOOKS_INSTALLED_NOT_EXERCISED`; transport loss: `NO_TELEMETRY_OBSERVED` with a detach reason).
2. **Java hooks were not exercised in any test** (no ART on the test host). Only the native `connect()` path was verified end-to-end with real Frida.
3. **Agent source was not modified** (contributing rule 6). Native hooks still stamp non-unique `native_ev_<ms>` ids; the host compensates with content fingerprints. Two native events identical in every field within one millisecond are counted once.
4. **The four multi-stage scenarios are approximations**, now stated in each stage's `limitations`: "rebooted" is a `BOOT_COMPLETED` broadcast sent before the stage reinstalls the app; "banking_apps" creates data directories only.
5. **TLS:** encrypted application traffic is inspected only when a mitmproxy HAR is configured and the app trusts the proxy CA; certificate-pinned traffic is never decrypted. `SSL_write`/`SSL_read` hooks see plaintext previews only where `libssl.so` is the TLS library in use.
6. `get_tracker` (pipeline-state registry) is still an unlocked `OrderedDict` shared with frida's callback thread (L5). Failures there are now recorded rather than silent; adding a lock is a recommended follow-up.
7. `POST /api/v1/analyze` still returns `str(e)` as the 500 detail, which can expose internal error text; recommended to replace with a generic message plus job id.
8. The HTML `report_generator.py` was not audited line by line for fixed strings; a search for the fabricated PDF strings found none there.
