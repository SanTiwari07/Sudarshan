# Tests — root suite

Engine-level tests for `sudarshan_core`: risk scoring, sandbox providers, the agentic explorer, VIDE, evidence handling and the dynamic pipeline. Gateway and API tests live in [`../backend/tests/`](../backend/README.md).

- Platform overview: [`../README.md`](../README.md)
- Evaluation methodology: [`../docs/10_VALIDATION/VALIDATION.md`](../docs/10_VALIDATION/VALIDATION.md)

---

## Running

```bash
# Linux / macOS, from the repository root
PYTHONPATH="backend:shared" JWT_SECRET_KEY=test_secret \
  python -m pytest tests/ backend/tests -q
```

```powershell
# Windows
$env:PYTHONPATH="backend;shared"
$env:JWT_SECRET_KEY="test_secret_key_for_pytest"
python -m pytest tests/ backend/tests -q
```

```bash
# Inside the running stack
docker compose exec backend python -m pytest tests/ backend/tests -q
```

Select a subset with `-k` against the full invocation rather than passing a bare file path.

**2,860 tests collected** on 2026-09-26 with no collection errors:

| Path | Collected |
| :--- | ---: |
| `tests/unit` | 1,813 |
| `tests/integration` | 12 |
| `backend/tests` | 797 |

There is **no CI workflow in this repository** — no `.github/` directory exists — so the suite is developer-run. The only automated git-side gate is `.githooks/pre-push`.

---

## Structure

```text
tests/
├── unit/           Engine-level tests (no device, no network)
├── integration/    Pipeline tests that assume more of the stack
└── apks/           Corpus manifest and validation run artifacts
```

### `tests/unit/`

Grouped by the subsystem each file covers:

| Area | Files |
| :--- | :--- |
| Risk and scoring | `test_risk_engine_nothing_happened.py`, `test_concealed_sample_scoring.py`, `test_code_execution_axis.py`, `test_ubiquitous_signal_not_scored.py`, `test_labelled_corpus.py` |
| Sandbox and providers | `test_sandbox_provider.py`, `test_sandbox_auto_detect.py`, `test_sandbox_containment.py`, `test_adb_policy_bypass.py`, `test_headless_launch_fallback.py`, `test_runtime_lifecycle.py` |
| Frida and instrumentation | `test_frida_pipeline_full.py`, `test_agent_deopt_gate.py`, `test_launch_handoff_instrumentation.py`, `test_webview_js_instrumentation.py` |
| Agentic exploration | `test_deep_exploration.py`, `test_action_execution_pipeline.py`, `test_action_verifier.py`, `test_semantic_action.py`, `test_perception_fraud_vision.py`, `test_explorer_scope_guard.py`, `test_target_boundary_and_depth.py`, `test_form_entry.py`, `test_form_navigation_and_observation.py`, `test_tier2_agentic.py` |
| Crash and recovery | `test_crash_and_loop_recovery.py`, `test_anr_is_not_a_crash_loop.py`, `test_checkpoint_recovery.py`, `test_sample_terminating_actions.py` |
| Evasion and resilience | `test_anti_evasion.py`, `test_anti_evasion_in_session.py`, `test_harness_attributed_evasion.py`, `test_device_state_simulator.py`, `test_time_warp.py` |
| Synthetic victim | `test_victim_profile.py`, `test_synthetic_victim_e2e.py`, `test_synthetic_victim_fields.py`, `test_synthetic_victim_orchestration.py`, `test_synthetic_victim_security.py`, `test_victim_simulation_journey.py` |
| Permissions | `test_permission_investigator.py`, `test_permission_orchestrator_verification.py`, `test_pregrant_permissions.py` |
| Evidence and screenshots | `test_evidence_pipeline.py`, `test_evidence_provenance.py`, `test_screenshot_audit.py`, `test_screenshot_captions.py`, `test_screenshot_hardening.py`, `test_vision_captions.py` |
| VIDE (20 files) | `test_vide_*.py` — comparison, corpus compare, ΔE, discriminative features, determinism, fuzzy matching, JS bundle, pipeline, rule F001, risk escalation, semantic matcher, signer registry, string axis, CH27, calibration, extraction sources, APK attribution, baseline shortlist, corpus bridge, Frida HTML |
| AI providers | `test_gemini_provider.py`, `test_gemini_fallback.py`, `test_artifact_explainer.py` |
| Intelligence and rules | `test_virustotal_crosscheck.py`, `test_network_signatures.py`, `test_yara_scanner.py`, `test_mobsf_client.py` |
| Payload and bridging | `test_secondary_payload.py`, `test_secondary_payload_wiring.py`, `test_static_dynamic_bridge.py`, `test_capability_profile.py` |
| Reporting | `test_report_investigation_section.py` |

### `tests/integration/`

| File | Covers |
| :--- | :--- |
| `test_pipeline.py` | End-to-end pipeline behaviour. Imports `requests` at module scope |
| `test_dynamic_pipeline_regression.py` | Dynamic pipeline regressions |

### `tests/apks/`

Corpus manifest and validation run outputs. APK binaries are **not committed** — see [`apks/README.md`](apks/README.md).

---

## Conventions

- **Async tests use `asyncio.run(...)`.** `pytest-asyncio` is not installed; `@pytest.mark.asyncio` is silently a no-op here. Do not add it to a test expecting it to work.
- **No device, no network in `tests/unit/`.** Device interaction is faked at the `SandboxProvider` or `run_adb` boundary. A unit test that needs a real emulator belongs in `scripts/` as a verification script.
- **Optional imports are skipped, not failed.** `google.genai`, `yara-python` and similar soft dependencies may be absent locally; guard with `pytest.importorskip(...)` or assert on module source.
- **Scoring changes need corpus evidence.** A test that changes an expected FRS, BFCI or band is asserting a model change. Validate it against the labelled corpus (`scripts/validate_corpus.py`) before merging, not by adjusting the expectation.
- **Determinism is a test target.** Replay tests assert that identical evidence produces an identical verdict; if a change makes a score non-reproducible, that is the bug, not the test.

---

## Environment requirements

| Requirement | Why |
| :--- | :--- |
| `PYTHONPATH` including `backend` and `shared` | `sudarshan_core` is not installed into the host interpreter |
| `JWT_SECRET_KEY` set to anything | The backend app refuses to import without it |
| `requests` installed | `tests/integration/test_pipeline.py` imports it at module scope; a single collection error aborts the entire session |
| A working `bcrypt` backend for `passlib` | Auth-touching modules fail to import otherwise, with a `MissingBackendError` at collection time |

Neither corpus is required. Corpus-dependent tests resolve the labelled malware corpus through `SUDARSHAN_LABELLED_CORPUS_DIR` and the VIDE banking baselines through `BANKING_BASELINE_CORPUS_DIR` (legacy alias `VIDE_CORPUS_DIR`). When either is unset, the dependent tests skip silently rather than failing — a skipped attribution test is not a passing one, so set the variable before treating that area as covered.
