# Dynamic Investigation — test coverage map (Phase 10)

Measured, not asserted. Every count below comes from `pytest --collect-only`.

```
tests/unit + tests/integration + backend/tests
1351 passed, 15 skipped, 4 failed          (4 failures pre-existing — see below)
1370 collected
```

## Suites

| suite | result |
| --- | --- |
| `tests/unit` | passing |
| `tests/integration` | 9 passed, 3 skipped (skips need an emulator/corpus) |
| `backend/tests` | passing except the 4 below |

## Added this cycle — 404 tests

| file | tests | covers |
| --- | ---: | --- |
| `test_investigation_controller.py` | 84 | state machine, branch selection, action allowlist, progress, oscillation |
| `test_action_verifier.py` | 37 | verification rules, device parsers, explorer wiring |
| `test_capability_profile.py` | 35 | category inference, expectation model |
| `test_explorer_scope_guard.py` | 35 | scope guard, escaping-action memory, launch component |
| `test_permission_orchestrator_verification.py` | 32 | grant verification, containment scoping, admin parsing |
| `test_yara_scanner.py` | 29 | scanner API compat, rule behaviour |
| `test_permission_investigator.py` | 26 | declared/requested/granted/expected matrix |
| `test_crash_and_loop_recovery.py` | 26 | §15 crash taxonomy, per-screen loop budget |
| `test_virustotal_crosscheck.py` | 31 | VT verdict bucketing, agreement matrix |
| `test_workflow_preconditions.py` | 20 | precondition split, record construction |
| `test_static_dynamic_bridge.py` | 19 | the bridge, at every hop |
| `test_report_investigation_section.py` | 17 | report rendering, escaping |
| `test_pregrant_permissions.py` | 13 | pre-grant switch and recording |

## §27 checklist

| § | requirement | where | state |
| --- | --- | --- | --- |
| A | manifest / runtime / granted permission detection | `test_permission_investigator.py` | covered |
| A | unexpected-permission classification | `test_capability_profile.py`, `test_permission_investigator.py` | covered |
| B | successful / failed permission grant | `test_action_verifier.py`, `test_permission_orchestrator_verification.py` | covered, **and confirmed live** |
| B | successful / failed click | `test_action_verifier.py` | covered |
| C | launch → permission → granted | `test_investigation_controller.py` | covered |
| C | accessibility flow | `test_permission_orchestrator_verification.py` | **unit only — the grant path has never run against an APK that declares an accessibility service** |
| C | goal completion / failure | pre-existing `test_agentic_explorer.py` | covered |
| D | repeated screen / action, max retry | `test_crash_and_loop_recovery.py`, `test_explorer_scope_guard.py` | covered |
| E | launch crash, crash after action, recovery, instrumentation-sensitive | `test_crash_and_loop_recovery.py` | covered; **no live crash observed to confirm against** |
| F | screenshot created / trigger / evidence / finding links | pre-existing `test_screenshot_*.py`, `test_visual_evidence_*.py` (10 files) | covered |
| G | valid accepted, invalid rejected, malformed LLM response | `test_investigation_controller.py` + 13 validation tests in `test_agentic_explorer.py` | covered |
| H | existing explorer / evidence / bus / workflow / risk tests pass | full suite | covered |

## The 4 failures are pre-existing

Verified by `git stash --include-untracked` of **every** change from this cycle
and re-running on the resulting clean tree. All four still fail:

```
backend/tests/test_baselines_api.py::test_admin_can_list_and_refresh
backend/tests/test_pdf_generator.py::test_frs_canonical_consistency
backend/tests/test_pdf_generator.py::test_threat_intel_unavailable_handling
backend/tests/test_pdf_generator.py::test_empty_evidence_records_handling
```

The PDF three are the `TypeError` in `FRSBarMeter` already recorded in
`CURRENT_STATE.md` ("PDF exports completely broken by a simple TypeError") and
`VERIFICATION_STATUS.md`. They are not in this cycle's scope.

A fifth, `test_boundaries.py::test_invalid_env_override_is_ignored`, comes and
goes between runs. It is environment-dependent rather than flaky: it asserts
`get_screen_size` falls back to 1080×1920, and an attached emulator answers
1080×2400 instead. Confirmed both ways in this cycle - it failed on every run
made while the Pixel_6 was up, and the full suite is 4-failure clean once the
emulator exits.

A sixth, `tests/integration/test_dynamic_pipeline_regression.py`, is
emulator-gated in the same way but for a different reason. It invokes
`validate_dynamic_pipeline.py` over the downloadable corpus, and
`tests/apks/categories/` is empty on this machine - all 16 corpus entries report
missing, so the validator exits 1. The test `pytest.skip`s when no emulator is
attached, which is why it was green for most of this cycle. It is a missing
fixture, not a regression: run `python validate_dynamic_pipeline.py --fetch`
to populate the corpus before treating it as a signal.

`device_properties.get_screen_size` also memoises per (device, adb_path) in a
module-level `_cache`, so within one pytest process the first real reading is
reused by every later test. Worth knowing when interpreting a partial run: the
result depends on whether a device was attached when the cache was first
populated, not only on whether one is attached now.

## What the tests do NOT establish

Stated plainly, because a green suite invites the opposite assumption.

* **One sample.** Every live validation ran on InsecureBankv2. The §28
  four-category matrix and the §30 banking-trojan acceptance test have **not**
  been run.
* **The accessibility grant path has never executed.** No sample run so far
  declares an accessibility service, so `grant_accessibility` →
  `verify_accessibility_enabled` is unit-tested only. Cerberus declares one.
* **No crash has been classified live.** The taxonomy is validated against a
  crash whose ground truth is known (the `ClassLoader.loadClass` hook crash
  diagnosed earlier this cycle), but no run has produced one.
* **Coverage depth is unmeasured.** Runs settle at 5–8 actions with the LLM
  planner versus 16 with the deterministic fallback — a latency effect inside a
  fixed 90 s window, not rejections. Whether 6 LLM-chosen actions beat 16
  fallback ones is an open question; `Screens` was 2–3 either way.
