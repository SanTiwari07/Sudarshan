# Feature status

Implementation status of every significant capability in SUDARSHAN, with the source file that implements it and the test or artifact that evidences it.

Verified against the active codebase on **2026-08-27**.

- Platform overview: [`../README.md`](../README.md)
- Operational boundaries: [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md)
- Route reference: [`api/ENDPOINTS.md`](api/ENDPOINTS.md)

---

## Status vocabulary

| Status | Meaning |
| :--- | :--- |
| **Implemented** | In production code, wired into the end-to-end pipeline, covered by automated tests |
| **Partially implemented** | Core logic present and wired in, but a documented branch, integration or mode is constrained |
| **Experimental** | Functional but environment-dependent or not exercised on the default path |
| **Planned** | Specified but absent from the executable codebase |
| **Removed** | Present in earlier revisions, deliberately deleted |

No feature here is described as "production-ready". The repository has no CI pipeline, persistence is a single SQLite file, and the queue is in-process — those are deployment properties, not feature properties, and they are recorded in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

Test paths are relative to the repository root. **2,622 tests collected** across `tests/` and `backend/tests` on 2026-08-27.

---

## Intake and gateway

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Synchronous APK upload | Implemented | `backend/app/routes/upload.py` | `backend/tests/test_analysis_client.py` | ZIP magic and extension validation, size cap, server-side SHA-256 |
| Asynchronous queued analysis | Implemented | `backend/app/routes/upload.py`, `backend/app/workers/analysis_queue.py` | `backend/tests/test_batch.py` | Returns `job_id`; poll `GET /api/v1/status/{job_id}` |
| Job cancellation | Implemented | `backend/app/routes/upload.py` | `backend/tests/test_batch.py` | `POST /api/v1/analyze/cancel/{job_id}` |
| Enterprise batch scan | Implemented | `backend/app/routes/batch.py`, `backend/app/workers/batch_worker.py` | `backend/tests/test_batch.py` | 2–50 APKs, FIFO, pause/resume/cancel/retry, role-scoped |
| APK discovery crawler | Implemented | `backend/app/routes/discovery.py`, `backend/app/services/discovery/` | `backend/tests/test_url_discovery.py`, `backend/tests/test_url_ingestion.py`, `backend/tests/test_discovery_security.py` | Crawls a target URL, validates candidates, ingests on request |
| JWT authentication | Implemented | `backend/app/auth/auth.py` | `backend/tests/test_hackathon_security_hardening.py` | Startup refuses to run without `JWT_SECRET_KEY` |
| Three-tier RBAC | Implemented | `backend/app/auth/auth.py`, `backend/app/case_access.py` | `backend/tests/test_boundaries.py`, `frontend/src/test/AuthFlowMatrix.test.tsx` | `analyst`, `soc_lead`, `admin`; self-registration always yields `analyst` |
| Session revocation | Implemented | `backend/app/auth/auth.py`, `backend/app/db/security.py` | `backend/tests/test_persistence_layer.py` | `jti`-tracked; logout, logout-all, admin revoke |
| Account and IP lockout | Implemented | `backend/app/db/security.py` | `backend/tests/test_hackathon_security_hardening.py` | Thresholds and window configured in `.env` |
| Rate limiting | Implemented | `backend/app/rate_limit.py` | `backend/tests/test_hackathon_security_hardening.py` | `slowapi`; disable only via `SUDARSHAN_RATE_LIMIT_DISABLED` in development |
| Audit log | Implemented | `backend/app/services/audit_service.py`, `backend/app/routes/audit.py` | `backend/tests/test_persistence_layer.py` | Queryable by `soc_lead` and above |
| Export ledger | Implemented | `backend/app/middleware/export_ledger.py` | `backend/tests/test_persistence_layer.py` | Records every report, IOC and rule export |

## Static analysis

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Native Androguard analysis | Implemented | `shared/sudarshan_core/analyzers/apk_analyzer.py` | `backend/tests/test_detection_regressions.py`, `backend/tests/test_activity_parser.py` | Manifest, permissions, components, entropy, hardcoded indicators |
| APK corruption repair | Implemented | `shared/sudarshan_core/engines/apk_repair.py` | `backend/tests/test_manifest_repair.py` | Rebuilds malformed AXML and string tables, resigns |
| APKTool 2.10.0 decompilation | Implemented | `shared/sudarshan_core/engines/apktool_engine.py` | Container toolchain check in `analysis-engine/entrypoint.sh` | Resources, smali, layout XML |
| JADX 1.5.1 decompilation | Implemented | `shared/sudarshan_core/engines/jadx_engine.py` | Container toolchain check in `analysis-engine/entrypoint.sh` | DEX to Java, fraud-pattern scanning |
| Concealed-payload detection | Implemented | `shared/sudarshan_core/analyzers/apk_analyzer.py` | `tests/unit/test_concealed_sample_scoring.py` | Nested APK/DEX in assets, high-entropy blobs relative to `classes.dex` |
| Investigation manifest | Implemented | `shared/sudarshan_core/models/manifest.py` | `tests/unit/test_static_dynamic_bridge.py` | Minimal hook profile handed to the dynamic run |
| Capability profile | Implemented | `shared/sudarshan_core/engines/capability_profile.py` | `tests/unit/test_capability_profile.py` | Declared-capability summary bridging static to runtime |
| MobSF enrichment | Partially implemented | `shared/sudarshan_core/services/mobsf_client.py` | `tests/unit/test_mobsf_client.py` | Optional. An unreachable `MOBSF_HOST` logs a warning and the pipeline continues; bound it with `MOBSF_MAX_SECONDS` |
| YARA scanning | Implemented | `shared/sudarshan_core/engines/yara_scanner.py`, `engines/yara_rules/` | `tests/unit/test_yara_scanner.py`, `docs/YARA_RULES.md` | Eight rules in two files, aimed at decrypted runtime strings rather than the packed APK. `yara-python` is a soft dependency; absent, the scanner logs that it is disabled |

## VIDE — visual impersonation

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Layout AST extraction and comparison | Implemented | `engines/vide/view_ast.py`, `ast_builders.py`, `compare.py` | `tests/unit/test_vide_compare.py`, `test_vide_pipeline.py` | Detection threshold 0.20 |
| CIEDE2000 ΔE colour matching | Implemented | `engines/vide/color_match.py` | `tests/unit/test_vide_delta_e.py` | Per-swatch distance and verdict |
| Fuzzy string axis | Implemented | `engines/vide/fuzzy.py` | `tests/unit/test_vide_string_axis.py`, `test_vide_fuzzy_match.py` | Match threshold 82.0; `rapidfuzz` with a pure-Python fallback |
| Corpus attribution | Implemented | `engines/vide/corpus_compare.py`, `discriminative.py` | `tests/unit/test_vide_corpus_compare.py`, `test_vide_apk_attribution.py`, `test_vide_discriminative.py` | Requires exclusive evidence; reports `ambiguous` with a reason when the margin is too small |
| Bank signer registry | Implemented | `engines/vide/signer_registry.py`, `data/bank_signer_registry.json` | `tests/unit/test_vide_signer_registry.py` | Twelve packages with deliberately empty allowlists — fail-closed, so an unprovisioned package has its identity claim rejected |
| CH27 triad escalation | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_vide_ch27_rule.py` | Clone confidence > 0.85 + signer mismatch + accessibility → score ≥ 95, band `Critical` |
| Determinism | Implemented | `engines/vide/` | `tests/unit/test_vide_determinism.py` | Identical input yields an identical verdict |
| WebView / JS overlay capture | Experimental | `engines/vide/html_profile.py`, `js_bundle.py`, `scripts/vide_live_probe.bundle.js` | `tests/unit/test_vide_frida_html.py`, `test_vide_js_bundle.py`, `test_webview_js_instrumentation.py` | Needs a live device and the compiled probe; verified by hand, see `scripts/verify_vide_webview_device.md` |
| Semantic matcher | Partially implemented | `engines/vide/semantic_matcher.py` | `tests/unit/test_vide_semantic_matcher.py` | Advisory only. Marked `advisory: true` and never the verdict; requires a Gemini key |
| Baseline corpus | Partially implemented | `data/ui_baselines/`, `engines/vide/corpus_loader.py` | `tests/unit/test_vide_baseline_shortlist.py`, `test_vide_corpus_bridge.py` | Ten lab baselines ship in-repo; the wider corpus is external, resolved through `BANKING_BASELINE_CORPUS_DIR`. Without it, attribution tests skip |

## Dynamic sandbox

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Sandbox provider abstraction | Implemented | `shared/sudarshan_core/sandbox/factory.py`, `provider.py` | `tests/unit/test_sandbox_provider.py` | Genymotion, Android Studio AVD, physical, auto-detect |
| Provider auto-detection | Implemented | `shared/sudarshan_core/sandbox/auto.py` | `tests/unit/test_sandbox_auto_detect.py` | Resolves the endpoint from `adb devices -l` |
| Corellium / Waydroid providers | Planned | `shared/sudarshan_core/sandbox/future.py` | — | Registered names and placeholder classes only; not usable backends |
| Sandbox containment policy | Implemented | `shared/sudarshan_core/security/sandbox_containment.py` | `tests/unit/test_sandbox_containment.py`, `test_adb_policy_bypass.py` | Fails closed under `SUDARSHAN_ENV=production` with `SANDBOX_CONTAINMENT_STRICT=true` |
| ADB gateway choke point | Implemented | `shared/sudarshan_core/security/adb_gateway.py` | `tests/unit/test_adb_policy_bypass.py` | Blocks `tcpip`, `usb`, `pair`, `unpair`, `kill-server`, `start-server` |
| Gateway dynamic-analysis gate | Implemented | `backend/app/routes/upload.py`, `backend/app/startup_validation.py` | `backend/tests/test_gateway_dynamic_blocker.py` | 503 unless `SUDARSHAN_ALLOW_GATEWAY_DYNAMIC` is set; off by default |
| Frida 17 compiled hook bundle | Implemented | `engines/frida_hooks/banking_trojan.bundle.js` | `tests/unit/test_frida_pipeline_full.py`, `backend/tests/test_frida_preflight.py` | Frida 17 removed the `Java` global, so only the `frida-java-bridge` bundle runs |
| ART deoptimization gate | Implemented | `shared/sudarshan_core/engines/frida_sandbox.py` | `tests/unit/test_agent_deopt_gate.py` | Runs before hooks are installed |
| Exact PID attachment | Implemented | `shared/sudarshan_core/engines/frida_sandbox.py` | `backend/tests/test_launch_ladder.py`, `tests/unit/test_launch_handoff_instrumentation.py` | Resolves the PID and requires a stability window before attaching |
| Launch fallback ladder | Implemented | `shared/sudarshan_core/engines/frida_sandbox.py` | `backend/tests/test_launch_ladder.py`, `tests/unit/test_headless_launch_fallback.py` | Five steps; the successful rung is recorded as `launch_method_used`, `"failed"` when all five fail |
| Spawn gating | Implemented | `shared/sudarshan_core/engines/frida_sandbox.py` | `backend/tests/test_spawn_gating.py` | Controls when spawn is preferred over attach |
| DAE pipeline state machine | Implemented | `shared/sudarshan_core/engines/dae_pipeline.py` | `tests/unit/test_runtime_lifecycle.py` | 16 states, logged transitions, exposed at `GET /api/runtime/pipeline` |
| Permission pre-grant | Implemented | `shared/sudarshan_core/engines/permission_orchestrator.py` | `tests/unit/test_pregrant_permissions.py`, `backend/tests/test_permission_orchestrator.py` | Default on; needed for legacy targetSdk apps to launch |
| Permission investigation | Implemented | `shared/sudarshan_core/engines/permission_investigator.py` | `tests/unit/test_permission_investigator.py` | Observes grant dialogs when pre-grant is disabled |
| Device channel (uiautomator2) | Implemented | `shared/sudarshan_core/sandbox/device_channel.py` | `backend/tests/test_device_channel.py` | Persistent session; degrades to per-command ADB when the package is absent |
| Network capture from HAR | Partially implemented | `shared/sudarshan_core/engines/network_capture.py` | `tests/unit/test_frida_pipeline_full.py`, `network_signatures.py` tests | Requires the mitmproxy sidecar and the CA in the guest system store; defeated by certificate pinning |
| Anti-analysis detection | Implemented | `shared/sudarshan_core/engines/anti_analysis_detector.py` | `tests/unit/test_harness_attributed_evasion.py` | Distinguishes sample-attributed from harness-attributed evasion |
| Autonomous anti-evasion | Implemented | `shared/sudarshan_core/engines/anti_evasion.py`, `backend/app/routes/resilience.py` | `tests/unit/test_anti_evasion.py`, `test_anti_evasion_in_session.py`, `backend/tests/test_anti_evasion_api.py` | Seeds persona state, warps the clock, measures the behavioural delta |
| Time warp | Implemented | `shared/sudarshan_core/engines/time_warp.py` | `tests/unit/test_time_warp.py` | Advances the guest clock and forces scheduled jobs |
| Synthetic victim persona | Implemented | `shared/sudarshan_core/engines/persona.py`, `engines/agentic/victim_profile.py` | `tests/unit/test_victim_profile.py`, `test_synthetic_victim_*.py` | Contacts, messages, calls, photos; seeding costs roughly one second per row |
| Device state simulation | Implemented | `shared/sudarshan_core/engines/device_state_simulator.py` | `tests/unit/test_device_state_simulator.py` | Battery, connectivity and related guest state |
| Session checkpoint and restore | Implemented | `shared/sudarshan_core/engines/session_manager.py`, `backend/app/routes/resilience.py` | `tests/unit/test_checkpoint_recovery.py` | Resume a session after an interruption |
| Second-stage payload observation | Partially implemented | `shared/sudarshan_core/engines/multi_stage_engine.py`, `engines/agentic/secondary_payload.py` | `tests/unit/test_secondary_payload.py`, `test_secondary_payload_wiring.py` | Dumps and records a dropped payload; automated re-analysis of the second stage is manual |
| Random input fuzzing | Removed | — | — | Deleted in favour of the deterministic agentic explorer; it corrupted evidence and contended for the ADB socket |

## Deep UI exploration

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Five-level perception pipeline | Implemented | `engines/agentic/perception.py` | `tests/unit/test_perception_fraud_vision.py` | UI XML → activity → Frida events → logcat → screenshot, with screenshot conditional |
| Semantic screen classification | Implemented | `engines/agentic/screen_classifier.py` | `tests/unit/test_deep_exploration.py` | Screen type plus package-ownership context |
| Screen graph and loop detection | Implemented | `engines/agentic/screen_graph.py` | `tests/unit/test_deep_exploration.py`, `backend/tests/test_deep_exploration_regression.py` | Stable topology hashes and a transition DAG |
| Canonical action dispatch | Implemented | `engines/agentic/action_dispatch.py`, `semantic_action.py` | `tests/unit/test_action_execution_pipeline.py`, `test_semantic_action.py` | Semantic action to executable input |
| Action verification | Implemented | `engines/agentic/action_verifier.py` | `tests/unit/test_action_verifier.py` | Pre/post observation diff confirms a state change |
| Goal planning and tracking | Implemented | `engines/agentic/goal_planner.py`, `goal_tracker.py`, `progress_tracker.py` | `backend/tests/test_goal_progression.py`, `tests/unit/test_goal_hook_contract.py` | 15-stage fraud goal graph with per-goal confirmation modes; a goal with no available instrument reports `UNSUPPORTED` rather than `FAILED` |
| Model-assisted planner | Partially implemented | `engines/agentic/planner.py`, `engines/ui_explorer.py` | `backend/tests/test_planner_budget.py`, `test_planner_cache.py` | Requires `google-genai` and a key. Without one it disables itself and the deterministic `FallbackPlanner` takes over |
| Adaptive action budget | Implemented | `engines/agentic/adaptive_budget.py` | `backend/tests/test_planner_budget.py` | Scales the budget to observed progress |
| Field classification and form entry | Implemented | `engines/agentic/field_classifier.py`, `field_taxonomy.py`, `field_constraints.py`, `form_recovery.py` | `tests/unit/test_form_entry.py`, `test_form_navigation_and_observation.py`, `backend/tests/test_credential_exploration.py` | Typed input against the synthetic victim profile |
| Scope guard and boundary control | Implemented | `engines/agentic/coverage_tracker.py`, `world_model.py` | `tests/unit/test_explorer_scope_guard.py`, `test_target_boundary_and_depth.py`, `backend/tests/test_boundary_exploration.py` | Keeps exploration inside the sample under test |
| Crash and ANR recovery | Implemented | `engines/agentic/crash_classifier.py`, `remediation.py` | `tests/unit/test_crash_and_loop_recovery.py`, `test_anr_is_not_a_crash_loop.py` | An ANR is classified distinctly from a crash loop |
| Screenshot policy and captions | Implemented | `engines/agentic/screenshot_policy.py`, `caption_generator.py`, `engines/screenshot_manager.py` | `tests/unit/test_screenshot_captions.py`, `test_screenshot_hardening.py`, `backend/tests/test_screenshot_api.py` | Duplicate suppression, bounded storage, disable with `SUDARSHAN_DISABLE_SCREENSHOTS` |
| Visual grounding | Partially implemented | `engines/agentic/visual_grounding.py` | `tests/unit/test_vision_captions.py` | OCR and vision fallback; needs `pytesseract` and a model key for the richer path |
| Agent memory and audit log | Implemented | `engines/agentic/agent_memory.py`, `audit_log.py` | `backend/tests/test_agentic_explorer.py` | Per-session action history |

## Evidence and reconstruction

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Runtime event bus | Implemented | `shared/sudarshan_core/engines/event_bus.py` | `tests/unit/test_evidence_pipeline.py`, `backend/tests/test_dynamic_event_pipeline.py` | Typed events with severity |
| Evidence store | Implemented | `shared/sudarshan_core/engines/evidence_store.py` | `tests/unit/test_evidence_provenance.py`, `backend/tests/test_artifact_persistence.py` | Normalised records with provenance |
| Memory bounds on evidence | Implemented | `engines/evidence_store.py`, `event_bus.py` | `backend/tests/test_memory_bounds.py` | Ring buffers and caps prevent unbounded growth |
| Workflow reconstruction | Implemented | `shared/sudarshan_core/engines/workflow_reconstructor.py` | `backend/tests/test_workflow_reconstructor.py`, `tests/unit/test_workflow_preconditions.py` | Temporal causal chains with confidence |
| MITRE ATT&CK mapping | Implemented | `shared/sudarshan_core/engines/mitre_mapper.py` | `frontend/src/components/investigation/MitreMatrix.test.tsx` | Ten distinct ATT&CK for Mobile techniques mapped |
| Behaviour graph | Implemented | `shared/sudarshan_core/engines/behavior_graph.py` | `backend/tests/test_workflow_reconstructor.py` | Relationship view over observed behaviour |
| IOC extraction | Implemented | `shared/sudarshan_core/engines/ioc_collector.py`, `backend/app/services/ioc_extraction.py` | `backend/tests/test_case_intel_enrichment.py` | Persisted to `case_iocs` |
| Visual evidence linking | Implemented | `shared/sudarshan_core/visual_evidence/` | `backend/tests/test_visual_evidence_linker.py`, `test_visual_evidence_claims.py`, `test_visual_evidence_api.py`, `test_visual_evidence_report.py`, `test_visual_evidence_phase3.py` | Links findings to screenshots and generates claims |
| Runtime telemetry API | Implemented | `backend/app/routes/runtime_api.py` | `backend/tests/test_dynamic_event_pipeline.py` | Health, status, hooks, events, pipeline, metrics, evidence, diagnostics |
| Resilience event stream | Implemented | `backend/app/services/resilience_events.py`, `resilience_summary.py` | `backend/tests/test_resilience_summary.py` | WebSocket stream with an HTTP replay-buffer fallback |

## Risk and scoring

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Five-axis STEI | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `backend/tests/test_risk_engine.py`, `backend/tests/test_static_scoring_wiring.py` | `0.60·CT + 0.20·BT + 0.10·PR + 0.05·OB + 0.05·IR` |
| Four-axis FRS | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `backend/tests/test_case_study_frs.py` | `0.25·STEI + 0.35·Dynamic + 0.20·Correlation + 0.20·BankingImpact` |
| Axis exclusion and renormalisation | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_risk_engine_nothing_happened.py` | An axis without data is excluded, not scored zero; `axes_used` and `axes_excluded` are returned |
| BFCI v2 | Implemented | `shared/sudarshan_core/engines/bfci_scorer.py` | `backend/tests/test_bfci_scorer.py` | Seven weighted categories, logarithmic volume scoring, ×1.25 sequence bonus in a 30 s window |
| Code-execution axis | Implemented | `shared/sudarshan_core/engines/bfci_scorer.py` | `tests/unit/test_code_execution_axis.py` | Weight 0.10; the six original categories scaled by 0.90 |
| Unscored evidence categories | Implemented | `shared/sudarshan_core/engines/bfci_scorer.py` | `tests/unit/test_ubiquitous_signal_not_scored.py` | `dangerous_apis`, `files_accessed`, `anti_analysis`, `device_fingerprint`, `app_telemetry`, `notification` |
| Visibility floor | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_concealed_sample_scoring.py`, `test_labelled_corpus.py` | Concealed payload with BFCI < 20 observed blocks a `Safe` verdict |
| Static evidence floor | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_risk_engine_nothing_happened.py` | STEI ≥ 50 with an empty dynamic run blocks a `Safe` verdict |
| Evasion floor | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_harness_attributed_evasion.py` | Only sample-attributed evasion counts |
| Execution Assertion Matrix | Implemented | `shared/sudarshan_core/engines/execution_assertions.py` | `tests/unit/test_risk_engine_nothing_happened.py` | `verdict = INCOMPLETE_EXERCISE`, confidence × 0.50 |
| VIDE escalation rules | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_vide_risk_escalation.py` | Signer mismatch ≥ 92, critical cluster ≥ 88, impersonation `min(55 + conf × 35, 75)` |
| Determinism invariant | Implemented | `shared/sudarshan_core/engines/replay_engine.py` | `backend/tests/test_determinism_replay.py` | Identical evidence yields an identical verdict |
| Family classification | Partially implemented | `shared/sudarshan_core/engines/classification_engine.py` | `backend/tests/test_classification_engine.py` | Confirms known families. On the labelled corpus, five of eight trojans were `Unknown` and three misattributed — it does not discover families |
| Threat scenario table | Implemented | `shared/sudarshan_core/engines/risk_engine.py` | `backend/tests/test_risk_engine.py` | Per-indicator risk narrative rows |

## Threat intelligence

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| VirusTotal / OTX / AbuseIPDB correlation | Implemented | `shared/sudarshan_core/services/threat_correlator.py` | `tests/unit/test_virustotal_crosscheck.py` | Parallel async queries; a missing key skips that source and excludes the axis |
| 24-hour IOC cache | Implemented | `backend/app/db/intel.py`, `threat_correlator.configure_ioc_cache` | `backend/tests/test_persistence_layer.py` | Injected by the backend; the analysis engine runs uncached |
| Case intelligence enrichment | Implemented | `backend/app/services/case_intel_enrichment.py` | `backend/tests/test_case_intel_enrichment.py` | Merges correlation into the stored case |
| Network signature matching | Implemented | `shared/sudarshan_core/engines/network_signatures.py` | `tests/unit/test_network_signatures.py` | C2 patterns over captured traffic |
| Analysis history and run comparison | Implemented | `shared/sudarshan_core/engines/analysis_history.py`, `backend/app/db/intel.py` | `backend/tests/test_persistence_layer.py` | Per-package run trend and deltas |

## AI investigation

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Gemini provider manager | Implemented | `shared/sudarshan_core/ai/gemini_provider.py`, `gemini_settings.py` | `tests/unit/test_gemini_provider.py`, `test_gemini_fallback.py` | Primary/fallback slots, per-slot circuit breaker, 60 s cooldown, bounded retries |
| Model-compatibility shim | Implemented | `shared/sudarshan_core/ai/gemini_provider.py` | `tests/unit/test_gemini_fallback.py` | Strips Gemini 3.x thinking config when failing over to a 2.5 model |
| Evidence-grounded RAG | Implemented | `backend/app/ai/gemini_rag.py` | `backend/tests/test_visual_evidence_rag.py` | Per-SHA-256 investigation graph, intent detection, bounded prompt |
| Server-side chat history | Implemented | `backend/app/routes/report.py`, `backend/app/db/intel.py` | `backend/tests/test_persistence_layer.py` | Client-supplied history is accepted for compatibility and ignored; capped at 20 turns |
| Prompt-injection sanitizer | Implemented | `shared/sudarshan_core/engines/agentic/sanitizer.py` | `backend/tests/test_prompt_injection.py` | Single choke point; neutralises fence delimiters, bounds length, never raises |
| Banking knowledge base | Partially implemented | `backend/app/rag/knowledge_base.py` | `backend/tests/test_remaining_features.py` | ChromaDB mode when installed; otherwise keyword lookup |
| Artifact explanation | Implemented | `shared/sudarshan_core/ai/artifact_explainer.py`, `backend/app/routes/report.py` | `tests/unit/test_artifact_explainer.py` | `POST /api/v1/explain/artifact` |
| Deterministic narrative fallback | Implemented | `shared/sudarshan_core/engines/report_generator.py` | `backend/tests/test_report_generator.py` | With no key or all providers open, reporting emits a template narrative from engine output |
| AI influence on the risk score | Not implemented, by design | — | `backend/tests/test_determinism_replay.py` | No code path allows model output to reach the scoring functions |

## Reporting and export

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| ReportLab PDF dossier | Implemented | `shared/sudarshan_core/engines/pdf_generator.py` | `backend/tests/test_pdf_generator.py`, `backend/tests/test_screenshot_report_pipeline.py` | Provenance-tagged fields, gauges, screenshot gallery |
| Standalone HTML report | Implemented | `shared/sudarshan_core/engines/report_generator.py` | `backend/tests/test_report_generator.py` | Single self-contained file |
| STIX 2.1 export | Implemented | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | Deterministic UUIDv5 identifiers |
| IOC CSV and TXT export | Implemented | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | SIEM-ready CSV and a plain indicator list |
| YARA rule export | Implemented | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | Rule name and string values sanitised so the output compiles |
| Suricata and Snort export | Implemented | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | Built from observed network indicators |
| MITRE mapping export | Implemented | `backend/app/routes/report.py` | `frontend/src/components/investigation/MitreMatrix.test.tsx` | JSON technique mapping |
| Investigation section in reports | Implemented | `shared/sudarshan_core/engines/report_generator.py` | `tests/unit/test_report_investigation_section.py` | Execution assertions and suggested triggers appear in the report |

## Analyst interface

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| React 18 SPA | Implemented | `frontend/src/App.tsx` | `frontend/src/test/AuthFlowMatrix.test.tsx` | Lazy routes with retry on stale-chunk failure |
| Case-addressed routes | Implemented | `frontend/src/lib/caseRoutes.ts` | `frontend/src/lib/caseRoutes.test.ts` | `/case/:sha256` with `evidence`, `intel`, `ask` sections; legacy paths redirect |
| Upload and live pipeline | Implemented | `frontend/src/components/upload/` | `frontend/src/components/upload/backendPipelineStages.ts` | Stage stepper driven by backend job progress |
| Case summary and verdict | Implemented | `frontend/src/pages/FraudCard.tsx` | `frontend/src/components/investigation/VerdictBlock.test.tsx`, `RiskInfluenceCard.test.tsx` | Score gauge, risk influence, recommended action |
| Technical evidence view | Implemented | `frontend/src/pages/TechnicalView.tsx` | `frontend/src/components/investigation/CoreFindingsList.test.tsx`, `AnalysisTabs.test.tsx` | Findings registry, evidence drawers, screenshots |
| Score ledger and influence detail | Implemented | `frontend/src/components/investigation/ScoreLedgerSlideOver.tsx`, `scoreInfluence/` | `frontend/src/lib/scoreInfluenceModel.ts` | Per-axis contribution, auditable against the engine |
| Threat intelligence view | Implemented | `frontend/src/pages/ThreatIntelView.tsx` | `frontend/src/components/threatIntel/IntelligenceSourcesPanel.test.tsx` | Sources, attribution, IOC registry, similarity |
| Visual impersonation panels | Implemented | `frontend/src/components/investigation/VisualImpersonationPanel.tsx`, `VisualDiffViewer.tsx` | `frontend/src/lib/visualEvidence.test.ts` | Baseline-vs-suspect diff and forensic breakdown |
| Attack story timeline | Implemented | `frontend/src/components/investigation/AttackStory.tsx` | `frontend/src/lib/attackStory.test.ts` | Causal chain with MITRE technique labels |
| MITRE matrix | Implemented | `frontend/src/components/investigation/MitreMatrix.tsx` | `frontend/src/components/investigation/MitreMatrix.test.tsx` | Technique coverage grid |
| AI investigation chat | Implemented | `frontend/src/pages/InvestigationChat.tsx` | `frontend/src/components/investigation/AiExplanation.test.tsx` | Streaming, grounded on the stored case |
| Analyst notes | Implemented | `frontend/src/components/investigation/AnalystNotesPanel.tsx` | Backend `GET`/`POST /api/v1/cases/{sha256}/notes` | Persisted per case |
| Case history registry | Implemented | `frontend/src/pages/History.tsx` | Backend `GET /api/v1/cases` | Server-side search and band filter |
| Batch scan management | Implemented | `frontend/src/pages/BatchScan.tsx`, `BatchDetail.tsx` | `frontend/src/components/batch/useBatchProgress.ts` | Queue, progress, pause/resume/cancel/retry |
| Resilience panel | Implemented | `frontend/src/components/investigation/ResiliencePanel.tsx` | `frontend/src/hooks/useResilience.ts` | Assertions, suggestions, anti-evasion controls |
| URL discovery area | Implemented | `frontend/src/components/discovery/UrlDiscoveryArea.tsx` | Backend `/api/v1/discovery` | Crawl and ingest from the upload page |
| Reduced-motion support | Implemented | `frontend/src/hooks/useReducedMotion.ts` | `frontend/src/hooks/useReducedMotion.test.ts` | Animated components degrade to static |

## Platform and operations

| Feature | Status | Implementation | Evidence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Docker Compose stack | Implemented | `docker-compose.yml` | — | frontend, backend, analysis-engine, mitmproxy, mobsf |
| Hardened production overlay | Implemented | `docker-compose.hardened.yml`, `deploy/security/seccomp-analysis-engine.json` | `docs/security/P0_SANDBOX_ESCAPE_INCIDENT.md` | Read-only rootfs, `cap_drop: ALL`, seccomp, no dev bind-mounts |
| Windows one-command bootstrap | Implemented | `start.ps1` | — | `-Detach` and `-SkipSandbox` variants |
| Preflight checks | Implemented | `scripts/preflight.py`, `shared/sudarshan_core/preflight.py` | `backend/tests/test_frida_preflight.py` | `--container`, `--strict`, `--json` |
| Database migrations | Implemented | `backend/app/db/migrations.py` | `backend/tests/test_persistence_layer.py` | Additive only |
| Retention sweeper | Implemented | `backend/app/workers/retention.py` | `backend/tests/test_persistence_layer.py` | Purges operational state; never forensic records |
| Baseline refresh worker | Implemented | `backend/app/workers/baseline_refresh.py` | `backend/tests/test_baselines_api.py` | Interval refresh plus an admin-triggered endpoint |
| Demo user seeding | Implemented | `backend/app/demo_seed.py` | `backend/tests/test_demo_seed.py` | Credentials come from `.env`; none are committed |
| Labelled corpus validation | Implemented | `scripts/validate_corpus.py`, `shared/sudarshan_core/validation/` | `docs/evaluation/corpus_static_validation.json`, `tests/unit/test_labelled_corpus.py` | Regenerable artifact; corpus is gitignored so it never runs in CI |
| Pipeline performance measurement | Implemented | `shared/sudarshan_core/engines/pipeline_timing.py` | `backend/tests/test_pipeline_performance.py` | Per-stage timings on every run |
| Continuous integration | Not implemented | — | — | No `.github/` directory exists. The only automated git-side gate is `.githooks/pre-push` |
| Horizontal scaling | Planned | — | — | Single SQLite file and an in-process queue; needs Postgres and an external broker |
