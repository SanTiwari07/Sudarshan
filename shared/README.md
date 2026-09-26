# Shared core — `sudarshan_core`

The domain layer both services depend on. Everything that decides something — what a sample is, what it did, and what it scores — lives here rather than in the backend or the analysis engine, so the two cannot drift apart.

Packaged as `sudarshan-core` 1.0.0 ([`pyproject.toml`](pyproject.toml)), requires Python ≥ 3.11. Both service images install it editable at `/opt/sudarshan-core` and bind-mount `./shared` over it in development.

- Platform overview: [`../README.md`](../README.md)
- Consumers: [`../backend/README.md`](../backend/README.md), [`../analysis-engine/README.md`](../analysis-engine/README.md)

> No dependency list is declared here on purpose. The two consuming services pin their own versions in their `requirements.txt`; duplicating them would reintroduce exactly the drift this package exists to remove.

Package data that ships with the wheel: the Frida agent bundles (`engines/frida_hooks/*.js`, `*.json`) and the brand marks (`brand/*.png`). Both are resolved at runtime from `Path(__file__).parent`, so an installed copy without them loses the agent and the report masthead.

---

## Module map

```text
sudarshan_core/
├── ai/                  Gemini provider manager, settings, artifact explainer
├── analyzers/           Native Androguard APK analyzer
├── brand/               Brand marks used by the PDF and HTML renderers
├── engines/             Analysis, scoring, reporting and exploration engines
│   ├── agentic/         Perception, planning, dispatch, verification, memory
│   ├── frida_hooks/     Frida agent sources and compiled bundles
│   └── vide/            Visual impersonation detection pipeline
├── ingest/              APK record model
├── models/              Pydantic schemas and the investigation manifest
├── sandbox/             SandboxProvider implementations and the device channel
├── security/            ADB gateway, containment policy, internal auth
├── services/            MobSF client, threat correlator
├── validation/          Labelled corpus, static scoring, coverage, stress harnesses
├── visual_evidence/     Finding-to-screenshot linking and claim templates
├── preflight.py         Environment and toolchain checks
└── runtime_paths.py     Artifact path resolution
```

---

## Engines

### Static analysis

| Module | Responsibility |
| :--- | :--- |
| [`analyzers/apk_analyzer.py`](sudarshan_core/analyzers/apk_analyzer.py) | Androguard manifest and DEX analysis, permissions, components, entropy, indicators, concealed-payload detection |
| [`engines/apk_repair.py`](sudarshan_core/engines/apk_repair.py) | Rebuilds malformed AXML and string tables, resigns the APK, computes SHA-256 |
| [`engines/apktool_engine.py`](sudarshan_core/engines/apktool_engine.py) | APKTool 2.10.0 resource and smali extraction |
| [`engines/jadx_engine.py`](sudarshan_core/engines/jadx_engine.py) | JADX 1.5.1 DEX-to-Java decompilation and fraud-pattern scanning |
| [`models/manifest.py`](sudarshan_core/models/manifest.py) | Investigation manifest — the minimal hook profile the dynamic run needs |
| [`engines/capability_profile.py`](sudarshan_core/engines/capability_profile.py) | Declared capability summary bridging static findings to runtime expectations |

### Dynamic analysis

| Module | Responsibility |
| :--- | :--- |
| [`engines/frida_sandbox.py`](sudarshan_core/engines/frida_sandbox.py) | Sandbox controller: install, launch ladder, PID resolution, ART deopt, hook install and verify, event collection |
| [`engines/dae_pipeline.py`](sudarshan_core/engines/dae_pipeline.py) | Explicit 16-state pipeline machine with logged transitions |
| [`engines/agentic_explorer.py`](sudarshan_core/engines/agentic_explorer.py) | Deep UI exploration driver |
| [`engines/agentic/`](sudarshan_core/engines/agentic/) | Perception, screen classification, screen graph, planner, action dispatch, action verifier, goal tracking, memory, remediation, sanitizer |
| [`engines/ui_explorer.py`](sudarshan_core/engines/ui_explorer.py) | Model-assisted exploration path (requires `google-genai`) |
| [`engines/permission_orchestrator.py`](sudarshan_core/engines/permission_orchestrator.py), [`permission_investigator.py`](sudarshan_core/engines/permission_investigator.py) | Permission pre-grant policy and grant-dialog investigation |
| [`engines/anti_evasion.py`](sudarshan_core/engines/anti_evasion.py), [`anti_analysis_detector.py`](sudarshan_core/engines/anti_analysis_detector.py) | Evasion probing and anti-analysis event detection |
| [`engines/device_state_simulator.py`](sudarshan_core/engines/device_state_simulator.py), [`time_warp.py`](sudarshan_core/engines/time_warp.py), [`persona.py`](sudarshan_core/engines/persona.py) | Synthetic device state, clock advancement, victim persona seeding |
| [`engines/network_capture.py`](sudarshan_core/engines/network_capture.py), [`network_signatures.py`](sudarshan_core/engines/network_signatures.py) | HAR ingest, socket and HTTP evidence, C2 signature matching |
| [`engines/multi_stage_engine.py`](sudarshan_core/engines/multi_stage_engine.py), [`agentic/secondary_payload.py`](sudarshan_core/engines/agentic/secondary_payload.py) | Second-stage payload observation |

### Evidence and reconstruction

| Module | Responsibility |
| :--- | :--- |
| [`engines/event_bus.py`](sudarshan_core/engines/event_bus.py) | `RuntimeEventBus` and the `RuntimeEvent` / `EventType` vocabulary |
| [`engines/evidence_store.py`](sudarshan_core/engines/evidence_store.py) | Normalised, deduplicated evidence records with provenance |
| [`engines/screenshot_manager.py`](sudarshan_core/engines/screenshot_manager.py) | Capture, dedup policy, storage layout |
| [`engines/workflow_reconstructor.py`](sudarshan_core/engines/workflow_reconstructor.py) | Temporal causal chains from evidence to fraud stages |
| [`engines/mitre_mapper.py`](sudarshan_core/engines/mitre_mapper.py) | MITRE ATT&CK for Mobile technique mapping |
| [`engines/behavior_graph.py`](sudarshan_core/engines/behavior_graph.py) | Behaviour relationship graph |
| [`engines/ioc_collector.py`](sudarshan_core/engines/ioc_collector.py) | Indicator extraction and normalisation |
| [`visual_evidence/`](sudarshan_core/visual_evidence/) | Links findings to screenshots, generates claims, merges into the API payload |

### Scoring

| Module | Responsibility |
| :--- | :--- |
| [`engines/risk_engine.py`](sudarshan_core/engines/risk_engine.py) | STEI, FRS, axis exclusion and renormalisation, risk bands, escalation rules, four safety floors, confidence |
| [`engines/bfci_scorer.py`](sudarshan_core/engines/bfci_scorer.py) | BFCI v2 — seven weighted categories, logarithmic volume scoring, fraud sequence detection |
| [`engines/execution_assertions.py`](sudarshan_core/engines/execution_assertions.py) | Execution Assertion Matrix and the `INCOMPLETE_EXERCISE` verdict |
| [`engines/classification_engine.py`](sudarshan_core/engines/classification_engine.py) | Deterministic malware-family classifier |

Scoring is the authority on `base_score`, `final_risk_score`, `risk_band` and `verdict`. Nothing in `ai/` can reach it.

### VIDE

[`engines/vide/`](sudarshan_core/engines/vide/) detects visual impersonation of banking brands by comparing the suspect's UI against baselines on three axes — string containment, view-hierarchy structure and CIEDE2000 ΔE colour distance — plus a fail-closed signer registry. Detection threshold is `0.20` in both `compare.py` and `corpus_compare.py`; the fuzzy string axis matches at `82.0`. See [`../docs/02_ANALYSIS/VISUAL_IMPERSONATION.md`](../docs/02_ANALYSIS/VISUAL_IMPERSONATION.md).

### Reporting

| Module | Responsibility |
| :--- | :--- |
| [`engines/pdf_generator.py`](sudarshan_core/engines/pdf_generator.py) | ReportLab dossier with provenance-tagged fields, gauges, bar meters and screenshot gallery |
| [`engines/report_generator.py`](sudarshan_core/engines/report_generator.py) | Self-contained single-file HTML report |
| [`engines/report_theme.py`](sudarshan_core/engines/report_theme.py) | Shared visual tokens for both renderers |

---

## Sandbox layer

[`sandbox/`](sudarshan_core/sandbox/) isolates device lifecycle from analysis logic behind `SandboxProvider`.

| `SANDBOX_PROVIDER` | Class | Status |
| :--- | :--- | :--- |
| `auto` (default) | `AutoDetectProvider` | Probes `adb devices` and selects Genymotion or AVD |
| `genymotion` | `GenymotionProvider` | Supported |
| `android_avd`, `android_studio`, `androidstudio`, `avd`, `emulator` | `AndroidStudioProvider` | Supported |
| `physical` | `PhysicalDeviceProvider` | Supported |
| `corellium`, `waydroid`, `future` | `CorelliumProvider`, `WaydroidProvider`, `FutureProvider` | Extension points, not usable backends |

`get_sandbox_provider()` caches one provider per configuration key; `register_provider()` allows tests and plugins to override. [`device_channel.py`](sudarshan_core/sandbox/device_channel.py) prefers a persistent `uiautomator2` session and degrades to per-command ADB when that package is absent — missing it makes runs slow, not broken.

---

## Security layer

| Module | Responsibility |
| :--- | :--- |
| [`security/adb_gateway.py`](sudarshan_core/security/adb_gateway.py) | The single choke point for ADB subprocess execution. Every component must go through `run_adb` or `SandboxProvider.adb` |
| [`security/sandbox_containment.py`](sudarshan_core/security/sandbox_containment.py) | Control-plane policy: allowed ADB targets, Frida listen address, blocked subcommands, production fail-closed validation |
| [`security/internal_auth.py`](sudarshan_core/security/internal_auth.py) | Shared-secret authentication between gateway and engine |

Blocked ADB subcommands: `tcpip`, `usb`, `pair`, `unpair`, `kill-server`, `start-server`.

---

## AI layer

[`ai/gemini_provider.py`](sudarshan_core/ai/gemini_provider.py) is the only place a model is called. It manages primary and fallback slots, a per-slot circuit breaker with cooldown, bounded retries with exponential backoff, and automatic stripping of Gemini 3.x thinking configuration when failing over to a 2.5 model. [`ai/gemini_settings.py`](sudarshan_core/ai/gemini_settings.py) resolves keys and models from the environment and reports one of `failover`, `primary_only`, `fallback_only` or `unconfigured`.

[`engines/agentic/sanitizer.py`](sudarshan_core/engines/agentic/sanitizer.py) is the single sanitization choke point for attacker-controlled strings. It neutralises prompt fence delimiters, defangs rather than drops, bounds output length, and never raises. It performs no scoring and is never consulted by the risk engine.

---

## Validation harnesses

[`validation/`](sudarshan_core/validation/) holds the machinery behind the reproducible evaluation artifacts:

| Module | Purpose |
| :--- | :--- |
| `labelled_corpus.py` | Resolves the labelled corpus from `SUDARSHAN_LABELLED_CORPUS_DIR` or known default locations |
| `static_scoring.py` | Static-only scoring pass used by `scripts/validate_corpus.py` |
| `corpus.py`, `runner.py` | Corpus iteration and run orchestration |
| `coverage.py`, `screenshot_audit.py` | Exploration coverage and screenshot quality audits |
| `recovery.py`, `stress.py` | Failure-recovery and load harnesses |
| `virustotal_crosscheck.py` | Cross-checks engine verdicts against VirusTotal |
| `engineering_report.py` | Renders validation output into a report |

The corpus itself is gitignored — it contains live banking trojans — so these harnesses never run in CI.

---

## Working on this package

Both service containers bind-mount `./shared`, so edits take effect on the next request without a rebuild. Tests import from the installed path; run them from the repository root:

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=test_secret \
  python -m pytest tests/ backend/tests -q
```

Argument order matters — `backend/tests/conftest.py` is the only conftest and it bootstraps `sys.path` for this package.

Guidance specific to this layer:

- Changing a BFCI weight, a category cap, an FRS axis weight or a safety-floor threshold is a **model change**. It moves existing verdicts and must be validated against the labelled corpus before merge.
- Adding a scored BFCI category is the same kind of change. `UNSCORED_CATEGORIES` exists so behaviour worth recording but not worth scoring has somewhere to go without inflating every verdict.
- Never add a second path to ADB. Anything that needs the device goes through `adb_gateway`.
- Never escape untrusted strings at a call site. Anything heading for a prompt goes through `sanitizer`.
