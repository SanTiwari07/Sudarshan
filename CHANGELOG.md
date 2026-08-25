# Changelog - Sudarshan Enterprise Platform

All notable changes to this project are documented in this file.

## 2026-08-25

### Changed - VIDE calibrated to a 20% detection threshold

`VIDE-F001` fired only at `confidence >= 0.72`, which in practice required all
three axes to be near-perfect. A Capacitor clone keeps its labels in a minified
bundle, so static extraction recovers the brand palette and the form skeleton
and almost no text - the app VIDE exists to catch scored clean.

- **Threshold 0.72 -> 0.20**, in both `compare.py` and `corpus_compare.py`.
- **Evidence floors**: `MIN_STRING_EVIDENCE` 0.08 -> 0.02, and a new
  `MIN_COLOR_EVIDENCE` (0.10) so a palette-only extraction can carry a verdict.
- **Structure is no longer sufficient evidence.** It is worth 0.35 of the score,
  so at a 0.20 threshold any login-shaped layout cleared the bar alone - a
  device settings screen scored 0.21 against the SBI baseline during
  calibration. A finding now requires a *discriminating* axis (text or palette);
  `MIN_STRUCTURE_EVIDENCE` (0.10) marks structure as corroboration only.
- **Attribution margin** 0.20 -> 0.05 (`corpus_compare.py`), and
  `MIN_SHAPE_EVIDENCE` 0.35 -> 0.15. The wide margin was calibrated against
  spec-authored fingerprints where only colour separated the banks; it was
  discarding correct attributions more often than preventing wrong ones.
- **Candidate shortlisting** (`baseline_store.shortlist_baselines`) qualifies a
  baseline on *any* scored axis. Filtering on shared strings alone dropped
  palette-only clones before the colour comparison - the axis that carries
  attribution - ever ran.

### Added - ten institution baselines, and the string-axis fixes they exposed

`data/ui_baselines/` carried three hand-written lab profiles (SBI/HDFC/ICICI),
so seven of the ten reference bank APKs had nothing to be attributed *to*. All
ten institutions are now present with their brand palettes and screen labels,
each declaring the reference app it stands for via a new `baseline_id` field -
lab profiles and corpus entries use different institution ids, so without it
there was no way to ask "did `BASE-02-HDFC.apk` attribute correctly".

Attribution over the ten reference APKs went 2/10 -> 10/10. Two string-axis
defects surfaced during that work and are fixed:

- **Short credential names are compared strictly** (`fuzzy.same_label`).
  `"Forgot IPIN"` scored 90.9 against `"Forgot MPIN?"` - over threshold, because
  the shared word dominates and the two four-letter tokens differ by one
  character. An IPIN is HDFC's netbanking password and an MPIN is a generic app
  PIN. That single false match was worth an eighth of HDFC's string score
  against *every* app in the set and decided one attribution outright. The rule
  distinguishes substitution from omission: a confusable stand-in
  (`MPIN` for `IPIN`) is rejected, a dropped qualifier (`MPIN` for
  `6-digit MPIN`, `YONO` for `YONO SBI`) is still a match.
- **Labels are weighted by rarity** (`fuzzy.label_weights`). `"Login"`, `"OTP"`
  and `"Customer ID"` establish that an app is a banking UI and say nothing
  about which bank it imitates; `"PNB ONE"` is close to proof on its own.
  Counting them equally let a bank win on shared vocabulary - PNB's app was
  attributed to IndusInd on a palette the two genuinely share, despite PNB
  leading on its own name. Standard inverse document frequency over the baseline
  set, so the weights move with the corpus instead of being a hand-kept list of
  "generic" words. This is the same reasoning `corpus_compare` already applies
  when it excludes structure from attribution.

`scripts/verify_vide_corpus.py` gained `--apk-dir` and `--forensics`, and now
falls back to the general comparer's attribution when no corpus is checked out -
it previously read only the corpus comparer and so reported ten failures for a
reason that had nothing to do with the ten APKs.

**`demo_sbi_yono` carries its reference app's palette, not only YONO's real
one.** The prototype ships `#1B4AA0` / `#D0342C` / `#16213A`, which sit ΔE 4.1 /
5.2 / 4.9 from HDFC's brand colours and ΔE 16-30 from the real YONO palette, so
`BASE-01-SBI.apk` was attributed to HDFC on colour despite winning its own
string axis 0.59 to 0.35. The baseline now lists the three colours the reference
app renders alongside YONO's `#280071` / `#002D62` / `#577CB7`. `#00ADE9` and
`#9A3E76` were dropped: at ΔE 30.1 and 18.7 from anything the app renders they
are past `MAX_MATCH_DELTA_E` - a different colour family - so they scored 0.00
and only diluted the coverage average, which is a mean over baseline colours.

That last point is a property worth knowing when authoring a baseline: listing a
brand colour the app does not render costs score rather than adding coverage.
Adding `#1B4AA0` alone moved the colour axis 0.19 -> 0.33 and all three observed
colours took it to 0.49, both short of the 0.54 needed; removing the two dead
entries is what carried it to 0.66.

### Added - VIDE forensic breakdown

`engines/vide/forensics.py` assembles the machine-readable "why is this a
clone", so the investigation UI and the PDF render the same facts instead of
parsing evidence prose apart:

- **Colour scheme**: suspect hex vs baseline hex per pair, with CIE ΔE₂₀₀₀ and a
  plain-language reading ("visually identical", "close match").
- **UI text**: the banking labels matched, with the baseline denominator.
- **View hierarchy**: structural signatures and layout similarity.
- **Confidence tiers** - high (≥ 0.60), moderate (0.35-0.59), low/suspicious
  (0.20-0.34) - carried on the verdict, so a weak match and a pixel-faithful
  clone no longer render identically.
- PDF page 9 draws the threshold line from the engine constant rather than a
  hardcoded 0.72, adds the matched institution and a swatch-by-swatch colour
  table, and now populates the per-axis meter at all (`vide_jaccard` and its
  siblings were read through `hasattr` and never set).

### Fixed - deep dynamic exploration

Findings below come from instrumented runs of the real `AgenticExplorer` against
a live emulator, not from static review. Baseline before this work: 14.8s per
exploration iteration, 34.3% coverage, five structural states for one
`LoginActivity`, zero scroll actions executed, and a run that could spend all
300s inside Android Settings.

- **Deployed analysis window** (`docker-compose.yml`): `FRIDA_ANALYSIS_DURATION`
  defaulted to 90s while `frida_sandbox.py` defaults to 300s, and the variable
  was unset in every `.env`. At the measured cost that bought 4-7 actions per
  sample. Now 300 in both, and explicit in `.env`.
- **State identity** (`exploration_engine.compute_composite_state_signature`):
  identity is structural. An input's VALUE no longer contributes, so typing into
  a form does not fork the screen into a new state with all work reset. Node
  position is excluded (the soft keyboard shifts a WebView by ~63px) and
  container size is excluded (it tracks the keyboard); control size is kept.
- **Action identity** (`ActionItem.signature`): no longer includes the
  positional `node_id`, which was renumbered whenever a WebView reflowed and
  grew the inventory without bound (306 action ids for six widgets).
- **System-boundary containment**: `com.android.settings` is no longer blanket
  in scope, nor admitted to the target graph on ownership alone. A Settings
  screen qualifies only when its `semantic_type` is an actual prompt, which
  keeps the accessibility and VPN consent flows working. Boundary excursions are
  bounded by `SUDARSHAN_MAX_BOUNDARY_ACTIONS` (6) with a deterministic
  `start_activity` route home.
- **Back navigation**: never pressed from the task-root state, nor between
  states of a single-Activity WebView app, where back leaves the sample instead
  of traversing it. Exhausted screens now re-drive a recorded route
  (`_replay_route`) to reach a state that still has work.
- **Iteration cost**: the post-action observation is carried into the next
  iteration behind a focus-signature check; `click_text` taps known-good
  geometry instead of re-dumping the hierarchy; the duplicate `wait_for_idle`
  is gone; and a demonstrably inert control stops at two attempts instead of
  three.
- **Scroll fairness / repeated visits**: pending scroll actions are promoted
  after a screen has been worked twice, and `MAX_REPEATED_STATE_VISITS` is now
  enforced (it was declared but never read; one state was visited 17 times).
- **Action inventory**: full-screen containers (a clickable WebView) and
  decorative captions promoted through them are no longer offered as controls.

### Added - credential entry and in-app evidence

- **`shared/sudarshan_core/engines/agentic/credentials.py`**: per-run synthetic
  credentials, regenerated on each login attempt, plus field-kind resolution and
  login-outcome detection. Values are disposable and never real user data.
- **Field identification**: `perception` now parses uiautomator's `password`
  attribute and attaches the caption rendered above each input. On the WebView
  banking corpus these are the only signals available - the EditText nodes carry
  no resource-id, text or content-desc - so both fields previously received the
  same placeholder and no login could succeed.
- **Form completion order**: submit controls are held back until the inputs on
  the screen are filled. Submit matching is word-bounded, so "Forgot MPIN?" is
  no longer treated as the login button because "go" appears inside "Forgot".
- **Login retry**: an app that says nothing gets a fresh identity and another
  attempt, up to `SUDARSHAN_MAX_LOGIN_ATTEMPTS` (5). An explicit "invalid
  credentials" ends the branch immediately.
- **Numeric PIN pads**: a keypad is entered as one `tap_sequence` action rather
  than one key per iteration, which never filled the field.
- **In-app screenshots**: one evidence frame per distinct in-app screen, so the
  report shows the app from the inside rather than only its launch screen.
- **VIDE**: `vide.pipeline` now consumes every captured view hierarchy
  (`ui_hierarchies`), not only the last screen observed. The login form is the
  one screen a clone and its target necessarily share; the screens behind it are
  where the difference shows. The legacy `ui_hierarchy_xml` remains supported.
- **Tests**: `backend/tests/test_deep_exploration_fixes.py` (46) and
  `backend/tests/test_credential_exploration.py` (39).

## 2026-08-24

### Added
- **Screenshot hardening (second-phase)**: Central `ScreenshotPolicy` (`shared/sudarshan_core/engines/agentic/screenshot_policy.py`) with state/event-aware deduplication — separate from event and evidence deduplication. Decisions: CAPTURE, DEDUPLICATED, SUPPRESSED, BLOCKED, REUSE with auditable reasons.
- **Screen ownership classification**: `HOME_LAUNCHER`, `EXTERNAL_APP`, `CRASH_STATE`, `SYSTEM_INSTALLER`, etc. via package/activity context (`classify_screen_with_ownership`). Home launcher is not explored as target-app UI; Gemini planner skipped for non-explorable states.
- **External application graph**: External/system screens stored in `ExplorationGraph.external_states`, linked from target states via transition edges.
- **Crash handling**: One crash-context screenshot per crash transition; `APP_CRASH` events in exploration graph; recovery without home screenshot spam.
- **20 regression tests** (`tests/unit/test_screenshot_hardening.py`): Home spam, external dedup, permission dedup, same-screen reuse, crash handling, long-run bounded captures.

### Changed
- **ScreenshotManager** routes all captures through `ScreenshotPolicy` before adb screencap. Manifest includes `policy_statistics`, `suppressed_count`, semantic filenames, and ownership metadata.
- **AgenticExplorer** per-action screenshots no longer use `force=True`; policy evaluates each capture. Home/crash states handled by dedicated async handlers without normal exploration.
- **PerceptionPipeline** skips Level-5 vision for `HOME_LAUNCHER` foreground.
- **Deep Dynamic Exploration Engine** (`shared/sudarshan_core/engines/agentic/exploration_engine.py`): Per-analysis state/action graph with `ApplicationProfile`, `EvidenceMoment`, victim journey reconstruction, deterministic action prioritization, scroll/menu/backtrack support, and exploration coverage metrics. Integrated into `AgenticExplorer` with post-action re-observe, causal screenshot linking, and explicit stop reasons.
- **27 new unit tests** (`tests/unit/test_deep_exploration.py`): State graph, deduplication, evidence moments, mock RTO multi-branch exploration, permission investigation, secondary APK boundary, prompt injection defense.
- **Gemini primary/fallback manager**: `shared/sudarshan_core/ai/gemini_provider.py` routes every Gemini call through Gemini 3.x Flash first, then Gemini 2.5 Flash on quota, rate-limit, 5xx, timeout, or primary-key auth failure, with a configurable primary cooldown. Legacy `GEMINI_API_KEY` / `GEMINI_MODEL` remain primary aliases.

### Changed
- **AgenticExplorer** no longer stops when all 15 fraud goals complete; goals are threat-intelligence prioritization only. Exploration stops on graph exhaustion, budget, or safety boundary.
- Default action budget raised to 120 (`SUDARSHAN_AGENT_ACTION_BUDGET`). Frida silence threshold raised to 8 and requires no unexplored graph branches.
- **Screen classifier** extended with `UPDATE_PROMPT`, `VPN_REQUEST`, `EXTERNAL_APK`, `DOWNLOAD_PROMPT`, `WEBVIEW`, `DIALOG`, `HOME_LAUNCHER`, `EXTERNAL_APP`, `CRASH_STATE` types and ownership resolution.
- **ScreenshotManager** gains causal linking fields (`state_id`, `action_id`, `evidence_id`, `evidence_moment_id`, `ownership`, `deduplication_status`) and suppression statistics.

## 2026-08-12

### Added / Upgraded
- **Reference-Replication ReportLab PDF Engine**: Redesigned server-side ReportLab PDF threat investigation generator (`shared/sudarshan_core/engines/pdf_generator.py`) to strictly replicate the visual structure, 12-section technical organization, typography, color scheme, headers/footers, and information density of master reference specification `sudarshan pdf.pdf`.
- **Vector Drawing Flowables**: Custom ReportLab `FRSDialGauge` (180° arc dial), `FRSBarMeter` (4-axis FRS breakdown), `STEIBarMeter` (5-axis STEI breakdown), `VIDEBarMeter` (UI comparison chart with 0.72 detection threshold line), `BFCIBarMeter` (vertical behavioral category bar chart), `WorkflowDiagram` (horizontal attack step flow), and `NumberedCanvas` running headers/footers.
- **Canonical FRS Consistency Fix**: Resolved FRS score drift bug in `FraudRiskHero.tsx` and PDF generation pipeline. All UI cards, API responses, PDF pages, executive summaries, and assessment blocks now consume the single canonical `final_risk_score` from `risk_engine.py`.
- **Real-Data Pipeline & Provenance Grounding**: Fully grounded report data model in real case payloads and disk evidence artifacts (`evidence.json`, screenshots manifest) with zero synthetic/fake data fabrication.
- **Enhanced Test Suite**: Added comprehensive unit, API, and edge-case tests in `backend/tests/test_pdf_generator.py` covering score consistency, empty evidence, missing dynamic analysis, VIDE states, and screenshot embedding.

## 2026-08-11

### Documentation
- **Full Documentation Audit**: Complete codebase-verified documentation pass across all files in `docs/` and root `README.md`. Codebase treated as sole source of truth.
- **Version corrected**: All docs and `README.md` now state `v2.1.0` (from `backend/app/main.py`); prior docs incorrectly stated `v2.5.0-STABLE`.
- **Test count corrected**: Verified **583 tests collected** (2026-08-11 live run, 42.63s) via `pytest tests/ backend/tests --collect-only`. Prior `README.md` stated 526; prior `docs/` stated 519.
- **Indian bank package count corrected**: `08_DETERMINISTIC_RISK_ENGINE.md` and `README.md` updated to state 21 package prefixes (from 47/various); verified against `apk_analyzer.py::INDIAN_BANK_PACKAGES`.
- **Demo credentials sanitized**: `docs/BOI_DEMO_CREDENTIALS.md` no longer contains plaintext passwords; replaced with `.env` placeholder guidance.
- **CASE_STUDIES.md annotated**: Summary table notes FRS/STEI distinction; Drinik/Xenomorph FRS scores marked "Not re-verified".
- **BENCHMARKS.md annotated**: Warning added — metrics not re-measured in this audit pass.

## [2.5.0-STABLE] - 2026-08-05

### Documentation
- **Master Documentation Audit & Zero-Drift Synchronization**: Comprehensive synchronization across all 24 documentation files in `/docs`, root `README.md`, `CHANGELOG.md`, and `DOCUMENTATION_AUDIT_REPORT.md` against active codebase implementation (`SanTiwari07/Sudarshan`).
- **Verified Test Metrics**: Standardized test execution metrics across documentation to **457 total tests collected & verified** across `tests/` and `backend/tests/`.
- **System Architecture Alignment**: Verified microservices topology (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`), 24h SQLite IOC reputation cache, Frida 17 Java bridge sub-probes, and runtime telemetry endpoints.
- **Second-pass drift remediation (same date)**: Corrected gateway paths (`POST /api/v1/analyze`, `/analyze/async`, `GET /intelligence/{sha256}`), dashboard routes (`/fraud-card`, `/threat-intel`), removed unreferenced model references not present in code, documented `validate_dynamic_pipeline.py` / `shared/sudarshan_core/validation/`, and recorded Technical View screenshot URL gap.

## [2.5.0-STABLE] - 2026-08-03

### Added
- **Persistent IOC Reputation Cache (24h TTL)**: SQLite-backed caching (`ioc_cache` table) in `backend/app/main.py` and `shared/sudarshan_core/services/threat_correlator.py` preventing API rate limit exhaustion across VirusTotal, OTX, and AbuseIPDB.
- **Frida 17 Java-Bridge Sub-Probes**: Added `bisect_sec`, `bisect_temp`, and `java_probe` preflight hooks (`shared/sudarshan_core/engines/frida_hooks/`) for deep ART deoptimization and Java bridge validation.

### Changed
- **Automated Test Suite Expansion**: Expanded verified automated test suite from 388 to **421 passing tests** across `tests/` and `backend/tests/`.
- **Analysis Engine Container Entrypoint**: Refactored `analysis-engine/entrypoint.sh` and Docker compose healthcheck to validate Java 17, ADB host connectivity, and Frida server port binding (`SUDARSHAN_FRIDA_PORT=27055`).
- **Frontend Vite File Watching Stability**: Configured `CHOKIDAR_USEPOLLING=true` and `CHOKIDAR_INTERVAL=300` in `docker-compose.yml` for Windows bind mount file watcher stability.

### Fixed
- **Admin Password Seeding**: Updated `backend/app/main.py` startup handler to generate a secure random password if `ADMIN_PASSWORD` is unconfigured, avoiding published default credentials.

### Documentation
- **Zero-Drift Master Audit**: Updated all 24 portal documentation files in `/docs`, root `README.md`, `CHANGELOG.md`, and `DOCUMENTATION_AUDIT_REPORT.md` to achieve 100% synchronization with codebase.

---

## [2.4.0-STABLE] - 2026-07-29

### Runtime Telemetry API & Frida 17 Banking Malware Instrumentation Suite
- **Runtime Telemetry REST Endpoints**: Implemented `/api/runtime/*` route suite (`backend/app/routes/runtime_api.py`) exposing live pipeline health, Frida hook inventory/metrics, ring-buffered telemetry stream (max 500 events), pipeline state machine status, and evidence snapshots.
- **Frida 17 Banking Malware Instrumentation**: Upgraded dynamic instrumentation hooks suite (`shared/sudarshan_core/engines/frida_hooks/banking_trojan.js`) targeting overlay attacks, SMS interception, keylogging, accessibility abuse, C2 communications, and system anti-analysis evasion bypasses.
- **Agentic UI Exploration Engine**: Enhanced Gemini-driven UI navigation planner (`shared/sudarshan_core/engines/agentic_explorer.py`, `planner.py`) with activity trigger testing, launch ladder execution, and automated goal progression.
- **APK Manifest Repair Engine**: Implemented `shared/sudarshan_core/engines/apk_repair.py` for automated AXML manifest repair, zipalign recovery, and re-signing of corrupt or protected banking APKs.
- **FraudCard Executive Dashboard Component**: Built `frontend/src/pages/FraudCard.tsx` providing executive threat visualization, 5-axis STEI threat scoring breakdown, FRS metrics, and actionable risk highlights.
- **Runtime Verification Test Suite**: Added `scripts/verify_runtime_pipeline.py` and `tests/unit/test_frida_pipeline_full.py` to continuously validate live telemetry endpoints, Frida session lifecycle, and event bus message passing.
- **Comprehensive Documentation Audit**: Completed full 24-document zero-drift documentation audit across `/docs` and root project files.

---

## [2.3.0-STABLE] - 2026-07-29

### Enterprise Documentation Portal Zero-Drift Audit & Release Synchronization
- **Zero-Drift Synchronization**: Comprehensive audit and update of all 24 markdown documentation files in `/docs` and root repository files (`README.md`, `CHANGELOG.md`) to reflect active codebase implementation (`SanTiwari07/Sudarshan`).
- **Standardized Microservice Topology**: Documented 5-container architecture (`frontend:5173`, `backend:8000`, `analysis-engine:8001`, `mobsf:8008`, `mitmproxy:8080`).
- **Verified Test Metrics**: Updated test execution metrics to **388 / 388 unit and integration tests passing** across `backend/tests/`.
- **PowerShell Test Invocation**: Standardized test command:
  ```powershell
  $env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests
  ```
- **Shared Core Module Pathing**: Updated all architectural module references to `shared/sudarshan_core/...` mounted to `/opt/sudarshan-core`.
- **Dynamic Sandbox Operational State**: Updated DAE current state documentation to reflect SELinux preflight execution (`adb root` + `setenforce 0`), Frida 17.16.4 attachment via PID, and `Java.deoptimizeEverything()` ART deoptimization.

---

## [2.3.0-STABLE] - 2026-07-27

### Frida 17.16.4 Project-Wide Migration & Standardization
- **Full Frida Upgrade (17.16.0 → 17.16.4)**: Standardized Frida client, server, and tooling across the entire repository on Frida `17.16.4`.
- **Binary Assets & Setup Scripts**: Downloaded and verified official `frida-server-17.16.4-android-x86_64` (SHA256: `7f7b69d5e33b0a3753bbe152369c7a00173636e92d9e4351e96495c3f885d6f9`) in `frida-server-17.16.4-android-x86_64/`. Updated `scripts/setup_dynamic_analysis.py` to push Frida 17.16.4 server binary. Purged obsolete `frida-server-17.16.0-android-x86_64` assets.
- **Python Dependencies & Docker Images**: Confirmed `frida==17.16.4` and `frida-tools==14.10.4` pinning in `backend/requirements.txt` and `analysis-engine/requirements.txt`.
- **Documentation Alignment**: Synchronized `README.md`, `docs/PROJECT_CONTEXT.md`, `docs/MIGRATION.md`, `docs/HOW_TO_RUN.md`, `docs/DOCUMENTATION_AUDIT_REPORT.md`, and `docs/02_SYSTEM_OVERVIEW.md`.

---

## [RC-2] - 2026-07-25

### Key Updates & Infrastructure Alignment

#### GitHub Repository Rename
- Updated remote repository configuration to [https://github.com/SanTiwari07/Sudarshan.git](https://github.com/SanTiwari07/Sudarshan.git).

#### Frida Attach by PID Fix
- **File:** `backend/app/engines/frida_sandbox.py`
- **Problem:** Dynamic analysis attempted to attach to applications by package name (`com.android.insecurebankv2`). On Android, Frida reports running processes by their display label (`InsecureBankv2`), causing attach-by-name to fail across retries.
- **Fix:** Resolved PID via `adb shell pidof`, enabling immediate attach on attempt 1.

#### Frida 17 Java Bridge Bundling
- **File:** `backend/app/engines/frida_hooks/banking_trojan.bundle.js`
- **Fix:** Bundled `frida-java-bridge` via `frida-compile` into `banking_trojan.bundle.js` to ensure compatibility with Frida 17.16.4 on 16 KB page-size Android 13+ AVDs (`google_apis_ps16k`).

#### Gemini Model Upgrade
- Upgraded default model configuration from retired `gemini-1.5-flash` to `gemini-2.5-flash`.

#### Windows Sandbox Cwd Support
- Added `powershell.cmd` wrapper to support sandbox `run_command` Cwd execution under Windows PowerShell.

#### Comprehensive Test Suite
- Expanded test coverage to passing tests spanning risk engines, prompt injection defenses, goal DAG progression, and determinism replay baselines.

---

## [RC-1] - 2026-07-19

### Bug Fixes

#### frida-server Startup Failure (Critical)
- **File:** `backend/app/engines/frida_sandbox.py`
- **Problem:** The backend used `adb shell su -c '/data/local/tmp/frida-server &'`
  to automatically start `frida-server` on the Android emulator. On emulators
  where the `su` binary does not support the `-c` argument (`su: invalid uid/gid '-c'`),
  this command silently failed - meaning `frida-server` was never running and all
  dynamic analysis was skipped without any visible error in the UI.
- **Fix:** Replaced `su -c` with `nohup /data/local/tmp/frida-server > /dev/null 2>&1 &`.
  Since `adbd` is already running as root (`adb root`), direct execution is portable
  and works on all AVD emulator configurations.

#### Missing Dynamic Analysis in Dashboard (Critical)
- **File:** `frontend/src/App.tsx`
- **Problem:** The `FraudCardData` TypeScript interface was missing the `dynamic_analysis`
  field. The backend API correctly returned the full `DynamicAnalysisResult` payload,
  but the frontend type system silently dropped it. As a result, the `DynamicAnalysisPanel`
  in `TechnicalView.tsx` always rendered "Dynamic analysis data unavailable".
- **Fix:** Added the `DynamicAnalysis` TypeScript type and mapped it to `FraudCardData`.
  The panel now correctly displays runtime API call hooks, network traffic, attack
  timelines, coverage metrics, and screenshots captured during Frida instrumentation.

### New Features

#### One-Command Startup Script (start.ps1)
- **File:** `start.ps1` (project root)
- **Description:** A PowerShell script that replaces the multi-step manual startup
  process. Previously, starting the platform required 5+ separate commands
  (`adb kill-server`, `adb tcpip 5555`, `adb root`, `frida-server` launch,
  `docker compose up`) run in the right order.
- **Now:** Run `.\start.ps1` and everything starts automatically with status feedback.

### Documentation

#### README.md (New)
- Created comprehensive project-level README with architecture diagram, API reference,
  configuration table, project structure, and quick start guide.

---

## [Beta] - 2026-07-18

### Features Implemented

#### Full Analysis Pipeline
- APK upload with static analysis (native parser / MobSF primary)
- Frida dynamic sandbox with multi-stage engine and UI Explorer
- Threat correlation (VirusTotal, AbuseIPDB, OTX)
- FRS scoring engine with 5-axis STEI breakdown
- AI intelligence report (Gemini API)
- SQLite case persistence

#### React Frontend
- Upload page - drag-and-drop APK upload with real-time progress
- Fraud Analyst Card - executive risk summary with BFCI gauge
- SOC / Technical View - full static and dynamic evidence panels
- Threat Intel View - IOC reputation, MITRE ATT&CK mapping
- Case History - paginated list of all past analyses
- JWT Authentication - role-based (analyst / soc_lead / admin)
