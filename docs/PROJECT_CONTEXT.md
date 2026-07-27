# Sudarshan — Full Project Context

**Purpose of this document.** A single, evidence-based reference describing what Sudarshan is,
how it works, what is verified to work, what is verified to be broken, and where the open
research questions are. Written for research use, technical review, and onboarding.

**Epistemic labelling.** Claims in this document are tagged:

| Tag | Meaning |
|---|---|
| **[VERIFIED]** | Directly observed by executing the code or reading the source in this repository |
| **[DESIGN]** | Intended behaviour per code structure, not yet empirically confirmed |
| **[CLAIMED]** | Asserted by project documentation but **contradicted or unconfirmed** by observation |

Do not cite **[CLAIMED]** items as fact. Several are demonstrably wrong; they are recorded here
precisely because the gap between documentation and reality is itself a finding.

---

## 1. Project Identity

**Sudarshan** — a banking-focused Android malware intelligence platform, submitted for the
Bank of India / IIT Hyderabad hackathon (BOI Hackathon 2026).

**Thesis.** Existing tools answer *"is this malware?"*. Sudarshan aims to answer
*"who is targeted, what is at risk, and what should the fraud team do?"* The project frames itself
as solving an **intelligence translation** problem rather than a malware detection problem: a
malicious APK can compromise an account in under 90 seconds, while a fraud analyst typically
begins investigating days later.

**Stated design principles** (from `README.md`):

1. *Deterministic Detection, Explainable Intelligence* — AI explains decisions, it does not make them.
2. *Human Judgment, Machine Scale* — machines process evidence, humans make accountable decisions.
3. *Fraud-First, Not Malware-First* — the output is a fraud-operations decision, not a technical report.

**The core invariant** (architecturally central, and the property most worth protecting):

> AI may control exploration and navigation.
> AI may **not** decide malware verdicts.
> Only deterministic evidence contributes to risk scoring.

**[VERIFIED]** This invariant currently holds at the scoring layer. Identical recorded evidence
produces a byte-identical verdict, and LLM-authored fields merged into the dynamic payload do not
move the score. See §9.

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite 5 (Port 5173) |
| Gateway Backend | Python 3.12, FastAPI, Uvicorn (Port 8000) |
| Analysis Engine | Containerized Python 3.12 + Java 17 + Ubuntu 24.04 (Internal Port 8001) |
| Shared Core | `sudarshan_core` python package mounted as `/opt/sudarshan-core` |
| Persistence | SQLite (`sudarshan.db`), aiosqlite, SQLAlchemy |
| Auth | JWT Bearer, passlib/bcrypt |
| Static analysis | Androguard, MobSF (Port 8008), APKTool 2.10.0, JADX 1.5.1 |
| Dynamic analysis | Frida 17.16.4 + frida-tools, ADB (`host.docker.internal:5555`), Android emulator |
| Network Proxy | mitmproxy sidecar (`127.0.0.1:8080:8080`), HAR ingest |
| Signatures | YARA Python 4.5.4 |
| Threat intel | VirusTotal, AlienVault OTX, AbuseIPDB (optional correlation) |
| LLM | Google Gemini via `google-genai` (`gemini-2.5-flash`), Ollama |
| Orchestration | Docker Compose (frontend, backend, analysis-engine, mitmproxy, mobsf) |

---

## 3. Repository Layout

```
Sudarshan/
├── start.ps1                       One-command bootstrapper (ADB → frida-server → docker compose)
├── docker-compose.yml              frontend:5173, backend:8000, analysis-engine:8001, mobsf:8008, mitmproxy:8080
├── shared/
│   ├── pyproject.toml              Shared library metadata
│   └── sudarshan_core/             Core shared library (mounted to /opt/sudarshan-core)
│       ├── analyzers/              apk_analyzer.py (Androguard engine)
│       ├── models/                 manifest.py (InvestigationManifest), schemas.py
│       ├── services/               mobsf_client.py, threat_correlator.py
│       └── engines/                
│           ├── risk_engine.py      5-axis STEI + 4-axis FRS deterministic scoring
│           ├── bfci_scorer.py      BFCI v2 logarithmic behavioral scorer
│           ├── frida_sandbox.py    Frida PID attach & sandbox controller
│           ├── apktool_engine.py   APKTool resource decompilation engine
│           ├── jadx_engine.py      JADX Java source decompilation & signature engine
│           ├── network_capture.py  mitmproxy HAR dump ingest
│           ├── workflow_reconstructor.py Causal chain temporal reconstruction
│           ├── agentic_explorer.py Agentic UI exploration orchestrator
│           ├── frida_hooks/        banking_trojan.js & banking_trojan.bundle.js
│           └── agentic/            planner.py, perception.py, goal_tracker.py, sanitizer.py, etc.
├── backend/
│   ├── Dockerfile                  Python 3.12 gateway container definition
│   ├── requirements.txt            Gateway dependencies
│   ├── app/
│   │   ├── main.py                 FastAPI Gateway entrypoint & lifecycle hooks
│   │   ├── routes/                 upload.py (orchestrator), cases.py, report.py
│   │   ├── auth/                   auth.py (JWT authentication & RBAC)
│   │   ├── db/                     database.py (SQLite case store & audit persistence)
│   │   ├── ai/                     gemini_rag.py (RAG indexer), ollama_client.py
│   │   └── workers/                analysis_queue.py (async worker pool)
│   └── tests/                      16 automated unit & integration test modules
├── analysis-engine/
│   ├── Dockerfile                  Ubuntu 24.04 + Java 17 + Python 3.12 microservice
│   ├── entrypoint.sh               Single-worker uvicorn launcher
│   └── app/
│       └── main.py                 REST microservice endpoints (/api/v1/analyze, /status, etc.)
├── frontend/
│   ├── src/
│   │   ├── pages/                  FraudCard.tsx, TechnicalView.tsx, ThreatIntelView.tsx, …
│   │   └── components/             WorkflowDiagram.tsx, ErrorBoundary.tsx
│   └── Dockerfile                  Vite/Nginx frontend container definition
└── tools/                          Standalone APKTool and JADX binaries
```

---

## 4. Deterministic Scoring Model

**[VERIFIED]** All formulas and constants below were read from `risk_engine.py` and confirmed by
executing the engine.

### 4.1 STEI — Static Threat Exposure Index

```
STEI = 0.60·CT + 0.20·BT + 0.10·PR + 0.05·OB + 0.05·IR
```

| Axis | Weight | Meaning | Scoring |
|---|---:|---|---|
| CT | 0.60 | Credential Theft | accessibility +40, SMS +35, overlay +25; cap 100 |
| BT | 0.20 | Banking Target | Indian banking package targeting |
| PR | 0.10 | Permission Risk | dangerous permission set size |
| OB | 0.05 | Obfuscation | DexClassLoader + reflection + entropy |
| IR | 0.05 | Infrastructure Risk | 10 points per hardcoded URL/IP; cap 100 |

### 4.2 BFCI — Behavioural Fraud Confidence Index

```
BFCI = 0.35·A + 0.25·S + 0.20·O + 0.10·B + 0.05·N + 0.05·P
```

| Component | Weight | Signal |
|---|---:|---|
| A — Accessibility abuse | 0.35 | Screen scraping, tap injection |
| S — SMS interception | 0.25 | OTP theft |
| O — Overlay attack | 0.20 | Phishing overlays |
| B — Banking interaction | 0.10 | Target enumeration |
| N — Network C2 | 0.05 | Command-and-control traffic |
| P — Persistence | 0.05 | Device admin, boot persistence |

Weights are documented as reflecting prevalence in real-world Indian banking trojans.
**No citation or dataset backs this claim in the repository** — see §14.

### 4.3 FRS — Fraud Risk Score

```
dynamic available:  FRS = 0.25·STEI + 0.35·BFCI + 0.20·Correlation + 0.20·BankingImpact
static only:        FRS = 0.50·STEI + 0.25·Correlation + 0.25·BankingImpact
final = min(FRS × clamp(ai_confidence, 0.5, 1.5), 100)
```

`ai_confidence` is **rule-derived, not LLM-derived**: 1.0 when family is Unknown, 1.2 on a
deterministic family-classifier match, 1.15 when the family came from threat correlation.
It is hard-clamped to [0.5, 1.5] as a last line of defence.

### 4.4 Bands and confidence

| Final score | Band |
|---|---|
| ≤ 30 | Safe |
| ≤ 60 | Suspicious |
| ≤ 89 | High Risk |
| > 89 | Critical |

```
confidence = min(60 + (sources_available / 3)·35 + (2 if family known else 0), 99)
```
where `sources_available` counts static (always 1), dynamic, and correlation.

---

## 5. Static Analysis Pipeline

**[VERIFIED as functional]**

1. APK upload → SHA-256 → Androguard (MobSF if configured)
2. Flag extraction → `StaticAnalysisFlags`: accessibility abuse, SMS read/write,
   SYSTEM_ALERT_WINDOW, dangerous APIs, hardcoded URLs/IPs, Indian bank targeting,
   obfuscation score, reflection, dynamic loading
3. Family classification — deterministic rule matching → `ai_confidence` multiplier
4. Threat correlation — VirusTotal / OTX / AbuseIPDB; gracefully skipped if unkeyed
5. STEI computed from flags + full permission list

Static analysis is the most reliable part of the system and functions independently of the
emulator.

---

## 6. Dynamic Analysis Pipeline — Detailed Flow

### 6.1 Gating

`POST /api/v1/analyze` (JWT-protected) runs static analysis, then calls `get_sandbox_status()`.
Dynamic analysis proceeds only if **all four** conditions hold:

```python
ready = frida_available and adb_path is not None and len(emulators) > 0 and hooks_ok
```

On failure, `dynamic_result` stays `None` and the entire dynamic branch is skipped **silently**.
The frontend binds both "Dynamic Sandbox" and "Network Behaviour" indicators to the single
`dynamic_available` boolean (`FraudCard.tsx:68-69`), so both go grey together.

### 6.2 Sandbox preparation

`run_frida_analysis(apk_path)`, dispatched via `run_in_executor`:

1. `get_connected_emulators()` — in Docker, `adb connect host.docker.internal:5555` first
2. `_extract_apk_info()` — aapt, falling back to Androguard → package name + main activity
3. `_adb_install_apk()` — 3 attempts, `--bypass-low-target-sdk-block` fallback for legacy samples
4. `artifact_dir_for()` — per-sample forensic directory under `sudarshan_artifacts/`
5. `FridaSession` constructed; collector modules subscribe to `RuntimeEventBus`:
   screenshot manager, IOC collector, MITRE mapper, permission orchestrator, replay engine,
   network capture, anti-analysis detector, YARA scanner, analysis history, report generator

### 6.3 Instrumentation

Inside `session.run(duration)` (synchronous, runs on a worker thread):

1. `frida.enumerate_devices()`, match serial, 3 attempts
2. Wake device — power keyevent 26, menu keyevent 82, `wm dismiss-keyguard`
3. Launch — `am start -n pkg/activity`, else `monkey -c LAUNCHER`
4. **Attach** — resolve PID via `adb shell pidof`, then `device.attach(pid)`
   > **[VERIFIED]** Attaching by *package name* can never succeed on Android: Frida reports
   > running apps by **display label** (`InsecureBankv2`), not package
   > (`com.android.insecurebankv2`). `attach(pid)` succeeds instantly.
5. Fallback — `device.spawn()` + `resume()`
6. Load hook script → the **bundled** build (see §11)
7. `script.on('message')` → `type=event` → categorised into `collected_events`,
   republished on `RuntimeEventBus`

### 6.4 Exploration

Selected by `SUDARSHAN_EXPLORER_MODE`:

| Mode | Explorer |
|---|---|
| `ai` (default) | `AgenticExplorer` |
| `monkey` | Monkey subprocess only (legacy) |
| `hybrid` | Both concurrently, with 100–300 ms jitter to reduce ADB socket contention |

The explorer runs on its own thread with its own event loop. The main thread waits on a stop
Event for the analysis duration (default 30 s), then signals stop, joins with a 20 s grace
period, and flushes artifacts.

### 6.5 The agent loop

Per iteration:

**OBSERVE** — drain Frida events; `uiautomator` XML dump; foreground activity; logcat when XML is
unusable; screenshot **only** on five specific triggers (empty XML, no actionable nodes, low
labelled-node fraction, WebView activity, previous action failed).

**THINK** — foreground observation confirms stage 1; Frida events advance goal state; seven
stopping conditions evaluated; `next_priority_goal()`; planner consults cache → Gemini →
5-step validation → deterministic `FallbackPlanner`.

**ACT** — `ToolExecutor` dispatches over ADB.

**RECORD** — memory, benchmark, audit log, attack timeline.

### 6.6 Stopping conditions

| ID | Condition | Status |
|---|---|---|
| SC1 | All goals complete | **Unreachable** — see §10 |
| SC2 | No Frida evidence for N actions | **Unreachable** — gated on `all_done()` |
| SC3 | Action budget exhausted (default 25) | Working |
| SC4 | Time budget exhausted | Working |
| SC5 | Crash screen detected | Working (was unreachable before activity-parser fix) |
| SC6 | Planner returns None | Working |
| SC7 | External cancellation | Working |

### 6.7 Scoring handoff

BFCI is computed from `collected_events` by category against the six weights, then passed to
`calculate_risk_score()` alongside static flags, correlation result, and family.
The LLM narrative (`analyze_with_llm`) runs **after** scoring and consumes the verdict.

---

## 7. The Fraud Goal DAG

15 stages with declared `depends_on` prerequisites. Selection requires `is_unblocked()`, so a
goal cannot be chosen until its dependencies are COMPLETED or SKIPPED.

**[VERIFIED]** Goal completability against the actual hook script:

| Stage | Goal | Skippable | Completable by hook |
|---:|---|---|---|
| 1 | Launch Application | No | No hooks — completes via foreground observation |
| 2 | Grant Runtime Permissions | Yes | No |
| 3 | Accessibility Abuse | No | **Yes** |
| 4 | Overlay Detection | Yes | **Yes** |
| 5 | **Login Flow** | **No** | **No — HARD STALL** |
| 6 | SMS / OTP Interception | Yes | Yes (unreachable) |
| 7 | Banking Application Detection | Yes | No (unreachable) |
| 8 | Network / C2 Communication | Yes | Yes (unreachable) |
| 9 | Persistence Mechanisms | Yes | No |
| 10 | Dynamic Code Loading | Yes | Yes (unreachable) |
| 11 | Runtime Reflection | Yes | No |
| 12 | Deep Links | Yes | No |
| 13 | Broadcast Receivers | Yes | No |
| 14 | Exported Components | Yes | No |
| 15 | Background Services | Yes | No |

**Stage 5 gates stages 6, 7, 8 and 10.** It requires `SharedPreferences.getString` and
`Cipher.doFinal`, and is not skippable. Hooks emitting those names have been *added* to the
script but do not fire (§10), so the graph cannot progress past stage 5. **SMS, banking
detection, C2 and dynamic loading are therefore never evaluated on any sample.**

Goal status is mutated only from observed device state — Frida events or foreground package.
There is no API by which the LLM can assert completion.

---

## 8. Hook Inventory

**[VERIFIED]** 19 hooks emit named events in `banking_trojan.js`:

```
AccessibilityNodeInfo            AccessibilityNodeInfo.getText
AccessibilityNodeInfo.performAction   AccessibilityService.onAccessibilityEvent
ActivityManager.getRunningTasks  Build.MODEL / Build.MODEL.read
ContentResolver.query            Debug.isDebuggerConnected
DevicePolicyManager              DevicePolicyManager.isAdminActive
DevicePolicyManager.lockNow      DexClassLoader / DexClassLoader.<init>
File / File.<init>               KeyStore.getInstance
OkHttp / OkHttp.RealCall.execute PackageManager.getPackageInfo
SmsManager.sendTextMessage       SmsMessage.getMessageBody
SystemProperties.get             URL.openConnection
WindowManager.addView
```

Plus two added during this work: `SharedPreferences.getString`, `Cipher.doFinal`
(both redact values — key/algorithm and byte lengths only).

**Documented but absent** — do not assume these exist:
`ClipboardManager`, `TelephonyManager`, SMS `BroadcastReceiver`s, `Class.forName`,
`Method.invoke`, `getInstalledPackages`, `getRunningAppProcesses`, `PathClassLoader`,
SSL pinning / TrustManager, MediaProjection, BiometricPrompt.

---

## 9. Determinism Enforcement

**[VERIFIED]** The invariant is enforced structurally, not by convention:

- `risk_engine.py` is the sole writer of score, band, severity and recommendation.
- Inputs are validated at the trust boundary (`_coerce_score`, `_validated_components`):
  non-numeric, NaN, ±inf and out-of-range values are rejected or clamped with a warning.
- `ai_confidence` is rule-derived and hard-clamped.
- The LLM narrative runs strictly downstream of scoring.
- A **replay baseline** (`tests/determinism_baseline.json`) captured before a ~3,600-line refactor
  pins STEI, BFCI, FRS, band, severity, confidence and recommendation across three scenarios.
  All still match exactly.
- A regression test asserts that LLM-authored fields (`confidence`, `reasoning`, `_source`,
  `explorer_used`, token counts) merged into the dynamic payload **do not move the score**.

**Architectural gap (unresolved).** The invariant protects *verdict computation* but not
*evidence selection*. If instrumentation becomes adaptive — hooks chosen at runtime — then AI
decides which evidence exists, which is verdict determination by proxy. A deterministic function
over adaptively-selected inputs is not deterministic. The proposed mitigation is a **versioned
hook profile as the sole scoring input, plus a per-run hook manifest**, with adaptive components
restricted to supplementary non-scoring evidence.

---

## 10. Verified Current State

### 10.1 What works

| Capability | Evidence |
|---|---|
| Static analysis | Produces flags, STEI, bands, recommendations |
| Deterministic scoring | 285 tests pass; replay baseline byte-identical |
| Frida attach | `Attached to com.android.insecurebankv2 (pid=…, attempt 1)` |
| Hook script initialisation | `ready` message received; 0 hook errors |
| Agentic loop | Observes, plans via Gemini, acts, logs, produces artifacts |
| Goal progression to stage 3 | Stage 1 COMPLETED, 2 SKIPPED, 3 IN_PROGRESS |
| Per-sample artifacts | Two consecutive analyses retain separate directories |
| Prompt-injection defence | 64 tests; fence holds against all payloads |
| LLM cost accounting | tokens + model recorded per run |

### 10.2 What does not work

| Defect | Evidence | Impact |
|---|---|---|
| **Hooks install but never fire** | `ready: 1`, `hook_errors: 0`, **0 events** — even with spawn-and-resume | **BFCI is 0.0 on every sample.** Root cause not yet isolated; ART method inlining is the leading hypothesis (`Java.deoptimizeEverything()` untested) |
| **Goal DAG stalls at stage 5** | Stage 5 not completable, not skippable | Stages 6, 7, 8, 10 unreachable |
| SC1/SC2 unreachable | Both gated on `all_done()`, which can never be true | Only budget/crash conditions can stop a run |
| Executor coordinate gate | `tool_executor.py:275` uses module constant `SCREEN_HEIGHT` (1920) | On a 1080×2400 device, a `click_text` fallback the planner *accepted* is rejected here |
| `ToolExecutor.screen_size` unused | No production caller | The fix it represents is inert |
| `mark_failed` never called | No production caller | `MAX_GOAL_RETRIES` retry branch is dead code |
| Legacy explorer prompt unsanitized | `ui_explorer.py:233` — 0 sanitize calls, no fence | Injection surface in the rollback path |
| `cred_note` unsanitized | `agent_memory.py:358` — LLM `field_hint` in the *trusted* prompt region | Injection surface |
| `explorer_error` unreachable | `agentic_explorer.py:457` catch-all precedes the sandbox handler | Agent-loop crashes are logged but not surfaced in results |
| `device_properties` caches failures | Fallback resolution cached with no TTL; `clear_cache()` has no caller | One transient adb failure pins 1080×1920 process-wide |
| Vision is a dead path | Screenshots captured; no image bytes ever reach the model | Wasted ADB round-trips |
| `evidence.json` empty | 0 records flushed on last run | Downstream of the firing defect |

---

## 11. Environment Constraints

**[VERIFIED]** These are hard constraints discovered empirically. They are non-obvious and each
one silently broke the system at some point.

### Frida version — a genuine bind

- **Frida 17 removed the built-in `Java` global.** Probe result inside an attached process:
  `typeof Java → undefined`, `runtime → QJS`. Classic `Java.perform` scripts load, spin in
  `waitForJava()` forever, install **nothing**, and report no error.
  → Mitigation: the hook script is bundled with `frida-java-bridge` via `frida-compile`, and
  `frida_sandbox` prefers `banking_trojan.bundle.js`.
- **Frida 16 cannot run on this device.** The project AVD is `google_apis_ps16k` — a **16 KB
  page-size** image (`getconf PAGESIZE → 16384`). frida-server 16.7.19 fails to link:
  `CANNOT LINK EXECUTABLE: empty/missing DT_HASH/DT_GNU_HASH`. 16 KB support arrived in 17.x.
- **Therefore 17.x is mandatory and bundling is mandatory.** `requirements.txt` pins
  `frida==17.16.4` / `frida-tools==14.10.4`. The frida-server pushed to the device **must match
  exactly**.
- `frida-server` is not in the repository (106 MB > GitHub's 100 MB limit) and does not survive
  an emulator reboot.

### Gemini model

- `gemini-1.5-flash` is **retired** — returns HTTP 404. It was hardcoded in two places and
  defaulted in a third; every LLM call was failing silently into the deterministic fallback.
- Current: `gemini-2.5-flash`, configured via `GEMINI_MODEL`, verified HTTP 200.
- The container reads env from `docker-compose.yml`, **not** `backend/.env` — a root-level `.env`
  is required for `${GEMINI_API_KEY}` interpolation.

### Emulator

- Pixel_6 AVD, x86_64, `android-37.1`, `google_apis_ps16k`, **1080×2400**, 16 KB pages
- Reached from the backend container via `adb connect host.docker.internal:5555`
- Android 13+ prints `ResumedActivity:` (no `m` prefix); dumpsys format is
  `topResumedActivity=ActivityRecord{hash u0 com.pkg/.Activity t42}`

### Ports

| Backend | 8000 | Gateway Orchestrator |
| Frontend | 5173 | React Dashboard |
| MobSF | 8008 | Mobile Security Framework Static Engine |
| Analysis Engine | 8001 | Microservice (Internal) |

A stale WSL relay entry can make `localhost:5173` accept the TCP connection then hang forever
while `127.0.0.1:5173` works. Fix: `wsl --shutdown`.

---

## 12. Test Suite

**[VERIFIED]** 285 tests, all passing.

| File | Tests | Covers |
|---|---:|---|
| `test_agentic_explorer.py` | 83 | Imports, goal tracker, memory, registry, executor |
| `test_prompt_injection.py` | 64 | Fence-escape payloads, bidi, fullwidth, control chars, oversize |
| `test_boundaries.py` | 31 | Risk-engine trust boundary, device resolution |
| `test_risk_engine.py` | 27 | STEI axes, both FRS branches, clamping, monotonicity |
| `test_activity_parser.py` | 15 | dumpsys formats incl. a real Android 37 capture |
| `test_planner_cache.py` | 15 | Isolation, LRU, invalidation, concurrency |
| `test_memory_bounds.py` | 15 | Capacity limits, 100k-event dedupe |
| `test_artifact_persistence.py` | 14 | Per-sample dirs, hostile filenames |
| `test_goal_progression.py` | 12 | DAG advancement, foreground completion, retry |
| `test_determinism_replay.py` | 9 | Verdict pinned to pre-refactor baseline |

**Not covered:** hook firing (the central defect), end-to-end API flow, frontend, and any
detection-quality metric.

---

## 13. Audit History

An independent strict audit of 17 requirements produced **82%** (11 Full, 6 Partial), up from a
pre-remediation 79%. Adversarial re-verification overturned two self-assessed grades — a useful
demonstration that self-audit is unreliable.

**Fully implemented:** Monkey→AI replacement, agent loop, LLM action selection, tool executor,
tool registry, JSON validation (5-step), memory system, audit logging, feature flags,
determinism isolation, success metrics.

**Partial:** observation contents (network absent), injection protection (3 surfaces open),
goal dependencies (stalls at stage 5), stopping conditions (SC1/SC2 unreachable), vision
(dead path), rollback (never reaches Monkey; provenance unreachable).

Design-vs-artifact scoring (the design is materially better than the current build):

| Dimension | Design | Artifact |
|---|---:|---:|
| Architecture | 8 | 7 |
| Scalability | 6 | 6 |
| Practicality | 6 | 4 |
| Maintainability | 6 | 5 |
| Research value | 8 | 7 |
| Innovation | 6 | 5 |
| Malware analysis effectiveness | 6 | 3 |
| Frida usage | 7 | 4 |
| Explainability | 8 | 7 |
| Enterprise readiness | 5 | 3 |

---

## 14. Competitive Position

**Genuinely differentiating:**
- **Fraud-goal-directed exploration.** Most sandboxes maximise *code coverage*; Sudarshan
  maximises progress toward *fraud outcomes*. This is the closest thing here to a research
  contribution — it automates what ThreatFabric analysts do manually.
- **Evidence/verdict isolation with a deterministic scorer.** Uncommon in this product category
  and correct for a regulated environment.
- **India/UPI-specific targeting.** Underexploited and more valuable than the AI layer.

**Table stakes, not innovation** — discovery/runtime mapping, tiered hooking, `DexClassLoader`
→ instrument-loaded-classes, pinning bypass, correlation timelines. All standard in Joe Sandbox,
VMRay, CAPE.

**Materially weaker than peers:**
- **Anti-evasion.** frida-server runs at the default path, name and port (27042). SOVA,
  Xenomorph, Hook and Cerberus variants check exactly this. A sample that detects Frida goes
  dormant → BFCI 0.0 → reported benign. **This is a silent false-negative generator.**
- **No config / target-list extraction.** The highest-value artifact for a bank
  (*"this sample targets your app"*) and CAPE's defining strength. Absent.
- **No TLS interception.** Connection metadata only; no C2 content.
- **No genetic/code-reuse attribution** (Intezer's core). Family attribution is heuristic.
- **Emulator-only.** No hardware attestation resistance, no device farm.
- **No ground truth.** No corpus, no FPR/FNR. Every quality claim is currently unfalsifiable.

---

## 15. Open Research Questions

1. **Why do installed hooks not fire?** ART inlining is the hypothesis; `Java.deoptimizeEverything()`
   is untested. This blocks all dynamic research.
2. **Are the BFCI weights empirically justified?** They are presented as reflecting prevalence in
   Indian banking trojans with no dataset or citation. A weight-sensitivity study against a
   labelled corpus would be a genuine contribution.
3. **Does goal-directed exploration beat random (Monkey) exploration?** The benchmark harness
   exists (`benchmark.json`, `explorer_mode` recorded) but the experiment has never been run.
   This is the most publishable result available and is comparatively cheap.
4. **What is the BFCI variance across repeated runs of one sample?** Exploration is stochastic;
   no aggregation policy is documented.
5. **How much behaviour is lost to the 30 s window?** Real bankers are latent — waiting for a
   bank app launch, an SMS, a C2 command, a locale match. Provocation (simulated SMS, decoy
   banking apps, Indian MCC/MNC, idle periods) is likely to shift results more than any
   instrumentation change.
6. **Can adaptive instrumentation coexist with a deterministic verdict?** The proposed
   baseline-profile + manifest split is untested.

---

## 16. Recommended Sequence

Ordered by dependency, not by appeal.

**Phase 1 — Substrate integrity.** Make hooks fire; add a canary hook so a zeroed run fails loudly
instead of reporting benign; add the hook manifest; unblock stage 5; basic Frida hygiene
(non-default name/path/port).
*Exit: a known-malicious sample yields non-zero BFCI with a full manifest.*

**Phase 2 — Ground truth.** 50–100 labelled samples; automated FPR/FNR; variance policy;
goal-directed vs Monkey baseline.
*Exit: you can state a false-positive rate.*

**Phase 3 — Fraud intelligence.** Trigger provocation; TLS interception + unconditional unpinning;
target-list extraction for the top three families.
*Exit: a report a fraud-ops lead acts on without reading a technical field.*

**Phase 4 — Enterprise readiness.** Device snapshot/restore between samples (currently the
emulator is reused dirty — cross-sample contamination is an evidentiary defect); chain of custody;
queue and throughput; corpus regression in CI.

**Phase 5 — Research + adaptive layer.** Publish the exploration result, *then* build the adaptive
planner behind a flag, supplementary evidence only.

**Scope warning.** The repository contains roughly 20 subsystems — YARA memory scanning, MITRE
mapping, three threat-intel integrations, IOC collection, screenshot management, replay engine,
permission orchestrator, network capture, anti-analysis detection, dual LLM paths (Ollama +
Gemini), hybrid Monkey mode, JWT auth, React dashboard — standing on a dynamic engine that emits
zero events. Candidates to postpone: adaptive planner, Stalker, vision, replay engine, MITRE
mapping, YARA memory scanning, Ollama, hybrid mode.

Protect: static analysis · Frida core · goal-directed exploration · deterministic risk engine ·
evidence store · analyst report.

---

## 17. Security Notes

- **Credential values are never stored.** Memory records the *key name* (`password`), never the
  value. Enforced by test against `FORM_VALUES`.
- **Form-fill credentials are synthetic** (`demo_user`, `Analysis@Secure99`) — not real data.
- **Prompt-injection defence:** app-controlled content is fenced in `<UNTRUSTED_APP_CONTENT>` tags,
  the system prompt is assembled only from trusted code strings, and a centralized sanitizer
  neutralises angle brackets, control characters, bidi overrides, and injection phrases, with
  bounded output. Three surfaces remain unsanitized (§10.2).
- **LLM output is constrained** by 5-step validation: JSON syntax → required fields/types →
  tool in registry → required params + ranges → coordinate bounds against the real device.
  Injection can misdirect exploration; it cannot execute arbitrary commands.
- **Command construction** uses `shlex.quote` and argv lists — no shell string interpolation of
  LLM data.
- **Secrets:** `.env` and `.env.*` are gitignored; no API key has ever been committed.
  `tools/` (frida-server binaries) and `backend/sudarshan_artifacts/` are gitignored.

---

*Compiled from direct source inspection and live execution against a Pixel_6 AVD
(x86_64, android-37.1, 16 KB pages) with frida 17.16.4. All [VERIFIED] claims are reproducible
from the repository state described here.*
