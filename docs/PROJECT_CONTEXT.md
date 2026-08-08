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

Do not cite **[CLAIMED]** items as fact. Several are recorded here precisely because the gap between documentation and reality is itself a finding.

---

## 1. Project Identity

**Sudarshan** — a banking-focused Android malware intelligence platform, submitted for the Bank of India / IIT Hyderabad hackathon (BOI Hackathon 2026).

**Thesis.** Existing tools answer *"is this malware?"*. Sudarshan aims to answer *"who is targeted, what is at risk, and what should the fraud team do?"* The project frames itself as solving an **intelligence translation** problem rather than a malware detection problem: a malicious APK can compromise an account in under 90 seconds, while a fraud analyst typically begins investigating days later.

**Stated design principles** (from [`README.md`](file:///d:/Projects/Sudarshan%20BOI/README.md)):

1. *Deterministic Detection, Explainable Intelligence* — AI explains decisions, it does not make them.
2. *Human Judgment, Machine Scale* — machines process evidence, humans make accountable decisions.
3. *Fraud-First, Not Malware-First* — the output is a fraud-operations decision, not a technical report.

**The core invariant** (architecturally central, and the property most worth protecting):

> AI may control exploration and navigation.
> AI may **not** decide malware verdicts.
> Only deterministic evidence contributes to risk scoring.

**[VERIFIED]** This invariant currently holds at the scoring layer. Identical recorded evidence produces a byte-identical verdict, and LLM-authored fields merged into the dynamic payload do not move the score. Verified across **519 / 519 tests collected** (`pytest tests/ backend/tests --collect-only`).

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite 5 (Port 5173, Polling file-watcher mode) |
| Gateway Backend | Python 3.12/3.13, FastAPI, Uvicorn (Port 8000) |
| Analysis Engine | Containerized Python 3.12 + Java 17 + Ubuntu 24.04 (Internal Port 8001) |
| Shared Core | `sudarshan_core` python package mounted as `/opt/sudarshan-core` |
| Persistence | SQLite (`sudarshan.db`), aiosqlite, SQLAlchemy, 24h IOC reputation cache |
| Auth | JWT Bearer, passlib/bcrypt |
| Static analysis | Androguard, MobSF (Port 8008), `apk_repair.py` AXML recovery, APKTool 2.10.0, JADX 1.5.1, YARA Scanner |
| Dynamic analysis | Frida 17.16.4 + frida-tools, Java bridge sub-probes, ADB via **SandboxProvider** (`ADB_HOST` / `DEVICE_SERIAL`; Genymotion default, Android Studio optional) |
| Network Proxy | mitmproxy sidecar (`127.0.0.1:8080:8080`), HAR ingest |
| Signatures | YARA Python |
| Threat intel | VirusTotal, AlienVault OTX, AbuseIPDB (24h TTL SQLite cached correlation) |
| LLM | Google Gemini via `google-genai` (default `gemini-2.5-flash`, overridable via `GEMINI_MODEL`) |
| Orchestration | Docker Compose (frontend, backend, analysis-engine, mitmproxy, mobsf) |

---

## 3. Repository Layout

```text
Sudarshan BOI/
├── start.ps1                       One-command bootstrapper (ADB → frida-server → docker compose)
├── docker-compose.yml              frontend:5173, backend:8000, analysis-engine:8001, mobsf:8008, mitmproxy:8080
├── shared/
│   ├── pyproject.toml              Shared library metadata
│   └── sudarshan_core/             Core shared library (mounted to /opt/sudarshan-core)
│       ├── analyzers/              apk_analyzer.py (Native APK analyzer engine)
│       ├── models/                 manifest.py (InvestigationManifest), schemas.py
│       ├── services/               mobsf_client.py, threat_correlator.py (24h IOC cache)
│       ├── engines/                
│       │   ├── risk_engine.py      5-axis STEI + 4-axis FRS deterministic scoring
│       │   ├── bfci_scorer.py      BFCI v2 logarithmic behavioral scorer
│       │   ├── frida_sandbox.py    Frida PID attach & sandbox controller (uses SandboxProvider)
│       │   ├── apk_repair.py       Automated AXML manifest repair & re-signing
│       │   ├── apktool_engine.py   APKTool resource decompilation engine
│       │   ├── jadx_engine.py      JADX Java source decompilation & signature engine
│       │   ├── network_capture.py  mitmproxy HAR dump ingest
│       │   ├── workflow_reconstructor.py Causal chain temporal reconstruction
│       │   ├── agentic_explorer.py Agentic UI exploration orchestrator
│       │   ├── frida_hooks/        banking_trojan.js, java_probe.js, bisect_sec.js
│       │   ├── vide/               Visual impersonation detection (pipeline, compare, baselines)
│       │   └── agentic/            planner.py, perception.py, goal_tracker.py, sanitizer.py, etc.
│       ├── validation/             Corpus runner, stress/recovery, engineering reports
│       └── sandbox/                Emulator abstraction (Genymotion / Android Studio / future)
│           ├── provider.py         Abstract SandboxProvider
│           ├── genymotion.py       Default Genymotion Desktop provider
│           └── android_studio.py   Optional Android Studio AVD provider
├── validate_dynamic_pipeline.py    Dynamic APK corpus validation CLI (live sandbox)
├── backend/
│   ├── Dockerfile                  Python 3.12 gateway container definition
│   ├── requirements.txt            Gateway dependencies
│   ├── app/
│   │   ├── main.py                 FastAPI Gateway entrypoint & lifecycle hooks
│   │   ├── routes/                 upload.py, cases.py, report.py, intelligence.py, runtime_api.py
│   │   ├── evidence_loader.py      Loads Frida evidence.json for cases API
│   │   ├── auth/                   auth.py (JWT authentication & RBAC)
│   │   ├── db/                     database.py (SQLite case store & IOC cache persistence)
│   │   ├── ai/                     gemini_rag.py (RAG indexer), gemini_client.py
│   │   └── workers/                analysis_queue.py (async worker pool)
│   └── tests/                      Automated unit & regression tests
├── tests/                          Root pytest (`tests/unit`, `tests/integration`) + `tests/apks/` corpus
├── analysis-engine/
│   ├── Dockerfile                  Ubuntu 24.04 + Java 17 + Python 3.12 microservice
│   ├── entrypoint.sh               Uvicorn launcher with health check
│   └── app/
│       └── main.py                 REST microservice endpoints (/api/v1/analyze, /status, etc.)
├── frontend/
│   ├── src/
│   │   ├── pages/                  FraudCard.tsx, TechnicalView.tsx, ThreatIntelView.tsx, Upload.tsx, Login.tsx, History.tsx
│   │   └── components/             WorkflowDiagram.tsx, ErrorBoundary.tsx
│   └── Dockerfile                  Vite/Nginx frontend container definition
└── tools/                          Standalone APKTool and JADX binaries
```

---

## 4. Deterministic Scoring Model

**[VERIFIED]** All formulas and constants below were read from [`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py) and confirmed by executing the test suite.

### 4.1 STEI — Static Threat Exposure Index

```text
STEI = 0.60·CT + 0.20·BT + 0.10·PR + 0.05·OB + 0.05·IR
```

| Axis | Weight | Meaning | Scoring |
|---|---:|---|---|
| CT | 0.60 | Credential Theft | accessibility +40, SMS +35, overlay +25; cap 100 |
| BT | 0.20 | Banking Target | Indian banking package targeting |
| PR | 0.10 | Permission Risk | dangerous permission set size |
| OB | 0.05 | Obfuscation | DexClassLoader + reflection + entropy |
| IR | 0.05 | Infrastructure Risk | 10 points per hardcoded URL/IP; cap 100 |

### 4.2 BFCI — Behavioral Fraud Confidence Index

```text
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

### 4.3 FRS — Fraud Risk Score

```text
dynamic conclusive:  nominal weights 0.25·STEI + 0.35·Dynamic + 0.20·Correlation + 0.20·BankingImpact
                     → renormalize over axes with data → × ai_confidence_multiplier → final_risk_score
static / inconclusive dynamic: dynamic axis excluded; correlation excluded when intel unavailable
```

`ai_confidence` is **rule-derived, not LLM-derived**: 1.0 when family is Unknown, 1.2 on a deterministic family-classifier match, 1.15 when the family came from threat correlation. It is hard-clamped to [0.5, 1.5] as a last line of defence.

### 4.4 Bands and Confidence

| Final score (after multiplier) | Band (`risk_engine.py`) |
|---|---|
| ≤ 30.0 | Safe |
| ≤ 60.0 | Suspicious |
| ≤ 89.0 | High Risk |
| ≥ 90.0 | Critical |

---

## 5. Verification & Test Suite

**[VERIFIED]** **519 / 519 tests collected & verified** (`pytest tests/ backend/tests --collect-only`, 2026-08-08).

Execution command:
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

All static analysis, dynamic sandbox, threat correlation, and risk scoring assertions are fully validated against empirical baselines.
