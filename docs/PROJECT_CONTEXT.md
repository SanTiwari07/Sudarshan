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

**[VERIFIED]** This invariant currently holds at the scoring layer. Identical recorded evidence produces a byte-identical verdict, and LLM-authored fields merged into the dynamic payload do not move the score. Verified across **388 / 388 passing tests** (`pytest backend/tests`).

---

## 2. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite 5 (Port 5173) |
| Gateway Backend | Python 3.12/3.13, FastAPI, Uvicorn (Port 8000) |
| Analysis Engine | Containerized Python 3.12 + Java 17 + Ubuntu 24.04 (Internal Port 8001) |
| Shared Core | `sudarshan_core` python package mounted as `/opt/sudarshan-core` |
| Persistence | SQLite (`sudarshan.db`), aiosqlite, SQLAlchemy |
| Auth | JWT Bearer, passlib/bcrypt |
| Static analysis | Androguard, MobSF (Port 8008), APKTool 2.10.0, JADX 1.5.1, YARA Scanner |
| Dynamic analysis | Frida 17.16.4 + frida-tools, ADB (`host.docker.internal:5555`), Android emulator |
| Network Proxy | mitmproxy sidecar (`127.0.0.1:8080:8080`), HAR ingest |
| Signatures | YARA Python |
| Threat intel | VirusTotal, AlienVault OTX, AbuseIPDB (optional correlation) |
| LLM | Google Gemini via `google-genai` (`gemini-2.5-flash`), Ollama |
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
│   │   ├── routes/                 upload.py (orchestrator), cases.py, report.py, intelligence.py
│   │   ├── auth/                   auth.py (JWT authentication & RBAC)
│   │   ├── db/                     database.py (SQLite case store & audit persistence)
│   │   ├── ai/                     gemini_rag.py (RAG indexer), gemini_client.py
│   │   └── workers/                analysis_queue.py (async worker pool)
│   └── tests/                      388 automated unit & integration tests
├── analysis-engine/
│   ├── Dockerfile                  Ubuntu 24.04 + Java 17 + Python 3.12 microservice
│   ├── entrypoint.sh               Uvicorn launcher
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
dynamic available:  FRS = clamp(0.40·STEI + 0.30·BFCI + 0.15·Correlation + 0.15·BankingImpact, 0, 100)
static only:        FRS = clamp(0.50·STEI + 0.25·Correlation + 0.25·BankingImpact, 0, 100)
```

`ai_confidence` is **rule-derived, not LLM-derived**: 1.0 when family is Unknown, 1.2 on a deterministic family-classifier match, 1.15 when the family came from threat correlation. It is hard-clamped to [0.5, 1.5] as a last line of defence.

### 4.4 Bands and Confidence

| Final score | Band |
|---|---|
| < 20.0 | SAFE |
| 20.0 – 39.9 | LOW |
| 40.0 – 59.9 | MEDIUM |
| 60.0 – 79.9 | HIGH |
| ≥ 80.0 | CRITICAL |

---

## 5. Verification & Test Suite

**[VERIFIED]** **388 / 388 tests passing clean**.

Execution command:
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests
```

All static analysis, dynamic sandbox, threat correlation, and risk scoring assertions are fully validated against empirical baselines.
