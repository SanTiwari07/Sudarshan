<div align="center">
  <img src="frontend/public/vite.svg" alt="Sudarshan Logo" width="120" height="120" />
  <h1>SUDARSHAN</h1>
  <p><b>AI-Assisted Autonomous Mobile Fraud Investigation Platform</b></p>
  <p><i>Prepared and Submitted for Bank of India and IIT Hyderabad under the BOI Hackathon 2026</i></p>
  
  <p>
    <b>457</b> Passing Unit & Integration Tests &nbsp;&nbsp;|&nbsp;&nbsp;
    <b>Deterministic Fraud Scoring</b> &nbsp;&nbsp;|&nbsp;&nbsp;
    <b>Containerized Microservice Architecture</b>
  </p>
</div>

---

## Table of Contents
- [Executive Overview](#executive-overview)
- [Master Architecture Flowchart](#master-architecture-flowchart)
- [Key Platform Features](#key-platform-features)
- [System Architecture & Technology Stack](#system-architecture--technology-stack)
- [Repository Structure](#repository-structure)
- [Deterministic Risk Engine & Scoring](#deterministic-risk-scoring)
- [Complete API Documentation Overview](#complete-api-documentation-overview)
- [Installation & Setup Guide](#installation--setup-guide)
- [Documentation Portal Index](#documentation-portal-index)
- [License & Governance](#license--governance)

---

## Executive Overview

A malicious Android application can execute account takeover (ATO), OTP theft, or overlay phishing within **90 seconds** of installation. Conversely, a financial fraud analyst typically begins an investigation days later. **Sudarshan** bridges this critical time gap by delivering an end-to-end autonomous mobile threat intelligence platform specifically tailored for banking fraud operations.

Rather than producing generic static vulnerability summaries, Sudarshan performs deep static code decompilation (via **MobSF**, **Androguard**, **APKTool**, and **JADX**), autonomous dynamic runtime sandbox execution (via **Frida 17** with ART deoptimization and **mitmproxy** transparent HTTPS decryption), deterministic multi-axis risk scoring ($STEI$, $BFCI\text{ v2}$, $FRS$), and causal workflow reconstruction. Structured findings are indexed into an evidence-constrained Large Language Model (**Gemini 2.5 Flash** / **Ollama**) to generate analyst-actionable threat intelligence cards, MITRE ATT&CK mappings, regulatory customer advisories, and STIX 2.1 feeds.

---

## Master Architecture Flowchart

The flowchart below represents the verified operational data flow of the Sudarshan platform. **All core nodes and failure paths are fully operational in the codebase.**

```mermaid
flowchart TB

%% =====================================================
%% INPUT
%% =====================================================

APK([APK Upload])

%% =====================================================
%% STATIC ANALYSIS
%% =====================================================

subgraph STATIC["Static Intelligence Layer"]

SA["Static Analysis"]

MobSF["MobSF Engine"]
Andro["Androguard & Native Parser"]
APKT["APKTool Engine"]
JADX["JADX Engine"]

Normalize["Evidence Normalizer"]

STEI["STEI Score (5-Axis)"]
Planner["Investigation Planner"]

SA --> MobSF
SA --> Andro
SA --> APKT
SA --> JADX

MobSF --> Normalize
Andro --> Normalize
APKT --> Normalize
JADX --> Normalize

Normalize --> STEI
Normalize --> Planner

end

APK --> SA

%% =====================================================
%% PLANNING
%% =====================================================

subgraph PLAN["Planning Layer"]

Manifest["Investigation Manifest"]

Goals["15-Stage Fraud Goals"]
Sandbox["Sandbox Config"]
Profiles["Dynamic Hook Profiles"]
UIGoals["UI Exploration Goals"]

Planner --> Manifest

Manifest --> Goals
Manifest --> Sandbox
Manifest --> Profiles
Manifest --> UIGoals

end

%% =====================================================
%% DYNAMIC EXECUTION
%% =====================================================

subgraph DYNAMIC["Dynamic Analysis Layer"]

Prepare["Prepare Android Sandbox"]

Install["Install APK (Bypass SDK)"]

Launch["Launch Application"]

Explorer["Agentic UI Explorer"]

Frida["Frida 17 (ART Deopt)"]

Proxy["mitmproxy Sidecar"]

Logcat["Logcat Collector"]

Prepare --> Install
Install --> Launch

Launch --> Explorer
Launch --> Frida
Launch --> Proxy
Launch --> Logcat

end

Manifest --> Prepare

%% =====================================================
%% EVIDENCE COLLECTION
%% =====================================================

subgraph EVIDENCE["Runtime Evidence"]

Collector["Versioned Event Collector"]

Evidence["Evidence Store"]

Explorer --> Collector
Frida --> Collector
Proxy --> Collector
Logcat --> Collector

Decision{"Stop Conditions Met?"}

Collector --> Decision

Decision -- "No" --> Explorer

Decision -- "Yes" --> Evidence

end

%% =====================================================
%% FAILURE PATH
%% =====================================================

Instrumentation{"Runtime Evidence Collected?"}

Evidence --> Instrumentation

Instrumentation -- "No" --> Failed["Instrumentation Failed"]

%% =====================================================
%% INTELLIGENCE
%% =====================================================

Instrumentation -- "Yes" --> BFCI

subgraph INTEL["Fraud Intelligence"]

BFCI["BFCI v2 Scorer"]

Workflow["Behavior Workflow Reconstruction"]

ThreatIntel["Threat Intelligence Correlation"]

BankImpact["Banking Impact"]

Evidence --> Workflow

Workflow --> ThreatIntel

Workflow --> BFCI

Risk["Fraud Risk Engine"]

STEI --> Risk
BFCI --> Risk
ThreatIntel --> Risk
BankImpact --> Risk

FRS["Fraud Risk Score (FRS)"]

Risk --> FRS

Confidence["Rule-derived AI Confidence Clamp"]

FRS --> Confidence

Report["AI Investigation Report"]

Confidence --> Report

end

%% =====================================================
%% STATIC FALLBACK
%% =====================================================

Gate{"Dynamic Analysis Available?"}

STEI --> Gate

Gate -- "No" --> StaticRisk["Static Fallback Risk Engine"]

ThreatIntel --> StaticRisk

BankImpact --> StaticRisk

StaticRisk --> Confidence

Gate -- "Yes" --> Prepare

%% =====================================================
%% OUTPUT
%% =====================================================

Dashboard([Analyst Dashboard])

Report --> Dashboard

Failed --> Dashboard
```

---

## Key Platform Features

- **Dual Static Decompilation Pipeline**: Combines **APKTool** (xml/asset decompilation & obfuscated resource extraction) and **JADX** (DEX-to-Java source scanning across 10 fraud patterns) to complement MobSF & native APK parsing.
- **Pre-Sandbox Investigation Manifest (`manifest.py`)**: Produces a standardized `manifest.json` artifact before dynamic execution to dynamically select hook profiles (`canary`, `accessibility`, `sms`, `overlay`, `banking`, `dynamic_code`, `persistence`, `network`) and weigh goal priorities.
- **Frida 17 ART Deoptimization**: Executes `Java.deoptimizeEverything()` unconditionally upon attachment to guarantee hook execution on JIT-compiled Android system methods.
- **mitmproxy Sidecar Interception**: Intercepts transparent HTTPS traffic via Docker sidecar and merges decrypted HAR dumps (headers, status codes, payload sizes) with Frida socket hooks.
- **Agentic Dynamic Explorer**: LLM-guided autonomous UI navigation engine operating over a 15-stage fraud goal DAG with screen-hash loop detection and deterministic action fallbacks.
- **Behavioral Fraud Confidence Index (BFCI v2)**: Calculates volume-aware logarithmic event scoring with a 30-second temporal sequence bonus.
- **Causal Workflow Reconstructor (`workflow_reconstructor.py`)**: Reconstructs temporal causal chains (e.g., Overlay Phishing $\rightarrow$ SMS Theft $\rightarrow$ Account Takeover) mapped directly to MITRE ATT&CK for Mobile techniques.
- **Interactive UI Workflow Timeline (`WorkflowDiagram.tsx`)**: Displays expandable causal chain stages, confidence levels, hook badges, and MITRE technique links in the Analyst Dashboard.
- **Evidence-Constrained RAG Core**: Gemini 2.5 Flash / Ollama integration guarded by input sanitization (`sanitizer.py`) preventing prompt injection and hallucinated verdicts.

---

## System Architecture & Technology Stack

| Layer | Component | Technologies Used |
| :--- | :--- | :--- |
| **Frontend UI** | React 18 SPA | TypeScript, Vite, Tailwind CSS, Lucide React, React Router v6 |
| **API & Gateway** | FastAPI Backend | Python 3.10+, Pydantic v2, PyJWT, Uvicorn, Asyncio |
| **Storage & Queue** | Persistent Case Store | SQLite (`sudarshan.db`), Async Worker Pool, File Artifact Store |
| **Shared Package** | Sudarshan Core | [`shared/sudarshan_core/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/) mounted via `PYTHONPATH=/app:/opt/sudarshan-core` |
| **Static Analysis** | Decompilation Engines | MobSF Docker (Port 8008), Native `apk_analyzer.py`, APKTool CLI, JADX CLI, YARA Scanner |
| **Dynamic Sandbox** | Execution Environment | Genymotion Desktop (default) or Android Studio AVD via `SandboxProvider`, ADB TCP (Port 5555), Frida 17.16.4 |
| **Network Intercept**| Transparent Proxy | mitmproxy Docker Sidecar (Port 8080), HAR Dump Parser |
| **Risk & Scoring** | Math Scoring Engine | 5-Axis STEI, Volume Logarithmic BFCI v2, 4-Axis FRS, Threat Scenario Matrix |
| **AI Intelligence** | RAG & LLM Engine | Gemini 2.5 Flash, Ollama, Vector RAG Knowledge Base |

---

## Repository Structure

```text
Sudarshan BOI/
├── analysis-engine/                # Analysis Engine container (Ubuntu 24.04, JDK 17, Python 3.12)
├── backend/
│   ├── app/
│   │   ├── ai/                      # Gemini 2.5 RAG indexer & client
│   │   ├── auth/                    # JWT authentication & user RBAC management
│   │   ├── db/                      # SQLite database initialization & case persistence
│   │   ├── rag/                     # Knowledge base & financial fraud indexer
│   │   ├── routes/                  # FastAPI endpoints (upload, report, cases, intelligence)
│   │   └── workers/                 # Async analysis queue dispatcher & worker pool
│   ├── tests/                       # 388 automated unit & integration tests
│   ├── Dockerfile                   # FastAPI backend container configuration
│   └── requirements.txt             # Backend Python dependencies
├── shared/
│   └── sudarshan_core/              # Core domain engines, analyzers, models & services
│       ├── analyzers/               # Native APK analyzer
│       ├── engines/                 # Frida sandbox, UI explorer, Risk engine, BFCI, Workflow
│       ├── models/                  # Pydantic schemas & Manifest models
│       └── services/                # MobSF REST client & Threat Correlator
├── frontend/
│   ├── src/
│   │   ├── components/              # UI components, ErrorBoundary & WorkflowDiagram.tsx
│   │   ├── pages/                   # Login, Upload, FraudCard, TechnicalView, ThreatIntel, Chat, History
│   │   ├── App.tsx                  # Primary router & layout
│   │   └── main.tsx                 # React entry point
│   ├── Dockerfile                   # Nginx frontend container configuration
│   └── package.json                 # Node.js dependencies
├── docs/                            # Enterprise documentation portal
├── docker-compose.yml               # Multi-container orchestration (Frontend, Backend, Engine, MobSF, mitmproxy)
└── start.ps1                        # One-command bootstrapper script
```

---

## Deterministic Risk Scoring

Sudarshan enforces a strict **Determinism Invariant**: AI models generate narrative explanations downstream, but mathematical risk scores are strictly computed by deterministic formulas.

### 1. Fraud Risk Score ($FRS$)
$$FRS = 0.40 \times STEI + 0.30 \times BFCI_{\text{v2}} + 0.15 \times \text{ThreatCorrelation} + 0.15 \times \text{BankingImpact}$$

### 2. Static Threat and Environmental Index ($STEI$)
$$STEI = 0.60 \times CT + 0.20 \times BT + 0.10 \times PR + 0.05 \times OB + 0.05 \times IR$$
- **Credential Theft ($CT$)**: Accessibility, SMS read/write, overlay window abuse.
- **Banking Targeting ($BT$)**: Matches against 47 Indian banking package signatures (SBI, HDFC, ICICI, etc.).
- **Permission Risk ($PR$)**: Ratio of dangerous Android permissions.
- **Obfuscation ($OB$)**: Shannon entropy ratio of classes.dex & reflection usage.
- **Infrastructure Risk ($IR$)**: Malicious C2 domains/IPs extracted from bytecode.

### 3. Behavioral Fraud Confidence Index ($BFCI\text{ v2}$)
$$BFCI_{\text{v2}} = \min\left(100.0, \sum_{c} W_c \cdot \min\left(1.0, \frac{\ln(1 + N_c)}{\ln(1 + M_c)}\right) \times 100 + S_{\text{sequence}}\right)$$
Where $N_c$ is the observed event count for category $c$, $M_c$ is the category saturation threshold, $W_c$ is category weight, and $S_{\text{sequence}}$ is a +15 bonus when a temporal causal chain (e.g., Overlay $\rightarrow$ SMS Intercept) completes within 30 seconds.

---

## Complete API Documentation Overview

The FastAPI backend exposes versioned REST API endpoints (`/api/v1`):

| Method | Endpoint | Authorization | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | None | Authenticate user & issue JWT Access Token. |
| `POST` | `/api/v1/upload` | Bearer Token | Upload APK, validate manifest, dispatch analysis job. |
| `GET` | `/api/v1/cases` | Bearer Token | Retrieve paginated historical analysis cases from SQLite. |
| `GET` | `/api/v1/cases/{sha256}` | Bearer Token | Retrieve a single stored case by hash. |
| `GET` | `/api/v1/intelligence/feed` | Bearer Token | Retrieve threat intelligence feeds & IOC correlations. |
| `GET` | `/api/v1/report/pdf/{sha256}` | Bearer Token | Export complete PDF report artifact. |
| `GET` | `/api/v1/report/json/{sha256}` | Bearer Token | Export complete JSON report artifact. |
| `POST` | `/api/v1/report/chat` | Bearer Token | RAG-grounded AI investigator query interface. |
| `GET` | `/api/v1/auth/me` | Bearer Token | Return the authenticated user's profile. |

---

## Installation & Setup Guide

### Prerequisites
- **Docker**: Docker Desktop with Docker Compose
- **Android Sandbox**: Genymotion Desktop (default) with a rooted Android 10/11 (API 29/30) x86/x86_64 image — or optionally an Android Studio AVD (`SANDBOX_PROVIDER=android_studio`)
- **ADB**: Installed and on PATH, or Genymotion's bundled tools (`adb tcpip 5555`)
- **Python** *(Optional for dev/tests)*: Version 3.10+ (`pytest backend/tests`)
- **Node.js** *(Optional for UI dev)*: Version 18.x or higher & `npm`

> [!NOTE]
> **Containerized Toolchain**: APKTool, JADX CLI, Java 17, Frida 17, Androguard, and ADB worker processes are **100% containerized** inside `sudarshan-analysis-engine`. Zero binary installations are required on your host machine.

### Quick Start (Single Command)
Run the automated bootstrapper script from PowerShell:
```powershell
.\start.ps1
```

### Automated Test Suite Execution
Run the full automated test suite (**457 tests collected & verified**):
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

### Accessing Platform Interfaces
- **Fraud Analyst Dashboard**: `http://localhost:5173`
- **FastAPI Interactive API Docs**: `http://localhost:8000/docs`
- **Analysis Engine Microservice**: `http://analysis-engine:8001/health` (internal)
- **MobSF Static Engine**: `http://localhost:8008`
- **mitmproxy Proxy Endpoint**: `127.0.0.1:8080`

---

## Documentation Portal Index

The detailed documentation portal is available under [`docs/`](file:///d:/Projects/Sudarshan%20BOI/docs/README.md):

| Guide / Document | Summary |
| :--- | :--- |
| [**Docs Portal Index**](docs/README.md) | Central entry point, component inventory, data flow specifications. |
| [**01 — Introduction**](docs/01_INTRODUCTION.md) | Problem statement, threat model, target banking operational scope. |
| [**02 — System Overview**](docs/02_SYSTEM_OVERVIEW.md) | Platform architecture, microservices layout, container topology. |
| [**03 — Static Threat Intelligence**](docs/architecture/03_STATIC_THREAT_INTELLIGENCE.md) | APKTool, JADX, MobSF, Androguard, Manifest serialization, STEI formula. |
| [**04 — Dynamic Analysis Engine**](docs/architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) | Frida 17 PID attach, ART deopt, mitmproxy HAR, Agentic Explorer 15-stage DAG. |
| [**05 — AI Investigation Engine**](docs/architecture/05_AI_INVESTIGATION_ENGINE.md) | RAG graph index, Gemini 2.5 Flash, Ollama, prompt sanitization. |
| [**06 — Evidence Processing**](docs/architecture/06_EVIDENCE_PROCESSING.md) | EventBus, EvidenceStore, WorkflowReconstructor causal chain engine. |
| [**07 — Fraud Intelligence Engine**](docs/architecture/07_FRAUD_INTELLIGENCE_ENGINE.md) | Threat correlation (VirusTotal/OTX/AbuseIPDB) & family classifier. |
| [**08 — Deterministic Risk Engine**](docs/architecture/08_DETERMINISTIC_RISK_ENGINE.md) | Math formulas for 5-axis STEI, BFCI v2, FRS, Threat Scenario Matrix. |
| [**09 — AI Report Generation**](docs/architecture/09_AI_REPORT_GENERATION.md) | HTML security reports, PDF report exporter, JSON report feed. |
| [**10 — Analyst Dashboard**](docs/dashboard/10_DASHBOARD.md) | React 18 SPA workflow, Executive Fraud Card, Technical View, Workflow UI. |
| [**11 — Evaluation Strategy**](docs/evaluation/11_EVALUATION.md) | Automated testing suite (`pytest backend/tests`), benchmarks, determinism baselines. |
| [**How to Run Guide**](docs/HOW_TO_RUN.md) | Comprehensive installation, configuration, and execution guide. |
| [**DAE Current State**](docs/DAE_CURRENT_STATE.md) | Complete resolution audit and technical current state document. |
| [**Documentation Audit Report**](docs/DOCUMENTATION_AUDIT_REPORT.md) | Formal documentation audit, file mapping, and verification report. |

---

## License & Governance

Distributed under the MIT License. Prepared for Bank of India and IIT Hyderabad (BOI Hackathon 2026).
