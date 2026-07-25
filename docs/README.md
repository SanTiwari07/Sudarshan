# Sudarshan Enterprise Documentation Portal Index

Welcome to the **Sudarshan Enterprise Documentation Portal**. This portal serves as the authoritative, evidence-grounded technical reference for the **SUDARSHAN Banking Threat Intelligence Platform**.

All documentation herein is strictly derived from and cross-verified against the active codebase (**SanTiwari07/Sudarshan**).

---

## Document Index & Directory Matrix

| Document | Title | Primary Focus & System Scope |
| :--- | :--- | :--- |
| [**01 — Introduction**](01_INTRODUCTION.md) | Problem Statement & Scope | Threat model, operational challenges in mobile banking fraud, target audience. |
| [**02 — System Overview**](02_SYSTEM_OVERVIEW.md) | Platform Architecture & Data Flow | End-to-end processing pipeline, microservices layout, container network topology. |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System Design & Technical Spec | In-depth technical specification of backend, frontend, engines, database, and APIs. |
| [**MIGRATION.md**](MIGRATION.md) | Microservice Migration Guide | Architectural specification of `analysis-engine` microservice container, REST APIs, and zero-copy shared volume. |
| [**03 — Static Threat Intelligence**](architecture/03_STATIC_THREAT_INTELLIGENCE.md) | Static Analysis & Decompilation | Containerized static engine, MobSF, Androguard, APKTool 2.10.0, JADX 1.5.1, `manifest.py` Investigation Manifest, STEI formula. |
| [**04 — Dynamic Analysis Engine**](architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) | Dynamic Sandbox & Agentic Explorer | Containerized Frida 17 PID attach, ART deoptimization, Network ADB (`host.docker.internal:5555`), mitmproxy HAR, Agentic Explorer 15-stage DAG. |
| [**05 — AI Investigation Engine**](architecture/05_AI_INVESTIGATION_ENGINE.md) | AI Core, RAG & Prompt Safety | Gemini 2.5 Flash, Ollama, vector RAG index (`gemini_rag.py`), prompt sanitizer. |
| [**06 — Evidence Processing**](architecture/06_EVIDENCE_PROCESSING.md) | Event Bus & Workflow Engine | `EventBus`, `EvidenceStore`, `WorkflowReconstructor` causal chain engine. |
| [**07 — Fraud Intelligence Engine**](architecture/07_FRAUD_INTELLIGENCE_ENGINE.md) | Threat Correlation & Attribution | VirusTotal, AlienVault OTX, AbuseIPDB lookup, deterministic family classifier. |
| [**08 — Deterministic Risk Engine**](architecture/08_DETERMINISTIC_RISK_ENGINE.md) | Risk Scoring & Math Formulas | 5-axis STEI, logarithmic volume-aware BFCI v2, 4-axis FRS formula, static fallback. |
| [**09 — AI Report Generation**](architecture/09_AI_REPORT_GENERATION.md) | Security Reporting & Export | Executive Fraud Cards, Jinja2 HTML exporter, STIX 2.1 JSON exporter, CSV IOC feed. |
| [**10 — Analyst Dashboard**](dashboard/10_DASHBOARD.md) | Analyst UI & Visual Workflows | React 18 SPA, Executive View, Technical SOC View, `WorkflowDiagram.tsx` timeline. |
| [**11 — Evaluation Strategy**](evaluation/11_EVALUATION.md) | Verification & Testing | 302 automated unit/integration tests (`pytest tests/`), determinism baselines. |
| [**HOW_TO_RUN.md**](HOW_TO_RUN.md) | Installation & Operations | Prerequisites, Docker Compose setup, single-command `start.ps1`, environment variables. |
| [**DAE_CURRENT_STATE.md**](DAE_CURRENT_STATE.md) | Technical Resolution Audit | Resolution state of containerization, ART JIT deopt, PID attach, BFCI v2, manifest, and HAR merger. |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | Developer Guidelines | Code standards, PEP-8/ESLint style, pytest testing workflows, pull request process. |
| [**CHANGELOG.md**](CHANGELOG.md) | Release Notes & Version History | Version history (`v2.3.0-STABLE`), release highlights, and commit traceability. |
| [**DOCUMENTATION_AUDIT_REPORT.md**](DOCUMENTATION_AUDIT_REPORT.md) | Master Audit Report | Summary of audit changes, updated files, new files, and link verification results. |

---

## High-Level Platform Architecture

```mermaid
graph TD
    subgraph Presentation Layer
        UI["React 18 Analyst Dashboard<br/>(Port 5173 / TechnicalView.tsx)"]
    end

    subgraph Core Gateway & Storage
        API["FastAPI Orchestrator Gateway<br/>(Port 8000 / main.py)"]
        AUTH["JWT Auth & RBAC"]
        DB[(SQLite Case Store<br/>sudarshan.db)]
        VOL[("Shared Volume /app/uploads")]
    end

    subgraph Containerized Analysis Engine Microservice
        ENGINE["Analysis Engine REST API<br/>(Port 8001 / main.py)"]
        MANIFEST["Investigation Manifest<br/>(manifest.py -> manifest.json)"]
        ANDRO["Androguard Engine<br/>(apk_analyzer.py)"]
        APKT["APKTool v2.10.0 Engine<br/>(apktool_engine.py)"]
        JADX["JADX v1.5.1 Source Scanner<br/>(jadx_engine.py)"]
        FRIDA["Frida 17 Sandbox Controller<br/>(frida_sandbox.py)"]
    end

    subgraph External Devices & Network Sidecars
        ADB["ADB TCP Bridge<br/>(host.docker.internal:5555)"]
        AVD["Android 13 AVD<br/>(frida-server 17.16.4)"]
        MITM["mitmproxy Sidecar<br/>(Port 8080 / HAR Dump Parser)"]
    endAR Dump Parser)"]
        AGENT["Agentic UI Explorer<br/>(agentic_explorer.py / 15-Stage DAG)"]
    end

    subgraph Intelligence & Scoring Layer
        BFCI_ENG["BFCI v2 Scorer<br/>(bfci_scorer.py)"]
        WORKFLOW["Workflow Reconstructor<br/>(workflow_reconstructor.py)"]
        CORR["Threat Correlator<br/>(VT / OTX / AbuseIPDB)"]
        RISK["Deterministic Risk Engine<br/>(risk_engine.py / STEI + FRS)"]
        RAG["Gemini 2.5 RAG Core<br/>(gemini_rag.py)"]
    end

    UI -->|HTTPS REST| API
    API --> AUTH
    API --> QUEUE
    QUEUE --> DB

    QUEUE --> MANIFEST
    MANIFEST --> MOBSF
    MANIFEST --> ANDRO
    MANIFEST --> APKT
    MANIFEST --> JADX

    QUEUE --> FRIDA
    FRIDA --> ADB
    ADB --> AVD
    FRIDA --> MITM
    FRIDA --> AGENT

    FRIDA --> BFCI_ENG
    FRIDA --> WORKFLOW
    QUEUE --> CORR
    QUEUE --> RISK
    RISK --> RAG
```

---

## Verification & Test Metrics

The Sudarshan platform codebase is backed by an automated regression and determinism verification test suite:

- **Total Test Cases**: **299 / 299 Passed (100% Pass Rate)**
- **Execution Latency**: ~1.2 seconds (`pytest tests/`)
- **Key Test Modules**:
  - `test_remaining_features.py`: Tests `InvestigationManifest`, `ApktoolEngine`, `JadxEngine`, and `NetworkCapture` mitmproxy HAR parsing.
  - `test_bfci_scorer.py`: Tests logarithmic volume scoring and 30s sequence bonuses.
  - `test_workflow_reconstructor.py`: Tests temporal causal chain reconstruction and MITRE stage mapping.
  - `test_risk_engine.py`: Tests 5-axis STEI, static fallback gate, and 4-axis FRS formula.
  - `test_prompt_injection.py`: Tests input sanitization against prompt injection attacks.
  - `test_determinism_replay.py`: Asserts byte-for-byte verdict stability across refactors.
