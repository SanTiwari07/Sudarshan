# Sudarshan Enterprise Documentation Portal Index

Welcome to the **Sudarshan Enterprise Documentation Portal**. This portal serves as the authoritative, evidence-grounded technical reference for the **SUDARSHAN Banking Threat Intelligence Platform**.

All documentation herein is strictly derived from and cross-verified against the active codebase (**SanTiwari07/Sudarshan**).

---

## Document Index & Directory Matrix

| Document | Title | Primary Focus & System Scope |
| :--- | :--- | :--- |
| [**01 — Introduction**](01_INTRODUCTION.md) | Problem Statement & Scope | Threat model, operational challenges in mobile banking fraud, target audience. |
| [**02 — System Overview**](02_SYSTEM_OVERVIEW.md) | Platform Architecture & Data Flow | End-to-end processing pipeline, microservices layout, container network topology, runtime telemetry. |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System Design & Technical Spec | In-depth technical specification of backend, frontend, engines, database, `/api/runtime/*` APIs, and zero-copy volumes. |
| [**MIGRATION.md**](MIGRATION.md) | Microservice Migration Guide | Architectural specification of `analysis-engine` microservice container, REST APIs, zero-copy shared volume, and entrypoint healthchecks. |
| [**03 — Static Threat Intelligence**](architecture/03_STATIC_THREAT_INTELLIGENCE.md) | Static Analysis & Decompilation | Containerized static engine, MobSF, native `apk_analyzer.py`, `apk_repair.py` AXML recovery, APKTool 2.10.0, JADX 1.5.1, `manifest.py` Investigation Manifest, STEI formula. |
| [**04 — Dynamic Analysis Engine**](architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) | Dynamic Sandbox & Agentic Explorer | Containerized Frida 17 PID attach, Java-bridge probing (`java_probe.js`), ART deoptimization, Network ADB (`host.docker.internal:5555`), mitmproxy HAR, Agentic Explorer 15-stage DAG. |
| [**05 — AI Investigation Engine**](architecture/05_AI_INVESTIGATION_ENGINE.md) | AI Core, RAG & Prompt Safety | Gemini 2.5 Flash / Gemini 3.6 Flash, Ollama, vector RAG index (`gemini_rag.py`), prompt sanitizer. |
| [**06 — Evidence Processing**](architecture/06_EVIDENCE_PROCESSING.md) | Event Bus & Workflow Engine | `EventBus`, `EvidenceStore`, `WorkflowReconstructor` causal chain engine, runtime telemetry sink (`runtime_api.py`). |
| [**07 — Fraud Intelligence Engine**](architecture/07_FRAUD_INTELLIGENCE_ENGINE.md) | Threat Correlation & Attribution | VirusTotal, AlienVault OTX, AbuseIPDB lookup, 24h TTL SQLite IOC reputation cache, deterministic family classifier. |
| [**08 — Deterministic Risk Engine**](architecture/08_DETERMINISTIC_RISK_ENGINE.md) | Risk Scoring & Math Formulas | 5-axis STEI, logarithmic volume-aware BFCI v2, 4-axis FRS formula, static fallback. |
| [**09 — AI Report Generation**](architecture/09_AI_REPORT_GENERATION.md) | Security Reporting & Export | Executive Fraud Cards, HTML security reports, PDF report exporter, STIX 2.1 exporter, CSV IOC feed. |
| [**10 — Analyst Dashboard**](dashboard/10_DASHBOARD.md) | Analyst UI & Visual Workflows | React 18 SPA, Executive View (`FraudCard.tsx`), Technical SOC View, `WorkflowDiagram.tsx` timeline. |
| [**11 — Evaluation Strategy**](evaluation/11_EVALUATION.md) | Verification & Testing | Automated test suite in `tests/` & `backend/tests/` (**421 passing tests**), benchmarks, determinism baselines. |
| [**HOW_TO_RUN.md**](HOW_TO_RUN.md) | Installation & Operations | Prerequisites, Docker Compose setup, single-command `start.ps1`, Vite polling mode, environment variables. |
| [**DAE_CURRENT_STATE.md**](DAE_CURRENT_STATE.md) | Technical Resolution Audit | Resolution state of containerization, Frida 17 Java bridge, ART JIT deopt, PID attach, BFCI v2, manifest, and HAR merger. |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | Developer Guidelines | Code standards, PEP-8/ESLint style, pytest testing workflows, pull request process. |
| [**CHANGELOG.md**](CHANGELOG.md) | Release Notes & Version History | Version history (`v2.4.0-STABLE`), release highlights, and commit traceability. |
| [**DOCUMENTATION_AUDIT_REPORT.md**](DOCUMENTATION_AUDIT_REPORT.md) | Master Audit Report | Summary of audit changes, updated files, new files, and link verification results. |

---

## High-Level Platform Architecture

```mermaid
graph TD
    subgraph Presentation Layer
        UI["React 18 Analyst Dashboard<br/>(Port 5173 / TechnicalView.tsx / FraudCard.tsx)"]
    end

    subgraph Core Gateway & Storage
        API["FastAPI Orchestrator Gateway<br/>(Port 8000 / backend/app/main.py)"]
        AUTH["JWT Auth & RBAC<br/>(backend/app/auth/auth.py)"]
        TELEMETRY["Runtime Telemetry API<br/>(backend/app/routes/runtime_api.py)"]
        DB[(SQLite Case Store & IOC Cache<br/>sudarshan.db)]
        VOL[("Shared Volume /app/uploads")]
    end

    subgraph Containerized Analysis Engine Microservice (Port 8001)
        ENGINE["Analysis Engine REST API<br/>(Port 8001 / analysis-engine/app/main.py)"]
        MANIFEST["Investigation Manifest<br/>(shared/sudarshan_core/models/manifest.py)"]
        ANDRO["Native APK Analyzer<br/>(shared/sudarshan_core/analyzers/apk_analyzer.py)"]
        REPAIR["APK Repair Engine<br/>(shared/sudarshan_core/engines/apk_repair.py)"]
        APKT["APKTool Engine<br/>(shared/sudarshan_core/engines/apktool_engine.py)"]
        JADX["JADX Source Scanner<br/>(shared/sudarshan_core/engines/jadx_engine.py)"]
        FRIDA["Frida 17 Sandbox Controller<br/>(shared/sudarshan_core/engines/frida_sandbox.py)"]
        AGENT["Agentic UI Explorer<br/>(shared/sudarshan_core/engines/agentic_explorer.py)"]
    end

    subgraph External Devices & Network Sidecars
        ADB["ADB TCP Bridge<br/>(host.docker.internal:5555)"]
        AVD["Android 13 AVD<br/>(frida-server 17.16.4)"]
        MITM["mitmproxy Sidecar<br/>(Port 8080 / HAR Dump Parser)"]
        MOBSF["MobSF Engine<br/>(Port 8008 / mobsf_client.py)"]
    end

    subgraph Intelligence & Scoring Layer
        BFCI_ENG["BFCI v2 Scorer<br/>(shared/sudarshan_core/engines/bfci_scorer.py)"]
        WORKFLOW["Workflow Reconstructor<br/>(shared/sudarshan_core/engines/workflow_reconstructor.py)"]
        CORR["Threat Correlator (24h Cache)<br/>(shared/sudarshan_core/services/threat_correlator.py)"]
        RISK["Deterministic Risk Engine<br/>(shared/sudarshan_core/engines/risk_engine.py)"]
        RAG["Gemini 2.5/3.6 RAG Core<br/>(backend/app/ai/gemini_rag.py)"]
    end

    UI -->|HTTPS REST| API
    API --> AUTH
    API --> TELEMETRY
    API --> DB
    API --- VOL
    API -->|HTTP REST / Shared Volume| ENGINE
    ENGINE --- VOL

    ENGINE --> MANIFEST
    MANIFEST --> MOBSF
    MANIFEST --> ANDRO
    MANIFEST --> REPAIR
    MANIFEST --> APKT
    MANIFEST --> JADX

    ENGINE --> FRIDA
    FRIDA --> ADB
    ADB --> AVD
    FRIDA --> MITM
    FRIDA --> AGENT

    FRIDA --> BFCI_ENG
    FRIDA --> WORKFLOW
    ENGINE --> CORR
    ENGINE --> RISK
    RISK --> RAG
```

---

## Verification & Test Metrics

The Sudarshan platform codebase is backed by an automated regression and determinism verification test suite:

- **Test Suite Command**: `$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests`
- **Verification Metric**: **421 / 421 tests passing clean**.
- **Key Test Modules (in [`tests/`](file:///d:/Projects/Sudarshan%20BOI/tests/) and [`backend/tests/`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/))**:
  - `test_remaining_features.py`: Tests `InvestigationManifest`, `ApktoolEngine`, `JadxEngine`, and `NetworkCapture` mitmproxy HAR parsing.
  - `test_bfci_scorer.py`: Tests logarithmic volume scoring and sequence bonuses.
  - `test_workflow_reconstructor.py`: Tests temporal causal chain reconstruction and MITRE stage mapping.
  - `test_risk_engine.py`: Tests 5-axis STEI, static fallback gate, and 4-axis FRS formula.
  - `test_manifest_repair.py`: Tests automated AXML manifest repair and fallback XML decoding.
  - `test_prompt_injection.py`: Tests input sanitization against prompt injection attacks.
  - `test_determinism_replay.py`: Asserts byte-for-byte verdict stability across refactors.
  - `test_detection_regressions.py`: Validates detection regression assertions across malware samples.
  - `test_frida_preflight.py`: Verifies Frida attach SELinux preflight and Java-bridge execution.

