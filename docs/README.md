# SUDARSHAN Enterprise Documentation Portal Index

Welcome to the **Sudarshan Enterprise Documentation Portal**. This portal serves as the authoritative, evidence-grounded technical reference for the **SUDARSHAN Banking Threat Intelligence Platform**.

All documentation herein is strictly derived from and cross-verified against the active codebase (**SanTiwari07/Sudarshan**).

---

## Core System & Architecture Index

| Document | Title | Primary Focus & System Scope |
| :--- | :--- | :--- |
| [**CURRENT_ARCHITECTURE.md**](CURRENT_ARCHITECTURE.md) | **Current System Architecture** | **Authoritative end-to-end technical reference: multi-container topology, pipelines, math formulas, and data flows.** |
| [**CODEBASE_MAP.md**](CODEBASE_MAP.md) | **Codebase Map & Reference** | **Exhaustive directory-by-directory, class, and function index across backend, engine, shared core, and frontend.** |
| [**FEATURE_STATUS.md**](FEATURE_STATUS.md) | **Feature Reality Matrix** | **Verified implementation matrix (Implemented, Partial, Experimental, Planned) with test evidence.** |
| [**KNOWN_LIMITATIONS.md**](KNOWN_LIMITATIONS.md) | **Known Limitations & Boundaries** | **Catalog of runtime constraints, dormancy detection, networking boundaries, token limits, and workarounds.** |
| [**SUDARSHAN_MASTER.md**](SUDARSHAN_MASTER.md) | **Master Knowledge Base** | **Comprehensive system reference covering all platform components and historical context.** |

---

## Subsystem & Architectural Documentation

| Document | Title | Primary Focus & System Scope |
| :--- | :--- | :--- |
| [**01 - Introduction**](01_INTRODUCTION.md) | Problem Statement & Scope | Threat model, targeted mobile banking trojans (Drinik, Xenomorph, Cerberus, Anubis, SOVA, etc.), operational scope. |
| [**02 - System Overview**](02_SYSTEM_OVERVIEW.md) | Platform Architecture & Data Flow | End-to-end processing pipeline, microservices layout, container network topology, runtime telemetry. |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System Design & Technical Spec | In-depth technical specification of backend gateway, frontend, microservice, database, and shared volumes. |
| [**API Endpoints**](api/ENDPOINTS.md) | REST API Route Index | Complete index of all API routes across `/api/v1/*` (Upload, Batch, Cases, Intel, Reports, Auth) and `/api/*` (Runtime). |
| [**03 - Static Threat Intelligence**](architecture/03_STATIC_THREAT_INTELLIGENCE.md) | Static Analysis & Decompilation | Androguard native analysis, `apk_repair.py` AXML recovery, APKTool 2.10.0, JADX 1.5.1, `manifest.py`, STEI formula. |
| [**VIDE - Visual Impersonation**](architecture/VIDE.md) | Visual Impersonation (VIDE) | Layout AST comparison, Delta-E CIE76 color matching, Bank Signer Registry, and CH27 triad escalation rule. |
| [**04 - Dynamic Analysis Engine**](architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) | Dynamic Sandbox & Deep Explorer | Frida 17 exact PID attach, `banking_trojan.bundle.js` hook bundle, SandboxProvider, Perception pipeline, and Action Dispatch. |
| [**05 - AI Investigation Engine**](architecture/05_AI_INVESTIGATION_ENGINE.md) | AI Core, RAG & Prompt Safety | Gemini circuit breaker (`AVAILABLE`/`DEGRADED`/`OPEN`), primary/fallback failover, thinking token budgeting, vector RAG. |
| [**06 - Evidence Processing**](architecture/06_EVIDENCE_PROCESSING.md) | Event Bus & Workflow Engine | `RuntimeEventBus`, `EvidenceStore`, `ScreenshotManager`, `WorkflowReconstructor` causal chain engine, and telemetry sinks. |
| [**07 - Fraud Intelligence Engine**](architecture/07_FRAUD_INTELLIGENCE_ENGINE.md) | Threat Correlation & Attribution | VirusTotal, AlienVault OTX, AbuseIPDB correlation, 24h TTL SQLite IOC cache, deterministic family classifier. |
| [**08 - Deterministic Risk Engine**](architecture/08_DETERMINISTIC_RISK_ENGINE.md) | Risk Scoring & Math Formulas | 5-axis STEI, BFCI v2, 4-axis FRS formula, axis exclusion/renormalization, and the 4 safety floors. |
| [**09 - AI Report Generation**](architecture/09_AI_REPORT_GENERATION.md) | Security Reporting & Export | ReportLab PDF generator (`pdf_generator.py`), standalone HTML reports, STIX 2.1 JSON exporter, CSV IOC feeds. |
| [**10 - Analyst Dashboard**](dashboard/10_DASHBOARD.md) | Analyst UI & Visual Workflows | React 18 SPA, `AppShell`, `FraudCard.tsx`, `TechnicalView.tsx`, `ThreatIntelView.tsx`, `BatchScan.tsx`, `InvestigationChat.tsx`. |
| [**11 - Evaluation Strategy**](evaluation/11_EVALUATION.md) | Verification & Testing | Pytest test suites across `tests/` and `backend/tests/`, ground-truth matrix, determinism replay. |
| [**Corpus Detection Validation**](evaluation/CORPUS_STATIC_VALIDATION.md) | Measured Accuracy | Static-only scoring of 17 labelled samples (8 real banking trojans, 9 controls): **8/8 flagged, 0/9 false positives**. |
| [**HOW_TO_RUN.md**](HOW_TO_RUN.md) | Installation & Operations | Prerequisites, Docker Compose setup, `start.ps1`, environment configuration, and emulator connectivity. |
| [**VALIDATION.md**](VALIDATION.md) | Validation Protocols | Determinism replay, ground-truth matrix, pytest suite, and dynamic pipeline validation. |
| [**DAE_CURRENT_STATE.md**](DAE_CURRENT_STATE.md) | Technical Resolution Audit | Resolution state of containerization, explicit TCP transport, preflight pipeline, Frida 17 Java bridge, exact PID attach, BFCI v2. |
| [**CONTRIBUTING.md**](CONTRIBUTING.md) | Developer Guidelines | Code standards, PEP-8/ESLint style, pytest testing workflows, pull request process. |
| [**CHANGELOG.md**](CHANGELOG.md) | Release Notes & Version History | Version history (`v2.1.0`), release highlights, and commit traceability. |
| [**security/P0_SANDBOX_ESCAPE_INCIDENT.md**](security/P0_SANDBOX_ESCAPE_INCIDENT.md) | Sandbox Escape Incident | P0 containment remediation, hardened compose, env checklist. |
| [**security/P0_RED_TEAM_PENETRATION_REPORT.md**](security/P0_RED_TEAM_PENETRATION_REPORT.md) | Red Team Findings | ADB bypass fixes, residual risks, regression test commands. |

---

## High-Level Platform Architecture

```mermaid
graph TD
    subgraph Presentation Layer
        UI["React 18 Analyst Dashboard<br/>(Port 5173 / TechnicalView.tsx / FraudCard.tsx / BatchScan.tsx)"]
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
        VIDE["VIDE Engine<br/>(shared/sudarshan_core/engines/vide/pipeline.py)"]
        FRIDA["Frida 17 Sandbox Controller<br/>(shared/sudarshan_core/engines/frida_sandbox.py)"]
        AGENT["Agentic UI Explorer<br/>(shared/sudarshan_core/engines/agentic_explorer.py)"]
    end

    subgraph External Devices & Network Sidecars
        ADB["ADB TCP Bridge<br/>(Genymotion VM IP or host.docker.internal:5037)"]
        DEVICE["Android Sandbox (Genymotion / AVD)<br/>frida-server 17.16.4 (Port 27055)"]
        MOBSF["Optional MobSF Engine<br/>(Port 8008 / mobsf_client.py)"]
    end

    subgraph Intelligence & Scoring Layer
        BFCI_ENG["BFCI v2 Scorer<br/>(shared/sudarshan_core/engines/bfci_scorer.py)"]
        WORKFLOW["Workflow Reconstructor<br/>(shared/sudarshan_core/engines/workflow_reconstructor.py)"]
        CORR["Threat Correlator (24h Cache)<br/>(shared/sudarshan_core/services/threat_correlator.py)"]
        RISK["Deterministic Risk Engine<br/>(shared/sudarshan_core/engines/risk_engine.py)"]
        RAG["Gemini RAG Core<br/>(backend/app/ai/gemini_rag.py)"]
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
    MANIFEST --> VIDE

    ENGINE --> FRIDA
    FRIDA --> ADB
    ADB --> DEVICE
    FRIDA --> AGENT

    FRIDA --> BFCI_ENG
    FRIDA --> WORKFLOW
    ENGINE --> CORR
    ENGINE --> RISK
    RISK --> RAG
```
