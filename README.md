<div align="center">
  <img src="frontend/public/vite.svg" alt="Sudarshan Logo" width="120" height="120" />
  <h1>SUDARSHAN</h1>
  <p><b>Banking Threat Intelligence Platform for Mobile Fraud Operations</b></p>
  <p><i>Prepared and Submitted for Bank of India and IIT Hyderabad under the BOI Hackathon 2026</i></p>
  
  <p>
    <b>80M+</b> Customers Protected &nbsp;&nbsp;|&nbsp;&nbsp; 
    <b>47</b> Banking Apps Monitored &nbsp;&nbsp;|&nbsp;&nbsp; 
    <b>&lt;5 Min</b> Intelligence Generation
  </p>
</div>

---

## The Problem: Intelligence Translation
A malicious APK can compromise a customer account in under 90 seconds. A fraud analyst typically begins an investigation 3–7 days later. **This is not a malware detection problem; this is an intelligence translation problem.**

*Existing tools generate technical reports. **Sudarshan generates fraud operations decisions.***

---

## Documentation System

Sudarshan features a complete enterprise documentation portal located in [`docs/`](docs/README.md):

| Document | Description |
| :--- | :--- |
| [**Documentation Portal**](docs/README.md) | Central index, technology stack, navigation map, quick start guide. |
| [**01 — Introduction**](docs/01_INTRODUCTION.md) | Problem statement, core principles, target audience, and scope. |
| [**02 — System Overview**](docs/02_SYSTEM_OVERVIEW.md) | High-level system architecture, microservices layout, and tech stack. |
| [**03 — Static Threat Intelligence**](docs/architecture/03_STATIC_THREAT_INTELLIGENCE.md) | MobSF container integration, Androguard fallback, manifest/code scanners. |
| [**04 — Dynamic Analysis Engine**](docs/architecture/04_DYNAMIC_ANALYSIS_ENGINE.md) | Frida 17 sandbox, AVD bridge, Agentic Explorer, 15-stage DAG. |
| [**05 — AI Investigation Engine**](docs/architecture/05_AI_INVESTIGATION_ENGINE.md) | Gemini 2.5 Flash, local Ollama, RAG evidence index, prompt sanitizer. |
| [**06 — Evidence Processing**](docs/architecture/06_EVIDENCE_PROCESSING.md) | EvidenceStore, EventBus, MITRE ATT&CK for Mobile mapper, YARA, IOCs. |
| [**07 — Fraud Intelligence Engine**](docs/architecture/07_FRAUD_INTELLIGENCE_ENGINE.md) | Threat correlator (VirusTotal/OTX/AbuseIPDB) and family classifier. |
| [**08 — Deterministic Risk Engine**](docs/architecture/08_DETERMINISTIC_RISK_ENGINE.md) | 5-axis STEI, BFCI, FRS mathematical models, threat scenario matrix. |
| [**09 — AI Report Generation**](docs/architecture/09_AI_REPORT_GENERATION.md) | Jinja2 HTML security reports, STIX 2.1 JSON exporter, CSV IOC feed. |
| [**10 — Analyst Dashboard**](docs/dashboard/10_DASHBOARD.md) | React 18 SPA architecture, Executive Fraud Card, Technical SOC View. |
| [**11 — Evaluation Strategy**](docs/evaluation/11_EVALUATION.md) | Automated testing framework (285 passing tests) and determinism baselines. |
| [**Case Studies**](docs/evaluation/CASE_STUDIES.md) | InsecureBankv2, Drinik, and Xenomorph trojan sample walkthroughs. |
| [**Benchmarks**](docs/evaluation/BENCHMARKS.md) | Execution latencies, resource consumption, and queue capacity bounds. |
| [**12 — Future Work**](docs/future/12_FUTURE_WORK.md) | eBPF kernel telemetry floor, Celery queue, ChromaDB vector RAG roadmap. |
| [**How to Run Guide**](docs/HOW_TO_RUN.md) | Complete local and Docker installation instructions. |
| [**Project Context**](docs/PROJECT_CONTEXT.md) | Master context document for developer onboarding. |
| [**DAE Current State**](docs/DAE_CURRENT_STATE.md) | Technical assessment of dynamic analysis engine state. |
| [**Validation Protocols**](docs/VALIDATION.md) | Pipeline validation standards and ground-truth mapping rules. |
| [**Changelog**](docs/CHANGELOG.md) | Version history and release notes. |
| [**Contributing Guide**](docs/CONTRIBUTING.md) | Contribution standards and developer guidelines. |

---

## Core Design Principles

1. **Deterministic Detection, Explainable Intelligence** *(Inspired by PayPal & RBI)*  
   AI should explain decisions, not make them. Every alert, risk score, or recommendation is derived from transparent, weighted mathematical formulas based on observable threat behaviors.
2. **Human Judgment, Machine Scale** *(Inspired by Palantir)*  
   Machines process evidence at scale; humans make accountable decisions. Sudarshan automates analysis while keeping critical fraud response decisions with analysts.
3. **Fraud-First, Not Malware-First** *(Inspired by UPI Ecosystem)*  
   Traditional tools ask "What is this malware?" Sudarshan asks "Who is at risk, what is being targeted, and what action should be taken?"

---

## Deterministic Risk Scoring

Sudarshan eliminates black-box AI by using transparent, weighted mathematical formulas:

### Fraud Risk Score (FRS)
```text
FRS = 0.25(Static Exposure) + 0.35(Dynamic Behavior) + 0.20(Correlation) + 0.20(Banking Impact)
```

### Static Threat and Environmental Index (STEI)
```text
STEI = 0.60(Credential Theft) + 0.20(Banking Targeting) + 0.10(Permission Risk) + 0.05(Obfuscation) + 0.05(Infrastructure)
```

---

## Quick Start

> **Prerequisite**: Ensure your Android Emulator (AVD) is running.

Launch the entire platform with a single command:

```powershell
.\start.ps1
```

| Service | Access URL |
|---|---|
| **Fraud Analyst Dashboard** | `http://localhost:5173` |
| **Backend API Gateway Docs** | `http://localhost:8000/docs` |
| **MobSF Engine** | `http://localhost:8001` (mobsf / mobsf) |

---

## License & Governance

Distributed under the MIT License. Prepared for Bank of India and IIT Hyderabad (BOI Hackathon 2026).
