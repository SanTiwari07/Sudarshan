# SUDARSHAN — Feature Reality Matrix

> **Authoritative Feature Status & Implementation Matrix**  
> **Source Repository**: `SanTiwari07/Sudarshan`  
> **Last Verified Against Active Codebase**: 2026-08-25  

This document provides a strictly verified status matrix of every capability in the **SUDARSHAN** platform. Each entry is backed by specific source files and test verification evidence.

---

## Status Classification Definitions

* **`IMPLEMENTED`**: Fully implemented in production code, wired into the end-to-end scan pipeline, and covered by automated tests.
* **`PARTIALLY IMPLEMENTED`**: Core logic is implemented, but specific optional branches, integrations, or operational modes have constraints.
* **`EXPERIMENTAL`**: Functional in the codebase but designated for research, evaluation, or specific runtime environments.
* **`PLANNED / NOT IMPLEMENTED`**: Specified in initial proposals or requirements but not present in the current executable codebase.

---

## Core Feature Matrix

| Feature Area | Feature Name | Status | Implementation File(s) | Verification Evidence | Operational Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Intake & Gateways** | Single APK Upload (Sync) | **IMPLEMENTED** | `backend/app/routes/upload.py` | `backend/tests/test_analysis_client.py` | Validates ZIP magic (`PK\x03\x04`), 200 MB limit, server SHA-256 computation. |
| | Async Queued Upload | **IMPLEMENTED** | `backend/app/routes/upload.py`, `backend/app/workers/analysis_queue.py` | `backend/tests/test_batch.py` | Returns `job_id`; pollable via `/api/v1/status/{job_id}`. |
| | APK Discovery Crawler | **IMPLEMENTED** | `backend/app/routes/discovery.py`, `backend/app/services/discovery/` | `backend/tests/test_url_ingestion.py`, `backend/tests/test_url_discovery.py` | Crawls target domain, extracts APK URLs, and ingests candidates. |
| | Enterprise Batch Scanning | **IMPLEMENTED** | `backend/app/routes/batch.py`, `backend/app/workers/batch_worker.py` | `backend/tests/test_batch.py` | Multi-file upload, queue pause/resume/cancel/retry, role-scoped. |
| | JWT Auth & RBAC | **IMPLEMENTED** | `backend/app/auth/auth.py` | `backend/tests/test_hackathon_security_hardening.py` | Roles: `analyst`, `soc_lead`, `admin`. Optional public registration policy. |
| **Static Analysis** | Native Androguard Analysis | **IMPLEMENTED** | `shared/sudarshan_core/analyzers/apk_analyzer.py` | `backend/tests/test_detection_regressions.py` | Manifest parsing, permissions, exported components, string entropy. |
| | APK Corruption Repair | **IMPLEMENTED** | `shared/sudarshan_core/engines/apk_repair.py` | `backend/tests/test_manifest_repair.py` | Automatically repairs malformed AXML string tables and headers. |
| | APKTool 2.10.0 Decompilation | **IMPLEMENTED** | `shared/sudarshan_core/engines/apktool_engine.py` | Containerized engine execution | Extracts smali and raw resource XML hierarchies. |
| | JADX 1.5.1 Decompilation | **IMPLEMENTED** | `shared/sudarshan_core/engines/jadx_engine.py` | Containerized engine execution | Java decompilation and regex secret scanning. |
| | Optional MobSF Integration | **PARTIALLY IMPLEMENTED** | `shared/sudarshan_core/services/mobsf_client.py` | `tests/unit/test_mobsf_client.py` | Optional enrichment; pipeline runs smoothly if MobSF is absent. |
| | VIDE Visual Impersonation | **IMPLEMENTED** | `shared/sudarshan_core/engines/vide/` | `tests/unit/test_vide_*.py` (12 test suites) | AST comparison, Delta-E CIE76 color matching, Bank Signer Registry. |
| **Dynamic Sandbox** | Auto-Detect Sandbox Provider | **IMPLEMENTED** | `shared/sudarshan_core/sandbox/auto.py` | `tests/unit/test_sandbox_auto_detect.py` | Auto-detects Genymotion Desktop VM or Android Studio AVD via ADB. |
| | Sandbox Containment | **IMPLEMENTED** | `shared/sudarshan_core/security/sandbox_containment.py` | `tests/unit/test_sandbox_containment.py` | Enforces network boundaries, prevents accidental LAN bridging. |
| | Frida 17 Java Hook Bundle | **IMPLEMENTED** | `shared/sudarshan_core/engines/frida_hooks/banking_trojan.bundle.js` | `tests/unit/test_frida_pipeline_full.py` | Pre-compiled bundle linking `frida-java-bridge`; hooks SMS/Accessibility/Overlays. |
| | Exact PID Attachment | **IMPLEMENTED** | `shared/sudarshan_core/engines/frida_sandbox.py` | `backend/tests/test_launch_ladder.py` | Resolves PID via `pidof`; validates $\ge 5\text{s}$ stability before attaching. |
| | Launch Stability Ladder | **IMPLEMENTED** | `shared/sudarshan_core/engines/frida_sandbox.py` | `backend/tests/test_launch_ladder.py` | Multi-stage launch fallback (Launcher Intent $\rightarrow$ `am start` $\rightarrow$ `monkey`). |
| | Pregrant Permissions Policy | **IMPLEMENTED** | `shared/sudarshan_core/engines/permission_orchestrator.py` | `tests/unit/test_pregrant_permissions.py` | Controlled via `SUDARSHAN_PREGRANT_PERMISSIONS=1` to bypass launch blockers. |
| | Network Packet / Socket Capture | **IMPLEMENTED** | `shared/sudarshan_core/engines/network_capture.py` | `tests/unit/test_frida_pipeline_full.py` | Intercepts HTTP/HTTPS endpoints and raw socket destinations. |
| **Deep UI Explorer** | 5-Level Priority Perception | **IMPLEMENTED** | `shared/sudarshan_core/engines/agentic/perception.py` | `tests/unit/test_perception_fraud_vision.py` | Priority: XML $\rightarrow$ Activity $\rightarrow$ Frida events $\rightarrow$ Logcat $\rightarrow$ Vision. |
| | Rule-Based Screen Classifier | **IMPLEMENTED** | `shared/sudarshan_core/engines/agentic/screen_classifier.py` | `tests/unit/test_deep_exploration.py` | 17 semantic screen types + package ownership context. |
| | Screen Hash & State Graph | **IMPLEMENTED** | `shared/sudarshan_core/engines/agentic/screen_graph.py` | `tests/unit/test_deep_exploration.py` | Stable SHA-256 topology hashes, transition DAG, loop detection. |
| | Canonical Action Dispatch | **IMPLEMENTED** | `shared/sudarshan_core/engines/agentic/action_dispatch.py` | `tests/unit/test_action_execution_pipeline.py` | Translates semantic actions into executable ADB inputs (`tap`, `text`, `back`). |
| | Action Progress Verification | **IMPLEMENTED** | `shared/sudarshan_core/engines/agentic/action_verifier.py` | `tests/unit/test_action_verifier.py` | Compares pre- and post-observation diffs to confirm state changes. |
| **Risk & Scoring** | 5-Axis STEI Formula | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `backend/tests/test_risk_engine.py` | $0.60\text{CT} + 0.20\text{BT} + 0.10\text{PR} + 0.05\text{OB} + 0.05\text{IR}$. |
| | BFCI v2 Behavioral Formula | **IMPLEMENTED** | `shared/sudarshan_core/engines/bfci_scorer.py` | `backend/tests/test_bfci_scorer.py` | Logarithmic volume-aware behavioral formula ($wa\cdot A + ws\cdot S + \dots$). |
| | Full 4-Axis FRS Formula | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `backend/tests/test_case_study_frs.py` | $0.25\text{STEI} + 0.35\text{Dyn} + 0.20\text{Corr} + 0.20\text{Bank}$. |
| | Dynamic Axis Renormalization | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_risk_engine_nothing_happened.py` | Excludes inconclusive dynamic runs without penalizing benign static score. |
| | CH27 On-Device Fraud Triad | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_vide_ch27_rule.py` | Visual clone + Signer mismatch + Accessibility $\rightarrow$ FRS $\ge 95.0$ (`Critical`). |
| | Visibility Safety Floor | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_labelled_corpus.py` | Concealed payload + no dynamic observation $\rightarrow$ floored to `Suspicious`. |
| | Static Evidence Floor | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_risk_engine_nothing_happened.py` | $\text{STEI} \ge 50$ + empty dynamic run $\rightarrow$ floored to `Suspicious`. |
| | Evasion Safety Floor | **IMPLEMENTED** | `shared/sudarshan_core/engines/risk_engine.py` | `tests/unit/test_risk_engine_nothing_happened.py` | Anti-analysis detected + empty dynamic run $\rightarrow$ floored to `Suspicious`. |
| | Execution Assertion Matrix | **IMPLEMENTED** | `shared/sudarshan_core/engines/execution_assertions.py` | `tests/unit/test_risk_engine_nothing_happened.py` | Unexercised trigger conditions $\rightarrow$ Verdict = `INCOMPLETE_EXERCISE`. |
| **AI & Intelligence** | Gemini Provider & Failover | **IMPLEMENTED** | `shared/sudarshan_core/ai/gemini_provider.py` | `tests/unit/test_gemini_provider.py`, `test_gemini_fallback.py` | Circuit breaker (`AVAILABLE`, `DEGRADED`, `OPEN`), 60s cooldown, failover key. |
| | Gemini RAG Vector Store | **IMPLEMENTED** | `backend/app/ai/gemini_rag.py` | `backend/tests/test_visual_evidence_rag.py` | In-memory cosine similarity indexing over findings and indicators. |
| | Threat Intelligence Correlation | **IMPLEMENTED** | `shared/sudarshan_core/services/threat_correlator.py` | `tests/unit/test_virustotal_crosscheck.py` | VirusTotal, AlienVault OTX, AbuseIPDB with 24h TTL SQLite cache. |
| | Deterministic Family Classifier | **IMPLEMENTED** | `shared/sudarshan_core/engines/classification_engine.py` | `backend/tests/test_classification_engine.py` | Classifies Drinik, Xenomorph, Cerberus, Anubis, SOVA, Hydra, SpyNote, etc. |
| **Reporting & Export** | Executive & Technical Report (PDF) | **IMPLEMENTED** | `shared/sudarshan_core/engines/pdf_generator.py` | `backend/tests/test_pdf_generator.py` | Deterministic ReportLab PDF generation with FRS breakdown and timeline. |
| | Standalone HTML Report | **IMPLEMENTED** | `shared/sudarshan_core/engines/report_generator.py` | `backend/tests/test_report_generator.py` | Self-contained single-file HTML report. |
| | STIX 2.1 JSON Export | **IMPLEMENTED** | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | Structured threat intelligence bundle format. |
| | CSV IOC Feed Export | **IMPLEMENTED** | `backend/app/routes/report.py` | `backend/tests/test_report_generator.py` | High-confidence indicators formatted for SIEM ingestion. |
| **Analyst UI** | React 18 SPA Frontend | **IMPLEMENTED** | `frontend/src/App.tsx`, `pages/`, `components/` | Vitest / TypeScript verification | Full suite of investigative views and real-time polling. |
| | Interactive Case RAG Chat | **IMPLEMENTED** | `frontend/src/pages/InvestigationChat.tsx` | Backend `/api/v1/cases/{sha256}/chat` | Multi-turn conversational Q&A grounded on findings. |
| | Batch Scanning Management | **IMPLEMENTED** | `frontend/src/pages/BatchScan.tsx`, `BatchDetail.tsx` | Backend `/api/v1/batches` | Upload queue, live job progress cards, retry/cancel controls. |
| **Experimental / Future** | Random Input Fuzzing | **REMOVED** | *Removed from codebase* | Replaced by deterministic Agentic Explorer | Removed due to evidence corruption and ADB socket contention. |
| | Live MITM HAR Capture | **EXPERIMENTAL** | `shared/sudarshan_core/engines/network_capture.py` | `deploy/docker-compose.yml` (mitmproxy sidecar) | Requires sidecar container deployment and system certificate pinning bypass. |
| | Automated On-Device Unpacking | **PARTIALLY IMPLEMENTED** | `shared/sudarshan_core/engines/frida_sandbox.py` | Dynamic DEX dumping hook | Injects dynamic dump hooks; full automated second-stage re-analysis is manual. |
