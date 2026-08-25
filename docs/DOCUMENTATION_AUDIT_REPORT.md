# Sudarshan Platform — Master Documentation Audit Report

```yaml
Audit Date:          2026-08-25
Auditor:             Antigravity AI Codebase Auditor
Platform Version:    v2.1.0 (backend/app/main.py — source of truth)
Target Repository:   SanTiwari07/Sudarshan (d:/Projects/Sudarshan BOI)
Audit Method:        Exhaustive multi-layer codebase audit (Backend, Analysis Engine, Core, Frontend, Tests, DB, Config)
Test Suite Metric:   920 tests collected, 525 enforced by CI
```

---

## 1. Executive Summary (2026-08-25)

An exhaustive, evidence-grounded audit and synchronization of the entire `docs/` repository was performed against the active **SUDARSHAN** codebase (`SanTiwari07/Sudarshan`).

### Key Accomplishments & Deliverables:
1. **Created 4 Foundational Architectural Documents**:
   - [`CURRENT_ARCHITECTURE.md`](CURRENT_ARCHITECTURE.md): Authoritative end-to-end technical reference documenting multi-container topologies, pipelines, mathematical scoring models, and data flows.
   - [`CODEBASE_MAP.md`](CODEBASE_MAP.md): Directory-by-directory, class, and function index across `backend/`, `analysis-engine/`, `shared/sudarshan_core/`, `frontend/`, `scripts/`, and `tests/`.
   - [`FEATURE_STATUS.md`](FEATURE_STATUS.md): Feature reality matrix categorizing all platform capabilities as `IMPLEMENTED`, `PARTIALLY IMPLEMENTED`, `EXPERIMENTAL`, or `PLANNED` with concrete code & test evidence.
   - [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md): Authoritative catalog of runtime constraints, dormant malware handling, network loopback boundaries, token consumption limits, and remediation workarounds.
2. **Synchronized REST API Specifications**:
   - Updated [`api/ENDPOINTS.md`](api/ENDPOINTS.md) with complete specifications of all 51+ active API routes across `/api/v1/*` (Upload, Enterprise Batch Scanning, Cases, Intel, Reports, Auth, VIDE Baselines, Discovery) and `/api/*` (Runtime Telemetry).
3. **Synchronized All Subsystem Specifications**:
   - Refreshed all 8 architecture documents (`03_STATIC_THREAT_INTELLIGENCE.md` through `09_AI_REPORT_GENERATION.md` and `VIDE.md`) to align with exact formula definitions, compiled Frida 17 Java bridges, 3-state Gemini circuit breakers, ReportLab vector gauges, and CH27 triad escalation rules.
4. **Refreshed Portal Navigation**:
   - Updated [`README.md`](README.md), [`01_INTRODUCTION.md`](01_INTRODUCTION.md), [`02_SYSTEM_OVERVIEW.md`](02_SYSTEM_OVERVIEW.md), [`HOW_TO_RUN.md`](HOW_TO_RUN.md), and [`dashboard/10_DASHBOARD.md`](dashboard/10_DASHBOARD.md).

---

## 2. Verified Architectural Reality Matrix

| Architectural Subsystem | Documented Reality & Code Verification |
| :--- | :--- |
| **API Gateway & Microservice** | Gateway runs on port 8000 (`backend/app/main.py`); Analysis Engine runs on port 8001 (`analysis-engine/app/main.py`) with a concurrency semaphore (`MAX_CONCURRENT_ANALYSES=2`) sharing `/app/uploads`. |
| **Database & Persistence** | Direct async SQL queries via `aiosqlite` on `sudarshan.db` (WAL mode enabled). No SQLAlchemy ORM used. Raw analysis payloads stored in `cases.raw_result`. |
| **Authentication & RBAC** | JWT Bearer authentication with `analyst`, `soc_lead`, and `admin` roles in `backend/app/auth/auth.py`. Public registration toggle via `ALLOW_PUBLIC_REGISTRATION`. |
| **Static Decompilation** | Native `apk_analyzer.py` (Androguard) + `apk_repair.py` (AXML corruption recovery) + `apktool_engine.py` (APKTool 2.10.0) + `jadx_engine.py` (JADX 1.5.1) + optional `mobsf_client.py` (Port 8008). |
| **Dynamic Sandbox** | Genymotion VM or Android Studio AVD via `SandboxProvider`. Preflight check (`scripts/preflight.py`), exact PID attach (`pidof`), compiled `banking_trojan.bundle.js` with `frida-java-bridge` (Frida 17+), and ART deoptimization (`Java.deoptimizeEverything()`). |
| **UI Deep Exploration** | Deterministic state machine with 5-level perception priority (`perception.py`), 17 semantic screen types (`screen_classifier.py`), action dispatching (`action_dispatch.py`), and post-action verification (`action_verifier.py`). |
| **Scoring Formulas** | 5-Axis STEI ($0.60\text{CT} + 0.20\text{BT} + 0.10\text{PR} + 0.05\text{OB} + 0.05\text{IR}$); Logarithmic BFCI v2; 4-Axis FRS with dynamic weight renormalization; CH27 Triad escalation ($\ge 95.0$ `Critical`); 4 Safety Floors. |
| **Visual Impersonation (VIDE)** | View-tree structural AST comparison (35%) + Brand keyword Jaccard (40%) + Delta-E CIE76 color matching (25%) + Bank signer registry certificate check. |
| **AI Intelligence & RAG** | `GeminiProviderManager` with 3-state circuit breaker (`AVAILABLE`, `DEGRADED`, `OPEN`), primary (`gemini-3.6-flash`) to fallback (`gemini-2.5-flash`) failover, 60s cooldown, token budgeting (2048 tokens), and in-memory vector RAG (`gemini_rag.py`). |
| **Enterprise Batch Scanning** | Async batch creation (`POST /api/v1/batches`), FIFO sequential processing via `batch_worker.py`, pause/resume/cancel/retry controls, and live progress streaming. |
| **Security Reporting** | ReportLab PDF generator (`pdf_generator.py`) with vector dials and meters, standalone HTML reports, STIX 2.1 JSON bundle export, and CSV IOC feeds. |
| **Frontend UI** | React 18 SPA with Vite, Tailwind CSS, `InvestigationShell`, `FraudCard.tsx`, `TechnicalView.tsx`, `ThreatIntelView.tsx`, `BatchScan.tsx`, `InvestigationChat.tsx`, and authenticated screenshot viewers. |
