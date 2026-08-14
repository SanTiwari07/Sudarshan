# Sudarshan Platform — Master Documentation Audit Report

```yaml
Audit Date:          2026-08-11
Auditor:             Documentation Engineer (automated codebase audit)
Platform Version:    v2.1.0 (backend/app/main.py — source of truth)
Target Repository:   SanTiwari07/Sudarshan (d:/Projects/Sudarshan BOI)
Audit Method:        Full codebase inspection — source files are the source of truth
Test Suite Metric:   730 tests collected in 16.61s (verified: 2026-08-14)
                     Command: $env:PYTHONPATH="backend;shared";
                              $env:JWT_SECRET_KEY="test_secret_key_for_pytest";
                              backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests --collect-only -q
```

---

## Executive Summary (2026-08-14)

A final documentation audit and synthesis was conducted. 

1. **Master Knowledge Base Synthesis**: 16 separate autonomous agent audits were conducted against the codebase. Findings were aggregated and synthesized into a single, unified 58-section master document: `SUDARSHAN_MASTER.md`.
2. **Legacy Documentation Deprecated**: All previous fragmented documentation files listed below are now officially deprecated. `SUDARSHAN_MASTER.md` is the single source of truth.
3. **Bug Fixes Documented**: The `pdf_generator.py` crash and `sanitizer.py` prompt injection gaps identified during the audit were successfully fixed in the codebase and logged in `CHANGELOG.md`.
4. **Dynamic Analysis Preflight & Test Pipelines**: Synchronized documentation across `README.md`, `02_SYSTEM_OVERVIEW.md`, `HOW_TO_RUN.md`, `04_DYNAMIC_ANALYSIS_ENGINE.md`, and `DAE_CURRENT_STATE.md` to reflect the newly integrated robust preflight scripts, exact PID matching (`pidof`), explicit TCP transport fallback logic, and 147 new automated dynamic test modules (test count increased from 583 to 730).

---

## Executive Summary (2026-08-11)

A full documentation audit was conducted against the live codebase. Key findings:

1. **Version mismatch corrected**: Multiple docs referenced `v2.5.0-STABLE` but `backend/app/main.py` declares `version="2.1.0"`. All documents have been updated to state `2.1.0`.
2. **Test count corrected**: Prior docs stated 583 tests. Verified count is **583** (2026-08-11 run — 64 additional tests discovered).
3. **BT axis bank count**: `08_DETERMINISTIC_RISK_ENGINE.md` cited "47 Indian banking apps" — `apk_analyzer.py` declares exactly **21 package prefixes** in `INDIAN_BANK_PACKAGES`. Corrected.
4. **Demo credentials exposure**: `BOI_DEMO_CREDENTIALS.md` published plaintext passwords in a documentation file. Replaced with placeholder references and guidance to configure via `.env`.
5. **CASE_STUDIES.md FRS/STEI conflation**: The summary table listed the same score for both STEI and FRS without noting they are different quantities. Annotated.
6. **BENCHMARKS.md**: Metrics were not empirically re-verified during this audit pass. Annotated "Not verified during this audit."
7. **`docs/security/`**: Two P0 reports exist; no general security overview document in this directory.

---

## Document Status Matrix

| File | Status | Accuracy | Issues Found | Action Taken |
|---|---|---|---|---|
| `docs/README.md` | CURRENT | HIGH | v2.5.0 ref; test count was 519 | Updated — 2.1.0; 583 tests |
| `docs/01_INTRODUCTION.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0 references | Updated |
| `docs/02_SYSTEM_OVERVIEW.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0 references; test count | Updated |
| `docs/ARCHITECTURE.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0 references; test count | Updated |
| `docs/BOI_DEMO_CREDENTIALS.md` | NEEDS UPDATE | LOW | Plaintext passwords in documentation | Updated — passwords replaced with placeholders |
| `docs/CHANGELOG.md` | PARTIALLY CURRENT | MEDIUM | References v2.5.0 as latest | Updated header |
| `docs/CONTRIBUTING.md` | CURRENT | HIGH | Accurate | Version note added |
| `docs/DAE_CURRENT_STATE.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0; test count 519 | Updated — 2.1.0; 583 |
| `docs/DOCUMENTATION_AUDIT_REPORT.md` | CURRENT | HIGH | This document | This file |
| `docs/HOW_TO_RUN.md` | CURRENT | HIGH | Commands verified against source | Version note added |
| `docs/MIGRATION.md` | CURRENT | HIGH | Still describes active architecture | Marked active; version corrected |
| `docs/PROJECT_CONTEXT.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0; test count | Updated |
| `docs/VALIDATION.md` | PARTIALLY CURRENT | MEDIUM | Test count was 519; actual 583 | Updated |
| `docs/architecture/03_STATIC_THREAT_INTELLIGENCE.md` | PARTIALLY CURRENT | MEDIUM | v2.5.0; bank count "47" | Updated |
| `docs/architecture/04_DYNAMIC_ANALYSIS_ENGINE.md` | CURRENT | HIGH | Accurate to codebase | Version corrected |
| `docs/architecture/05_AI_INVESTIGATION_ENGINE.md` | CURRENT | HIGH | Accurate | Version corrected |
| `docs/architecture/06_EVIDENCE_PROCESSING.md` | CURRENT | HIGH | Accurate | Version corrected |
| `docs/architecture/07_FRAUD_INTELLIGENCE_ENGINE.md` | CURRENT | HIGH | Accurate | Version corrected |
| `docs/architecture/08_DETERMINISTIC_RISK_ENGINE.md` | PARTIALLY CURRENT | MEDIUM | "47 Indian banking apps" — source has 21 | Updated |
| `docs/architecture/09_AI_REPORT_GENERATION.md` | CURRENT | HIGH | Accurate | Version corrected |
| `docs/architecture/VIDE.md` | CURRENT | HIGH | Verification status well-documented | No change needed |
| `docs/dashboard/10_DASHBOARD.md` | CURRENT | HIGH | Accurate to frontend source | Version corrected |
| `docs/evaluation/11_EVALUATION.md` | PARTIALLY CURRENT | MEDIUM | Test count was 519; actual 583 | Updated |
| `docs/evaluation/BENCHMARKS.md` | PARTIALLY CURRENT | LOW | Metrics not re-verified this pass | Annotated "Not verified" |
| `docs/evaluation/CASE_STUDIES.md` | PARTIALLY CURRENT | MEDIUM | FRS/STEI conflation in summary table | Annotated |
| `docs/future/12_FUTURE_WORK.md` | CURRENT | HIGH | Accurate | Version corrected |
| `docs/security/P0_RED_TEAM_PENETRATION_REPORT.md` | CURRENT | HIGH | P0 remediation record | No change needed |
| `docs/security/P0_SANDBOX_ESCAPE_INCIDENT.md` | CURRENT | HIGH | P0 incident record | No change needed |

---

## Cross-Document Consistency Issues

| Issue | Affected Files | Severity | Status |
|---|---|---|---|
| Version declared as `v2.5.0-STABLE` — actual is `2.1.0` | Most docs | MEDIUM | **Fixed** — corrected throughout |
| Test count stated as 519 — actual is 583 | `README.md`, `VALIDATION.md`, `11_EVALUATION.md`, `DAE_CURRENT_STATE.md` | MEDIUM | **Fixed** |
| "47 Indian banking apps" — `apk_analyzer.py` has 21 | `08_DETERMINISTIC_RISK_ENGINE.md`, `05_AI_INVESTIGATION_ENGINE.md`, `03_STATIC_THREAT_INTELLIGENCE.md` | LOW | **Fixed** (all three instances — 05 and 03 were missed in initial pass, corrected 2026-08-11) |
| Plaintext demo passwords in documentation | `BOI_DEMO_CREDENTIALS.md` | HIGH | **Fixed** — placeholders only |
| CASE_STUDIES.md conflates STEI and FRS in summary table | `CASE_STUDIES.md` | MEDIUM | **Annotated** |
| BENCHMARKS.md metrics not empirically re-verified | `BENCHMARKS.md` | MEDIUM | **Annotated** |

---

## What Could Not Be Verified in This Audit Pass

- **BENCHMARKS.md latency figures** — Not measured; figures retained from prior benchmarking.
- **VIDE live device WebView path** — Requires connected device; documented as needing `scripts/verify_vide_webview_device.md`.
- **VirusTotal/OTX/AbuseIPDB results** — Require live API keys not present during audit.
- **MobSF scan results** — Require running MobSF container; not tested during this audit.
- **CASE_STUDIES.md numeric scores** — Not re-run against current `risk_engine.py`; annotated as pending re-baseline.

---

## Remaining TODOs (Carry-Forward)

- Re-baseline `CASE_STUDIES.md` numeric scores against current `risk_engine.py` when corpus APKs are re-analyzed.
- Per-session ephemeral artifact roots — partial mitigation only; see `security/P0_RED_TEAM_PENETRATION_REPORT.md`.
- VIDE live WebView device path — run `scripts/verify_vide_webview_device.md` when frida-server is active.
- Add `docs/security/` overview document indexing the two P0 reports.
- **[CONFIRMED OPEN — G2d]** `sanitizer.py` is NOT imported by `gemini_client.py` or `gemini_rag.py`. The production LLM narrative paths (`analyze_with_llm`, RAG chat) receive APK-controlled strings (activity names, MobSF text) with no sanitization fence. `05_AI_INVESTIGATION_ENGINE.md` §4 implies it is wired — it is not. This is not a documentation fix; it requires a code change.

---

## Warnings

- `BOI_DEMO_CREDENTIALS.md` previously contained plaintext hackathon demo passwords. Best practice is to document that users configure passwords via `.env`, not to publish them in tracked markdown.
- Dynamic analysis requires an external rooted Android sandbox. The system does NOT perform dynamic analysis inside Docker containers — the sandbox must run on the host.
- Default `docker-compose.yml` bind-mounts source trees; not equivalent to hardened production posture.
- `SUDARSHAN_ALLOW_GATEWAY_DYNAMIC=true` runs dynamic analysis in the gateway container and is unsafe for production.
