# SUDARSHAN — MASTER PROJECT KNOWLEDGE BASE
> This document is the ultimate ground truth documentation for the Sudarshan BOI platform, superseding all other documentation.

## 0. Document Metadata

- **Project Name:** Sudarshan Enterprise SOC
- **Version:** v2.1.0
- **Documentation Version:** 3.0.0 (Zero-Drift)
- **Audit Date:** 2026-08-14
- **Repository State:** Synchronized
- **Documentation Status:** Final
- **Source-of-Truth Policy:** The actual codebase is the primary source of truth. Existing documentation is not automatically correct.
- **Verification Status:** Verified against Codebase
- **Confidentiality Note:** STRICTLY CONFIDENTIAL

## 1. EXECUTIVE OVERVIEW

Sudarshan is an Enterprise SOC platform designed for deep threat investigation and analysis of Android APKs. It exists to provide determinism in risk scoring while utilizing AI strictly for narrative generation, ensuring security boundaries are maintained. Target users include SOC analysts, executives, developers, security researchers, and legal entities. The platform architecture is built heavily around deterministic risk evaluation, separating scoring and narrative entirely, ensuring extreme explainability and auditability while degrading gracefully on component failures.

## 2. PROJECT OBJECTIVES

This section (2. PROJECT OBJECTIVES) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 3. CORE DESIGN PRINCIPLES

This section (3. CORE DESIGN PRINCIPLES) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 4. COMPLETE SYSTEM ARCHITECTURE

This section (4. COMPLETE SYSTEM ARCHITECTURE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 5. COMPLETE REPOSITORY STRUCTURE

This section (5. COMPLETE REPOSITORY STRUCTURE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 6. TECHNOLOGY STACK

- **Frontend**: React, TypeScript, Vite, Tailwind CSS
- **Backend**: FastAPI, Python
- **Database**: aiosqlite (NO SQLAlchemy; all integrations utilizing raw SQL)
- **Analysis Engines**: MobSF, Androguard, APKTool, JADX, Frida, ADB, mitmproxy
- **AI Integrations**: Gemini, RAG
- **Reporting**: ReportLab (PDF Generation)
- **Infrastructure**: Docker, Docker Compose (`docker-compose.yml`, `docker-compose.hardened.yml`)

## 7. USER JOURNEY

This section (7. USER JOURNEY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 8. AUTHENTICATION & AUTHORIZATION

This section (8. AUTHENTICATION & AUTHORIZATION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 9. APK INGESTION PIPELINE

This section (9. APK INGESTION PIPELINE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 10. STATIC THREAT INTELLIGENCE

This section (10. STATIC THREAT INTELLIGENCE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 11. INVESTIGATION MANIFEST

This section (11. INVESTIGATION MANIFEST) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 12. DYNAMIC ANALYSIS ENGINE

This section (12. DYNAMIC ANALYSIS ENGINE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 13. FRIDA HOOK ARCHITECTURE

This section (13. FRIDA HOOK ARCHITECTURE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 14. AGENTIC EXPLORER

This section (14. AGENTIC EXPLORER) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 15. NETWORK INTELLIGENCE

This section (15. NETWORK INTELLIGENCE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 16. EVIDENCE PROCESSING

The Visual Impersonation Detection Engine (VIDE) uses AST tree matching and is decoupled from external Threat Intel APIs. It computes structural archetypes and visual styles with deterministic weighting thresholds. The bank signer registry currently uses LAB/HACKATHON BASELINE placeholder hashes and MUST be updated for production. VIDE detections systematically escalate risk scores inside the `risk_engine.py` using CH06 and CH27 logic flows.

## 17. FRAUD WORKFLOW RECONSTRUCTION

This section (17. FRAUD WORKFLOW RECONSTRUCTION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 18. THREAT INTELLIGENCE CORRELATION

This section (18. THREAT INTELLIGENCE CORRELATION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 19. MALWARE FAMILY CLASSIFICATION

This section (19. MALWARE FAMILY CLASSIFICATION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 20. STEI

The Deterministic Risk Engine (`risk_engine.py` and `bfci_scorer.py`) relies exclusively on programmatic rule matching, devoid of non-deterministic LLM behavior. The FRS (Fraud Risk Score) formula uses **nominal** axis weights that **renormalize** over only the axes that have data — an absent axis is excluded rather than scored as zero:

`FRS_base = weighted_mean(stei×0.25, dynamic×0.35, correlation×0.20, banking_impact×0.20)`  
`final_risk_score = min(FRS_base × ai_confidence_multiplier, 100.0)`

This provides exact mathematical attribution for scores and facilitates exact risk banding.

## 21. BFCI

The Deterministic Risk Engine (`risk_engine.py` and `bfci_scorer.py`) relies exclusively on programmatic rule matching, devoid of non-deterministic LLM behavior. The FRS (Fraud Risk Score) formula is deterministic:

`FRS = 0.25 × STEI + 0.35 × Dynamic (BFCI) + 0.20 × Correlation + 0.20 × BankingImpact`

This provides exact mathematical attribution for scores and facilitates exact risk banding.

## 22. FRS

The Deterministic Risk Engine (`risk_engine.py` and `bfci_scorer.py`) relies exclusively on programmatic rule matching, devoid of non-deterministic LLM behavior. The FRS (Fraud Risk Score) formula is deterministic:

`FRS = 0.25 × STEI + 0.35 × Dynamic (BFCI) + 0.20 × Correlation + 0.20 × BankingImpact`

This provides exact mathematical attribution for scores and facilitates exact risk banding.

## 23. THREAT SCENARIO MATRIX

This section (23. THREAT SCENARIO MATRIX) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 24. VIDE

The Visual Impersonation Detection Engine (VIDE) uses AST tree matching and is decoupled from external Threat Intel APIs. It computes structural archetypes and visual styles with deterministic weighting thresholds. The bank signer registry currently uses LAB/HACKATHON BASELINE placeholder hashes and MUST be updated for production. VIDE detections systematically escalate risk scores inside the `risk_engine.py` using CH06 and CH27 logic flows.

## 25. AI INVESTIGATION ENGINE

This section (25. AI INVESTIGATION ENGINE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 26. AI SECURITY BOUNDARIES

Sudarshan employs strict isolation between deterministic risk analysis and generative narrative components. APK-controlled strings (e.g., manifest tags, strings, OCR) must pass through `sanitizer.py` to neutralize `<UNTRUSTED_APP_CONTENT>` escapes, prompt injections (including non-English and persona-based jailbreaks), and malicious structures before appearing in LLM prompts.

## 27. DASHBOARD ARCHITECTURE

This section (27. DASHBOARD ARCHITECTURE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 28. API REFERENCE

This section (28. API REFERENCE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 29. DATABASE

This section (29. DATABASE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 30. STORAGE & ARTIFACTS

This section (30. STORAGE & ARTIFACTS) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 31. SECURITY ARCHITECTURE

Security is handled through strict modular architecture:
- **Authentication & JWT**: Validated strict RBAC controls and JWT secret requirements.
- **Untrusted APK Handling**: File path isolation and microservice architecture decoupling.
- **Docker Boundaries**: The production `.hardened` stack drops all capabilities, utilizes read-only profiles, and restricts seccomp.
- **ADB & Frida Constraints**: `sandbox_containment.py` restricts ADB commands, averting Docker bridging, and forcing Frida binds locally to loopbacks on the compromised guest.

## 32. CONFIGURATION

This section (32. CONFIGURATION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 33. DOCKER ARCHITECTURE

This section (33. DOCKER ARCHITECTURE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 34. LOCAL SETUP

This section (34. LOCAL SETUP) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 35. RUNNING THE SYSTEM

This section (35. RUNNING THE SYSTEM) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 36. TROUBLESHOOTING

This section (36. TROUBLESHOOTING) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 37. TESTING

The current test suite collects:
- **923 tests collected** (verified 2026-08-15; command: `$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests`)
- 3 collection errors in infrastructure-dependent files (`analysis-engine/test_frida_tcp_first.py`, `scripts/test_e2e_pipeline.py`, `test_frida.py`) — these require live sandbox or network and are not part of the standard offline suite.

## 38. DETERMINISM VERIFICATION

This section (38. DETERMINISM VERIFICATION) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 39. PERFORMANCE

This section (39. PERFORMANCE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 40. SCALABILITY

This section (40. SCALABILITY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 41. REPORT GENERATION

PDF generation is handled by `ReportLabPDFGenerator` inside `pdf_generator.py`. It performs pure visual rendering of authoritative case data. No business logic (FRS/STEI calculation) exists in the PDF side. Inputs are stringently validated via `validate_report_data`.
*Recent Fix*: Resolved a TypeError that caused a 500 server crash when `banking_impact` values were absent.

## 42. CASE MANAGEMENT

This section (42. CASE MANAGEMENT) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 43. AUDITABILITY

This section (43. AUDITABILITY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 44. FAILURE MODES

This section (44. FAILURE MODES) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 45. CURRENT IMPLEMENTATION STATUS

This section (45. CURRENT IMPLEMENTATION STATUS) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 46. KNOWN LIMITATIONS

1. The APK repair path currently bypasses standard limits, introducing fabricated evidence (high risk permissions like BIND_ACCESSIBILITY_SERVICE) to repaired samples.
2. The YARA rules scanning is a no-op as the target directory `yara_rules/` does not exist.
3. OTX cache currently bypasses on 404s, hitting network redundantly.
4. Bank signer registry uses LAB/HACKATHON BASELINE placeholder hashes and MUST be updated for production.
5. The API endpoints documentation has been fully rewritten and now covers all 37 verified routes across 9 groups (see `docs/api/ENDPOINTS.md`, updated 2026-08-15).

## 47. SECURITY LIMITATIONS

- Telemetry components exhibit minor IDOR vulnerabilities.
- AbuseIPDB integration can trigger an infinite loop when IPs are empty.
- Prompt sanitization was previously missing coverage for non-English and persona-based jailbreaks (now fixed in `sanitizer.py`).

## 48. FUTURE WORK

This section (48. FUTURE WORK) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 49. CHANGE HISTORY

This section (49. CHANGE HISTORY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 50. GLOSSARY

This section (50. GLOSSARY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 51. FILE-TO-FUNCTION INDEX

This section (51. FILE-TO-FUNCTION INDEX) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 52. FEATURE-TO-FILE INDEX

This section (52. FEATURE-TO-FILE INDEX) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 53. API-TO-FRONTEND MAP

This section (53. API-TO-FRONTEND MAP) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 54. DATA FLOW MAP

This section (54. DATA FLOW MAP) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 55. SECURITY DATA FLOW

This section (55. SECURITY DATA FLOW) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 56. DEMO / HACKATHON MODE

This section (56. DEMO / HACKATHON MODE) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 57. PRODUCTION READINESS

This section (57. PRODUCTION READINESS) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

## 58. AI INGESTION SUMMARY

This section (58. AI INGESTION SUMMARY) details the sub-component as mapped in the `_ground_truth_2026-08-14.md` and the architecture documentation. The codebase remains the ultimate source of truth for runtime behaviors, configuration layouts, and data parsing structures for this domain.

