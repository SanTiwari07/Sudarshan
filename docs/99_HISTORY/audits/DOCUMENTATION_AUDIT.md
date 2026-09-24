# SUDARSHAN Documentation Audit Report

**Date:** 2026-09-24
**Scope:** `C:\Projects\Sudarshan\docs\` and repository root.
**Objective:** Identify duplicate, contradictory, stale, and obsolete documentation across the project.

## 1. Classification

The following represents the classified state of key documentation artifacts:

### AUTHORITATIVE
* `README.md` (Root entry point, despite minor link drift)
* `docs/README.md` (Docs entry point, despite minor link drift)
* `docs/01_INTRODUCTION.md` through `docs/04_DYNAMIC_ANALYSIS_ENGINE.md`
* `docs/architecture/05_AI_INVESTIGATION_ENGINE.md` through `docs/architecture/09_AI_REPORT_GENERATION.md`
* `docs/CURRENT_ARCHITECTURE.md` (Latest topology and mathematical models)
* `docs/HOW_TO_RUN.md` (Primary setup/operations guide)
* `docs/FEATURE_STATUS.md` (Source of truth for implementation state)

### DUPLICATE
* `docs/ARCHITECTURE.md` (Largely duplicates and overlaps with `docs/CURRENT_ARCHITECTURE.md`)
* `docs/architecture/DYNAMIC_ANALYSIS_CURRENT_STATE.md` (Overlaps with `04_DYNAMIC_ANALYSIS_ENGINE.md` and `CURRENT_ARCHITECTURE.md`)

### OBSOLETE / HISTORICAL
* `docs/SUDARSHAN_MASTER.md` (Broken structural template containing unfulfilled placeholders)
* `docs/reports/historical/*` (Past state descriptions, e.g., `_ground_truth_2026-08-14.md`)
* `docs/reports/reports/FINAL_ARCHITECTURE.md` (Reflects Phase 7 state; superseded by `CURRENT_ARCHITECTURE.md`)
* `docs/architecture/DYNAMIC_ANALYSIS_2.0.md` (Historical cycle report)
* `docs/audits/*` (Past audits, though they still contain local paths)
* `docs/FEATURE.md` (A verbose prose document that is mostly superseded by the structured `docs/FEATURE_STATUS.md`)

### NEEDS MERGE
* `docs/ARCHITECTURE.md` and `docs/CURRENT_ARCHITECTURE.md` must be reconciled into a single authoritative architecture file.
* `README.md` and `docs/README.md` both contain "Documentation map" tables that need consolidation, as they currently maintain divergent path references.

---

## 2. Findings

### 2.1 Contradictory Documentation & Stale Paths

The documentation maps are significantly out of sync with the actual repository structure due to refactoring:
* **Root `README.md` Path Drift:**
  * Links to `docs/architecture/SYSTEM_ARCHITECTURE.md`, but no such file exists. It should point to `docs/CURRENT_ARCHITECTURE.md`.
  * Links to `docs/reference/CODEBASE_MAP.md`, but the file is located at `docs/CODEBASE_MAP.md`.
  * Links to `docs/getting-started/HOW_TO_RUN.md`, but the file is located at `docs/HOW_TO_RUN.md`.
  * Links to `docs/architecture/03_STATIC_THREAT_INTELLIGENCE.md`, but it is at `docs/03_STATIC_THREAT_INTELLIGENCE.md`.
* **`docs/README.md` Path Drift:**
  * Links to `api/ENDPOINTS.md`, but the file is at `docs/reference/api/ENDPOINTS.md`.
  * Links to `dashboard/10_DASHBOARD.md`, but it is at `docs/reference/dashboard/10_DASHBOARD.md`.
  * Links to `evaluation/11_EVALUATION.md`, but it is at `docs/reference/evaluation/11_EVALUATION.md`.

### 2.2 Local Developer Paths and `file://` Links

Several documents contain hardcoded absolute filesystem paths, exposing local developer context:
* `artifacts/screenshots_artifact.md` contains active `../sudarshan_artifacts/screenshots/...` URIs that will not render on remote git platforms.
* `docs/audits/SECURITY_AUDIT.md` extensively references `C:\Projects\Sudarshan\...`.
* `docs/audits/DUPLICATE_CODE_AUDIT.md` contains dozens of hardcoded `C:\Projects\Sudarshan\...` paths.
* `docs/reference/testing/KREP_CRASH_ROOT_CAUSE_REPORT.md` references `C:\Projects\Sudarshan\test apk\...`.

### 2.3 Stale Claims and Test Counts

* **Hardcoded Test Verification**: `README.md`, `docs/ARCHITECTURE.md`, and `docs/FEATURE_STATUS.md` all contain the exact string `"2,622 tests collected... (measured 2026-08-27)"`. This is a point-in-time metric that becomes stale immediately and contradicts the live state.
* **Verification Dates**: Multiple authoritative documents (`CURRENT_ARCHITECTURE.md`, `04_DYNAMIC_ANALYSIS_ENGINE.md`) proudly declare "Last Verified Against Active Codebase: 2026-08-25". This gives the illusion of current truth despite being a month out of date (current date 2026-09-24).
* **Architecture Models**: `docs/ARCHITECTURE.md` indicates Last Revision: `2026-08-08`, meaning it trails behind `CURRENT_ARCHITECTURE.md` (2026-08-25).

### 2.4 Obsolete Commands
* The `docs/HOW_TO_RUN.md` attempts to clarify Docker instructions but retains mixed verbiage between `docker-compose` (V1) and `docker compose` (V2), which could be streamlined given the system's reliance on modern containers.
* The test command references (`pytest` vs `python -m pytest`) assume globally active virtual environments that may not apply directly to standard setups.

## 3. Recommended Actions
1. **DO NOT DELETE**, but update `README.md` and `docs/README.md` to point to the actual physical locations of the markdown files.
2. Refactor absolute `file:///` and `C:\Projects\...` paths to relative paths.
3. Merge `ARCHITECTURE.md` into `CURRENT_ARCHITECTURE.md` and delete the older duplicate.
4. Replace hardcoded test count sentences with dynamic badges or simplified claims.
