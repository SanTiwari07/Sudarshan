# SUDARSHAN Validation Results

This document summarizes the validation results from Phase 5A, Phase 5B, and Phase 6 of the Sudarshan Hybrid Dynamic Analysis Engine.

## 1. Test Execution
The regression suite continuously tests the offline boundaries, mock integrations, and core deterministic pipelines.
- **Agentic & Planner Regression:** 145/145 passed.
- **AgenticExplorer / Component Regression:** 206/207 passed (1 skipped).
- **Total Tests Passing:** 351 tests.
- **New Failures Introduced:** 0.

## 2. Jev & HybridPlanner Behaviors Observed
Throughout Phase 5 and Phase 6 validations:
- **Jev Usage:** Mock Jev correctly fulfilled all integration constraints without invoking real external TypeSafe APIs during Phase 6 and final regressions.
- **Jev Success:** Phase 5B observed a valid high-confidence Jev decision that completely bypassed Gemini execution, validating cost-saving constraints.
- **Gemini Fallback:** Phase 5B observed that when Jev returned low-confidence (<0.85 by default) or failed internally, the execution gracefully fell back to Gemini, which successfully issued the correct action.
- **Real Jev API Calls in Phase 6/7:** 0 calls.

## 3. UI and State Exploration Behaviors Observed
- **Navigation:** The AgenticExplorer natively detected boundaries and successfully issued `press_back()` and `start_activity()` intents when out of scope (e.g., clicking external URL and opening the system browser).
- **Authentication:** `field_classifier.py` consistently bounded credential fields, allowing `credentials.py` to dispense test synthetic strings safely.
- **Permission Tests:** Handled `ALLOW`, `DENY` system permissions gracefully without AI hallucination.
- **Evidence Verification:** RuntimeEventBus and EvidenceStore preserved screenshots, events, and API telemetry cleanly into the final `FINAL_RISK_SCORE` report.

## 4. Frida Integration Status
- **Status:** PARTIALLY VERIFIED.
- **Result:** Phase 6 generated zero live Frida events because the test emulator lacked frida-server/root access.
- **Observation:** Offline unit testing and the `verify_runtime_pipeline.py` script proved that *if* Frida events are generated, the downstream pipeline (EventBus -> EvidenceStore -> RiskEngine -> BFCI update) processes them accurately and synchronously. Live instrumentation remains environment-dependent.
