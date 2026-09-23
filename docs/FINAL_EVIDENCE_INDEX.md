# SUDARSHAN Final Evidence Index

This document catalogues the critical engineering evidence, architectural documentation, and phase reports proving the operational status of the Sudarshan Hybrid Dynamic Analysis Engine.

## Phase Reports
These reports capture the direct results, test counts, and discoveries during the iterative development of the Agentic Explorer and HybridPlanner.
- [Phase 5A Report](../phase_5a_report.md) - Offline HybridPlanner validation and constraint testing.
- [Phase 5B Report](../phase_5b_report.md) - Real Jev + HybridPlanner integration, and execution boundary validation.
- [Phase 6 Final Report](../PHASE_6_FINAL_REPORT.md) - Controlled Dynamic Analysis validation and E2E simulation.

## Architecture & Validation
- [Final Architecture](FINAL_ARCHITECTURE.md) - The complete operational model frozen at Phase 7.
- [Validation Results](VALIDATION_RESULTS.md) - Measured outcomes from all regression tests and pipeline audits.
- [Limitations](LIMITATIONS.md) - Explicit, honest documentation of environment constraints (e.g. Frida Sandbox root limitation) and SaaS dependencies.

## Operations & Demo
- [Demo Guide](DEMO_GUIDE.md) - Steps to reproduce a complete Sudarshan dynamic analysis.
- [Demo Recovery](DEMO_RECOVERY.md) - Supported troubleshooting and fallback steps.

## Regression Evidence
- The backend test suite contains **361** unit and integration tests covering the perception pipeline, bounding extraction, execution abstractions, event buses, and risk scoring.
- Final Phase 7 run resulted in **360 Passed, 1 Skipped**. 
- 0 real Jev API calls were generated during regression testing, validating mock boundaries and cost constraints.
