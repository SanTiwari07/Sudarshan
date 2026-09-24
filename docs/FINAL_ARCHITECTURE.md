# SUDARSHAN Final Architecture

This document describes the finalized architecture of the Sudarshan Hybrid Dynamic Analysis Engine, freezing the state at Phase 7 (Post-10K Readiness Validation).

## 1. Executive Architecture
The system integrates deterministic risk aggregation with AI-assisted UI exploration to analyze Android applications for fraudulent behavior in a sandboxed environment.

```
                    APK
                     |
                     v
              Static Analysis
                     |
                     +
                     |
              Dynamic Analysis
                     |
                     v
                Perception
                     |
                     v
            Candidate Generation
                     |
                     v
             Planner Selection
               /           \
             Jev          Gemini
               \           /
                \         /
                 HybridPlanner
                     |
                     v
              Action Validation
                     |
                     v
              ActionDispatcher
                     |
                     v
                ToolExecutor
                     |
                     v
              ActionVerifier
                     |
                     v
              State / Events
                     |
          +----------+----------+
          |                     |
          v                     v
   RuntimeEventBus        EvidenceStore
          |                     |
          +----------+----------+
                     |
                     v
            Deterministic Risk
                Aggregation
                     |
          +----------+----------+
          |                     |
          v                     v
       BFCI/FRS            Threat Intel
          |                     |
          +----------+----------+
                     |
                     v
             AI Investigation
             / RAG / Reporting
                     |
                     v
              SOC Dashboard
```

## 2. Static Threat Intelligence (STEI)
Deterministic scoring based on static manifest analysis, decompiled code, and mobSF integration. It contributes to the base FRS (Final Risk Score) deterministically without AI hallucination.

## 3. Dynamic Analysis Engine
A sandboxed emulation environment running the target APK. It provides ADB hooks and uiautomator access for dynamic execution and exploration. 

## 4. Perception
Uses ADB UI Automator dumps to perceive screen state. Nodes are processed and unlabelled fields are categorized. The `field_classifier.py` deterministically assigns field types (e.g. `PASSWORD`, `USERNAME`) to text inputs.

## 5. Candidate Generation
Translates UI structures into bounding boxes and potential tool actions (e.g., `click`, `type_text`, `scroll`). Candidates are scoped by the exploration engine to prevent infinite loops.

## 6. Jev (TypeSafe)
The primary action selection planner. Operates on textual descriptions of candidates. Extremely fast and reliable for standard Android topologies.

## 7. Gemini
The fallback planner and complex reasoning engine. Used when Jev confidence is low, or when vision capabilities (screenshots) are required to decipher custom, WebView, or canvas-based UIs.

## 8. HybridPlanner
The orchestration layer that defaults to `Jev` for speed and low cost, falling back to `Gemini` upon low confidence or failure. `HybridPlanner` strictly decides *what* action to take; it does not execute ADB.

## 9. Action Validation
Candidate actions are verified to ensure they do not exceed bounded execution limits or violate security protocols before being dispatched.

## 10. ActionDispatcher
Authoritative entity that receives a selected action from the HybridPlanner, coordinates any required synthetic credentials from the `CredentialVault`, and dispatches the raw command.

## 11. ToolExecutor
The lowest-level executor that physically translates the dispatcher's command into ADB and UI Automator events. 

## 12. ActionVerifier
Post-action validation that compares UI state hashes deterministically to confirm if the action resulted in a state change or if the UI is stuck.

## 13. RuntimeEventBus
Pub/Sub bus to ingest runtime events asynchronously.

## 14. EvidenceStore
Stores captured screens, API interactions, and telemetry synchronously with the event bus for final aggregation.

## 15. Risk Engine
The core aggregator of both static and dynamic findings.

## 16. BFCI (Banking Fraud Confidence Index)
Deterministically calculates confidence of fraudulent intent based on specific weighted signals (e.g., Accessibility service abuse).

## 17. FRS (Final Risk Score)
Calculated strictly through deterministic equations mixing STEI and BFCI results. 

## 18. AI Investigation
AI models (Gemini) consume the EvidenceStore and risk scores to produce plain-english narrative reporting.

## 19. SOC Dashboard
Presents the FRS, Evidence, and AI narrative to the Security Operations Center.

## 20. Security Boundaries
- **Credentials:** Planners never see raw passwords. `CredentialVault` manages synthetic payloads deterministically.
- **Execution:** Planners never execute shell commands. 
- **Risk:** Planners never adjust BFCI or FRS directly.

## 21. Failure/Fallback Boundaries
- Jev timeout/failure -> Gemini fallback.
- Gemini timeout/failure -> Deterministic positional fallback.
- Out of scope -> Deterministic recovery (`ADB BACK`, `start_activity`).


## 22. 10K Scaling Enhancements
- **Connection Pooling**: PostgreSQL-backed syncpg pooling isolates connections properly to prevent transaction leaking.
- **Durable Queues**: canonical_analyses schema leverages lease-mechanisms to enable multi-node worker recovery and idempotency.
- **Quotas and Limits**: Configurable concurrency caps (STATIC_MAX_CONCURRENCY, DYNAMIC_MAX_CONCURRENCY) isolate resources.
- **Backpressure**: Atomic limits and slowapi rate limits throttle excessive load.
