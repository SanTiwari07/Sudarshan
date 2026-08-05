# Dynamic Analysis Engine — Current Operational State & Resolution Audit

**Audience:** Sudarshan Core Engineering & Threat Research Team  
**Version:** `v2.5.0-STABLE`  
**Last Audit Date:** 2026-08-05  
**Verification Method:** Empirical log trace, automated test suite, live AVD Frida execution, and runtime telemetry pipeline verification (`verify_runtime_pipeline.py`).

---

## Executive Summary & Resolution State

**Instrumentation and behavioral analysis are fully operational.** Verified via empirical testing across all core modules in [`shared/sudarshan_core/engines/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/).

**Verified working (2026-08-05):**
- Frida attaches and executes banking trojan hooks after SELinux preflight (`adb root` + `setenforce 0`). Sub-probes (`java_probe.js`, `bisect_sec.js`) validate Java bridge binding and ART deoptimization.
- Runtime Telemetry REST API ([`runtime_api.py`](file:///d:/Projects/Sudarshan%20BOI/backend/app/routes/runtime_api.py)) streams live pipeline status, telemetry events, Frida hook hit counters, error rates, and evidence snapshots.
- Deterministic scoring ([`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py)), workflow reconstruction ([`workflow_reconstructor.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py)), investigation manifest generation ([`manifest.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/manifest.py)), static analysis ([`apktool_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apktool_engine.py), [`jadx_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/jadx_engine.py)), and network capture ingest ([`network_capture.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) parsing mitmproxy HAR dumps) function cleanly.
- Test coverage verified: Full automated suite passing (**457 / 457 tests collected & verified** via `pytest tests/ backend/tests`).

### Core Operational Capabilities
1. **Frida Runtime Instrumentation**: Active & verified via [`frida_sandbox.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_sandbox.py) and [`banking_trojan.js`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_hooks/banking_trojan.js). `Java.deoptimizeEverything()` runs unconditionally at script startup, preventing ART JIT inlining from suppressing hooks.
2. **Runtime Telemetry & Telemetry API**: Exposes live state via `/api/runtime/*` endpoints ([`runtime_api.py`](file:///d:/Projects/Sudarshan%20BOI/backend/app/routes/runtime_api.py)), tracking hook installations, invocation counts, error metrics, and ring-buffered event streams (max 500 events).
3. **Agentic UI Exploration**: [`agentic_explorer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic_explorer.py) and [`planner.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic/planner.py) drive Gemini-powered UI navigation with launch ladder fallbacks and goal progression tracking.
4. **APK Manifest Repair Engine**: [`apk_repair.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apk_repair.py) repairs corrupted AXML headers, zip alignment, and package signature structures prior to dynamic analysis.
5. **BFCI Scoring Engine v2**: [`bfci_scorer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/bfci_scorer.py) uses logarithmic volume-aware scoring and temporal sequence analysis.
6. **Behavioral Workflow Reconstruction**: [`workflow_reconstructor.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py) converts raw Frida hook events into causal MITRE ATT&CK stage chains.
7. **Pre-Sandbox Investigation Manifest**: [`manifest.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/manifest.py) generates `manifest.json` prior to execution, dynamically selecting hook profiles and goal priorities based on static threat signals.
8. **Static Analysis Pipeline**: [`apktool_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apktool_engine.py) and [`jadx_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/jadx_engine.py) provide standalone resource decompilation and DEX-to-Java source scanning.
9. **Network Interception**: Sidecar container runs `mitmproxy`, with [`network_capture.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) parsing HAR dumps and merging full HTTPS headers/responses with Frida socket hooks.
10. **Analyst Dashboard**: [`WorkflowDiagram.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx) and [`FraudCard.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/FraudCard.tsx) render interactive causal workflow chains and executive risk views directly in the React frontend.

---

## Part 1 — Verified Operational Foundations

### 1. The Determinism Invariant Holds
AI controls UI exploration; deterministic engines control scoring. The `RiskEngine` computes the final score ($FRS$) from four independent inputs ($STEI$, $BFCI$, $ThreatIntel$, $BankingImpact$). LLM narrative generation runs strictly downstream.

### 2. Frida 17.16.4 PID-Attach & ART Deoptimization
- Attachment is performed via PID (`pidof`), eliminating package-name display string mismatches.
- `banking_trojan.bundle.js` includes `frida-java-bridge` un-wrapped module handling (`Java.perform`).
- `Java.deoptimizeEverything()` forces the Android Runtime (ART) interpreter mode to guarantee hook execution even on JIT-compiled system methods.

### 3. Dynamic Analysis Status Enums
- Synthetic `canary` event is emitted on script load.
- `frida_sandbox.py` monitors canary delivery and sets `dynamic_status`:
  - `EVENTS_CAPTURED`: Hooks fired and recorded in `EvidenceStore`.
  - `NO_BEHAVIOR_OBSERVED`: Script loaded but app exhibited no hook-triggering behavior.
  - `INSTRUMENTATION_FAILED`: Hook attachment or execution failed (triggers **Static Fallback Risk Engine**).
  - `COMPLETED`: Run finished normally.
  - `SKIPPED`: Sandbox skipped due to user configuration or static analysis early-exit.

---

## Part 2 — Remediation Scorecard

| Identified Defect | Resolution Strategy | Location / Artifact | Audit Status |
|---|---|---|---|
| Silent Hook Suppression | Added `Java.deoptimizeEverything()` call | [banking_trojan.js](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_hooks/banking_trojan.js) | ✅ **RESOLVED** |
| Missing Live Telemetry | Implemented `/api/runtime/*` route suite | [runtime_api.py](file:///d:/Projects/Sudarshan%20BOI/backend/app/routes/runtime_api.py) | ✅ **RESOLVED** |
| Hook-Counting BFCI | Created volume-aware & temporal BFCI v2 | [bfci_scorer.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/bfci_scorer.py) | ✅ **RESOLVED** |
| Corrupt APK Launch Failure | Implemented automated AXML & Zip repair engine | [apk_repair.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apk_repair.py) | ✅ **RESOLVED** |
| Missing Workflow Reconstructor | Created causal chain reconstruction engine | [workflow_reconstructor.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py) | ✅ **RESOLVED** |
| Missing Pre-Sandbox Manifest | Created Pydantic `InvestigationManifest` model | [manifest.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/manifest.py) | ✅ **RESOLVED** |
| Standalone Decompilation | Added APKTool & JADX CLI engines | [apktool_engine.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apktool_engine.py), [jadx_engine.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/jadx_engine.py) | ✅ **RESOLVED** |
| Encrypted HTTPS Interception | Added `mitmproxy` sidecar + HAR dump merger | [docker-compose.yml](file:///d:/Projects/Sudarshan%20BOI/docker-compose.yml), [network_capture.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) | ✅ **RESOLVED** |
| UI Workflow Visualization | Built interactive MITRE ATT&CK React timeline | [WorkflowDiagram.tsx](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx) | ✅ **RESOLVED** |
| Executive Risk Dashboard | Created FraudCard component for executive threat assessment | [FraudCard.tsx](file:///d:/Projects/Sudarshan%20BOI/frontend/src/pages/FraudCard.tsx) | ✅ **RESOLVED** |

---

## Part 3 — Verification Metrics

```powershell
# Run full automated pytest test suite
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests

# Run live runtime pipeline verification
$env:PYTHONPATH="backend;shared"; backend\.venv\Scripts\python.exe scripts/verify_runtime_pipeline.py
```

All automated unit & integration test modules pass clean across static analysis, dynamic sandbox, threat correlation, and deterministic risk scoring engines.
