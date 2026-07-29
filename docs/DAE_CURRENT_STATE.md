# Dynamic Analysis Engine — Current Operational State & Resolution Audit

**Audience:** Sudarshan Core Engineering & Threat Research Team  
**Version:** `2.3.0`  
**Last Audit Date:** 2026-07-29  
**Verification Method:** Empirical log trace, automated test suite (`388 / 388 tests passing`), and live AVD Frida execution.

---

## Executive Summary & Resolution State

**Instrumentation and behavioral analysis are operational.** Verified via empirical testing across all core modules in [`shared/sudarshan_core/engines/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/).

**Verified working (2026-07-29):**
- Frida attaches and executes hooks after the SELinux preflight (`adb root` + `setenforce 0`).
- Deterministic scoring (`risk_engine.py`), workflow reconstruction (`workflow_reconstructor.py`), investigation manifest generation (`manifest.py`), static analysis (`apktool_engine.py`, `jadx_engine.py`, `apk_analyzer.py`), and network capture ingest (`network_capture.py` parsing mitmproxy HAR dumps) function cleanly.
- Test coverage verified: **388 / 388 tests passing** (`pytest backend/tests`).

### Core Operational Capabilities
1. **Frida Runtime Instrumentation**: Active & verified via [`frida_sandbox.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_sandbox.py). `Java.deoptimizeEverything()` runs unconditionally at script startup, preventing ART JIT inlining from suppressing hooks.
2. **BFCI Scoring Engine v2**: [`bfci_scorer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/bfci_scorer.py) uses logarithmic volume-aware scoring and temporal sequence analysis.
3. **Behavioral Workflow Reconstruction**: [`workflow_reconstructor.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py) converts raw Frida hook events into causal MITRE ATT&CK stage chains.
4. **Pre-Sandbox Investigation Manifest**: [`manifest.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/manifest.py) generates `manifest.json` prior to execution, dynamically selecting hook profiles and goal priorities based on static threat signals.
5. **Static Analysis Pipeline**: [`apktool_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apktool_engine.py) and [`jadx_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/jadx_engine.py) provide standalone resource decompilation and DEX-to-Java source scanning.
6. **Network Interception**: Sidecar container runs `mitmproxy`, with [`network_capture.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) parsing HAR dumps and merging full HTTPS headers/responses with Frida socket hooks.
7. **Analyst Dashboard**: [`WorkflowDiagram.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx) renders interactive causal workflow chains directly in the React frontend.
8. **Test Coverage**: **388 / 388 tests passing** (`pytest backend/tests`), measured 2026-07-29.

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
| Hook-Counting BFCI | Created volume-aware & temporal BFCI v2 | [bfci_scorer.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/bfci_scorer.py) | ✅ **RESOLVED** |
| Missing Workflow Reconstructor | Created causal chain reconstruction engine | [workflow_reconstructor.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py) | ✅ **RESOLVED** |
| Missing Pre-Sandbox Manifest | Created Pydantic `InvestigationManifest` model | [manifest.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/models/manifest.py) | ✅ **RESOLVED** |
| Standalone Decompilation | Added APKTool & JADX CLI engines | [apktool_engine.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/apktool_engine.py), [jadx_engine.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/jadx_engine.py) | ✅ **RESOLVED** |
| Encrypted HTTPS Interception | Added `mitmproxy` sidecar + HAR dump merger | [docker-compose.yml](file:///d:/Projects/Sudarshan%20BOI/docker-compose.yml), [network_capture.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) | ✅ **RESOLVED** |
| UI Workflow Visualization | Built interactive MITRE ATT&CK React timeline | [WorkflowDiagram.tsx](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx) | ✅ **RESOLVED** |
| Screen Height Coordinate Rejection | Dynamic `display_metrics` resolution | [ui_explorer.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/ui_explorer.py) | ✅ **RESOLVED** |
| Stage 5 Gating Stall | Made Login stage skippable | [goal_tracker.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic/goal_tracker.py) | ✅ **RESOLVED** |
| Prompt Injection Exposure | Input sanitization wrappers applied | [sanitizer.py](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic/sanitizer.py) | ✅ **RESOLVED** |

---

## Part 3 — Verification Metrics

```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests
```

All 388 automated unit & integration test modules pass clean across static analysis, dynamic sandbox, threat correlation, and deterministic risk scoring engines.
