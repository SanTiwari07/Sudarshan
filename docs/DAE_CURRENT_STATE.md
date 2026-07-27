# Dynamic Analysis Engine — Current Operational State & Resolution Audit

**Audience:** Sudarshan Core Engineering & Threat Research Team  
**Version:** `2.3.0`  
**Last Audit Date:** 2026-07-27  
**Verification Method:** Empirical log trace, automated unit suite (`pytest tests/`), and live AVD Frida execution.

---

## Executive Summary & Resolution State

**Instrumentation now works; behavioural coverage does not yet.** The 2026-07-25 revision of this
document claimed all silent failures were resolved. That claim did not hold, and the corrections are
recorded below rather than removed, because the gap between the claim and the measurement is itself
a finding.

**Verified working (2026-07-27):** Frida attaches and executes hooks after the SELinux preflight;
scoring, workflow reconstruction, manifest generation, static CLI pipeline and network ingest all
behave as described.

**Verified NOT working:** approximately 4 of 8 corpus trojans instrument successfully, and every
BFCI component except `activity` still reads 0.0. Root causes are enumerated in Part 3.

1. **Frida Runtime Instrumentation**: Active & verified. `Java.deoptimizeEverything()` runs unconditionally at script startup, preventing ART JIT inlining from suppressing hooks.
2. **BFCI Scoring Engine v2**: `bfci_scorer.py` replaced primitive hook counting with logarithmic volume-aware scoring and a 30-second temporal sequence bonus.
3. **Behavioral Workflow Reconstruction**: `workflow_reconstructor.py` converts raw Frida hook events into causal MITRE ATT&CK stage chains.
4. **Pre-Sandbox Investigation Manifest**: `manifest.py` generates `manifest.json` prior to execution, dynamically selecting hook profiles and goal priorities based on static threat signals.
5. **Static Analysis CLI Pipeline**: `apktool_engine.py` and `jadx_engine.py` provide standalone resource decompilation and DEX-to-Java source scanning.
6. **Network Interception**: `docker-compose.yml` sidecar runs `mitmproxy`, with `network_capture.py` parsing HAR dumps and merging full HTTPS headers/responses with Frida socket hooks.
7. **Analyst Dashboard**: `WorkflowDiagram.tsx` renders interactive causal workflow chains directly in the React frontend.
8. **Test Coverage**: **320 / 320 tests passing** (`pytest tests/`), measured 2026-07-27. Includes new regression suites `test_detection_regressions.py` and `test_frida_preflight.py`.

---

## Part 1 — Verified Operational Foundations

### 1. The Determinism Invariant Holds
AI controls UI exploration; deterministic engines control scoring. The `RiskEngine` computes the final score ($FRS$) from four independent inputs ($STEI$, $BFCI$, $ThreatIntel$, $BankingImpact$). LLM narrative generation runs strictly downstream.

### 2. Frida 17.16.4 PID-Attach & ART Deoptimization
- Attachment is performed via PID (`pidof`), eliminating package-name display string mismatches.
- `banking_trojan.bundle.js` includes `frida-java-bridge` un-wrapped module handling (`Java.perform`).
- `Java.deoptimizeEverything()` forces the Android Runtime (ART) interpreter mode to guarantee hook execution even on JIT-compiled system methods.

### 3. Fail-Loud Canary & Fail-Safe Status
- Synthetic `canary` event is emitted on script load.
- `frida_sandbox.py` monitors canary delivery and sets `dynamic_status`:
  - `EVENTS_CAPTURED`: Hooks fired and recorded in `EvidenceStore`.
  - `NO_BEHAVIOR_OBSERVED`: Script loaded but app exhibited no hook-triggering behavior.
  - `INSTRUMENTATION_FAILED`: Hook attachment or execution failed (triggers **Static Fallback Risk Engine**).

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

```bash
$ cd backend && pytest tests/
```

All automated unit & integration test modules pass clean across static analysis, dynamic sandbox, threat correlation, and deterministic risk scoring engines.



---

## Part 3 — Open Defects (added 2026-07-27)

Each verified against the running stack. None are resolved.

| # | Defect | Effect | Location |
|---|---|---|---|
| 1 | Accessibility service class is hardcoded as `{package}/.AccessibilityService`; real malware obfuscates it (Cerberus uses `.zWPzgfI`) | Android ignores the non-existent component, so the service never activates and the **0.35-weight** BFCI component is 0.0 on every sample | `permission_orchestrator.py:86` |
| 2 | Cerberus and Drinik declare no launcher activity; the declared main-activity class is not in `classes.dex` | Nothing can launch them; `INSTRUMENTATION_FAILED` | sample property |
| 3 | Teabot ships a deliberately malformed manifest | `INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION` | sample property |
| 4 | The compiled `banking_trojan.bundle.js` is preferred over the source with no staleness check | An edited source has **no effect**; the bundle is what runs | `frida_sandbox.py:106` |
| 5 | `activities_triggered` is hardcoded to `[package_name]` | A fabricated value counts toward the conclusiveness test in `risk_engine._dynamic_run_was_conclusive` | `frida_sandbox.py:1123` |

### Corrected diagnosis

The previously documented cause — *"Frida 17 / ART inlining suppresses hooks"* — was wrong.
`Java.deoptimizeEverything()` was working. The actual blocker was **SELinux Enforcing** denying the
`ptrace` required for injection. After adding an `adb root` + `setenforce 0` preflight,
instrumentation went from **0 of 8** samples to **4 of 8**, with hooks confirmed executing
(`SharedPreferencesImpl.getString executed, key: 'package'`).

Two further defects were found in the hook agent itself and fixed:

- **SMS/OTP hooks** called `.length()` on a `java.lang.String`, which frida-java-bridge unboxes to a
  JS primitive. The hook threw before `emit()`, so the **0.25-weight** SMS component had never
  scored on any sample. Fixed in both `banking_trojan.js` and the compiled bundle.
- **`Activity.onResume`** emitted into the scored `banking` category for *any* app including its own
  activities. Three screen transitions produced `banking: 100` for a benign app — and since UI
  exploration navigates screens, this fired on 100% of runs. Moved to an unscored `activity`
  category; verified 50-79 to 0.0.

### Caveat on the bundle

`banking_trojan.bundle.js` is a frida-compile package whose second line is a **byte count**:

```
(package emoji)
495916 /path/to/banking_trojan.js
(scissors)
<body>
```

Editing the body without recomputing that number causes Frida to reject the entire script with
`InvalidArgumentError: malformed package`, and every sample silently returns
`INSTRUMENTATION_FAILED`. There is no build step or CI check binding source and bundle.
