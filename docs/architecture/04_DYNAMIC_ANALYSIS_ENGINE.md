# 04 — Dynamic Analysis Engine & Agentic Explorer Specification

```yaml
Module Title:        Dynamic Analysis Engine (DAE) & Agentic Explorer
Version:             2.3.0-STABLE
Primary Files:       analysis-engine/app/main.py
                     shared/sudarshan_core/engines/frida_sandbox.py
                     shared/sudarshan_core/engines/agentic_explorer.py
                     shared/sudarshan_core/engines/network_capture.py
                     shared/sudarshan_core/engines/bfci_scorer.py
                     shared/sudarshan_core/engines/workflow_reconstructor.py
                     shared/sudarshan_core/engines/frida_hooks/banking_trojan.js
                     frontend/src/components/WorkflowDiagram.tsx
Test Suite:          backend/tests/test_analysis_client.py, backend/tests/test_remaining_features.py, backend/tests/test_agentic_explorer.py
```

---

## Table of Contents
- [1. Executive Overview](#1-executive-overview)
- [2. Dynamic Execution Architecture](#2-dynamic-execution-architecture)
- [3. Frida 17 Runtime & ART Deoptimization](#3-frida-17-runtime--art-deoptimization)
- [4. Dynamic Hook Bundle Inventory](#4-dynamic-hook-bundle-inventory)
- [5. mitmproxy Sidecar & Network Interception](#5-mitmproxy-sidecar--network-interception)
- [6. Agentic UI Explorer & 15-Stage Goal DAG](#6-agentic-ui-explorer--15-stage-goal-dag)
- [7. Scripted vs Agentic Analysis Comparison](#7-scripted-vs-agentic-analysis-comparison)
- [8. Behavioral Fraud Confidence Index (BFCI v2)](#8-behavioral-fraud-confidence-index-bfci-v2)
- [9. Fraud Workflow Reconstruction](#9-fraud-workflow-reconstruction)

---

## 1. Executive Overview

The **Dynamic Analysis Engine (DAE)** executes suspicious Android applications inside an isolated Android Virtual Device (x86_64, 16 KB page size; verified against Android 13 / `google_apis_ps16k`). Combining Frida 17 binary instrumentation, `mitmproxy` transparent HTTPS decryption, an autonomous LLM UI explorer ([`agentic_explorer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic_explorer.py)), and a causal workflow reconstructor ([`workflow_reconstructor.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py)), the DAE captures real-time behavioral evidence of mobile banking fraud.

---

## 2. Dynamic Execution Architecture

```mermaid
graph TD
    PREP[ADB Sandbox Prep & Low-SDK Install] --> LAUNCH[Launch Target Activity & PID Resolve]
    LAUNCH --> ATTACH[Attach Frida 17 Script via PID]
    ATTACH --> DEOPT[Execute Java.deoptimizeEverything]
    ATTACH --> CANARY[Emit Fail-Loud Canary Event]

    DEOPT --> EXPLORE[Agentic UI Explorer Loop]
    DEOPT --> HOOKS[Runtime API Instrumentation]
    DEOPT --> PROXY[mitmproxy HTTPS Intercept]

    EXPLORE --> BUS[Runtime Event Bus]
    HOOKS --> BUS
    PROXY --> BUS

    BUS --> STORE[Evidence Store]
    STORE --> WORKFLOW[Workflow Reconstructor]
    STORE --> BFCI[BFCI v2 Scorer]
```

---

## 2a. SELinux Preflight (required)

Before `frida-server` is checked, `run_frida_analysis` performs:

```powershell
adb -s <serial> root
adb -s <serial> shell getenforce      # if "Enforcing":
adb -s <serial> shell setenforce 0
```

**Why this is not optional.** SELinux is Enforcing by default on Android 13+ and denies the `ptrace` that Frida injection requires, *even for uid 0*. Without this step every attach fails with `PermissionDeniedError: unable to access process with pid <n>` while `frida-server` reports healthy.

---

## 3. Frida 17 Runtime & ART Deoptimization

- **PID Attachment**: Resolves running application process ID via `adb shell pidof <package>`, avoiding package label retries.
- **Unconditional ART Deoptimization ([`banking_trojan.js`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_hooks/banking_trojan.js))**:
  ```javascript
  if (Java.available) {
    Java.perform(function () {
      if (Java.deoptimizeEverything) {
        Java.deoptimizeEverything();
        console.log("[Sudarshan] Java.deoptimizeEverything() executed successfully.");
      }
    });
  }
  ```
  Forces Android Runtime (ART) into interpreter mode, eliminating JIT inlining silent hook suppression.
- **Fail-Loud Canary**: Emits a `canary` event at load time. If unreceived, [`frida_sandbox.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/frida_sandbox.py) flags `INSTRUMENTATION_FAILED`, invoking the **Static Fallback Risk Engine**.

---

## 4. Dynamic Hook Bundle Inventory

The DAE injects modular hook profiles selected by the `InvestigationManifest`:

| Hook Bundle | Monitored API / Classes | Fraud Behavioral Signatures |
| :--- | :--- | :--- |
| `canary` | Synthetic Script Health Check | Asserts runtime script load and bridge health. |
| `accessibility` | `AccessibilityService`, `AccessibilityEvent` | UI scraping, OTP field extraction, node clicking. |
| `sms` | `SmsManager`, `SmsMessage`, `BroadcastReceiver` | Inbound SMS interception, OTP theft, SMS exfiltration. |
| `overlay` | `WindowManager`, `TYPE_APPLICATION_OVERLAY` | Phishing window overlays over banking applications. |
| `banking` | Target package intent launches | Financial app detection, overlay triggers. |
| `dynamic_code` | `DexClassLoader`, `InMemoryDexClassLoader`, `PathClassLoader` | Secondary payload dropping and dynamic DEX loading. |
| `persistence` | `DeviceAdminReceiver`, `PackageManager` | Device administrator privilege escalation and app icon hiding. |
| `network` | `OkHttp3`, `URLConnection`, `Socket`, `SSLSocket` | C2 heartbeat communication, exfiltration POST requests. |

---

## 5. mitmproxy Sidecar & Network Interception

[`network_capture.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/network_capture.py) combines two network evidence streams:
1. **Frida Socket Hooks**: Intercepts HTTP/HTTPS connections at call time.
2. **mitmproxy Sidecar Container**: Intercepts transparent proxy traffic via port 8080. Parses HAR dumps (`dump.har`) written to shared volumes to extract full decrypted HTTP request/response headers, status codes, and body sizes.

---

## 6. Agentic UI Explorer & 15-Stage Goal DAG

`AgenticExplorer` uses an LLM planner and screen-hash state abstraction to navigate app UIs:

```mermaid
graph TD
    S1[Stage 1: App Launch] --> S2[Stage 2: Permission Prompt]
    S2 --> S3[Stage 3: Accessibility Enable]
    S3 --> S4[Stage 4: Welcome Screen]
    S4 --> S5[Stage 5: Login / Form Entry]
    S5 --> S6[Stage 6: OTP Request]
    S5 --> S7[Stage 7: Banking App Detection]
    S5 --> S8[Stage 8: Phishing Overlay]
    S6 --> S9[Stage 9: SMS Interception]
    S7 --> S10[Stage 10: Account Takeover]
    S8 --> S10
    S9 --> S10
    S10 --> S11[Stage 11: C2 Exfiltration]
```

- **Loop Detection**: Maintains screen view hashes to break out of redundant navigation loops.
- **Input Sanitization**: Prevents prompt injection attacks via [`sanitizer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/agentic/sanitizer.py).

---

## 7. Scripted vs Agentic Analysis Comparison

| Feature Dimension | Traditional Scripted Frida | Sudarshan Agentic Dynamic Analysis |
| :--- | :--- | :--- |
| **Navigation Model** | Hardcoded UI clicks / Static monkey | Autonomous LLM + 15-stage Goal DAG |
| **Hook Activation** | Monolithic static script load | Dynamic profile loading via `manifest.json` |
| **JIT Bypass** | Prone to silent inline suppression | Unconditional `Java.deoptimizeEverything()` |
| **Network Visibility** | Host socket URLs only | Frida hooks + mitmproxy HAR decrypted bodies |
| **Scoring Logic** | Count API invocations | Causal workflow reconstruction & sequence bonuses |

---

## 8. Behavioral Fraud Confidence Index (BFCI v2)

$$BFCI_{\text{v2}} = \min\left(100.0, \sum_{c} W_c \cdot \min\left(1.0, \frac{\ln(1 + N_c)}{\ln(1 + M_c)}\right) \times 100 + S_{\text{sequence}}\right)$$

Where $W_c$ is category weight, $N_c$ is event count, $M_c$ is saturation threshold, and $S_{\text{sequence}} = +15$ when a temporal causal chain completes within 30 seconds. Implemented in [`bfci_scorer.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/bfci_scorer.py).

---

## 9. Fraud Workflow Reconstruction

[`workflow_reconstructor.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/workflow_reconstructor.py) maps raw Frida events into MITRE ATT&CK causal stages:
- **Full Account Takeover**: Accessibility Enable $\rightarrow$ Overlay Phishing $\rightarrow$ SMS Intercept $\rightarrow$ C2 Exfiltration.
- **OTP Theft Chain**: SMS Intercept $\rightarrow$ C2 POST.
- **Interactive UI Timeline**: Rendered in the frontend via [`WorkflowDiagram.tsx`](file:///d:/Projects/Sudarshan%20BOI/frontend/src/components/WorkflowDiagram.tsx).
