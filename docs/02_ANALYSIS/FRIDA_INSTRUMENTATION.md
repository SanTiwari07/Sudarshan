# SUDARSHAN — Frida Instrumentation & Hook Architecture

> **Classification:** AUTHORITATIVE  
> **Source Directory:** `shared/sudarshan_core/engines/frida_hooks/`  
> **Frida Version:** 17.16.4  
> **Last Verified:** 2026-09-25  

---

## 1. Overview

SUDARSHAN utilizes pre-compiled, highly optimized JavaScript hook bundles (`banking_trojan.bundle.js`) compiled via Webpack from modern TypeScript/ES6 sources.

---

## 2. Monitored API Categories

| Hook Category | Targeted Android APIs | Fraud Significance |
| :--- | :--- | :--- |
| **Accessibility** | `AccessibilityService`, `AccessibilityNodeInfo`, `AccessibilityEvent` | Detects screen scraping, keystroke logging, and automated tap injection (ATS). |
| **SMS** | `SmsManager.sendTextMessage`, `Telephony.Sms.Intents.SMS_RECEIVED_ACTION` | Detects OTP exfiltration, outgoing premium SMS fraud, and inbox suppression. |
| **Overlay** | `WindowManager.addView`, `TYPE_APPLICATION_OVERLAY`, `TYPE_SYSTEM_ALERT` | Detects phishing overlays positioned above legitimate banking applications. |
| **Code Execution** | `DexClassLoader`, `InMemoryDexClassLoader`, `ProcessBuilder.start`, `Runtime.exec` | Identifies secondary payload dropped from assets or loaded dynamically from C2. |
| **Network** | `java.net.Socket.connect`, `okhttp3.OkHttpClient`, `HttpURLConnection` | Extracts destination C2 IP addresses, ports, and API endpoints. |
| **Persistence** | `DevicePolicyManager.lockNow`, `startForegroundService` | Detects device admin locking and resistance to user uninstallation. |

---

## 3. Anti-Hooking & Bypass Handlers
- **SSL Pinning Bypass:** Automatically disables certificate pinning for `TrustManagerImpl`, `OkHttpClient`, and `WebViewClient` to enable transparent inspection by mitmproxy.
- **Root & Frida Evasion Hooks:** Intercepts common checks for `/system/bin/su`, `/system/xbin/su`, `test-keys`, and Frida listening ports.

---

## Telemetry pipeline diagnostics

`shared/sudarshan_core/engines/telemetry_diagnostics.py` records each stage of the runtime-telemetry pipeline for a session and classifies the run. Every dynamic result carries it as `telemetry_diagnostics`; the PDF report and dashboard render it.

| Classification | Meaning |
| :--- | :--- |
| `FRIDA_ATTACH_FAILED` | No Frida session was established. |
| `AGENT_INIT_FAILED` | Session existed, but the agent failed to load, sent no load canary, or had no Java bridge. |
| `HOOK_INSTALL_FAILED` | Agent loaded, zero hooks installed. |
| `HOOKS_INSTALLED_NOT_EXERCISED` | Hooks installed and the session stayed attached for the whole window; no hooked API was called. |
| `NO_TELEMETRY_OBSERVED` | Hooks installed but instrumentation was lost before the window ended (`detached` reason recorded), or the window never closed normally. |
| `EVENT_PROCESSING_FAILED` | Events arrived but some were lost on the host: handler exception, unpublished event, event-bus drop or subscriber error, evidence build or persistence failure. |
| `RUNTIME_EVENTS_RECEIVED` | Events arrived and every one was processed. |

What it records: attach pid/error; agent load attempt/error, canary, Java-bridge failure, agent `diag` milestones (e.g. `deoptimizeEverything_skipped_api34_plus`); hooks installed/errors/fired per hook; Frida messages by type, malformed messages, script errors, handler exceptions; events received/accepted/filtered/published; session `detached` reason and crash; whether the session was still attached when the window closed; event-bus and evidence-store counters.

Implementation notes:

- `FridaSession._dispatch_message` counts every message before handling it and never raises into frida-python (which would print and drop the event).
- `FridaSession._load_primary_agent` is the single place the primary agent is loaded; it registers the `detached` handler and records load failures.
- Companion-package agents are dispatched as non-primary: their canary/hook messages never count as the target agent's.
- This classification describes the **instrumentation**, not the sample. It does not change `dynamic_status` or any score.

Verification: `tests/unit/test_telemetry_diagnostics.py` (mocked transport) and `tests/integration/test_frida_local_agent.py`, which loads the production bundle with real Frida 17.16.4 into a **local Linux** process. That host has no ART, so the Java bridge is unavailable and only the native `connect()` hook is exercised there; it is not evidence about behaviour on an Android device.
