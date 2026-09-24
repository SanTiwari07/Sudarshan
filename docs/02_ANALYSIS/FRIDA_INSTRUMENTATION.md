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
