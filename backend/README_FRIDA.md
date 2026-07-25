# SUDARSHAN — Frida Dynamic Analysis Setup Guide

This document explains how to set up the Frida-based dynamic behavioral analysis sandbox for the Sudarshan platform.

## Prerequisites

| Requirement | Status | Notes |
|---|---|---|
| `frida` (Python) | In `requirements.txt` (`17.16.4`) | Auto-installed via `pip` / Docker build |
| `adb` | In `Dockerfile` | `android-sdk-platform-tools` installed in container |
| Android Studio (AVD) | On your HOST machine | Runs Pixel 6 AVD (Android 13+ / 16 KB pages) |
| `frida-server` | One-time emulator setup | Downloaded matching version `17.16.4` |

---

## Quick Start (Recommended)

After the one-time emulator setup (Steps 1–2 below), use the startup script to launch the **entire platform with a single command**:

```powershell
.\start.ps1
```

This script automatically:
1. Restarts ADB server
2. Enables ADB over TCP (port 5555)
3. Restarts `adbd` as root
4. Kills any stale `frida-server` and starts a fresh instance using `nohup`
5. Launches `docker compose up`

> **First-time execution policy:** If Windows blocks the script, run once:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```

---

## Running with Docker

The backend Docker container has `adb` and `frida`/`frida-tools` pre-installed.
The Android emulator runs on your **host machine** (via Android Studio AVD).
The container reaches the emulator over **ADB TCP** using `host.docker.internal`.

### One-time host setup (run on your host machine, NOT inside Docker)

```powershell
# 1. Start your Pixel 6 AVD emulator in Android Studio

# 2. Add ADB to PATH:
#    C:\Users\<YourUser>\AppData\Local\Android\Sdk\platform-tools\

# 3. Switch the emulator's ADB to TCP mode:
adb tcpip 5555

# 4. Verify:
adb devices
# Should show: emulator-5554   device
```

### Start the full stack:

```powershell
docker compose up --build
```

The backend automatically calls `adb connect host.docker.internal:5555` on startup.

### Sandbox status health check:

```
GET http://localhost:8000/api/v1/sandbox/status
```

Expected response when Docker + emulator are configured:
```json
{
  "ready": true,
  "mode": "docker-tcp",
  "frida_available": true,
  "frida_version": "17.16.4",
  "adb_found": true,
  "adb_host": "host.docker.internal",
  "adb_port": "5555",
  "emulators_connected": ["host.docker.internal:5555"],
  "hooks_script_present": true,
  "message": "Frida sandbox is ready for dynamic analysis."
}
```

---

## Architecture & Instrumentation Flow

```
APK Uploaded
     │
     ▼
Static Analysis (Androguard / MobSF)
     │
     ▼
[FRIDA SANDBOX]
  ├─ ADB installs APK on Android Emulator (AVD)
  ├─ Resolves PID via `adb shell pidof` and attaches Frida instantly
  ├─ Loads bundled banking_trojan.bundle.js (compiled with frida-java-bridge):
  │     [A] Accessibility Service Abuse  (wa = 0.35)
  │     [S] SMS Interception / OTP       (ws = 0.25)
  │     [O] Overlay Phishing Attacks     (wo = 0.20)
  │     [B] Banking App Detection        (wb = 0.10)
  │     [N] Network / C2                 (wn = 0.05)
  │     [P] Persistence                  (wp = 0.05)
  └─ Behavioral events collected by AgenticExplorer (15-stage Fraud Goal DAG)
     │
     ▼
BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
     │
     ▼
FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact
     │
     ▼
Fraud Intelligence Report (via Gemini 2.5 Flash / Ollama)
```

---

## Step 1 — Create an Android Emulator in Android Studio

1. Open **Android Studio → Virtual Device Manager**.
2. Click **Create Device**.
3. Choose **Pixel 6** → **Next**.
4. Select system image **API 33/34 (x86_64, google_apis_ps16k)** supporting 16 KB page alignment.
5. Click **Finish** and start the emulator.

---

## Step 2 — Deploy frida-server on the Emulator

1. Download `frida-server-17.16.4-android-x86_64.xz` from [Frida Releases](https://github.com/frida/frida/releases/tag/17.16.4).
2. Extract the file and push it to the device:
   ```powershell
   adb root
   adb push frida-server-17.16.4-android-x86_64 /data/local/tmp/frida-server
   adb shell chmod 755 /data/local/tmp/frida-server
   adb shell "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
   ```
3. Verify connection:
   ```powershell
   frida-ps -D emulator-5554
   ```

---

## Files Reference

| File | Purpose |
|---|---|
| `app/engines/frida_sandbox.py` | Controller for ADB, PID resolution, attach, and event collection |
| `app/engines/frida_hooks/banking_trojan.bundle.js` | Compiled Frida JS bundle with `frida-java-bridge` |
| `app/engines/risk_engine.py` | Sole verdict authority implementing STEI, BFCI, and FRS |
| `app/engines/agentic_explorer.py` | Agentic exploration loop executing tool calls and goal DAG tracking |
| `start.ps1` | Automated platform bootstrapper script |

---

## Graceful Degradation

If the emulator or Frida server is offline, the platform automatically degrades gracefully to static-only analysis, redistributing the STEI weight to 50% without failing requests.
