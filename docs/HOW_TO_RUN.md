# How to Run & Operational Setup Guide

```yaml
Document Title:      Sudarshan Installation & Execution Manual
Version:             2.1.0
Last Revision:       2026-08-14
Target OS:           Windows 10/11, Linux (Ubuntu 22.04+), macOS 13+
```

---

## Table of Contents
- [1. System Prerequisites](#1-system-prerequisites)
- [2. Environment Variables & Configuration](#2-environment-variables--configuration)
- [3. Quick Start (Single Command)](#3-quick-start-single-command)
- [4. Manual Service Installation](#4-manual-service-installation)
- [5. Running with Docker Compose](#5-running-with-docker-compose)
- [6. Setting Up Genymotion Desktop & Frida](#6-setting-up-genymotion-desktop--frida)
- [7. Verification & Health Checks](#7-verification--health-checks)
- [8. Troubleshooting Common Issues](#8-troubleshooting-common-issues)

---

## 1. System Prerequisites

Ensure the following tools are installed on your host system:

| Dependency | Minimum Version | Installation Check | Purpose |
| :--- | :--- | :--- | :--- |
| **Docker & Compose** | 24.0+ | `docker compose version` | Containerized stack orchestration (`frontend`, `backend`, `analysis-engine`, `mitmproxy`, `mobsf`). |
| **Genymotion Desktop** *(or Android Studio AVD)* | Android 10/11 (API 29/30), x86 / x86_64 | `adb devices` | Isolated dynamic execution sandbox on host (`SANDBOX_PROVIDER`). |
| **ADB** | 1.0.41+ | `adb version` | Android Debug Bridge for TCP emulator connection (`adb tcpip 5555`). |
| **Python** *(Dev Optional)* | 3.10+ | `python --version` | Local development and unit testing (`pytest backend/tests`). |
| **Node.js** *(Dev Optional)* | 18.x+ | `node --version` | Local frontend UI development. |
| **Google Gemini API** | `google-genai` | API Key | Primary Gemini 3.x Flash with automatic 2.5 Flash failover. |

> [!NOTE]
> **Host Dependency Elimination**: APKTool, JADX CLI, Java 17, Frida 17, Androguard, AAPT, and ADB worker processes are **100% containerized** inside the `sudarshan-analysis-engine` microservice container. Zero binary installations are required on your host machine.

---

## 2. Environment Variables & Configuration

Create a `.env` file in the project root based on `.env.example`:

```bash
# ── AI Model Configuration ──
# Primary (Gemini 3.x Flash). Legacy GEMINI_API_KEY still maps to primary.
GEMINI_PRIMARY_API_KEY="your_primary_api_key"
GEMINI_PRIMARY_MODEL="gemini-3.6-flash"
# Fallback (Gemini 2.5 Flash) — used only when primary is exhausted/unavailable.
GEMINI_FALLBACK_API_KEY="your_fallback_api_key"
GEMINI_FALLBACK_MODEL="gemini-2.5-flash"
GEMINI_PRIMARY_COOLDOWN_SECONDS=60
# Legacy aliases (optional if PRIMARY_* is set):
GEMINI_API_KEY="your_primary_api_key"
GEMINI_MODEL="gemini-3.6-flash"

# ── Dynamic Sandbox & ADB ──
SANDBOX_PROVIDER="genymotion"
# ADB_HOST controls where the container connects to ADB. When left blank (default),
# the analysis-engine automatically determines the host interface based on the
# chosen SANDBOX_PROVIDER. Override this only if your host network topology requires it.
ADB_HOST=""
ADB_PORT="5555"
# Only needed when multiple physical devices/emulators are attached simultaneously.
DEVICE_SERIAL=""
FRIDA_PORT="27055"
AUTO_CONNECT="true"
ROOT_REQUIRED="true"
FRIDA_ANALYSIS_DURATION="30"

# ── Threat Intelligence ──
VIRUSTOTAL_API_KEY=""
OTX_API_KEY=""
ABUSEIPDB_API_KEY=""

# ── Static Engines ──
MOBSF_HOST="http://mobsf:8000"
MOBSF_API_KEY="sudarshan_mobsf_api_key_2026"

# ── Security & Authentication ──
JWT_SECRET_KEY="generate_with_python_secrets_token_urlsafe_48"
ANALYSIS_ENGINE_INTERNAL_TOKEN=""   # Required when SUDARSHAN_ENV=production
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=""                   # If blank on first boot, a random password is logged once by the backend
CORS_ALLOW_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
SUDARSHAN_ENV=""                    # Set to production for strict containment + engine auth
# SANDBOX_CONTAINMENT_STRICT=true   # Implied when SUDARSHAN_ENV=production
# SUDARSHAN_ALLOW_GATEWAY_DYNAMIC=false  # Never enable in production (dev-only local dynamic fallback)
FRIDA_LISTEN_HOST="127.0.0.1"
```

> [!NOTE]
> The `analysis-engine/.env` file is now optional. Fresh clones will gracefully fallback to default configurations without aborting the stack due to a missing environment file.

---

## 3. Quick Start (Single Command)

Launch all platform microservices, database migrations, and web interfaces with a single command from PowerShell:

```powershell
.\start.ps1
```

---

## 4. Manual Service Installation

### 4.1 Backend API Gateway
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4.2 Frontend Analyst Dashboard
```powershell
cd frontend
npm install
npm run dev
```

---

## 5. Running with Docker Compose

```bash
# 1. Build and launch all containers
docker compose up --build -d

# 2. View running containers
docker compose ps

# 3. Stream backend logs
docker compose logs -f backend
```

### 5.1 Production-hardened stack (optional)

For deployments that remove dev bind-mounts and enable containment strict mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up --build -d
```

Requires `SUDARSHAN_ENV=production`, `ANALYSIS_ENGINE_INTERNAL_TOKEN`, correct Genymotion `ADB_HOST`, and `JWT_SECRET_KEY`. See [`security/P0_SANDBOX_ESCAPE_INCIDENT.md`](security/P0_SANDBOX_ESCAPE_INCIDENT.md).

---

## 6. Setting Up Genymotion Desktop & Frida

### 6.1 Genymotion (default - `SANDBOX_PROVIDER=genymotion`)

1. **Install Genymotion Desktop** and create a rooted virtual device (Android 10/11, x86_64 recommended).
2. **Start the device** from the Genymotion UI and confirm ADB can see it:
   ```bash
   adb devices
   # Example: 192.168.56.101:5555    device
   ```
3. **Pin the serial** (recommended when multiple devices are online):
   ```bash
   # In .env
   DEVICE_SERIAL=192.168.56.101:5555
   ```
4. **Enable ADB TCP, root, SELinux, Frida** (or use the setup script):
   ```bash
   adb -s $DEVICE_SERIAL tcpip 5555
   adb -s $DEVICE_SERIAL root
   adb -s $DEVICE_SERIAL shell "whoami"   # must print: root
   adb -s $DEVICE_SERIAL shell "setenforce 0"
   python scripts/setup_dynamic_analysis.py --serial $DEVICE_SERIAL
   ```
5. Point Genymotion HTTP proxy at `127.0.0.1:8080` if using mitmproxy network capture.

### 6.2 Android Studio AVD (optional - `SANDBOX_PROVIDER=android_studio`)

1. Set `SANDBOX_PROVIDER=android_studio` in `.env`.
2. Launch an AVD (Android 10/11+, x86_64).
3. Run the same ADB/root/Frida steps as above (serial is typically `emulator-5554`).

---

## 7. Verification & Health Checks

Verify all microservice endpoints:

| Service | Access URL | Expected Response |
| :--- | :--- | :--- |
| **Analyst Dashboard** | `http://localhost:5173` | React SPA Login / Upload Page |
| **API Health Check** | `http://localhost:8000/health` | `{"status": "ok"}` |
| **Runtime Telemetry** | `http://localhost:8000/api/runtime/status` | `{"status": "ok", "active_sessions": 0, ...}` |
| **API Interactive Docs** | `http://localhost:8000/docs` | Swagger UI documentation |
| **Analysis Engine Health** | `http://analysis-engine:8001/health` (internal) | `{"status": "ok", "service": "analysis-engine"}` |
| **MobSF Engine** | `http://localhost:8008` | MobSF Static Analyzer UI |
| **mitmproxy Proxy** | `127.0.0.1:8080` | Transparent HTTPS proxy endpoint |

Run system health diagnostic script:
```powershell
$env:PYTHONPATH="backend;shared"; backend\.venv\Scripts\python.exe scripts/health_check.py
```

Run environmental preflight diagnostic script to prevent silent sandbox degradations:
```powershell
$env:PYTHONPATH="backend;shared"; backend\.venv\Scripts\python.exe scripts/preflight.py
```

Run runtime pipeline telemetry verification script:
```powershell
$env:PYTHONPATH="backend;shared"; backend\.venv\Scripts\python.exe scripts/verify_runtime_pipeline.py
```

Run full unit and integration test suite:
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

Run dynamic APK corpus validation (requires live sandbox + Frida):
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="validation"; python validate_dynamic_pipeline.py
```
See [`docs/VALIDATION.md`](VALIDATION.md) and [`tests/apks/README.md`](../tests/apks/README.md).

---

## 8. Troubleshooting Common Issues

- **Frida PID Attach Fails**: Verify `frida-server` is running on the AVD (`adb shell "ps -A | grep frida"`), and verify `adb root` and `setenforce 0` were executed.
- **mitmproxy Certificate Warnings**: Install `mitmproxy-ca-cert.pem` on the AVD under Settings $\rightarrow$ Security $\rightarrow$ Install Certificate.
- **MobSF Unreachable**: Ensure the MobSF container is running on port 8008 (`docker compose ps`).
