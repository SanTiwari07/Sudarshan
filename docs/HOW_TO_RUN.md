# How to Run & Operational Setup Guide

```yaml
Document Title:      Sudarshan Installation & Execution Manual
Version:             2.4.0-STABLE
Last Revision:       2026-07-29
Target OS:           Windows 10/11, Linux (Ubuntu 22.04+), macOS 13+
```

---

## Table of Contents
- [1. System Prerequisites](#1-system-prerequisites)
- [2. Environment Variables & Configuration](#2-environment-variables--configuration)
- [3. Quick Start (Single Command)](#3-quick-start-single-command)
- [4. Manual Service Installation](#4-manual-service-installation)
- [5. Running with Docker Compose](#5-running-with-docker-compose)
- [6. Setting Up Android Studio AVD & Frida](#6-setting-up-android-studio-avd--frida)
- [7. Verification & Health Checks](#7-verification--health-checks)
- [8. Troubleshooting Common Issues](#8-troubleshooting-common-issues)

---

## 1. System Prerequisites

Ensure the following tools are installed on your host system:

| Dependency | Minimum Version | Installation Check | Purpose |
| :--- | :--- | :--- | :--- |
| **Docker & Compose** | 24.0+ | `docker compose version` | Containerized stack orchestration (`frontend`, `backend`, `analysis-engine`, `mitmproxy`, `mobsf`). |
| **Android Studio AVD** | Android 13 (API 33) | `adb devices` | Isolated AVD dynamic execution sandbox on host. |
| **ADB** | 1.0.41+ | `adb version` | Android Debug Bridge for TCP emulator connection (`adb tcpip 5555`). |
| **Python** *(Dev Optional)* | 3.10+ | `python --version` | Local development and unit testing (`pytest backend/tests`). |
| **Node.js** *(Dev Optional)* | 18.x+ | `node --version` | Local frontend UI development. |
| **Google Gemini API** | `google-genai` | API Key | Primary AI Threat Intelligence Provider (`gemini-2.5-flash`). |

> [!NOTE]
> **Host Dependency Elimination**: APKTool, JADX CLI, Java 17, Frida 17, Androguard, AAPT, and ADB worker processes are **100% containerized** inside the `sudarshan-analysis-engine` microservice container. Zero binary installations are required on your host machine.

---

## 2. Environment Variables & Configuration

Create a `.env` file in the project root based on `.env.example`:

```bash
# ── AI Model Configuration ──
GEMINI_API_KEY="your_api_key_here"
GEMINI_MODEL="gemini-2.5-flash"

# ── Dynamic Sandbox & ADB ──
ADB_HOST="host.docker.internal"
ADB_PORT="5555"
FRIDA_ANALYSIS_DURATION="30"
SUDARSHAN_EXPLORER_MODE="ai"

# ── Threat Intelligence ──
VIRUSTOTAL_API_KEY=""
OTX_API_KEY=""
ABUSEIPDB_API_KEY=""

# ── Static Engines ──
MOBSF_HOST="http://mobsf:8000"
MOBSF_API_KEY="sudarshan_mobsf_api_key_2026"

# ── Security & Authentication ──
JWT_SECRET_KEY="generate_with_python_secrets_token_urlsafe_48"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="sudarshan_admin_2024"
```

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

---

## 6. Setting Up Android Studio AVD & Frida

1. **Start Android Studio AVD**: Launch a Pixel AVD running Android 13 (x86_64).
2. **Enable ADB TCP & Root**:
   ```bash
   adb tcpip 5555
   adb connect 127.0.0.1:5555
   adb root
   adb shell "setenforce 0"
   ```
3. **Deploy frida-server 17.16.4**:
   ```bash
   adb push frida-server-17.16.4-android-x86_64/frida-server /data/local/tmp/frida-server
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "nohup /data/local/tmp/frida-server > /dev/null 2>&1 &"
   ```

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

Run runtime pipeline telemetry verification script:
```powershell
$env:PYTHONPATH="backend;shared"; backend\.venv\Scripts\python.exe scripts/verify_runtime_pipeline.py
```

Run full unit and integration test suite:
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

---

## 8. Troubleshooting Common Issues

- **Frida PID Attach Fails**: Verify `frida-server` is running on the AVD (`adb shell "ps -A | grep frida"`), and verify `adb root` and `setenforce 0` were executed.
- **mitmproxy Certificate Warnings**: Install `mitmproxy-ca-cert.pem` on the AVD under Settings $\rightarrow$ Security $\rightarrow$ Install Certificate.
- **MobSF Unreachable**: Ensure the MobSF container is running on port 8008 (`docker compose ps`).
