# How to Run & Operational Setup Guide

```yaml
Document Title:      Sudarshan Installation & Execution Manual
Version:             2.2.0-STABLE
Last Revision:       2026-07-25
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
| **Docker & Compose** | 24.0+ | `docker compose version` | Containerized stack orchestration (`frontend`, `backend`, `analysis-engine`, `mitmproxy`). |
| **Android Studio AVD** | Android 13 (API 33) | `adb devices` | Isolated AVD dynamic execution sandbox on host. |
| **ADB** | 1.0.41+ | `adb version` | Android Debug Bridge for TCP emulator connection (`adb tcpip 5555`). |
| **Python** *(Dev Optional)* | 3.10+ | `python --version` | Local development and unit testing (`pytest tests/`). |
| **Node.js** *(Dev Optional)* | 18.x+ | `node --version` | Local frontend UI development. |
| **Ollama** *(Optional)* | 0.1.30+ | `ollama --version` | Local air-gapped LLM inference provider. |

> [!NOTE]
> **Host Dependency Elimination**: APKTool, JADX CLI, Java 17, Frida 17, Androguard, and ADB worker processes are **100% containerized** inside the `sudarshan-analysis-engine` microservice container. Zero binary installations are required on your host machine.

---

## 2. Environment Variables & Configuration

Create a `.env` file in the project root or set environment variables:

```bash
# ── AI Model Configuration ──
GEMINI_API_KEY="your_api_key_here"
GEMINI_MODEL="gemini-2.5-flash"
OLLAMA_HOST="http://localhost:11434"

# ── Dynamic Sandbox & ADB ──
ADB_HOST="host.docker.internal"
ADB_PORT="5555"
FRIDA_ANALYSIS_DURATION="30"

# ── Static Engines ──
MOBSF_HOST="http://mobsf:8000"
MOBSF_API_KEY="sudarshan_mobsf_api_key_2026"
APKTOOL_PATH="apktool"
JADX_PATH="jadx"

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
```bash
cd backend
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4.2 Frontend Analyst Dashboard
```bash
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
2. **Enable ADB TCP**:
   ```bash
   adb tcpip 5555
   adb connect 127.0.0.1:5555
   ```
3. **Deploy frida-server 17.16.0**:
   ```bash
   adb push frida-server-17.16.0-android-x86_64/frida-server /data/local/tmp/frida-server
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
| **API Interactive Docs** | `http://localhost:8000/docs` | Swagger UI documentation |
| **Analysis Engine Health** | `http://localhost:8001/health` (internal) | `{"status": "ok", "service": "analysis-engine"}` |
| **MobSF Engine** | `http://localhost:8008` | MobSF Static Analyzer UI |
| **mitmproxy Proxy** | `127.0.0.1:8080` | Transparent HTTPS proxy endpoint |

Run the backend unit test suite:
```bash
cd backend
pytest tests/
```

---

## 8. Troubleshooting Common Issues

- **Frida PID Attach Fails**: Verify `frida-server` is running on the AVD (`adb shell "ps -A | grep frida"`).
- **mitmproxy Certificate Warnings**: Install `mitmproxy-ca-cert.pem` on the AVD under Settings $\rightarrow$ Security $\rightarrow$ Install Certificate.
- **MobSF Unreachable**: Ensure the MobSF container is running on port 8008 (`docker compose ps`).

