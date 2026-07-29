# Sudarshan Microservice Containerization & Migration Guide

## Architecture Overview

The Sudarshan platform has been refactored into a **5-container microservice architecture**. All heavy reverse-engineering binaries (APKTool, JADX, Java 17, Frida 17, Androguard, and ADB) have been moved into a dedicated `analysis-engine` microservice container.

```mermaid
graph TD
    User([User Analyst]) -->|HTTP Port 5173| Frontend[sudarshan-frontend<br/>React 18 SPA]
    Frontend -->|REST API Port 8000| Backend[sudarshan-backend<br/>FastAPI Orchestrator Gateway]
    Backend -->|REST API Port 8001| Engine[sudarshan-analysis-engine<br/>Ubuntu 24.04 + OpenJDK 17 + Python 3.12<br/>APKTool 2.10.0 + JADX 1.5.1 + Frida 17.16.4]
    Backend -->|REST API Port 8008| MobSF[sudarshan-mobsf<br/>Mobile Security Framework]
    Engine ---|Shared Volume mitmproxy_har| Mitmproxy[sudarshan-mitmproxy<br/>Transparent HTTPS Sidecar]

    Backend ---|Shared Volume /app/uploads| Engine
    Engine -->|Network ADB TCP Port 5555| HostAVD[Android Studio AVD Emulator<br/>Host Machine]
```

---

## Key Technical Specifications

1. **`analysis-engine` Container**:
   - Base OS: **Ubuntu 24.04**
   - Java: OpenJDK 17
   - Python: 3.12 with PyPI verified `frida==17.16.4` and `frida-tools`
   - Shared Library: [`shared/sudarshan_core/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/) mounted at `/opt/sudarshan-core`
   - Static Tools: Pinned **APKTool v2.10.0** (`/usr/local/bin/apktool`) and **JADX CLI v1.5.1** (`/usr/local/bin/jadx`)
   - Network ADB: Auto-connects to Android Studio AVD via `host.docker.internal:5555` with an idempotent 10-attempt retry loop.
   - Resource Constraints: Hard limits (`mem_limit: 4g`, `cpus: 2.0`, `no-new-privileges:true`).

2. **Backend Orchestrator**:
   - Contains **zero local binary dependencies** (no local `apktool`, `jadx`, `java`, `frida`, or `adb`).
   - Delegates analysis jobs to `http://analysis-engine:8001/api/v1/analyze` over internal Docker networking.
   - Uses zero-copy shared volume `/app/uploads` (`uploads` Docker named volume).

3. **Analysis Engine REST API Endpoints**:
   - `GET /health`: Healthcheck endpoint (`{"status": "ok"}`).
   - `GET /status`: Detailed toolchain availability and ADB connectivity status.
   - `POST /api/v1/analyze`: Synchronous analysis endpoint.
   - `POST /api/v1/analyze/async`: Asynchronous job submission returning `job_id`.
   - `GET /api/v1/status/{job_id}`: Poll status of an async analysis job.

---

## How to Run

### Step 1: Start Host Emulator & Enable Network ADB
On your host Windows machine:
```powershell
# 1. Launch your Android Studio AVD Emulator
# 2. Enable ADB TCP Port 5555, root, and SELinux permissive mode:
adb tcpip 5555
adb connect 127.0.0.1:5555
adb root
adb shell "setenforce 0"
```

### Step 2: Build & Boot Docker Microservices Stack
```powershell
docker compose up --build -d
```

### Step 3: Verify Container Health
```powershell
docker compose ps
```

Services running:
- `sudarshan-frontend`: `http://localhost:5173`
- `sudarshan-backend`: `http://localhost:8000`
- `sudarshan-analysis-engine`: `http://analysis-engine:8001` (internal)
- `sudarshan-mobsf`: `http://localhost:8008`
- `sudarshan-mitmproxy`: `127.0.0.1:8080`

---

## Verification & Testing

Execute unit test suite against the backend orchestrator:
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests
```
Result: **388 / 388 automated tests passing clean**.
