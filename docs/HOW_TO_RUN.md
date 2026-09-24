# How to run

Installation and operations guide for the SUDARSHAN platform.

```yaml
Backend app version:    2.1.0
Analysis engine version: 2.3.0
Last verified:          2026-08-27
Target platforms:       Windows 10/11, Linux (Ubuntu 22.04+), macOS 13+
```

- Platform overview: [`../README.md`](../README.md)
- Architecture: [`CURRENT_ARCHITECTURE.md`](CURRENT_ARCHITECTURE.md)
- Boundaries you will hit: [`KNOWN_LIMITATIONS.md`](features/KNOWN_LIMITATIONS.md)

---

## Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Configuration](#2-configuration)
- [3. Quick start](#3-quick-start)
- [4. Running with Docker Compose](#4-running-with-docker-compose)
- [5. Running services directly](#5-running-services-directly)
- [6. Sandbox setup](#6-sandbox-setup)
- [7. Verification](#7-verification)
- [8. Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

| Dependency | Minimum | Check | Purpose |
| :--- | :--- | :--- | :--- |
| Docker and Compose | 24.0+ | `docker compose version` | Runs `frontend`, `backend`, `analysis-engine`, `mitmproxy`, `mobsf` |
| Rooted Android emulator | Android 10/11 (API 29/30), x86_64 | `adb devices` | Genymotion Desktop or Android Studio AVD; the dynamic sandbox |
| ADB | 1.0.41+ | `adb version` | Host bridge to the emulator |
| Python | 3.11+ | `python --version` | `start.ps1` bootstrap, preflight, local test runs |
| Node.js | 18+ | `node --version` | Frontend development outside Docker only |
| Gemini API key | — | — | Optional but consequential: without one the agentic planner disables itself |

APKTool, JADX, Java 17, Frida, Androguard, `aapt` and `adb` are installed **inside** the `sudarshan-analysis-engine` image. On the host you need only Docker, ADB and Python.

`frida-server` is roughly 106 MB and exceeds GitHub's file limit, so `tools/` is gitignored. The analysis engine downloads the ABI-matched binary into the bind-mounted host cache (`FRIDA_SERVER_DIR`, default `/opt/frida-cache` → `./tools`) on first use and reuses it thereafter.

---

## 2. Configuration

One `.env` at the repository root is read by every service. Start from the annotated reference:

```bash
cp .env.example .env
```

### Required

```env
JWT_SECRET_KEY=            # generate: python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The backend refuses to start without it rather than generating one, because a generated key would let anyone forge a token for any role.

### Commonly set

```env
# ── Admin bootstrap ──
ADMIN_USERNAME=admin
ADMIN_PASSWORD=                 # blank on first boot: a random password is logged once

# ── AI ──
GEMINI_PRIMARY_API_KEY=
GEMINI_PRIMARY_MODEL=gemini-3.6-flash
GEMINI_FALLBACK_API_KEY=
GEMINI_FALLBACK_MODEL=gemini-2.5-flash
GEMINI_PRIMARY_COOLDOWN_SECONDS=60
GEMINI_MAX_RETRIES=3
SUDARSHAN_AGENT_MAX_OUTPUT_TOKENS=2048
# Legacy aliases, still honoured as the primary slot:
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.6-flash

# ── Sandbox ──
SANDBOX_PROVIDER=auto           # auto | genymotion | android_avd | physical
DEVICE_SERIAL=                  # pin when more than one device is attached
ADB_HOST=                       # leave empty on Docker Desktop
ADB_PORT=5555
ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
FRIDA_PORT=27055
FRIDA_VERSION=17.16.4
FRIDA_LISTEN_HOST=127.0.0.1
ROOT_REQUIRED=true
AUTO_CONNECT=true
FRIDA_ANALYSIS_DURATION=240     # exploration window, seconds
SUDARSHAN_PREGRANT_PERMISSIONS=1
SUDARSHAN_ACTION_DELAY_SCALE=1.0

# ── Threat intelligence (optional; the axis is excluded when unset) ──
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
ABUSEIPDB_API_KEY=

# ── Services ──
MOBSF_HOST=http://mobsf:8000
MOBSF_API_KEY=
MITMPROXY_PORT=8085
SUDARSHAN_DB_PATH=/app/data/sudarshan.db

# ── Security posture ──
SUDARSHAN_ENV=                  # "production" enables fail-closed startup validation
SANDBOX_CONTAINMENT_STRICT=
ANALYSIS_ENGINE_INTERNAL_TOKEN= # required when SUDARSHAN_ENV=production
CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
# SUDARSHAN_ALLOW_GATEWAY_DYNAMIC=  # leave unset; the gateway must not drive the device
```

The `ADB_SERVER_SOCKET` value written by `docker-compose.yml` is `tcp:host.docker.internal:5037`. Leave `ADB_HOST` **empty** on Docker Desktop for Windows and macOS — the default route proxies the host ADB server correctly. Set `ADB_HOST` only on Linux Docker or for a Genymotion VM on a host-only network; `.env.example` documents both routes.

`analysis-engine/.env` is an optional per-service override. It is gitignored, so a fresh clone does not have one, and Compose declares it `required: false` — a missing file does not abort the stack.

Never commit `.env`. Demo account configuration: [`BOI_DEMO_CREDENTIALS.md`](operations/DEMO_CREDENTIALS.md).

---

## 3. Quick start

### Windows

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # first run only
.\start.ps1 -Detach
```

`start.ps1` creates `.env` if missing, generates a `JWT_SECRET_KEY`, locates Docker and a usable Python interpreter, auto-detects Genymotion or an AVD, pushes `frida-server`, and brings up Compose.

| Command | Use |
| :--- | :--- |
| `.\start.ps1` | Foreground; logs stream in the terminal |
| `.\start.ps1 -Detach` | Background; recommended for daily use |
| `.\start.ps1 -SkipSandbox` | Static analysis only — no emulator or Frida required |

### Linux and macOS

```bash
cp .env.example .env      # set JWT_SECRET_KEY and ADMIN_PASSWORD
docker compose up -d --build
```

---

## 4. Running with Docker Compose

```bash
docker compose up --build -d     # build and start
docker compose ps                # container state
docker compose logs -f backend   # follow gateway logs
docker compose down              # stop; the dbdata volume survives
```

### Published ports

| Service | Binding | Notes |
| :--- | :--- | :--- |
| `frontend` | `5173` on all interfaces | Vite dev server |
| `backend` | `8000` on all interfaces | API gateway |
| `analysis-engine` | not published | Internal Compose network only, at `http://analysis-engine:8001` |
| `mobsf` | `127.0.0.1:8008` | Loopback only |
| `mitmproxy` | `127.0.0.1:${MITMPROXY_PORT:-8085}` → container `8080` | Loopback only |

### Hardened overlay

```bash
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up --build -d
```

Removes the development bind-mounts, sets a read-only rootfs, drops all capabilities, applies the seccomp profile to the analysis engine, and sets `SUDARSHAN_ENV=production` with `SANDBOX_CONTAINMENT_STRICT=true`. It also stops mounting `~/.android`, so the host keystore is not exposed.

Requires `JWT_SECRET_KEY`, `ANALYSIS_ENGINE_INTERNAL_TOKEN`, and a containment-compliant ADB route. Startup validation aborts on a non-compliant configuration. Background: [`security/P0_SANDBOX_ESCAPE_INCIDENT.md`](security/P0_SANDBOX_ESCAPE_INCIDENT.md).

### Database

The case database lives on the `dbdata` volume at `/app/data/sudarshan.db`, not inside the source bind-mount, so it survives `docker compose down`, image rebuilds and the hardened overlay.

An older install keeping data in `backend/sudarshan.db` is **not** picked up automatically — a silent switch would make existing cases disappear. Move it deliberately:

```bash
docker compose run --rm backend \
  python /opt/sudarshan-scripts/db_admin.py adopt /app/sudarshan.db
```

---

## 5. Running services directly

Useful when iterating on one service with the rest in Docker.

### Backend

```bash
export PYTHONPATH="$PWD/backend:$PWD/shared"
export JWT_SECRET_KEY=... ADMIN_USERNAME=admin ADMIN_PASSWORD=...
export ANALYSIS_ENGINE_URL=http://localhost:8001
cd backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend

```bash
cd frontend
npm ci
npm run dev          # http://localhost:5173
```

Set `VITE_API_URL` to point at a backend other than `http://localhost:8000/api/v1`.

---

## 6. Sandbox setup

The Android guest runs on the **host**, never in a container. Both providers need root and permissive SELinux for Frida to attach; treat the guest as fully compromised after every session.

### 6.1 Genymotion Desktop

1. Create an x86_64 virtual device (Android 10 or 11). Genymotion images are rooted by default.
2. Start it and confirm the endpoint:

   ```bash
   adb devices -l
   # 192.168.56.101:5555   device   product:vbox86p ...
   ```

3. Configure `.env`:

   ```env
   SANDBOX_PROVIDER=genymotion
   DEVICE_SERIAL=192.168.56.101:5555
   ADB_PORT=5555
   # Linux Docker only - leave empty on Docker Desktop:
   # ADB_HOST=192.168.56.101
   ```

4. Prepare the guest and push `frida-server`:

   ```bash
   adb -s "$DEVICE_SERIAL" root
   adb -s "$DEVICE_SERIAL" shell whoami       # must print: root
   adb -s "$DEVICE_SERIAL" shell setenforce 0
   python scripts/setup_dynamic_analysis.py --serial "$DEVICE_SERIAL"
   ```

   `setup_dynamic_analysis.py` accepts `--serial`, `--avd`, `--push-server` / `--no-push-server` and `--skip-start`.

5. For network capture, point the guest's HTTP proxy at the mitmproxy endpoint (`127.0.0.1:8085` by default, or whatever `MITMPROXY_PORT` is set to) and install the mitmproxy CA into the guest **system** store.

> `adb tcpip` is blocked by the ADB gateway policy (`shared/sudarshan_core/security/adb_gateway.py`) and cannot be issued from analysis code — it opens network ADB on the device without session binding. Genymotion already exposes a TCP endpoint, so this step is not needed.

### 6.2 Android Studio AVD

1. Create an x86_64 AVD **without** Google Play — Play images cannot be rooted. Google APIs images can.
2. Start it, then:

   ```bash
   adb devices           # emulator-5554   device
   adb root
   adb shell getenforce  # Permissive
   ```

3. Configure `.env`:

   ```env
   SANDBOX_PROVIDER=android_avd
   DEVICE_SERIAL=emulator-5554
   SUDARSHAN_AVD=<avd_name>
   ADB_SERVER_SOCKET=tcp:host.docker.internal:5037
   ```

Accepted aliases for the AVD provider: `android_avd`, `android_studio`, `androidstudio`, `avd`, `emulator`.

---

## 7. Verification

| Check | Command or URL | Expected |
| :--- | :--- | :--- |
| Containers | `docker compose ps` | All services `running`, analysis-engine `healthy` |
| API liveness | `http://localhost:8000/health` | `{"status": "ok"}` |
| Interactive API reference | `http://localhost:8000/docs` | Swagger UI |
| Analyst dashboard | `http://localhost:5173` | Login page |
| Runtime telemetry | `http://localhost:8000/api/runtime/status` | Requires a bearer token |
| Analysis engine | `docker compose exec analysis-engine curl -s localhost:8001/status` | Toolchain and ADB readiness |
| MobSF | `http://127.0.0.1:8008` | MobSF UI |
| mitmproxy | `127.0.0.1:8085` | Proxy endpoint |

### Diagnostic scripts

```bash
# Environment and toolchain preflight; --container also checks inside the engine
PYTHONPATH="backend:shared" python scripts/preflight.py --container

# Platform health across startup validation subsystems
PYTHONPATH="backend:shared" python scripts/health_check.py        # --quick skips the MobSF scan

# Dynamic pipeline self-test end to end
PYTHONPATH="backend:shared" python scripts/verify_runtime_pipeline.py
```

### Test suite

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=test_secret \
  python -m pytest tests/ backend/tests -q
```

**2,622 tests collected** on 2026-08-27. There is no CI workflow in this repository, so this is the only gate — run it before pushing.

### Dynamic corpus validation

Requires a live sandbox and Frida. Reports land under `tests/apks/validation_runs/<timestamp>/`.

```bash
PYTHONPATH="backend:shared" JWT_SECRET_KEY=validation \
  python validate_dynamic_pipeline.py            # [--fetch] [--stress 10,20] [--recovery]
```

See [`VALIDATION.md`](operations/VALIDATION.md) and [`../tests/apks/README.md`](../tests/apks/README.md).

---

## 8. Troubleshooting

**Frida attach fails.** Confirm `frida-server` is running on the guest (`adb shell "ps -A | grep frida"`), that `adb root` succeeded, and that `getenforce` reports `Permissive`. Host and guest Frida versions must match exactly (17.16.4) — a mismatch is the most common cause and `scripts/preflight.py` reports it.

**Sandbox appears absent under Docker Desktop.** Leave `ADB_HOST` empty. Genymotion VMs sit on a VirtualBox host-only adapter that `host.docker.internal` cannot reach; the auto-detect provider resolves the endpoint from `adb devices -l` instead.

**Exploration is shallow and every run reports `TIME_BUDGET_EXHAUSTED`.** Check that a Gemini key is configured — without one the deterministic fallback planner takes over silently. Then raise `FRIDA_ANALYSIS_DURATION` and, on a slow sandbox, `SUDARSHAN_ACTION_DELAY_SCALE`.

**Analysis completes but the verdict says `INCOMPLETE_EXERCISE`.** The sandbox ran and reached no fraud trigger condition. This is a real result, not an error. `GET /api/v1/analysis/{session_id}/suggestions` returns the triggers that were not reached.

**No network evidence.** The mitmproxy CA must be in the guest **system** store, not the user store, and certificate-pinned samples defeat interception regardless. Frida socket and HTTP hooks still observe below the TLS layer.

**MobSF unreachable.** It is optional. The pipeline logs a warning and continues. Confirm the container is up with `docker compose ps`; it binds to `127.0.0.1:8008`.

**Backend will not start.** The most common causes are an unset `JWT_SECRET_KEY`, and — under `SUDARSHAN_ENV=production` — a containment posture that startup validation rejects. Both are logged explicitly at startup.

**Analysis-engine 404 on a job that was just created.** The engine holds job state in-process and is pinned to `--workers 1` for exactly this reason. If it was restarted, the job is gone; the gateway's `analysis_jobs` record is authoritative.
