#!/bin/bash
set -e

echo "[Analysis Engine] Initializing container runtime..."

# Verify Java, APKTool, and JADX availability
echo "[Analysis Engine] Verifying toolchain..."
java -version 2>&1 | head -n 1
apktool --version 2>&1 | head -n 1
jadx --version 2>&1 | head -n 1

# Idempotent ADB connection retry loop
ADB_HOST="${ADB_HOST:-host.docker.internal}"
ADB_PORT="${ADB_PORT:-5555}"

echo "[Analysis Engine] Starting background ADB daemon..."
adb start-server || true

echo "[Analysis Engine] Attempting ADB connection to ${ADB_HOST}:${ADB_PORT}..."
(
    _connected=0
    for i in {1..10}; do
        if adb connect "${ADB_HOST}:${ADB_PORT}" | grep -E "connected|already"; then
            echo "[Analysis Engine] ADB connection established to ${ADB_HOST}:${ADB_PORT}"
            _connected=1
            break
        fi
        echo "[Analysis Engine] ADB target ${ADB_HOST}:${ADB_PORT} not ready (attempt $i/10)."
        # Do not sleep after the last attempt — no emulator is a normal operating
        # mode for static-only analysis; the extra delay just makes cold-start noisy.
        if [ "$i" -lt 10 ]; then
            sleep 3
        fi
    done
    # Only print when all retries were exhausted — not on a successful connect.
    if [ "$_connected" -eq 0 ]; then
        echo "[Analysis Engine] No emulator reachable at ${ADB_HOST}:${ADB_PORT} — static analysis only."
    fi
) &

# Launch FastAPI Uvicorn Server on 0.0.0.0:8001
echo "[Analysis Engine] Launching FastAPI worker pool on port 8001..."
# --workers 1 is REQUIRED until the JOBS store is externalised: JOBS is an
# in-process dict, so with >1 worker a job created in one process returns 404
# from the other on /api/v1/status/{job_id}.
exec uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 1
