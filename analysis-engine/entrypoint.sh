#!/bin/bash
set -e

echo "[Analysis Engine] Initializing container runtime..."

# Verify Java, APKTool, and JADX availability
echo "[Analysis Engine] Verifying toolchain..."
java -version 2>&1 | head -n 1
apktool --version 2>&1 | head -n 1
jadx --version 2>&1 | head -n 1

# ADB warm-up / connect - policy-validated via adb_gateway (not raw shell adb).
echo "[Analysis Engine] Starting background ADB bootstrap (validated)..."
(
    python -m app.adb_bootstrap || true
) &

# Launch FastAPI Uvicorn Server on 0.0.0.0:8001
echo "[Analysis Engine] Launching FastAPI worker pool on port 8001..."
# --workers 1 is REQUIRED until the JOBS store is externalised: JOBS is an
# in-process dict, so with >1 worker a job created in one process returns 404
# from the other on /api/v1/status/{job_id}.
exec uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 1
