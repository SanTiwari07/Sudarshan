# SUDARSHAN — Batch Scanning API

> **Classification:** AUTHORITATIVE  
> **Prefix:** `/api/v1/batches`  

---

## Endpoints

- `POST /api/v1/batches`: Submit batch of 2–50 APK files.
- `GET /api/v1/batches`: List all batches submitted by analyst or tenant.
- `GET /api/v1/batches/{id}`: Detailed batch status with per-file progress metrics.
- `POST /api/v1/batches/{id}/pause`: Pause queued jobs in batch.
- `POST /api/v1/batches/{id}/resume`: Resume paused batch processing.
- `POST /api/v1/batches/{id}/cancel`: Abort remaining queued analyses.
- `POST /api/v1/batches/{id}/retry`: Retry failed jobs in batch.
