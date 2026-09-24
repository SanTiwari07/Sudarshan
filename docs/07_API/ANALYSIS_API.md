# SUDARSHAN — Analysis API

> **Classification:** AUTHORITATIVE  
> **Prefix:** `/api/v1`  

---

## Endpoints

### 1. Synchronous Analysis: `POST /api/v1/analyze`
- **Auth:** Bearer token (`require_analyst`)
- **Body:** `multipart/form-data`, file field `file`
- **Limits:** 10 requests / minute, 200 MB max size
- **Response:** Complete JSON investigation payload including static indicators, dynamic Frida telemetry, VIDE visual clone score, threat correlation, and deterministic FRS score.

### 2. Asynchronous Queued Analysis: `POST /api/v1/analyze/async`
- **Auth:** Bearer token (`require_analyst`)
- **Body:** `multipart/form-data`, file field `file`
- **Response:** `202 Accepted` with `job_id`, `sha256`, `status: queued`.

### 3. Job Status Polling: `GET /api/v1/status/{job_id}`
- **Response:** `JobStatusResponse` containing `status`, `stage`, `progress_percent`, and full results upon completion.

### 4. Job Cancellation: `POST /api/v1/analyze/cancel/{job_id}`
- **Response:** `{"cancelled": true, "job_id": "..."}`
