# SUDARSHAN — Runtime Telemetry & Resilience API

> **Classification:** AUTHORITATIVE  
> **Prefix:** `/api` & `/api/v1/sandbox`  

---

## Endpoints

- `GET /api/runtime/status`: Real-time status of Frida bridge and event flusher.
- `GET /api/runtime/events`: Live streaming event feed.
- `GET /api/runtime/metrics`: Telemetry counter metrics.
- `POST /api/v1/sandbox/time-warp`: Advance guest Android clock to bypass timer evasions.
- `POST /api/v1/sandbox/seed-persona`: Populate dummy contacts, SMS, and accounts into guest.
- `POST /api/v1/sandbox/autonomous-anti-evasion`: Run full automated evasion countermeasure sequence.
- `GET /api/v1/sandbox/suggestions`: Retrieve unreached trigger conditions and dynamic hints.
