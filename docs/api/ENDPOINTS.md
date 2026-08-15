# SUDARSHAN - API Endpoints Documentation

> All endpoints verified against source 2026-08-15 by grepping `@router.(get|post|patch)` in `backend/app/routes/*.py` and `backend/app/auth/auth.py`.
> Runtime telemetry endpoints share prefix `/api` (not `/api/v1`) as registered in `backend/app/main.py:96`.
> All other endpoints use prefix `/api/v1`.

## Authentication (`/api/v1` — `auth.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/register` | POST | Register a new user account |
| `/api/v1/login` | POST | Authenticate and receive JWT Bearer token |
| `/api/v1/me` | GET | Return current authenticated user info |
| `/api/v1/users/{user_id}/role` | PATCH | Update a user's role (admin only) |

## Analysis (`/api/v1` — `upload.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/analyze` | POST | Upload APK for synchronous analysis |
| `/api/v1/analyze/async` | POST | Upload APK for asynchronous (queued) analysis; returns `job_id` |
| `/api/v1/status/{job_id}` | GET | Poll async job status |
| `/api/v1/sandbox/status` | GET | Check dynamic sandbox availability |
| `/api/v1/sandbox/debug/{case_id}` | GET | Return sandbox debug info for a specific case |

## Case History (`/api/v1` — `cases.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/cases` | GET | List all historical analysis cases |
| `/api/v1/cases/{sha256}` | GET | Retrieve full analysis results for a case |
| `/api/v1/cases/{sha256}/evidence` | GET | Retrieve runtime evidence records for a case |
| `/api/v1/cases/{sha256}/notes` | GET | Retrieve analyst notes for a case |
| `/api/v1/cases/{sha256}/notes` | POST | Save analyst notes for a case |

## Threat Intelligence (`/api/v1` — `intelligence.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/intelligence/{sha256}` | GET | Retrieve correlated threat intelligence for a case |

## Reports & Export (`/api/v1` — `report.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/report/html/{sha256}` | GET | Serve standalone HTML security report |
| `/api/v1/report/pdf/{sha256}` | GET | Serve ReportLab PDF threat investigation report |
| `/api/v1/report/stix/{sha256}` | GET | Export IOCs as STIX 2.1 JSON bundle |
| `/api/v1/report/iocs/{sha256}` | GET | Export high-confidence IOCs as CSV |
| `/api/v1/report/iocs-txt/{sha256}` | GET | Export IOCs as plain text |
| `/api/v1/report/yara/{sha256}` | GET | YARA export endpoint (NOT IMPLEMENTED — no `.yar` files deployed; returns empty) |
| `/api/v1/report/mitre/{sha256}` | GET | Export MITRE ATT&CK technique mapping |
| `/api/v1/report/technical-pdf/{sha256}` | GET | Serve technical-grade HTML report |
| `/api/v1/chat/stream` | POST | SSE streaming chat with RAG-grounded Gemini |
| `/api/v1/chat` | POST | Non-streaming chat with RAG-grounded Gemini |

## Screenshots (`/api/v1` — `screenshots.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/screenshots/{sha256}/manifest` | GET | Retrieve screenshot timeline manifest for a case |
| `/api/v1/screenshots/{sha256}/{filename}` | GET | Serve authenticated screenshot image file |

## VIDE Baselines (`/api/v1` — `baselines.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/baselines` | GET | List available VIDE institution baselines (LAB/DEMO only) |
| `/api/v1/baselines/{institution_id}` | GET | Retrieve a specific VIDE baseline |
| `/api/v1/baselines/refresh` | POST | Trigger baseline corpus reload |

## APK Discovery (`/api/v1` — `discovery.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/discovery/start` | POST | Start APK URL discovery session |
| `/api/v1/discovery/{session_id}/status` | GET | Poll discovery session status |
| `/api/v1/discovery/{session_id}/results` | GET | Retrieve discovered APK candidates |
| `/api/v1/discovery/{session_id}/analyze` | POST | Enqueue a discovered candidate for analysis |

## Investigation Resilience (`/api/v1` — `resilience.py`)
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/resilience/personas` | GET | List available analysis personas |
| `/api/v1/resilience/{session_id}/assertions` | POST | Submit investigation assertions |
| `/api/v1/resilience/{session_id}/suggestions` | GET | Get investigation suggestions |
| `/api/v1/resilience/{session_id}/suggestions` | POST | Submit suggestions |
| `/api/v1/resilience/{session_id}/time-warp` | POST | Apply time-warp scenario |
| `/api/v1/resilience/{session_id}/seed-persona` | POST | Seed analysis persona |
| `/api/v1/resilience/{session_id}/checkpoint` | GET | Get analysis checkpoint |
| `/api/v1/resilience/{session_id}/checkpoint/restore` | POST | Restore from checkpoint |
| `/api/v1/resilience/{session_id}/events` | GET | List session events |

## Runtime Telemetry (`/api` — `runtime_api.py`)
> Note: These endpoints use prefix `/api` (not `/api/v1`) — registered at `backend/app/main.py:96`.

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/runtime/health` | GET | Runtime API health check |
| `/api/runtime/status` | GET | High-level pipeline health summary and active `PipelineTracker` states |
| `/api/runtime/hooks` | GET | Frida hook install status, hit counters, and error rates per hook |
| `/api/runtime/events` | GET | Ring buffer of recent telemetry events (max 500 events) |
| `/api/runtime/pipeline` | GET | State machine transitions (`INIT`, `DECOMPILING`, `SANDBOXING`, `CORRELATING`, `SCORING`, `RAG_INDEXING`, `COMPLETED`) |
| `/api/runtime/metrics` | GET | Rolling event processing rate (events/sec), dropped events, error totals |
| `/api/runtime/evidence` | GET | Snapshots of `evidence.json` from dynamic analysis runs |
| `/api/runtime/diagnostics` | GET | Combined diagnostics (memory, queue, frida bridge, IOC cache) |

## Root & Health
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/` | GET | Platform status, version, and engine inventory |
| `/health` | GET | Basic health check (`{"status": "ok"}`) |
| `/docs` | GET | Swagger UI interactive API documentation |
