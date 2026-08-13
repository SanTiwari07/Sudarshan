# SUDARSHAN - API Endpoints Documentation

## Core Analysis Endpoints
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/analyze` | POST | Upload APK for analysis |
| `/api/v1/cases/{sha256}` | GET | Retrieve full analysis results |

## 18 Newly Documented Telemetry & Export Endpoints
The following endpoints were discovered during the August 2026 Audit and provide critical diagnostic, streaming, and export functionality.

### Runtime Telemetry & Streaming
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/runtime/status` | GET | Returns high-level pipeline health summary and active `PipelineTracker` states across analysis jobs. |
| `/api/runtime/hooks` | GET | Tracks Frida hook installation status, hit counters, and runtime error rates per hook. |
| `/api/runtime/events` | GET | Exposes a ring buffer of recent telemetry events (max 500 events) for real-time analyst streaming. |
| `/api/runtime/pipeline` | GET | Reports state machine transitions across `INIT`, `DECOMPILING`, `SANDBOXING`, `CORRELATING`, `SCORING`, `RAG_INDEXING`, and `COMPLETED`. |
| `/api/runtime/metrics` | GET | Calculates rolling event processing rate (events/sec), dropped event metrics, and error totals. |
| `/api/runtime/evidence` | GET | Provides snapshots of `evidence.json` generated during dynamic analysis runs. |

### Diagnostic Trackers
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/diagnostics/memory` | GET | Returns memory usage profiles for the `analysis-engine` containers. |
| `/api/diagnostics/cache` | GET | Inspects Hit/Miss/TTL ratios for Threat Correlator caches. |
| `/api/diagnostics/queue` | GET | Async task queue depth, starvation alerts, and worker availability. |
| `/api/diagnostics/frida` | GET | Details of connected Frida bridges, process IDs, and stability scores. |

### Discovery & Evidence
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/discovery/packages` | GET | Lists all unique package names intercepted across all historical cases. |
| `/api/discovery/families` | GET | Lists aggregated family classifications (e.g. Cerberus, Anubis). |
| `/api/evidence/screenshots`| GET | Retreive screenshot timeline metadata for a specific case. |
| `/api/evidence/network` | GET | Retrieve decrypted `mitmproxy` HAR dumps for a case. |

### Advanced Exports
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/export/{sha256}/stix` | GET | Export IOCs and C2 observables as a STIX 2.1 JSON bundle. |
| `/api/export/{sha256}/csv` | GET | Export high-confidence IOCs as a flattened CSV. |
| `/api/export/{sha256}/pdf` | GET | Export narrative audit as an executive PDF (Currently impacted by Type Bug). |
| `/api/export/{sha256}/html`| GET | Export narrative audit as an offline HTML package. |
