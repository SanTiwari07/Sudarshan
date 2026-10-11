# SUDARSHAN — Unified Evidence Model

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/models/evidence.py`  

---

## 1. Schema & Categorization

Every observation across static and dynamic analysis is normalized into a unified `EvidenceEvent` record:
- `timestamp`: UTC ISO 8601 timestamp.
- `category`: `accessibility`, `sms`, `overlay`, `code_execution`, `banking`, `network`, `persistence`, `anti_analysis`.
- `source`: `static_axml`, `static_dex`, `frida_hook`, `network_proxy`, `vide`.
- `severity`: `informational`, `low`, `medium`, `high`, `critical`.
- `details`: Arbitrary structured dictionary containing API parameters, target package names, or matched strings.

---

## Identity, de-duplication and provenance (EvidenceStore)

- **`evidence_key`** — a 32-hex content fingerprint (`runtime_event.event_fingerprint`). Host-added fields (`event_type` rewrites, `evidence_record_id`) are excluded, so the raw event in `collected_events` and its event-bus copy share a key, and the same key appears in `bfci_explanation` evidence references.
- **De-duplication** — a second delivery of the same observation is not stored again; the event is pointed at the existing record (`metrics()["duplicates"]`). Distinct native events that share an agent `event_id` (`native_ev_<ms>`) are kept apart by their content.
- **`provenance`** — `source` (`frida_java`, `frida_native`, `harness`, `network_capture`, `threat_correlator`, `screenshot_manager`), `analysis_kind: "dynamic"` (static findings never enter this store), `source_event_id`, `source_package`, `case_id`, `analysis_stage` (the multi-stage stage name), and `synthetic`.
- **Synthetic events** — events marked `synthetic` are refused unless the store is constructed with `allow_synthetic=True` (tests only), and the refusal is counted.
- **EVID numbering** — allocated only when a record is stored, so a malformed event no longer leaves a gap in the `EVID-NNN` sequence.
