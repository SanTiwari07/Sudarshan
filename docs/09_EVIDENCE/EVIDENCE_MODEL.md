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
