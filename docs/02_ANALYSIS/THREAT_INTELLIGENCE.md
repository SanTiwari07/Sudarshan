# SUDARSHAN — Threat Intelligence & Reputation Correlation

> **Classification:** AUTHORITATIVE  
> **Source Modules:** `shared/sudarshan_core/services/threat_correlator.py`  
> **Last Verified:** 2026-09-25  

---

## 1. Multi-Feed Threat Correlation

SUDARSHAN aggregates external threat intelligence to corroborate on-device forensic evidence:

1. **VirusTotal (v3 API):** Queries file SHA-256 hashes for multi-engine antivirus detection ratios. Strictly enforced 4 requests/minute client-side rate limiting.
2. **AlienVault OTX:** Pulls threat pulses, associated malware family tags, and campaign identifiers.
3. **AbuseIPDB:** Evaluates IP reputation for discovered C2 infrastructure, extracting confidence-of-abuse percentages.

---

## 2. 24-Hour Persistence Caching

External API lookups are costly and subject to rate limits. SUDARSHAN caches all reputation queries inside the local relational database (`threat_intelligence_cache` table) with a **24-hour Time-to-Live (TTL)**. Duplicate uploads of the same hash or inquiries against identical C2 domains resolve in sub-millisecond time without consuming API quota.
