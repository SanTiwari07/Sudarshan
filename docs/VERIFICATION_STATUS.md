# Verification status

Findings from the **2026-08-14** audit that were proven by running code rather than by reading it, with each one re-checked against the active codebase on **2026-08-27**.

A finding here was reproduced at least once. "Still present" means the code path that produced it is unchanged; "resolved" means the code now behaves differently and the reproduction no longer applies.

Maintained views: [BUGS_AND_IMPROVEMENTS.md](BUGS_AND_IMPROVEMENTS.md) · [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)

---

| Finding | Verification method | 2026-08-14 | 2026-08-27 | Notes |
| :--- | :--- | :--- | :--- | :--- |
| SSRF TOCTOU via DNS rebinding | Mocked `socket.getaddrinfo` to return a safe IP, then a private one | Reproduced | **Still present** | `SSRFSafeAsyncClient.send` calls `resolve_and_check_url(str(request.url))` and then `super().send(request)` with the hostname intact, so httpx re-resolves at connect time |
| Analysis engine concurrency | Monkeypatched the heavy stages and observed queueing | Reproduced | **Still current, working as designed** | `asyncio.Semaphore(MAX_CONCURRENT_ANALYSES)` plus a per-device lock queue execution without crashing |
| Threat correlator does not cache 404s | Submitted hashes unknown to VirusTotal | Reproduced | **Still present** | `_cache_store` writes only when a lookup returned a payload |
| OTX hash lookups bypass the cache | Compared call counts across runs | Reproduced | **Still present** | `_otx_check_hash` calls neither `_cached_lookup` nor `_cache_store`, unlike every other lookup in that module |
| AbuseIPDB re-correlation loop | Configured a key with zero IPs in the case | Reproduced | **Still present** | `sources_queried.append("AbuseIPDB")` sits inside the per-IP loop, so a key with no IPs never marks the source as queried and `should_recorrelate_threat_intel` stays true |
| Explorer crash fallback `AttributeError` | Simulated three consecutive crashes | Reproduced | **Resolved** | `self.main_activity` is initialised in `AgenticExplorer.__init__`; crash recovery no longer raises |
| Frida launch ladder fallback | Forced failures on the first rungs | Reproduced | **Still current, working as designed** | The ladder proceeds to the explicit `am start` rung; the successful rung is recorded as `launch_method_used` |
| PDF generator `TypeError` | Passed a `ReportData` whose `banking_impact` was a string | Reproduced | **Resolved** | `pdf_generator.py` now carries `banking_impact_score: FieldValue[float]` separately from the narrative `banking_impact: FieldValue[str]`, and the FRS bar meter reads the numeric field |
| Prompt-injection sanitizer | 25 adversarial payloads through the sanitizer | Held | **Still holds** | `engines/agentic/sanitizer.py` remains the single choke point; covered by `backend/tests/test_prompt_injection.py` |
| Screenshot ID collision and remote-path overwrite | Concurrent screenshot pulls | Reproduced | **Partially resolved** | Each capture now carries a `scr_uuid`, but `self._counter -= 1` still runs on duplicate suppression and the remote path is still `sudarshan_screen_<timestamp_ms>.png` with no unique suffix |
| Auth bypass under development environment | Ran validation with `SUDARSHAN_ENV=development` | Reproduced | **Still present, by design** | The analysis engine's internal-auth middleware passes unauthenticated requests through when the token is unset and the environment is not `production`; in production it returns 503 instead. The compensating control is that the service is never published |

---

## What this list is not

It is not a coverage claim. It records findings that were reproduced by hand with throwaway scripts, which is a different thing from the automated suite (**2,622 tests collected**, 2026-08-27). Nothing here runs on a schedule, and this repository has no CI to run it.

Items marked "still present" are open. They are carried into [BUGS_AND_IMPROVEMENTS.md](BUGS_AND_IMPROVEMENTS.md) with severity and remediation.
