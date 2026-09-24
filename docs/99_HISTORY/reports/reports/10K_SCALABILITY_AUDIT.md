# SUDARSHAN - 10,000 USER SCALABILITY AUDIT

This document provides a comprehensive scalability audit of the SUDARSHAN architecture against the design targets of 10,000 registered users, 1,000 concurrent connected users, 100 concurrent API requests, and significant batch analysis workloads.

The current architecture relies heavily on single-node assumptions, local state, and unbound queue growth which prevents safe horizontal scaling.

## 1. Stateless + Horizontally Scalable
* **FastAPI Request Handlers:** The FastAPI routes (excluding the local queues) are fundamentally stateless and can scale horizontally behind a load balancer.
* **React/Vite Frontend:** The compiled static assets can be deployed to a CDN or static hosting for infinite, low-cost scaling.
* **Stateless Triage (Level 1 Analysis):** Simple ZIP validation, SHA-256 calculation, and basic manifest extraction could scale horizontally if detached from the expensive analysis stages.

## 2. Stateful + Requires Redesign
* **Database (`backend/app/db/database.py`):** Relies on `aiosqlite`. Hardcoded to use local `sudarshan.db`. Will cause file lock contention and does not scale across instances. Must be abstracted and migrated to PostgreSQL.
* **Analysis Job Queues (`backend/app/workers/analysis_queue.py` & `analysis-engine/app/main.py`):** Uses an in-memory `asyncio.Queue` and local dictionaries (`_jobs`, `JOBS`). Job records are lost if the container crashes or restarts. Must be replaced with a durable distributed queue (e.g., Cloud Tasks or Pub/Sub).
* **Uploads Directory (`UPLOADS_DIR`):** Relies on a shared filesystem volume (`/app/uploads`). Does not scale across distributed instances. Must be migrated to Google Cloud Storage (GCS).
* **RAG / AI Investigation (`app/ai/gemini_rag.py`):** The vector indices/embeddings appear to be held locally or built synchronously. Must be persisted or handled via a durable cache to prevent repeated rebuilds.
* **Runtime Event Bus (`backend/app/routes/runtime_api.py`):** Uses a local ring buffer. Must separate live in-memory telemetry from durable persistent evidence.

## 3. CPU-Bound
* **Androguard:** Heavy DEX parsing. Currently mitigated by running in a separate process, but still consumes significant CPU time.
* **APKTool & JADX (`analysis-engine/app/main.py`):** Very heavy on CPU. Needs to be conditionally executed based on the required depth of analysis.
* **MobSF (`mobsf` container):** Expensive to run. Must be limited by `MOBSF_MAX_CONCURRENCY` to prevent CPU exhaustion on the worker nodes.
* **Report Generation:** Constructing large PDFs synchronously in the API limits throughput.

## 4. Memory-Bound
* **Androguard DEX Parsing:** Can consume 2-3 GB of RAM per analysis. The container is capped at 4 GB. Multiple concurrent requests will trigger OOM kills.
* **JADX & APKTool:** Significant memory footprint during decompilation.
* **In-Memory Jobs (`JOBS` dict):** Previously unbounded growth holding massive results. Currently bounded by TTL, but still risky under high load.
* **Batch Scans (`backend/app/workers/batch_worker.py`):** Large batch uploads can overwhelm memory. Needs chunking or durable queueing.

## 5. I/O-Bound
* **SQLite:** High concurrent write volume (telemetry, job updates, case saves) will cause WAL locking and timeouts.
* **Shared Volume (`/app/uploads`):** File I/O bottleneck across multiple workers reading and writing APKs and artifacts simultaneously.
* **Network Requests:** Calls to MobSF, Gemini, and Threat Intel APIs block execution flow, necessitating full async handling.

## 6. GPU/Device-Bound
* **Android Sandbox (`frida_sandbox.py`):** Heavily bound by emulator resources (Genymotion/AVD).
* **Concurrency:** The sandbox uses an internal lock, effectively serializing analyses if only one device is available. Scaling this requires a dedicated, autoscaling sandbox pool separate from static analysis workers.

## 7. External-API-Rate-Limited
* **Threat Intel (VirusTotal, OTX, AbuseIPDB):** Strictly rate-limited. Must use robust negative and positive caching.
* **Gemini 2.5 Flash:** Rate-limited and cost-incurring. AI invocation should be deduplicated and constrained by budget controls. RAG contexts should be compact.

## 8. Single-Instance Bottleneck
* **Database Writer:** SQLite limits write concurrency to a single thread/process.
* **In-Memory Job Manager:** Only one API gateway instance can hold the truth of a job's status.
* **Sandbox Mutex:** A single physical lock over the local ADB device array.

## 9. Cost-Sensitive
* **Android Emulator VMs:** Highly expensive compute. Must support scale-to-zero when idle and controlled scale-up.
* **Gemini API:** Unnecessary repeated narrative generation wastes budget. Requires strict caching and timeout/fallback logic.
* **External Threat Intel:** Repeated queries for known hashes wastes API quotas.
* **Storage:** Endless retention of intermediate artifacts (APK, decompiled source) costs money. Requires TTL lifecycle policies.

## 10. Security-Sensitive
* **API Keys & Secrets:** Must not be stored in environment variables within the source tree. Must be migrated to Google Secret Manager.
* **Sandbox Network Isolation:** Dynamic malware execution must remain fail-closed. Public exposure of ADB or Frida is strictly forbidden.
* **Deterministic Risk Engine:** Must remain the final authority on risk scoring, isolated from LLM hallucinations.
* **Internal Microservice Auth (`ANALYSIS_ENGINE_INTERNAL_TOKEN`):** Must enforce authentication in production to prevent unauthenticated analysis invocation.
