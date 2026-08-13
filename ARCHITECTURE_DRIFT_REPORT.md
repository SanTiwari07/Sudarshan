# SUDARSHAN - Architecture Drift Report (August 2026 Audit)

This document catalogs significant deviations between the legacy documentation and the actual runtime codebase of SUDARSHAN, as verified through static analysis and runtime proof-of-concept scripts.

## 1. Database & Persistence Layer
* **Documented**: Uses SQLAlchemy with synchronous blocking connections for data modeling.
* **Actual Runtime**: Fully relies on raw `aiosqlite` (async SQLite) with direct SQL queries. SQLAlchemy is completely absent from the runtime data layer, meaning performance is much higher but ORM features do not exist.
* **Severity**: High (Core Architectural Drift)

## 2. Static Analysis Engine Pipeline
* **Documented**: Employs "Sequential Triaged Gating" where tasks wait for earlier checks.
* **Actual Runtime**: Implements "Parallel Concurrent Execution", strongly bounded by a `asyncio.Semaphore(2)` and `_DEVICE_LOCK`. Tasks run independently up to the container limit.
* **Severity**: Medium

## 3. Dynamic Analysis & Agentic Explorer
* **Documented**: Uses a "random input fuzzer", "hybrid mode", and relies on an 11-stage explorer graph.
* **Actual Runtime**: Fuzzer and hybrid mode have been removed in favor of a 15-stage Agentic Explorer graph. Additionally, the sandbox launch leverages a highly robust 7-Step Launch Fallback Ladder.
* **Severity**: Medium

## 4. Threat Intelligence Resiliency
* **Documented**: Implements broad fallback to VirusTotal if primary services fail, caching OTX hashes.
* **Actual Runtime**: VirusTotal fallback logic has been stripped, and OTX Hash lookups bypass the cache entirely, resulting in heavy redundant API calls (a verified cache bug exists on 404s).
* **Severity**: High

## 5. Security Mitigations
* **Documented**: The `P0_SANDBOX_ESCAPE_INCIDENT` notes unmitigated container vulnerabilities.
* **Actual Runtime**: The runtime sandbox is heavily locked down (e.g., `docker-compose.hardened.yml`, seccomp profiles, loopback Frida bindings, blocked ADB `tcpip`), fully mitigating the historical Sandbox Escape and Prompt Injection vectors.
* **Severity**: Positive Drift (Security significantly improved beyond documentation).

## Conclusion
The active codebase is significantly more advanced, concurrent, and secure than the documentation describes, although caching and reporting bugs plague the integration layers. All future developments MUST reference the codebase as the ultimate source of truth, not legacy design documents.
