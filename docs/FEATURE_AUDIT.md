# SUDARSHAN — FEATURE CODE AUDIT & CONTRADICTIONS

This document logs verified discrepancies between the stated architectural intent (documentation/instructions) and the actual source code implemented in the repository.

## 1. Test Suite Discrepancy
*   **Stated Intent**: The system has 730 automated tests (583 integration + 202 unit tests = 785 expected total).
*   **Actual Code**: An AST analysis of `tests/` and `backend/tests/` yields exactly **725** test cases across 90 test files. Furthermore, active CI/CD configurations reveal that only **202** tests are actually executed during the pipeline.
*   **Conclusion**: There is configuration drift where ~523 tests are being skipped or disabled during CI/CD.

## 2. Threat Intelligence Caching Flaw
*   **Stated Intent**: Threat Intel requests (VirusTotal, OTX) are cached with a 24-hour TTL to prevent quota burn.
*   **Actual Code**: The caching logic successfully caches positive "Hits," but explicitly drops or ignores "404 Not Found" (benign/unknown) responses. 
*   **Conclusion**: Submitting benign or completely novel APKs repeatedly will trigger API quota burn because the engine does not cache the "known safe" state.

## 3. YARA Scanner is a "Silent No-Op"
*   **Stated Intent**: A YARA scanner runs alongside the static analysis engine to classify malware families.
*   **Actual Code**: While the YARA execution logic exists in Python, there are exactly **zero** `.yar` rule files deployed in the repository or Docker containers. 
*   **Conclusion**: The YARA engine silently returns empty results on every scan.

## 4. Database ORM Discrepancy
*   **Stated Intent**: General platform documentation implies the use of a standard ORM (like SQLAlchemy) for persistence.
*   **Actual Code**: The backend utilizes direct, asynchronous SQL execution via `aiosqlite` connected to a local `sudarshan.db` configured in WAL (Write-Ahead Logging) mode.
*   **Conclusion**: There is no SQLAlchemy ORM. Queries are executed directly against the async connection pool.

## 5. Security Architecture Fail-Open
*   **Stated Intent**: Internal microservices are locked down.
*   **Actual Code**: The `internal_auth_middleware` has a fail-open state for development environments but enforces fail-closed in production. However, it relies entirely on environment variable validation (`PROD=true`), which can easily be misconfigured.

## 6. Undocumented API Surface
*   **Stated Intent**: A known core set of APIs powers the platform.
*   **Actual Code**: The API router registers **51** distinct endpoints, including 18 completely undocumented endpoints primarily utilized for internal state inspection, raw artifact retrieval, and sandbox checkpointing.

## 7. VIDE Signer Registry is Demo Only
*   **Stated Intent**: VIDE cross-references certificates against `bank_signer_registry.json`.
*   **Actual Code**: The registry only contains 3 sample banks. It is missing the production corpus necessary to accurately identify the majority of Indian banking applications.

---
*Audit completed 2026-08-15 by Antigravity AI.*
