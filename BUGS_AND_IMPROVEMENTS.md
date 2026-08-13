# SUDARSHAN - Bugs & Improvements Roadmap (August 2026 Audit)

This document outlines the critical bugs, broken flows, and architectural vulnerabilities identified and empirically verified during the comprehensive repository audit. 

## 1. Critical Blockers (P0/P1)

### 1.1 PDF Generator TypeError Crash (P0)
* **Location**: `shared/sudarshan_core/engines/pdf_generator.py`
* **Issue**: `banking_impact` is modeled as a string/narrative field, but the `FRSBarMeter` chart expects a float. Attempting to multiply a string by a float throws a `TypeError: can't multiply sequence by non-int of type 'float'`, resulting in a 500 error that fully crashes the PDF export flow.
* **Remediation**: Parse the `banking_impact` string back to a numeric float before passing it to `FRSBarMeter`, or update the `ReportData` structure to hold both a narrative string and a base numeric score.

### 1.2 SSRF DNS Rebinding (TOCTOU) (P1)
* **Location**: `SSRFSafeAsyncClient`
* **Issue**: Resolves the hostname during the pre-check phase (Time of Check) but re-resolves it when making the connection (Time of Use). Malicious DNS servers can return a safe public IP first, and a private internal IP (like `127.0.0.1`) on the second request, bypassing the SSRF protection completely.
* **Remediation**: Force the HTTPX client to connect directly to the verified IP address resolved during the initial check, rather than passing the hostname into the connection phase.

### 1.3 Threat Correlator Cache Bypass (P1)
* **Location**: `shared/sudarshan_core/services/threat_correlator.py`
* **Issue**: The cache logic does not store 404/Not Found results. If a file hash is unknown to VirusTotal, the system continues hitting the external network on every scan request, severely burning API quotas.
* **Remediation**: Implement Negative Caching to store 404 responses with a specific TTL so the system knows a hash was recently checked and not found.

### 1.4 AbuseIPDB Infinite Loop (P1)
* **Location**: `backend/app/services/case_intel_enrichment.py`
* **Issue**: If an AbuseIPDB check is initialized but no IPs are found, the state evaluates as incomplete, causing `should_recorrelate_threat_intel` to trigger in an infinite loop.
* **Remediation**: Add a specific state flag to represent "checked but empty" to prevent infinite re-correlation when no IPs exist.

## 2. Medium Severity / Structural Bugs (P2)

### 2.1 ScreenshotManager Race Condition & ID Collision
* **Location**: `ScreenshotManager` (Evidence Pipeline)
* **Issue**: When handling concurrent screenshot requests, the ID counter is decremented if a duplicate is found. This causes ID collisions (`SCR-003` assigned to two different images) and remote path overwrites (`/data/local/tmp/sudarshan_screen_1723555200123.png`).
* **Remediation**: Never decrement the counter. Append UUID suffixes to remote paths to prevent concurrent overwrites.

### 2.2 Explorer Crash Fallback Missing Attribute
* **Location**: `AgenticExplorer` 
* **Issue**: During crash recovery (after 3 consecutive crashes), a missing `self.main_activity` initialization causes an `AttributeError`, bypassing the intended fallback logic (e.g., `press_home`).
* **Remediation**: Initialize `self.main_activity = None` in the constructor.

### 2.3 IDOR in Telemetry & Undocumented Endpoints
* **Location**: `backend/app/routes/`
* **Issue**: 18 endpoints are completely missing from the `ENDPOINTS.md` documentation, and telemetry components exhibit minor Insecure Direct Object Reference (IDOR) behavior where analysts can query other analysts' states.
* **Remediation**: Update `ENDPOINTS.md` and wrap telemetry requests in tenant/analyst ownership checks.

## 3. Recommended Improvements

* **Centralize Dependency Verification**: `validate_backend_production_config` bypasses security checks cleanly in Dev, which is good, but unifying environment config files could streamline this.
* **Documentation Sync CI/CD**: Implement a hook that checks `P0_SANDBOX_ESCAPE_INCIDENT.md` or architectural specs whenever core logic (like `aiosqlite`) changes to prevent drift.
* **Frontend Visualization**: Ensure that the "Base Risk Score" calculated by the engine actually surfaces in the UI.
