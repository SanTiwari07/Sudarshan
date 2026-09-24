# Legacy Code Audit

## Overview
This audit identifies legacy, deprecated, or abandoned code components within the SUDARSHAN repository. No code has been deleted; this report serves as a record of components that are candidates for removal or cleanup.

---

## 1. Analysis History Shim (Deprecated Module)
- **PATH:** `shared/sudarshan_core/engines/analysis_history.py`
- **PURPOSE:** Legacy synchronous `sqlite3` database writer for analysis runs. It previously created a stray `analysis-engine/sudarshan.db` database and did not effectively record real analysis measurements.
- **CURRENT REFERENCES:** Dynamically imported by `shared/sudarshan_core/engines/frida_sandbox.py` (which catches `ImportError`). Also referenced in `docs/operations/DATABASE.md`.
- **RUNTIME USAGE:** Refactored into a no-op shim that writes nothing. Kept to avoid crashes in legacy callers.
- **TEST USAGE:** None observed.
- **REPLACEMENT:** Replaced by `backend/app/services/run_recorder.py` and `backend/app/db/intel.py` (which use the central gateway database).
- **GIT HISTORY:** Explicitly marked as deprecated in recent migrations. 
- **SAFE TO DELETE?:** **Yes.** It is safe to remove, though the dynamic import in `frida_sandbox.py` should be stripped simultaneously for cleanliness.

---

## 2. Frida Hook Bisect Variant (Abandoned Experiment)
- **PATH:** `shared/sudarshan_core/engines/frida_hooks/_bisect_variant.js`
- **PURPOSE:** A modified variant of the main Frida hook script (`banking_trojan.js`). It was created during a debugging/bisect experiment to isolate the cause of ANR stalls on API 34+ (related to ART boot image deoptimization and accessibility scans).
- **CURRENT REFERENCES:** None.
- **RUNTIME USAGE:** Not bundled or injected by the sandbox. The active bundle relies on `banking_trojan.js`.
- **TEST USAGE:** None.
- **REPLACEMENT:** The required fixes were already incorporated into the main `banking_trojan.js`.
- **GIT HISTORY:** Leftover from historical debugging efforts.
- **SAFE TO DELETE?:** **Yes.** 

---

## 3. Mock JEV Planner Test Script (Abandoned Prototype)
- **PATH:** `scripts/test_jev_mock_live.py`
- **PURPOSE:** A standalone test script used to run the `AgenticExplorer` against a live emulator using the mock JEV provider, designed to extract and print execution metrics without burning real API calls.
- **CURRENT REFERENCES:** None from the core framework.
- **RUNTIME USAGE:** Never invoked automatically; only used manually by developers.
- **TEST USAGE:** Standalone manual end-to-end experiment. Not integrated into the `pytest` test suite.
- **REPLACEMENT:** Proper unit tests in `backend/tests/test_jev_mock.py` test the mocking logic robustly.
- **GIT HISTORY:** Abandoned developer scratchpad / prototype test.
- **SAFE TO DELETE?:** **Yes.** It is an isolated script that is no longer part of the standard testing workflow.

---

## 4. Git Repo Migration Script (Migration Leftover)
- **PATH:** `scripts/migrate-to-new-github-repo.ps1`
- **PURPOSE:** PowerShell script created to clone the main branch, strip specific author metadata (Cursor co-author lines) using `git-filter-repo`, and push to a new clean GitHub repository.
- **CURRENT REFERENCES:** None.
- **RUNTIME USAGE:** None.
- **TEST USAGE:** None.
- **REPLACEMENT:** None.
- **GIT HISTORY:** One-off migration leftover.
- **SAFE TO DELETE?:** **Yes.** The repository migration has already been completed.

---

## Summary
The above modules and scripts are isolated, deprecated, or replaced. They do not affect the main runtime, testing suite, or core capabilities, making them completely safe for future deletion.
