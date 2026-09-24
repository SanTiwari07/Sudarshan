# SUDARSHAN Test Audit Report

## Overview
This document contains a comprehensive audit of all test locations across the SUDARSHAN repository. Tests have been classified according to their purpose and status. Broken tests have been identified and analyzed.

## Test Location Classifications

| Location | Classification | Description |
|----------|----------------|-------------|
| `tests/unit/` | **CURRENT_REQUIRED** | Core logic unit tests for the Python engine. Includes 97 active test files. |
| `tests/integration/` | **REGRESSION** | End-to-end and pipeline regression tests. |
| `backend/tests/` | **CURRENT_REQUIRED** | Unit and API tests specific to the backend server (72 active test files). |
| `frontend/src/**/*.test.ts(x)` | **CURRENT_REQUIRED** | React UI and frontend utility tests run via Vitest. |
| `VIDE/baseline-library/*/app/.../test` | **ENVIRONMENT_DEPENDENT** | Android native tests (JUnit/Espresso) required for verifying baseline APKs. |
| `analysis-engine/` (tests) | **OBSOLETE** | Original test files (`test_frida*.py`) were deleted, though `__pycache__` artifacts remain. |
| `tests/dynamic/` | **TEMPORARY / OBSOLETE** | Directory exists but is empty. |
| `tests/sandbox/` | **TEMPORARY / OBSOLETE** | Directory exists but is empty. |
| `tests/security/` | **TEMPORARY / OBSOLETE** | Directory exists but is empty. |
| `tests/regression/` | **TEMPORARY / OBSOLETE** | Directory exists but is empty (regression tests are in `tests/integration/`). |
| `tests/vide/` | **TEMPORARY / OBSOLETE** | Directory exists but is empty. |
| `scripts/test_*.py` | **EXPERIMENTAL / DEBUG** | Standalone scratch scripts used for manual testing and debugging. |

## Broken Tests Analysis

During the audit, the following tests were found to be failing. Below is the analysis of why they fail.

### Python Backend Tests
1. **`tests/unit/test_code_execution_axis.py`**
   - **Failing Tests:** `test_execution_hooks_are_scored[FileOutputStream.apkWrite]`, `test_the_compiled_bundle_carries_the_split`
   - **Reason:** `AssertionError: 'FileOutputStream.apkWrite' does not appear in the agent at all`. 
   - **Details:** The tests assert that the Frida instrumentation scripts (`banking_trojan.js` and `banking_trojan.bundle.js`) contain the hook `"FileOutputStream.apkWrite"`. The hook is missing from these JS files, causing the assertion to fail.

### Frontend Tests (Vitest)
1. **`frontend/src/lib/caseQuestions.test.ts`**
   - **Failing Test:** `buildCaseQuestions - always present > groups every question into decide / evidence / act`
   - **Reason:** `AssertionError: expected [ 'decision', 'evidence', 'action' ] to include 'impact'`.
   - **Details:** The test assumes that the `buildCaseQuestions` function will output questions of kind `decision`, `evidence`, or `action`, but one of the questions is incorrectly typed or categorized as `impact`.

2. **`frontend/src/components/investigation/VerdictBlock.test.tsx`**
   - **Failing Test:** `VerdictBlock identity strip > shows the facts it does have`
   - **Reason:** `TestingLibraryElementError: Unable to find an element with the text: 3 · 1 dangerous.`
   - **Details:** The testing library could not locate the exact text string in the rendered output. This is typically due to a change in the UI component's text formatting or because the text is broken across multiple DOM elements.

3. **`frontend/src/test/AuthFlowMatrix.test.tsx`**
   - **Failing Tests:** Multiple routing and flow tests.
   - **Reason:** `Error: Element type is invalid: expected a string (for built-in components) or a class/function (for composite components) but got: undefined.`
   - **Details:** A React component is imported incorrectly (e.g., using a default import instead of a named import, or vice versa), causing the test renderer to receive `undefined` instead of a valid React component.

## Recommendations

### Convert Scratch Scripts to Regression Tests
The `scripts/` directory contains numerous standalone `test_*.py` files that are currently functioning as debug or experimental scratchpads. These scripts contain valuable end-to-end execution paths and API usage examples that are highly beneficial for preventing regressions.

**Recommended Action:**
The following files should be formalized, parameterized, and moved to `tests/integration/` or `tests/regression/`:
- `test_api_vide.py`
- `test_bridge_spawn.py`
- `test_frida_stages.py`
- `test_gemini_api_fallback.py`
- `test_mobsf_api.py`
- `test_schedule_main.py`
- `test_phase6_e2e.py`
- `test_webview_trigger.py`
- `test_vide_corpus.py` (and related `test_vide_matrix.py`)
- *...and other relevant integration scripts in the `scripts/` folder.*

They should be updated to use standard `pytest` assert patterns rather than raw `print()` statements, and any hardcoded environment dependencies (like specific emulator IDs) should be mocked or dynamically resolved.
