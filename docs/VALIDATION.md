# Validation Protocols & Ground Truth Mapping

## Purpose

This document specifies the validation protocols, ground-truth verification rules, and regression assertion standards governing the **SUDARSHAN** platform. It provides security researchers, quality assurance engineers, and auditors with the exact mathematical and operational criteria required to validate that analysis pipeline outputs remain accurate, reproducible, and uncorrupted.

---

## Responsibilities

This document is responsible for:
1. **Pipeline Ground-Truth Mapping**: Establishing the validation standards used to classify analysis findings into verified True Positives (TP), True Negatives (TN), False Positives (FP), and False Negatives (FN).
2. **Determinism Baseline Invariant**: Enforcing the strict mathematical assertion that identical input APK binaries produce 100% identical $STEI$, $BFCI$, $FRS$, and severity band outputs.
3. **Validation Test Suite Protocol**: Documenting the execution of the **519 test cases** in `tests/` and `backend/tests/`.
4. **Audit Rule Governance**: Enforcing the rule that no simulated or mock scores are permitted in production reports.

---

## High-Level Overview

Validation in Sudarshan is divided into three verification domains:

```text
[ Sudarshan Validation Framework ]
                 │
  ┌──────────────┼──────────────┐
  │              │              │
  ▼              ▼              ▼
[ Determinism ] [ Ground-Truth] [ Security ]
Score Replay   Sample Matrix  Prompt Sanitizer
Verification   (TP/TN Audits) (519 Tests Total)
```

1. **Determinism Verification**: Replays pinned baseline feature vectors against [`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py) to assert that zero score drift occurs across codebase updates.
2. **Ground-Truth Matrix**: Labelled trojan fixtures in `test_detection_regressions.py` and determinism baselines must remain stable; **risk bands** are `Safe` / `Suspicious` / `High Risk` / `Critical` per [`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py) (see [`architecture/08_DETERMINISTIC_RISK_ENGINE.md`](architecture/08_DETERMINISTIC_RISK_ENGINE.md)). Numeric score ranges in the table below are **historical targets** - re-measure after FRS renormalization changes.
3. **Prompt Injection Resilience**: Asserts that malicious prompt injection payloads embedded in APK metadata fail to alter LLM behavior or override risk scoring ([`test_prompt_injection.py`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/test_prompt_injection.py)).

---

## Ground-Truth Verification Matrix

> **Note:** Severity band names and score cutoffs are defined in code (`Safe` ≤30, `Suspicious` ≤60, `High Risk` ≤89, `Critical` ≥90). The FRS numeric ranges in this table are legacy documentation targets pending corpus re-baseline.

Validation criteria for ground-truth sample classification:

| Ground-Truth Class | Target Characteristics | Required FRS Score Range | Target Severity Band | Required Action |
| :--- | :--- | :--- | :--- | :--- |
| **True Positive (Banking Trojan)** | Accessibility abuse + SMS OTP read + Indian bank overlay strings | $85.0 - 100.0$ | **CRITICAL** | Immediate Account Quarantine |
| **True Positive (Generic Malware)**| Hardcoded C2 + DexClassLoader + Dangerous permissions | $60.0 - 84.9$ | **HIGH** | Fraud Team Quarantine |
| **True Negative (Benign App)** | Clean manifest + Standard permissions + No obfuscation | $0.0 - 19.9$ | **SAFE / LOW** | Standard Monitoring |
| **Vulnerable Test App** | Insecure storage / cleartext HTTP without active fraud code | $30.0 - 59.9$ | **MEDIUM** | Step-Up Authentication Alert |

---

## Determinism Replay Verification Protocol

To run pipeline validation locally:

```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest backend/tests/test_determinism_replay.py -v
```

Verification assertions enforced by [`test_determinism_replay.py`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/test_determinism_replay.py):
1. `calculated_stei == baseline.expected_stei`
2. `calculated_frs == baseline.expected_frs`
3. `calculated_band == baseline.expected_band`
4. `stei_axes.ct == baseline.expected_ct`

To run the full suite (**519 tests collected & verified**):
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

---

## Dynamic APK Corpus Validation (Live Sandbox)

For end-to-end dynamic validation against the APK corpus (requires a connected sandbox and Frida), use the root CLI and shared validation package:

| Artifact | Path |
| :--- | :--- |
| Entry CLI | [`validate_dynamic_pipeline.py`](file:///d:/Projects/Sudarshan%20BOI/validate_dynamic_pipeline.py) |
| Corpus manifest | [`tests/apks/corpus.manifest.json`](file:///d:/Projects/Sudarshan%20BOI/tests/apks/corpus.manifest.json) |
| Runner / reports | [`shared/sudarshan_core/validation/`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/validation/) |
| Corpus README | [`tests/apks/README.md`](file:///d:/Projects/Sudarshan%20BOI/tests/apks/README.md) |

```powershell
$env:PYTHONPATH = "backend;shared"
$env:JWT_SECRET_KEY = "validation"
python validate_dynamic_pipeline.py              # all corpus APKs
python validate_dynamic_pipeline.py --fetch      # download OSS samples first
python validate_dynamic_pipeline.py --stress 10,20 --recovery --force
```

Each run writes `preflight.txt`, per-APK JSON under `tests/apks/validation_runs/<UTC timestamp>/apk_runs/`, and optional `engineering_report.html` / `.json`. Preflight invokes [`scripts/verify_runtime_pipeline.py`](file:///d:/Projects/Sudarshan%20BOI/scripts/verify_runtime_pipeline.py).

---

## Current Implementation Status

Validation protocols are **Implemented** and enforced across automated tests in [`tests/`](file:///d:/Projects/Sudarshan%20BOI/tests/) and [`backend/tests/`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/).
