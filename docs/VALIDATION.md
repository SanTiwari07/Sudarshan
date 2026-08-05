# Validation Protocols & Ground Truth Mapping

## Purpose

This document specifies the validation protocols, ground-truth verification rules, and regression assertion standards governing the **SUDARSHAN** platform. It provides security researchers, quality assurance engineers, and auditors with the exact mathematical and operational criteria required to validate that analysis pipeline outputs remain accurate, reproducible, and uncorrupted.

---

## Responsibilities

This document is responsible for:
1. **Pipeline Ground-Truth Mapping**: Establishing the validation standards used to classify analysis findings into verified True Positives (TP), True Negatives (TN), False Positives (FP), and False Negatives (FN).
2. **Determinism Baseline Invariant**: Enforcing the strict mathematical assertion that identical input APK binaries produce 100% identical $STEI$, $BFCI$, $FRS$, and severity band outputs.
3. **Validation Test Suite Protocol**: Documenting the execution of the **457 test cases** in `tests/` and `backend/tests/`.
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
Verification   (TP/TN Audits) (421 Tests Total)
```

1. **Determinism Verification**: Replays pinned baseline feature vectors against [`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py) to assert that zero score drift occurs across codebase updates.
2. **Ground-Truth Matrix**: Verifies that known malicious banking trojans (*Drinik*, *Xenomorph*) trigger `CRITICAL` ($FRS \ge 85.0$) verdicts, while benign and low-risk applications yield `LOW` or `SAFE` scores.
3. **Prompt Injection Resilience**: Asserts that malicious prompt injection payloads embedded in APK metadata fail to alter LLM behavior or override risk scoring ([`test_prompt_injection.py`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/test_prompt_injection.py)).

---

## Ground-Truth Verification Matrix

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

To run the full suite (**457 tests collected & verified**):
```powershell
$env:PYTHONPATH="backend;shared"; $env:JWT_SECRET_KEY="test_secret_key_for_pytest"; backend\.venv\Scripts\python.exe -m pytest tests/ backend/tests
```

---

## Current Implementation Status

Validation protocols are **Implemented** and enforced across automated tests in [`tests/`](file:///d:/Projects/Sudarshan%20BOI/tests/) and [`backend/tests/`](file:///d:/Projects/Sudarshan%20BOI/backend/tests/).
