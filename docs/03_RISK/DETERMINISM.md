# SUDARSHAN — Mathematical Determinism & Verifiable Verdicts

> **Classification:** AUTHORITATIVE  

---

## 1. Why Determinism is Mandatory

In financial fraud investigations, regulatory compliance and evidentiary standards demand that risk scores be mathematically defensible:
- An analyst in Mumbai and an auditor in London evaluating the same evidence bundle must arrive at the exact same numerical score.
- Machine learning models can drift; deterministic scoring algorithms provide auditable, reproducible guarantees.

---

## 2. Test Verification

The determinism of the Risk Engine is verified across automated regression suites:
- `backend/tests/test_risk_engine_determinism.py`
- `tests/unit/test_vide_determinism.py`
- Executing the scoring engine $10,000$ times on identical inputs yields zero variance ($\sigma^2 = 0$).
