# SUDARSHAN — Deterministic Risk Engine

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/engines/risk_engine.py`  
> **Last Verified:** 2026-09-25  

---

## 1. Engine Mission & Mathematical Determinism

The Deterministic Risk Engine is the final and absolute authority on risk assessment in SUDARSHAN.

**The Invariant:** Identical input vectors MUST produce mathematically identical Fraud Risk Scores (FRS) and Risk Bands. Generative AI models are strictly forbidden from modifying or overriding deterministic scores.

---

## 2. Master Composite Formula

The overall Fraud Risk Score (FRS) combines static, dynamic, reputation, and impact dimensions:

$$\text{FRS} = 0.25 \times \text{STEI} + 0.35 \times \text{BFCI} + 0.20 \times \text{Correlation} + 0.20 \times \text{BankingImpact}$$

All sub-indices are strictly normalized to a $0–100$ scale prior to weight application. The composite FRS is capped at $100.0$.

---

## 3. Four Safety Floors

Malware authors employ evasion techniques to suppress dynamic triggers. SUDARSHAN applies 4 deterministic safety floors that elevate the risk band even if the numerical score was depressed by evasion:

1. **Visibility Floor:** If dynamic execution failed to confirm foreground rendering, the verdict cannot be classified as `Safe`.
2. **Static Evidence Floor:** When critical static capabilities are confirmed (e.g. `BIND_ACCESSIBILITY_SERVICE` + `RECEIVE_SMS`), the sample is elevated to at least `Suspicious` / `Medium`.
3. **Evasion Floor:** Attributed anti-analysis and emulator fingerprinting routines guarantee non-safe classification.
4. **Execution Assertions Floor:** If critical dynamic goals were not reached, an assertion penalty halves reported confidence and marks the verdict as `INCOMPLETE_EXERCISE`.
