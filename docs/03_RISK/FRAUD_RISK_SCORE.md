# SUDARSHAN — Fraud Risk Score (FRS) & Risk Bands

> **Classification:** AUTHORITATIVE  
> **Formula:** `0.25 * STEI + 0.35 * Dynamic + 0.20 * Correlation + 0.20 * BankingImpact`  

---

## 1. Risk Bands & Operational Semantics

| Score Range | Risk Band | Color Code | Operational Meaning & Recommended Action |
| :--- | :--- | :--- | :--- |
| **0.0 – 19.9** | `Safe` | Green | Benign application. No banking fraud capabilities detected. |
| **20.0 – 39.9** | `Low` | Blue | Minor risk. Contains analytics or non-sensitive permissions. Routine monitoring. |
| **40.0 – 59.9** | `Medium` | Yellow | Suspicious capabilities detected (e.g. overlay without targeting). Quarantine for secondary review. |
| **60.0 – 79.9** | `High` | Orange | Severe threat. Confirmed credential harvesting or targeting. Block app and notify customers. |
| **80.0 – 100.0**| `Critical` | Red | Active Banking Trojan. Implements OTP theft, ATS, or CH27 Triad. Immediate session revocation and C2 blacklisting. |
