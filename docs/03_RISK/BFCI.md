# SUDARSHAN — Behavioral Fraud Confidence Index (BFCI v2)

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/engines/bfci_scorer.py`  

---

## 1. BFCI v2 Improvements over v1

BFCI v1 counted distinct hook names per category, which allowed unrelated benign API calls to score equally with a multi-step fraud attack chain.

**BFCI v2 introduces 3 scoring tiers:**
1. **Presence Tier (Base):** Confirms that a categorized hook fired during runtime.
2. **Volume Tier (Logarithmic Scaling):** Scales with the frequency of hook events up to category caps using logarithmic normalization, preventing a single event from dominating the score.
3. **Temporal Sequence Bonus:** When events from multiple weighted categories occur within a sequence window (`SEQUENCE_WINDOW_SECONDS = 15s`) in a known attack sequence (e.g., Overlay $\rightarrow$ Accessibility $\rightarrow$ SMS), the score receives a multiplier bonus.

---

## 2. Validated Category Weights

$$\sum w_i = 1.0$$

| Category | Weight ($w_i$) | Description |
| :--- | :--- | :--- |
| **accessibility** | `0.315` | Screen scraping, tap injection, keylogging ($0.35 \times 0.90$) |
| **sms** | `0.225` | OTP SMS reading and transmission ($0.25 \times 0.90$) |
| **overlay** | `0.180` | Phishing window overlays ($0.20 \times 0.90$) |
| **code_execution**| `0.100` | Dynamic DEX loading, ProcessBuilder, native execve |
| **banking** | `0.090` | Active targeting of known banking applications ($0.10 \times 0.90$) |
| **network** | `0.045` | C2 network communication ($0.05 \times 0.90$) |
| **persistence** | `0.045` | Device administration and anti-kill mechanisms ($0.05 \times 0.90$) |
