# SUDARSHAN — Behavioral Fraud Confidence Index (BFCI v2)

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/engines/bfci_scorer.py`  

---

## 1. BFCI v2 Improvements over v1

BFCI v1 counted distinct hook names per category, which allowed unrelated benign API calls to score equally with a multi-step fraud attack chain.

**BFCI v2 introduces 3 scoring tiers:**
1. **Presence Tier (Base):** Confirms that a categorized hook fired during runtime.
2. **Volume Tier (Logarithmic Scaling):** Scales with the frequency of hook events up to category caps using logarithmic normalization, preventing a single event from dominating the score.
3. **Temporal Sequence Bonus:** When events from multiple weighted categories occur within a sequence window (`SEQUENCE_WINDOW_SECONDS = 30s`) matching a defined sequence (`FRAUD_SEQUENCES`: OTP theft, overlay+banking, account takeover, dropper), the score receives a ×1.25 multiplier (capped at 100). Only events carrying an agent timestamp can establish a sequence.

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

---

## 3. Evidence integrity rules (ruleset `bfci-v2.1`)

These rules restore the intended semantics; weights, caps, window and multiplier are unchanged. Covered by `tests/unit/test_evidence_integrity.py`.

| Rule | Before | Now |
| :--- | :--- | :--- |
| **Count distinct observations** | `len(events)`: the same event delivered twice counted twice (one re-delivered SMS event raised BFCI 14.2 → 22.5) | Events are de-duplicated by content fingerprint (`runtime_event.event_fingerprint`) before counting. Two events identical in every identifying field are indistinguishable from a re-delivery and count once. |
| **Unstamped events cannot correlate** | A missing timestamp was scored as `t=0`, so unstamped events in accessibility/sms/network all fell in one window and earned the ×1.25 bonus with no temporal evidence | Events without an agent timestamp are ignored by sequence detection (they still count toward their component). |
| **Every contribution is explained** | `code_execution` (weight 0.10) had no evidence string | All seven axes have a label; `explain_bfci()` returns, per axis, weight, distinct count, duplicates ignored, contribution, reason, and the fingerprints of the supporting events. |
| **Reproducible** | — | Same normalized evidence + same ruleset ⇒ identical output, independent of event order. `BFCI_RULESET_VERSION` identifies the ruleset. |

The fingerprints in `bfci_explanation.contributions.*.evidence_refs` are the same values `EvidenceStore` records as `evidence_key`, so each score contribution can be traced to persisted evidence records. AI components never read or write these values.
