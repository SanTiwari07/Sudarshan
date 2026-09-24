# SUDARSHAN — Empirical Validation & System Verification

> **Classification:** AUTHORITATIVE  
> **Source Reference:** `docs/operations/VALIDATION.md`  

---

## 1. Multi-Stage Verification Protocol

1. **Pre-flight Check:** Toolchain validation (Java 17, APKTool 2.10.0, JADX 1.5.1, ADB).
2. **Static Ingestion:** Analyzes a test suite of clean and malicious APKs.
3. **Dynamic Sandbox:** Spawns sandbox, verifies hook attachment, and collects events.
4. **Deterministic Scoring:** Verifies that FRS and risk bands match expected ground truth.
5. **RAG Grounding:** Confirms AI responses contain zero hallucinations and cite valid evidence.
