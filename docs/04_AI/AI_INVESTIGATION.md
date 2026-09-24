# SUDARSHAN — AI Investigation Assistant & Architecture

> **Classification:** AUTHORITATIVE  
> **Source Modules:** `backend/app/ai/gemini_rag.py`, `backend/app/ai/gemini_client.py`  
> **Model:** Google Gemini (`gemini-2.5-flash`)  
> **Last Verified:** 2026-09-25  

---

## 1. The Role of AI in SUDARSHAN

Generative AI in SUDARSHAN serves as an **analyst translation and narrative synthesis layer**. 

### What AI DOES:
- Synthesizes dense static and dynamic forensic evidence into human-readable executive summaries.
- Translates technical bytecode findings (e.g. accessibility event dispatchers) into operational fraud narratives.
- Answers natural language questions from SOC analysts about specific malware behaviors, targeted banks, or C2 endpoints.
- Recommends operational incident response playbooks.

### What AI NEVER DOES:
- AI **NEVER** computes or calculates the Fraud Risk Score (FRS).
- AI **NEVER** mutates or overrides deterministic risk bands.
- AI **NEVER** operates directly on raw binary APK files.
