# SUDARSHAN — Project Context & Evolution

> **Classification:** AUTHORITATIVE  
> **Repository:** `SanTiwari07/Sudarshan`  
> **Origin:** Bank of India / IIT Hyderabad Hackathon (BOI Hackathon 2026)  
> **Current Version:** Backend 2.1.0 · Analysis Engine 2.3.0  

---

## 1. Project Genesis

SUDARSHAN was initially conceived to solve targeted Android banking trojan threats in the Indian financial ecosystem (specifically targeting Indian public and private sector banks including SBI, HDFC, ICICI, Axis, PNB, Bank of Baroda, Bank of India, Kotak Mahindra, IndusInd, and Union Bank).

Targeted banking trojans like **Drinik**, **Xenomorph**, **Cerberus**, **Anubis**, **SOVA**, **Hydra**, and **Octo** represent an evolved threat category:
- They actively deploy anti-analysis and sandbox-evasion heuristics.
- They delay execution until specific banking apps are opened.
- They exploit Android's legitimate Accessibility Service API to act as an on-device proxy.

---

## 2. Architecture Evolution

### Milestone 1: Monolithic Prototyping
Initial iterations ran analysis pipelines directly inside a single backend container. This created resource contention where heavy DEX decompiler memory spikes (Androguard/JADX) interfered with web API responsiveness.

### Milestone 2: Microservice Decoupling
The architecture was decoupled into:
1. **Presentation Layer:** React 18 SPA analyst dashboard.
2. **Gateway Orchestrator:** FastAPI backend managing JWT auth, case store, batch queuing, and RAG chat.
3. **Containerized Analysis Engine:** Dedicated Ubuntu 24.04 microservice hosting Java 17, APKTool 2.10.0, JADX 1.5.1, Androguard, and Frida runtime controllers.

### Milestone 3: Hardened Deterministic Risk Engine & VIDE
- Implementation of **BFCI v2** (volume-aware logarithmic scoring and temporal fraud sequence detection).
- Introduction of **VIDE** (Visual Impersonation Detection Engine) using 4 independent axes (Layout AST, CIEDE2000 color matching, RapidFuzz string distance, and Signer Registry allowlists).
- The **CH27 On-Device Fraud Triad** escalation rule.
- Full test suite expansion to **2,841 automated tests**.
