# SUDARSHAN — Platform Vision & Mission

> **Classification:** AUTHORITATIVE  
> **Status:** Active Platform Doctrine  
> **Target Audience:** Security Executives, SOC Leads, Security Engineers, and Threat Researchers  

---

## 1. The Core Problem: The 90-Second Fraud Asymmetry

In modern mobile banking fraud, the adversary operates on a timescale orders of magnitude faster than traditional defensive incident response:

1. **The Infiltration Phase (0–30s):** A victim receives a convincing SMS/WhatsApp message spoofing their bank (e.g. KYC verification, account suspension alert, tax refund). The link delivers a trojanized APK payload.
2. **The Execution Phase (30–60s):** Upon installation, the malware displays authentic-looking institutional branding. Under the guise of enabling mandatory banking protections, it coerces the victim into granting Android Accessibility Services (`BIND_ACCESSIBILITY_SERVICE`).
3. **The Extraction Phase (60–90s):** With accessibility privileges granted, the malware silently registers overlay windows over legitimate banking apps, intercepts incoming 2FA SMS one-time passwords (OTPs), exfiltrates credentials to a Command-and-Control (C2) server, and initiates fraudulent fund transfers via automated tap-injection (Automated Transfer System, or ATS).

By the time the victim notices missing funds and contacts customer support, the fraud is complete, the session tokens are burned, and the funds have moved through multiple mule accounts. Traditional anti-malware tools answer only: *"Is this binary technically malicious?"* 

**SUDARSHAN fundamentally changes this paradigm.**

---

## 2. Platform Mission: Intelligence Translation

SUDARSHAN does not simply output a binary benign/malicious label. It answers three operational questions for the banking fraud team:
1. **Who is targeted?** Which financial institutions, specific banking apps, and customer cohorts are under attack?
2. **What is at risk?** What specific operational capabilities does the malware possess (e.g., OTP interception, ATS transfers, overlay phishing, remote device control)?
3. **What must the fraud operations team do right now?** Immediate, actionable playbooks: revoking active mobile banking sessions, blacklisting C2 infrastructure, updating perimeter WAF rules, and issuing customer advisory bulletins.

---

## 3. The Core Invariants

SUDARSHAN is built on non-negotiable architectural tenets:

### Invariant 1: Deterministic Risk Authority
> **Deterministic detection is the final authority on numerical risk.**  
> The Deterministic Risk Engine (`shared/sudarshan_core/engines/risk_engine.py`) calculates the Fraud Risk Score (FRS) on a strictly bounded 0–100 scale using empirical static bytecode evidence, live dynamic instrumentation events, threat intelligence correlation, and institutional banking impact. Identical inputs produce byte-identical scores.

### Invariant 2: AI as Grounded Explainer, Never Verdict Author
> **Generative AI provides investigation assistance, semantic navigation, and narrative translation, but NEVER directly mutates or calculates deterministic risk scores.**  
> AI models can hallucinate; financial fraud decisions cannot tolerate hallucinated risk scores. AI in SUDARSHAN is grounded strictly in indexed evidence chunks through a specialized RAG engine (`backend/app/ai/gemini_rag.py`).

### Invariant 3: Defense-in-Depth Sandbox Containment
> **Host network isolation and sandbox containment must never be weakened.**  
> Hostile malware running in dynamic analysis must be contained within dedicated Android sandboxes with zero LAN-leak risk. Production configurations fail closed if host networks are exposed.
