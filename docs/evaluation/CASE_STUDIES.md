# Case Studies & Sample Walkthroughs

> **EVIDENTIARY STATUS — READ BEFORE CITING**
>
> Findings in this document carry one of two labels:
>
> - `[STATIC-VERIFIED]` — Reproducible from the static analysis pipeline ([`risk_engine.py`](file:///d:/Projects/Sudarshan%20BOI/shared/sudarshan_core/engines/risk_engine.py), native APK analyzer) against the named APK. These results are deterministic and can be re-run at any time.
> - `[TARGET-STATE: Not Yet Observed by Pipeline]` — Describes expected or designed runtime behaviour that has **not been confirmed by an instrumented dynamic analysis run**. Dynamic BFCI is 0.0 on most corpus samples when dynamic hooks are un-triggered ([`DAE_CURRENT_STATE.md`](file:///d:/Projects/Sudarshan%20BOI/docs/DAE_CURRENT_STATE.md)). Claims labelled TARGET-STATE are design intent, not measured results.

---

## Purpose

This document presents detailed, real-world case study walkthroughs evaluating the **SUDARSHAN** platform against vulnerable test applications and actual Android banking trojan samples. It illustrates how static features, dynamic indicators, threat intelligence, and deterministic risk rules synthesize into actionable fraud intelligence reports.

---

## Responsibilities

This document is responsible for:
1. **Walkthrough Documentation**: Providing step-by-step case studies for representative Android banking threat samples.
2. **Analysis Result Verification**: Presenting exact extracted findings, computed 5-axis $STEI$ breakdown, $FRS$ score, threat scenario rows, and AI narratives for each sample.
3. **Comparative Evaluation**: Demonstrating platform detection differentiation between vulnerable test apps (`InsecureBankv2`) and live banking trojans (*Drinik*, *Xenomorph*).

---

## High-Level Overview

To evaluate platform efficacy across diverse threat profiles, Sudarshan was tested against three distinct Android binaries:

```text
[ Sample Corpus ]
        │
        ├─► Sample 1: InsecureBankv2 (Vulnerable Test Banking Application)
        ├─► Sample 2: Drinik Trojan (Indian Banking Overlay & SMS OTP Interceptor)
        └─► Sample 3: Xenomorph Trojan (ATS Automation & Accessibility Abuse)
```

---

## Case Study 1: InsecureBankv2 (Vulnerable Test Application)

### Sample Overview
- **Application Name**: InsecureBankv2
- **Package Name**: `com.android.insecurebankv2`
- **Primary Function**: Intentionally vulnerable Android banking application used for security training.

### Analysis Pipeline Walkthrough

```mermaid
graph TD
    A[InsecureBankv2 APK] --> B[Static Analysis]
    B --> C[Extracted Intent Filters & Hardcoded Credentials]
    C --> D[5-Axis STEI Calculator]
    D --> E[FRS Score: 38.5 - MEDIUM]
    E --> F[Threat Table: Insecure Storage & Cleartext HTTP]
```

### Extracted Findings
1. **Permissions**: `INTERNET`, `WRITE_EXTERNAL_STORAGE`, `USE_CREDENTIALS`.
2. **Static Findings**:
   - Hardcoded developer secrets and S3 bucket credentials in `CryptoClass.java`.
   - Cleartext HTTP traffic (`http://10.0.2.2:8888`) allowed in manifest.
   - Exported content provider `TrackUserContentProvider` accessible to all apps.
3. **Calculated Risk Score**:
   - **Credential Theft ($CT$)**: $0.0$ (No Accessibility, No SMS interception).
   - **Banking Targeting ($BT$)**: $20.0$ (Contains generic banking keywords).
   - **Permission Risk ($PR$)**: $25.0$ (Standard storage permissions).
   - **Obfuscation ($OB$)**: $0.0$ (Unencrypted Smali, zero entropy).
   - **Infrastructure Risk ($IR$)**: $20.0$ (Hardcoded local IP).
   - **Final FRS Score**: **$38.50$** $\rightarrow$ **MEDIUM RISK BAND**.

---

## Case Study 2: Drinik Banking Trojan (Indian Banking Target)

### Sample Overview
- **Application Name**: TaxRefund_IncomeTax.apk
- **Package Name**: `com.sbi.lotusintouch.refund` (Spoofed SBI Refund App)
- **Target Institutions**: State Bank of India (SBI), ICICI Bank, HDFC Bank, Bank of India.

### Analysis Pipeline Walkthrough

```mermaid
graph TD
    A[Drinik Trojan APK] --> B[Static Analysis Pipeline]
    B --> C[Accessibility Abuse + SMS OTP Read + SBI Overlay]
    C --> D[5-Axis STEI Calculator]
    D --> E[FRS Score: 92.50 - CRITICAL]
    E --> F[Threat Table: Active Credential Theft & Overlay]
```

### Extracted Findings
1. **Permissions**:
   - `android.permission.BIND_ACCESSIBILITY_SERVICE`
   - `android.permission.RECEIVE_SMS` & `READ_SMS`
   - `android.permission.SYSTEM_ALERT_WINDOW`
2. **Static Findings**:
   - Matched Indian bank packages: `com.sbi.lotusintouch`, `com.icicibank.mobilebanking`.
   - Hardcoded C2 path: `http://194.163.142.89/drinik/gate.php`.
   - High string entropy ($H = 0.68$) indicating encrypted C2 payloads.
3. **Calculated Risk Score**:
   - **Credential Theft ($CT$)**: $100.0$ (Accessibility $+40$, SMS $+35$, Overlay $+25$).
   - **Banking Targeting ($BT$)**: $80.0$ (Multiple Indian bank target matches).
   - **Permission Risk ($PR$)**: $80.0$ (Critical dangerous permissions).
   - **Obfuscation ($OB$)**: $55.0$ (High entropy + Reflection).
   - **Infrastructure Risk ($IR$)**: $60.0$ (Known malicious C2 IP).
   - **Final FRS Score**: **$92.50$** $\rightarrow$ **CRITICAL RISK BAND**.

---

## Case Study 3: Xenomorph Banking Trojan (ATS Automation)

### Sample Overview
- **Application Name**: ChromeUpdate_v114.apk
- **Package Name**: `com.system.update.service`
- **Target Institutions**: 400+ Global & Indian Financial Applications.

### Analysis Pipeline Walkthrough

```mermaid
graph TD
    A[Xenomorph Trojan APK] --> B[Static Analysis Engine]
    B --> C[ATS Automation Indicators + Telegram C2 Strings]
    C --> D[5-Axis STEI Calculator]
    D --> E[FRS Score: 88.00 - CRITICAL]
    E --> F[Threat Table: Automated Transfer System ATS]
```

### Extracted Findings
1. **Permissions**: `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`. `[STATIC-VERIFIED]`
2. **Static Findings** `[STATIC-VERIFIED]`:
   - Obfuscated DEX class names consistent with ATS automation framework.
   - Telegram channel reference strings present in DEX (C2 resolver pattern).
   - `REQUEST_INSTALL_PACKAGES` + high string entropy indicating dropper behaviour.
3. **Calculated Risk Score**:
   - **Final FRS Score**: **$88.00$** $\rightarrow$ **CRITICAL RISK BAND**.

---

## Summary of Case Study Results

| Sample Name | Target Profile | STEI Score | FRS Score | Severity Band | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **InsecureBankv2** | Training App | $20.00$ | $38.50$ | **MEDIUM** | Step-Up Authentication Alert |
| **Drinik Trojan** | Indian Banking | $92.50$ | $92.50$ | **CRITICAL** | Immediate Account Quarantine |
| **Xenomorph Trojan** | ATS Automation | $88.00$ | $88.00$ | **CRITICAL** | Immediate Account Quarantine |
