# Visual Impersonation Detection Engine (VIDE) — Banking Baseline Corpus

**A streamlined, research-grounded corpus of 10 Indian retail banking baseline applications for trusted-baseline generation in the SUDARSHAN clone-detection pipeline.**

---

## 1. Executive Summary & Core Objective

Adversaries running On-Device Fraud (ODF) via **Automated Transfer Systems (ATS)**—such as *Anatsa*, *Klopatra*, and *Xenomorph*—frequently use dynamic overlays or completely unrelated package names (e.g., `quizzical.washbowl.calamity`) to evade traditional package name blocklists and signature verification.

The **Visual Impersonation Detection Engine (VIDE)** targets the adversary's primary constraint: **they cannot change the visual UI**. They must mimic the bank's interface perfectly to deceive the victim. VIDE treats the **frontend UI structure itself as the ultimate Indicator of Compromise (IOC)**.

By automatically comparing a suspect app's UI (statically via `res/layout` AST dumps and dynamically via Frida/UIAutomator) against a known baseline of legitimate banking layouts, VIDE moves detection to the top of the Pyramid of Pain (TTPs).

---

## 2. Repository Structure

This repository is organized into self-contained baseline packages for each protected institution:

```text
banking-baseline-corpus/
├── README.md                           ← Main repository documentation
├── baselines_index.json                ← Master index of all 10 baseline profiles for VIDE
├── built_apks/                         ← Pre-compiled ready-to-test APKs
│   ├── BASE-01-SBI.apk
│   ├── BASE-02-HDFC.apk
│   ├── ...
│   └── BASE-10-UNION.apk
├── baseline-library/                   ← Self-contained baseline packages
│   ├── BASE-01-SBI/
│   │   ├── app/                        ← React + Capacitor source code & Android build
│   │   ├── design.md                   ← Per-app design specification
│   │   ├── app.meta.json               ← Machine-readable baseline registration profile
│   │   ├── navigation.manifest.json    ← Screen transition graph (nodes & edges)
│   │   └── fingerprints.json           ← VIDE UI structural AST signatures & brand tokens
│   ├── BASE-02-HDFC/
│   └── ... (BASE-03 to BASE-10)
└── 04-baseline-architecture/           ← Corpus schema & baseline registration pipeline docs
```

---

## 3. Protected Banking Baselines (10 Applications)

| # | Baseline ID | App Name | Bank Name | Sector | Compiled APK |
|---|---|---|---|---|---|
| 01 | `BASE-01-SBI` | YONO SBI | State Bank of India | Public | [`built_apks/BASE-01-SBI.apk`](built_apks/BASE-01-SBI.apk) |
| 02 | `BASE-02-HDFC` | HDFC Bank MobileBanking | HDFC Bank | Private | [`built_apks/BASE-02-HDFC.apk`](built_apks/BASE-02-HDFC.apk) |
| 03 | `BASE-03-ICICI` | iMobile Pay | ICICI Bank | Private | [`built_apks/BASE-03-ICICI.apk`](built_apks/BASE-03-ICICI.apk) |
| 04 | `BASE-04-AXIS` | Axis Mobile | Axis Bank | Private | [`built_apks/BASE-04-AXIS.apk`](built_apks/BASE-04-AXIS.apk) |
| 05 | `BASE-05-BOB` | bob World | Bank of Baroda | Public | [`built_apks/BASE-05-BOB.apk`](built_apks/BASE-05-BOB.apk) |
| 06 | `BASE-06-PNB` | PNB ONE | Punjab National Bank | Public | [`built_apks/BASE-06-PNB.apk`](built_apks/BASE-06-PNB.apk) |
| 07 | `BASE-07-BOI` | BOI Mobile | Bank of India | Public | [`built_apks/BASE-07-BOI.apk`](built_apks/BASE-07-BOI.apk) |
| 08 | `BASE-08-KOTAK` | Kotak811 | Kotak Mahindra Bank | Private | [`built_apks/BASE-08-KOTAK.apk`](built_apks/BASE-08-KOTAK.apk) |
| 09 | `BASE-09-INDUS` | IndusMobile | IndusInd Bank | Private | [`built_apks/BASE-09-INDUS.apk`](built_apks/BASE-09-INDUS.apk) |
| 10 | `BASE-10-UNION` | Vyom | Union Bank of India | Public | [`built_apks/BASE-10-UNION.apk`](built_apks/BASE-10-UNION.apk) |

---

## 4. VIDE Feeding Schemas

### 4.1 Master Registry (`baselines_index.json`)
The central registry consumed by VIDE's evaluator:
```json
{
  "corpusVersion": "1.0",
  "baselines": [
    {
      "id": "BASE-01-SBI",
      "appName": "YONO SBI",
      "bank": "State Bank of India",
      "meta": "baseline-library/BASE-01-SBI/app.meta.json",
      "design": "baseline-library/BASE-01-SBI/design.md",
      "navigation": "baseline-library/BASE-01-SBI/navigation.manifest.json",
      "fingerprints": "baseline-library/BASE-01-SBI/fingerprints.json"
    }
  ]
}
```

### 4.2 Structural Fingerprints (`fingerprints.json`)
Defines the visual and structural signatures used for LLM & semantic comparison:
```json
{
  "baselineId": "BASE-01-SBI",
  "screens": [
    {
      "screenId": "SBI-LOGIN",
      "structuralSignature": "AUTH_FORM_VERTICAL_PRIMARY_CTA",
      "regionOrder": ["HEADER", "PRIMARY_CONTENT", "FOOTER_CTA"],
      "exactStrings": ["User ID", "Password", "Login", "Forgot Password?"],
      "brandTokens": {
        "colorPrimary": "#1B4AA0",
        "colorSecondary": "#2E9E4B"
      }
    }
  ]
}
```

---

## 5. Testing & Verification

### Running & Installing APKs
1. **On Android Studio Emulator:**
   Drag and drop any `.apk` from `built_apks/` directly onto a running emulator.
2. **On Physical Device:**
   Transfer the `.apk` file to an Android phone and install it (enable "Install from unknown sources" if prompted).

### Opening Source Code in Android Studio
To inspect or build an app in Android Studio:
1. Open Android Studio.
2. Click **File > Open**.
3. Select `baseline-library/[BASE-ID]/app/android`.
