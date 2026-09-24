# BASELINE_REGISTRATION_PIPELINE.md

How a **legitimate test prototype APK** produced from this corpus becomes a
**trusted baseline profile** consumable by VIDE.

> This pipeline processes **our own controlled prototypes** built from mock data.
> It is not a tool for collecting, unpacking, or analysing third-party apps
> without authorization, and it contains **no** credential-collection or
> detection-evasion steps.

---

## 1. Conceptual flow

```
LEGITIMATE TEST PROTOTYPE APK
        │
        ▼
STATIC COLLECTION
        ├── package metadata (name, id, version)
        ├── resources (original test assets)
        ├── strings (short functional labels only)
        └── signing metadata (self-signed debug identity)
        │
        ▼
DYNAMIC UI COLLECTION
        ├── launch (local, offline)
        ├── deterministic traversal (fixed script from navigation manifest)
        ├── screenshots (one per canonical screen)
        ├── semantic UI metadata (authored fingerprints)
        └── navigation relationships (nodes/edges)
        │
        ▼
VIDE BASELINE PROCESSING
        ├── visual representation
        ├── OCR / text representation
        ├── structural representation
        └── navigation representation
        │
        ▼
TRUSTED BASELINE PROFILE
```

## 2. Stage 1 — Static collection

**Input:** the prototype's built APK + `app.meta.json`.

| Field | Source | Notes |
|---|---|---|
| package id | build config | debug/test package (e.g. `com.sudarshan.baseline.sbi`) — **not** the real bank package |
| app label | manifest | baseline label, clearly a test build |
| version | build config | corpus version |
| resources | bundle | original test assets only |
| strings | bundle | short functional UI labels; no copyrighted blocks |
| signing | debug keystore | self-signed **test** identity — recorded to *contrast* with any suspect's signing |

**Guardrail:** baselines are intentionally built with **test package names and
test signing**, so identity/signing evidence can later *distinguish* a baseline
from any real or malicious app claiming to be the bank.

## 3. Stage 2 — Dynamic UI collection

- **Deterministic traversal:** a fixed script derived from
  `navigation.manifest.json` visits every MUST-IMPLEMENT screen in a fixed order.
- **Offline:** device/emulator is offline or on a sandbox network; there is
  nothing real to call.
- **Capture per screen:** one screenshot + the authored semantic fingerprint +
  the outgoing edges.
- **Reproducibility check:** two traversals must yield identical screen sets and
  navigation edges (mock data is static).

Output artifacts land in `baseline-library/BASE-XX/screens|fingerprints`.

## 4. Stage 3 — VIDE baseline processing

For each captured screen, derive four aligned representations:

| Representation | Method (conceptual) | Confidence handling |
|---|---|---|
| **Visual** | perceptual embedding / hashing of the screenshot | down-weight screens built from APPROXIMATED layout |
| **Text/OCR** | OCR of short on-screen labels | ignore mock PII-shaped strings |
| **Structural** | encode semantic hierarchy + structural signature | authoritative (authored) |
| **Navigation** | encode graph position + edges | authoritative (from manifest) |

## 5. Output — Trusted Baseline Profile

```json
{
  "baselineId": "BASE-01-SBI",
  "institution": "State Bank of India",
  "appBaselineName": "YONO SBI",
  "isTrustedBaseline": true,
  "screens": [
    {
      "screenId": "SBI-LOGIN",
      "structuralSignature": "AUTH_FORM_VERTICAL_PRIMARY_CTA",
      "visualRef": "screens/SBI-LOGIN.png",
      "textLabels": ["Login","MPIN","Forgot MPIN"],
      "confidence": { "layout": "APPROXIMATED", "color": "APPROXIMATED" }
    }
  ],
  "navigation": "navigation.manifest.json",
  "identity": { "packageId": "com.sudarshan.baseline.sbi", "signing": "test-debug" }
}
```

## 6. How a suspect is compared (downstream, informative)

When VIDE later evaluates a suspect app, its **conceptual** report is:

```
Potential Institution:   <bank the suspect most resembles>
Similarity Confidence:   <low | moderate | high, with score>
Supporting Screens:      <baseline screens that matched>
Supporting Features:     <structural signatures / brand cues that matched>
Conflicting Evidence:    <e.g. different signing, different package, benign behaviour>
Limitations:             <baseline approximations, generic-UI caveat>
```

### Mandatory interpretation rules

1. **Visual similarity alone must not equal malware.** A match is a *lead*.
2. The report **must** populate *Conflicting Evidence* and *Limitations*.
3. Similarity should be **correlated** with independent evidence — static
   indicators, runtime behaviour, and identity/signing differences — before any
   impersonation conclusion.
4. Baselines built on APPROXIMATED/UNKNOWN regions contribute **less** weight.
5. Generic banking-UI resemblance is expected and must not, by itself, trigger an
   impersonation classification (see TEST_MATRIX category 5).

## 7. What this pipeline explicitly excludes

- No unpacking/decompiling of third-party or real bank APKs.
- No collection of real credentials, OTPs, tokens, or personal data.
- No network calls to real banking endpoints.
- No overlay/accessibility-abuse capture.
- No evasion, obfuscation, or anti-analysis tooling.

## 8. Registration checklist (per baseline)

- [ ] `app.meta.json` present & schema-valid
- [ ] `navigation.manifest.json` present & acyclic-where-required, no dead ends
- [ ] All MUST-IMPLEMENT screens captured
- [ ] Fingerprints authored for every captured screen
- [ ] Tokens exported with confidence labels
- [ ] Test package id + test signing recorded
- [ ] `BASELINE_READINESS_REPORT` passed
- [ ] Entry added to `baseline-library/index.json`
