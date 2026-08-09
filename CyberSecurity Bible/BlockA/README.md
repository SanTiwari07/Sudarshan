# SUDARSHAN Engineering Knowledge Base

Internal engineering documentation for **SUDARSHAN** - an AI-powered enterprise Android
malware investigation platform built for banks.

**→ Start at [index.md](index.md)**

---

## What this is

A 38-chapter engineering knowledge base covering Android internals, APK architecture,
reverse engineering, static and dynamic analysis, Android banking malware, threat
intelligence, digital forensics, SOC operations, incident response, AI-assisted analysis,
and the design of the SUDARSHAN platform itself.

It is written to be used for years as onboarding documentation and a daily reference - not
read once. Every concept answers **WHAT / WHY / HOW / WHEN / WHERE / LIMITATIONS**, follows
complete lifecycles rather than isolated definitions, and ends with *Judge Insights* and
*Interview Insights*.

## Scope and intent

**This is defensive security documentation.** It covers detection, analysis, forensics,
threat intelligence, and incident response. It does not contain instructions for building
malware. Analysis techniques described here (repackaging, instrumentation, TLS interception)
are for **authorised laboratory analysis of malware samples** under proper legal authority
and chain of custody.

## Status

| Block | Chapters | Status |
|---|---|---|
| **A - Foundations** | 00–09 | ✅ **Complete** |
| **B - Analysis Craft** | 10–12 | ✅ **Complete** |
| **C - The Adversary** | 13–16 | ✅ **Complete** |
| **D - Operations** | 17–21 | ✅ **Complete** |
| **E - Building SUDARSHAN** | 22–30 | ✅ **Complete** |
| **F - Reference** | 31–37 | ✅ **Complete** |

**All 38 chapters (00–37) written.** ~163,000 words.

## Publishing

These files are plain CommonMark with relative links and work without modification in:

- **GitHub Wiki** - push the `docs/` contents to the wiki repo
- **Docusaurus** - point `docs.path` at `docs/`; `index.md` is the landing page
- **MkDocs** - set `docs_dir: docs`; the chapter tables in `index.md` mirror the nav
- **Obsidian** - open `docs/` as a vault; relative links and tags resolve natively
- **Notion** - import the folder; the heading hierarchy maps to Notion blocks

### Suggested MkDocs nav stub

```yaml
nav:
  - Home: index.md
  - "00 Introduction": 00-introduction.md
  - Foundations:
      - "01 Android Internals": android/01-android-internals.md
      - "02 APK Architecture": apk/02-apk-architecture.md
      - "03 Android Runtime": android/03-android-runtime.md
      - "04 Android Security Model": security/04-android-security-model.md
      - "05 Android Cryptography": security/05-android-cryptography.md
      - "06 Certificates": security/06-certificates.md
      - "07 APK Signing": security/07-apk-signing.md
      - "08 APK File Format": apk/08-apk-file-format.md
      - "09 Package Manager": apk/09-package-manager.md
  - Analysis Craft:
      - "10 Reverse Engineering": reverse-engineering/10-reverse-engineering.md
      - "11 Static Analysis": static-analysis/11-static-analysis.md
      - "12 Dynamic Analysis": dynamic-analysis/12-dynamic-analysis.md
  - The Adversary:
      - "13 Android Malware": malware/13-android-malware.md
      - "14 Banking Malware": banking-malware/14-banking-malware.md
      - "15 Malware Infrastructure": malware/15-malware-infrastructure.md
      - "16 Threat Intelligence": threat-intelligence/16-threat-intelligence.md
  - Operations:
      - "17 Digital Forensics": digital-forensics/17-digital-forensics.md
      - "18 Mobile Threat Hunting": soc/18-mobile-threat-hunting.md
      - "19 Enterprise SOC Operations": soc/19-enterprise-soc-operations.md
      - "20 Incident Response": incident-response/20-incident-response.md
      - "21 AI-assisted Malware Analysis": ai-malware-analysis/21-ai-assisted-malware-analysis.md
  - Building SUDARSHAN:
      - "22 Building SUDARSHAN": sudarshan/22-building-sudarshan.md
      - "23 Detection Pipeline": sudarshan/23-detection-pipeline.md
      - "24 Threat Intake": sudarshan/24-threat-intake.md
      - "25 Investigation Engine": sudarshan/25-investigation-engine.md
      - "26 IOC Extraction": sudarshan/26-ioc-extraction.md
      - "27 Risk Scoring": sudarshan/27-risk-scoring.md
      - "28 Campaign Correlation": sudarshan/28-campaign-correlation.md
      - "29 Investigation Reports": sudarshan/29-investigation-reports.md
      - "30 Threat Intelligence Database": threat-intelligence/30-threat-intelligence-database.md
  - Reference:
      - "31 Future Research": appendix/31-future-research.md
      - "32 Common Misconceptions": appendix/32-common-misconceptions.md
      - "33 Cheat Sheets": appendix/33-cheat-sheets.md
      - "34 Judge Preparation": appendix/34-judge-preparation.md
      - "35 Interview Preparation": appendix/35-interview-preparation.md
      - "36 Glossary": appendix/36-glossary.md
      - "37 References": appendix/37-references.md
```

## Contributing

1. Keep the chapter skeleton: header block → TOC → body → detection logic → limitations →
   engineering tips → Judge Insights → Interview Insights → cross-references → references.
2. **Version-gate every platform claim** (`Android 14 (API 34)+`, never "modern Android").
3. **Attribute every threat-intel claim** to a named vendor with a publication date.
4. Bump `Version` and `Last Updated` in the file header.
5. Update cross-references in both directions - upstream and downstream.
6. Prefer primary sources: `developer.android.com`, `source.android.com`, OWASP, MITRE, NIST,
   and named vendor threat research.

## Source quality

Threat-intelligence content is dated and attributed throughout. Vendor naming diverges
(Anatsa / TeaBot / Toddler; Octo / Coper), so families are always named with their source.
Where sources disagree or a claim is single-vendor, the text says so.

---

*Version 1.5.0 · Last updated 2026-08-05*
