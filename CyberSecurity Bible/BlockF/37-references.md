# 37 — References

> **Chapter ID:** `CH37` · **Block:** F (Reference) · **Status:** Living document
> **Tags:** `#references` `#bibliography` `#sources` `#citations`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

> Consolidated bibliography for the entire knowledge base. Threat-intelligence sources carry
> **publication dates**; telemetry figures represent that vendor's visibility, not global ground
> truth.

---

## Table of Contents

1. [How sources are weighted](#1-how-sources-are-weighted)
2. [Primary platform documentation](#2-primary-platform-documentation)
3. [Standards and frameworks](#3-standards-and-frameworks)
4. [Indian regulatory and statistical sources](#4-indian-regulatory-and-statistical-sources)
5. [Vendor threat research](#5-vendor-threat-research)
6. [Vulnerability disclosures](#6-vulnerability-disclosures)
7. [Tools](#7-tools)
8. [Academic and research literature](#8-academic-and-research-literature)
9. [Books and long-form](#9-books-and-long-form)
10. [Source quality caveats](#10-source-quality-caveats)
11. [Citation conventions](#11-citation-conventions)

---

## 1. How sources are weighted

```
  STRONGEST ◄──────────────────────────────────────────────► WEAKEST

  Platform docs    Standards     Vendor threat    Secondary    Community
  (AOSP, Android   (MITRE,       research         press        posts
   Developers)      OWASP, NIST) (dated,
                                  attributed)
       │                │              │              │            │
   normative        normative     first-hand      derivative   unverified
   for behaviour    for practice  telemetry       — cite the
                                  + bias           primary
```

| Tier | Use for | Caveat |
|---|---|---|
| **Platform documentation** | Anything about how Android behaves | Version-gate every claim |
| **Standards** | Practice, taxonomy, testing | Versioned — pin them |
| **Vendor threat research** | Families, campaigns, IOCs | Visibility bias; distinguish observation from prediction |
| **Government / CERT** | Statistics, regulation | Slower; less technical |
| **Secondary press** | Timeliness only | **Always cite the primary** |

---

## 2. Primary platform documentation

### Android Open Source Project (source.android.com)

1. *Android Security Overview* — https://source.android.com/docs/security
2. *Application Sandbox* — https://source.android.com/docs/security/app-sandbox
3. *Application Signing* (v1–v4 overview) — https://source.android.com/docs/security/features/apksigning
4. *APK Signature Scheme v2* — https://source.android.com/docs/security/features/apksigning/v2
5. *APK Signature Scheme v3* (key rotation) — https://source.android.com/docs/security/features/apksigning/v3
6. *APK Signature Scheme v4* — https://source.android.com/docs/security/features/apksigning/v4
7. *Dalvik Executable format* — https://source.android.com/docs/core/runtime/dex-format
8. *Dalvik bytecode reference* — https://source.android.com/docs/core/runtime/dalvik-bytecode
9. *Android Runtime (ART) and Dalvik* — https://source.android.com/docs/core/runtime
10. *Configuring ART / compiler filters* — https://source.android.com/docs/core/runtime/configure
11. *ART as a Mainline module* — https://source.android.com/docs/core/ota/modular-system/art
12. *Security-Enhanced Linux in Android* — https://source.android.com/docs/security/features/selinux
13. *Verified Boot* — https://source.android.com/docs/security/features/verifiedboot
14. *Hardware-backed Keystore / StrongBox* — https://source.android.com/docs/security/features/keystore
15. *File-Based Encryption* — https://source.android.com/docs/security/features/encryption/file-based
16. *Trusty TEE* — https://source.android.com/docs/security/features/trusty
17. *Binder / AIDL* — https://source.android.com/docs/core/architecture/hidl/binder-ipc
18. Android Security Bulletins — https://source.android.com/docs/security/bulletin
19. AOSP source: `tools/apksig/`, `system/sepolicy/`, `frameworks/base/services/core/java/com/android/server/pm/`, `frameworks/base/tools/aapt2/`, `art/`

### Android Developers (developer.android.com)

20. *Platform Architecture* — https://developer.android.com/guide/platform
21. *Application Fundamentals* / *App Manifest Overview* — https://developer.android.com/guide/topics/manifest/manifest-intro
22. *Permissions on Android* — https://developer.android.com/guide/topics/permissions/overview
23. *AccessibilityService* reference — https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
24. *Restrictions on non-SDK interfaces* — https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces
25. *Android Keystore system* — https://developer.android.com/privacy-and-security/keystore
26. *Key attestation* — https://developer.android.com/privacy-and-security/security-key-attestation
27. *Play Integrity API* — https://developer.android.com/google/play/integrity
28. *Network security configuration* — https://developer.android.com/privacy-and-security/security-config
29. *Android App Bundle* — https://developer.android.com/guide/app-bundle
30. *Sign your app* — https://developer.android.com/studio/publish/app-signing
31. *PackageInstaller* reference — https://developer.android.com/reference/android/content/pm/PackageInstaller
32. *Verify Android App Links* — https://developer.android.com/training/app-links/verify-android-applinks
33. *JNI tips* — https://developer.android.com/training/articles/perf-jni
34. Build tools: `apksigner` · `zipalign` · `aapt2` · `adb`
35. Behaviour changes: [Android 11](https://developer.android.com/about/versions/11/behavior-changes-all) · [12](https://developer.android.com/about/versions/12/behavior-changes-12) · [14](https://developer.android.com/about/versions/14/behavior-changes-all) · [15](https://developer.android.com/about/versions/15/behavior-changes-all)
36. *Foreground service types are required (Android 14)* — https://developer.android.com/about/versions/14/changes/fgs-types-required

### Google security publications

37. Google Security Blog — *How we kept the Google Play & Android app ecosystems safe in 2024* — https://security.googleblog.com/
38. Google Play Console Help — *Play App Signing* — https://support.google.com/googleplay/android-developer/answer/9842756
39. Google Project Zero — Android research archive — https://googleprojectzero.blogspot.com/
40. Google Cloud / Mandiant — *Delving into Dalvik: A Look Inside the DEX File Format*

---

## 3. Standards and frameworks

41. **MITRE ATT&CK for Mobile** — https://attack.mitre.org/matrices/mobile/
42. MITRE ATT&CK detection strategies (e.g. DET0697, accessibility abuse)
43. **MITRE D3FEND** — https://d3fend.mitre.org/
44. MITRE ATLAS — adversarial threat landscape for AI systems
45. **OWASP MASVS v2.1.0** (January 18, 2024) — https://mas.owasp.org/MASVS/
46. **OWASP MASTG** — https://mas.owasp.org/MASTG/
47. OWASP Mobile Top 10 (2024)
48. OWASP Top 10 for Large Language Model Applications
49. **NIST SP 800-61 Rev. 2** — *Computer Security Incident Handling Guide*
50. **NIST SP 800-86** — *Integrating Forensic Techniques into Incident Response*
51. **NIST SP 800-101 Rev. 1** — *Guidelines on Mobile Device Forensics*
52. **NIST SP 800-124 Rev. 2** — *Managing the Security of Mobile Devices*
53. **NIST SP 800-163 Rev. 1** — *Vetting the Security of Mobile Applications*
54. NIST SP 800-150 — *Guide to Cyber Threat Information Sharing*
55. NIST SP 800-30 Rev. 1 — *Guide for Conducting Risk Assessments*
56. NIST SP 800-137 — *Information Security Continuous Monitoring*
57. NIST AI Risk Management Framework (AI RMF 1.0)
58. NIST SP 800-38 series — block cipher modes of operation
59. **OASIS** — STIX 2.1 / TAXII 2.1 — https://oasis-open.github.io/cti-documentation/
60. **FIRST** — Traffic Light Protocol 2.0 — https://www.first.org/tlp/
61. FIRST — CSIRT Services Framework; CVSS specification
62. RFC 5280 — X.509 PKI Certificate and CRL Profile
63. PKWARE — *.ZIP File Format Specification* (APPNOTE.TXT)
64. Lockheed Martin — *Cyber Kill Chain*
65. Caltagirone, Pendergast, Betz — *The Diamond Model of Intrusion Analysis* (2013)
66. David Bianco — *The Pyramid of Pain* (2013)
67. Splunk — **PEAK** Threat Hunting Framework
68. Betaalvereniging Nederland / DCC-NL — **TaHiTI** threat hunting methodology
69. MITRE — *11 Strategies of a World-Class Cybersecurity Operations Center*
70. ODNI / Sherman Kent — analytic confidence and estimative language standards

---

## 4. Indian regulatory and statistical sources

71. **CERT-In** — Directions of **April 28, 2022** (6-hour incident reporting; 180-day log retention within India)
72. **Reserve Bank of India** — Cyber Security Framework for Banks; customer protection framework on unauthorised electronic banking transactions
73. **Digital Personal Data Protection Act, 2023** (India)
74. **Bharatiya Sakshya Adhiniyam, 2023** (India) — electronic evidence, replacing the Indian Evidence Act
75. Information Technology Act, 2000 (India)
76. **Lok Sabha**, Ministry of Finance (MoS Pankaj Chaudhary) — UPI fraud statistics, disclosed **November 25, 2024**: 7.25 lakh cases / ₹573 crore (FY2022–23) → **13.42 lakh cases / ₹1,087 crore (FY2023–24)**
77. **Indian Cyber Crime Coordination Centre (I4C)** — cybercrime loss figures (2024): **₹1,750+ crore** in the first four months
78. National Cybercrime Reporting Portal / helpline **1930**
79. NPCI — UPI circulars on fraud handling and beneficiary freezes

---

## 5. Vendor threat research

*Dated and attributed. Telemetry figures are single-vendor unless noted.*

### ThreatFabric

80. *Cerberus — A new banking Trojan from the underworld* (June 2019); Google Authenticator OTP theft (February 2020)
81. *Alien* analysis (September 24, 2020)
82. *BlackRock — the Trojan that wanted to get them all* (2020)
83. *Vultur, with a V for VNC* (2021)
84. *Xenomorph: A newly hatched Banking Trojan* (February 2022); v3 (March 2023); US expansion (September 2023)
85. *Hook* (January 2023)
86. *SpyNote* analysis (January 2023)
87. *Chameleon* biometric bypass (December 2023)
88. *Octo2* (September 2024) — DGA, Zombinder first stage, Android 13+ restriction bypass
89. *Crocodilus* (March 29, 2025) — seed-phrase parser, command `TRU9MMRHBCRO`
90. Anatsa Google Play dropper campaign, *"Hybrid Cars Simulator, Drift & Racing"* (July 2025) — **#4 in Play Top Free Tools by June 29, 2025**

### Cleafy Labs

91. TeaBot / Anatsa initial analysis (January 2021)
92. *BRATA* evolution analyses (2021–2022) — factory-reset kill switch
93. *Copybara* — MQTT C2, "Mr. Robot" and "JOKER RAT" panels
94. *Medusa Reborn: A New Compact Variant Discovered* (June 2024)
95. *BingoMod: The new Android RAT that steals money and wipes data* (July 31, 2024)
96. *ToxicPanda* (October 2024) — AES-ECB C2, `dksu[.]top`, `mixcom[.]one`
97. *DroidBot* (2024)
98. *Klopatra* (August 2025) — Virbox protector, Hidden VNC, `adsservices.uk` / `adsservice2.org`
99. *PlayPraetor* (August 2025)

### Other vendors

100. **Zimperium zLabs** — *Banking Heist Report* (**March 19, 2026**): 34 families, 1,243 institutions, 90 countries, +67% YoY
101. **Zscaler ThreatLabz** — *Anatsa's Latest Updates* (**August 2025**): 831 institutions; shift from remote DEX loading to direct payload installation
102. **Hunt.io** — *ERMAC 3.0 source code leak* (published August 2025) — open directory `141.164.62[.]236:443`
103. **Group-IB** — *GoldDigger* (October 2023); *GoldPickaxe* (**February 15, 2024**) — first iOS trojan harvesting facial-recognition data
104. **Cyble (CRIL)** — *Chameleon* (April 2023); *Antidot* (**May 16, 2024**); *TsarBot* (**March 28, 2025**); GodFather variant analysis
105. **NCC Group** — Vultur upgrade analysis (**March 28, 2024**)
106. **ESET** — ERMAC v2 analysis (May 2022) — ~$5,000/month rental
107. **Kaspersky** — BRATA initial naming (2019)
108. **Trend Micro** — TgToxic (early 2023); Janus technical analysis (2017)
109. **McAfee** — "PM Surya Ghar: Muft Bijli Yojana" India campaign — Firebase C2, GitHub-hosted APKs
110. **CYFIRMA** — droppers impersonating Indian banking apps using cloud services as C2
111. **CTM360** — *PlayPraetor* (March 2025)
112. **Verimatrix** — Copybara alert (39 samples / 781 apps targeted)
113. **Guardsquare** — ProGuard/DexGuard documentation; Janus disclosure (2017)
114. **Promon** — StrandHogg task-hijacking research
115. **Bluebox Security** — *Master Key* (Android bug 8219321, 2013); *Fake ID* (2014)
116. Appdome, Build38, Lookout — in-app protection and MTD documentation

---

## 6. Vulnerability disclosures

117. **CVE-2017-13156 (Janus)** — Android Security Bulletin, **December 2017** — https://source.android.com/docs/security/bulletin/2017-12-01
118. **Android bug 8219321 (Master Key)** — Bluebox Security, 2013
119. **Fake ID** — Bluebox Security, 2014
120. **Zip Slip** — Snyk archive path-traversal research
121. MobSF v4.4.6 (March 2026) — SQLite viewer SQL injection fix

---

## 7. Tools

| Tool | URL |
|---|---|
| jadx | https://github.com/skylot/jadx |
| Apktool | https://apktool.org/ |
| Androguard | https://androguard.readthedocs.io/ |
| smali/baksmali | https://github.com/google/smali |
| Ghidra | https://ghidra-sre.org/ |
| Frida | https://frida.re/docs/android/ |
| objection | https://github.com/sensepost/objection |
| jnitrace | https://github.com/chame1eon/jnitrace |
| Magisk | https://topjohnwu.github.io/Magisk/ |
| LSPosed | https://github.com/LSPosed/LSPosed |
| MobSF | https://mobsf.github.io/docs/ |
| YARA-X | https://virustotal.github.io/yara-x/ |
| YARA (legacy) | https://yara.readthedocs.io/ |
| Sigma | https://github.com/SigmaHQ/sigma |
| TLSH | https://github.com/trendmicro/tlsh |
| ssdeep | https://ssdeep-project.github.io/ssdeep/ |
| FlowDroid | https://github.com/secure-software-engineering/FlowDroid |
| ALEAPP | https://github.com/abrignoni/ALEAPP |
| Autopsy / Sleuth Kit | https://www.autopsy.com/ |
| mitmproxy | https://docs.mitmproxy.org/ |
| CAPE Sandbox | https://github.com/kevoreilly/CAPEv2 |
| VirusTotal | https://docs.virustotal.com/ |
| MISP | https://www.misp-project.org/ |
| OpenCTI | https://www.filigran.io/en/products/opencti/ |
| reFlutter | Flutter app reverse engineering |
| vdexExtractor | DEX recovery from `.vdex` |
| SQLite WAL | https://www.sqlite.org/wal.html |

Commercial forensics: Cellebrite UFED / Physical Analyzer · MSAB XRY · Magnet AXIOM

---

## 8. Academic and research literature

122. Arp et al. — *DREBIN: Effective and Explainable Detection of Android Malware in Your Pocket* (NDSS 2014) — **note: dataset is 2010–2012**
123. Allix et al. — *AndroZoo: Collecting Millions of Android Apps for the Research Community* (MSR 2016) — https://androzoo.uni.lu/
124. *MalRadar* — curated, manually verified Android malware dataset
125. Canadian Institute for Cybersecurity — CICMalDroid dataset
126. **Pendlebury et al.** — *TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time* (USENIX Security 2019)
127. **Jordaney et al.** — *Transcend: Detecting Concept Drift in Malware Classification Models* (USENIX Security 2017)
128. Biggio & Roli — *Wild Patterns: Ten Years After the Rise of Adversarial Machine Learning*
129. abuse.ch projects — MalwareBazaar, URLhaus, ThreatFox
130. VirusShare — sample repository
131. Certificate Transparency logs — infrastructure discovery
132. fs-verity documentation (Linux kernel) — the Merkle-tree mechanism behind APK v4

---

## 9. Books and long-form

133. Jonathan Levin — *Android Internals: A Confectioner's Cookbook*
134. Chris Eagle & Kara Nance — *The Ghidra Book*
135. SANS FOR585 — *Advanced Smartphone Forensics* course materials
136. Alexis Brignoni — mobile forensics artifact research blog
137. The ThreatHunting Project — open hunt procedure library
138. Detection Engineering community resources (Detection Engineering Weekly, DeTT&CT)

---

## 10. Source quality caveats

### Recency

Threat-intelligence content decays fastest. **Anything in Blocks C and D older than 12 months should
be re-verified before use in a customer-facing report.** [Ch 14](../banking-malware/14-banking-malware.md)
carries an explicit decay warning for this reason.

### Vendor visibility bias

| Vendor | Strongest visibility |
|---|---|
| Cleafy | Italy, Spain, Portugal, France |
| ThreatFabric | Western Europe, US, Canada |
| Group-IB | Southeast Asia (Vietnam, Thailand) |
| Cyble / CYFIRMA | India |
| Zimperium / Zscaler | Global telemetry, enterprise-weighted |

> **"Not seen in India" frequently means "no vendor with Indian visibility has published."**
> → [Ch 30 §5](../threat-intelligence/30-threat-intelligence-database.md#5-provenance)

### Claim types

Vendor reports mix four claim types freely. Separate them:

| Type | Treatment |
|---|---|
| **Observation** | Fact — e.g. "dropper reached #4 in Play Top Free Tools" |
| **Telemetry** | That vendor's visibility — e.g. "1,500+ infected devices" |
| **Prediction** | **Never quote as fact** — e.g. "Octo2 expected to become more widespread" |
| **Assessment** | Hedged — e.g. "operators assessed as Turkish-speaking" (spoofable) |

### Known uncertainties in this knowledge base

- **Hydra's** first-documentation date is weakly sourced and varies across vendors.
- **ToxicPanda's** regional percentages and device counts are single-vendor telemetry.
- **"Medusa"** is a three-way naming collision (Android banker / ransomware gang / Mirai-based DDoS
  botnet) — always qualify.
- **Cerberus's** relationship to Anubis is disputed; ThreatFabric states it was written from scratch.

---

## 11. Citation conventions

Used throughout this knowledge base:

```
  Platform behaviour   → cite AOSP or Android Developers, WITH the API level
                         "Android 14 (API 34) blocks installing apps targeting below API 23"

  Threat intelligence  → cite VENDOR + PUBLICATION DATE on first use per chapter
                         "Anatsa (ThreatFabric; TeaBot per Cleafy)"
                         "Zscaler ThreatLabz, August 2025"

  Statistics           → cite SOURCE + DATE + the period measured
                         "13.42 lakh cases / ₹1,087 crore (FY2023-24),
                          Lok Sabha, disclosed November 25, 2024"

  Techniques           → cite MITRE ID + pinned ATT&CK version
                         "T1453, ATT&CK for Mobile v17"

  Standards            → cite the version
                         "OWASP MASVS v2.1.0 (January 18, 2024)"

  Secondary press      → DON'T. Find and cite the primary.

  Defanging            → hxxps://  ·  dksu[.]top  ·  141.164.62[.]236
                         in every human-readable surface
```

---

## ✅ Block F complete — knowledge base complete

Chapters 31–37 close the knowledge base: consolidated research gaps, the full misconception
catalogue with origins, operational cheat sheets, judge and interview preparation, glossary, and
this bibliography.

**All 38 chapters (00–37) are now written.** The remaining work is assembly: the two PDFs
(*Android Security Bible*, *Quick Revision Guide*) and the Knowledge Cards set, all derived from
this wiki with consistent terminology, cross-references, and versioning.

---

*Previous: [← Ch 36 Glossary](36-glossary.md) · [Back to index →](../index.md)*
