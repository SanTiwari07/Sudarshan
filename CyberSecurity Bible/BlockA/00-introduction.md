# 00 - Introduction

> **Chapter ID:** `CH00` · **Block:** A (Foundations) · **Status:** Stable
> **Tags:** `#introduction` `#conventions` `#sudarshan` `#roadmap`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

---

## Table of Contents

1. [Why this knowledge base exists](#1-why-this-knowledge-base-exists)
2. [What SUDARSHAN is](#2-what-sudarshan-is)
3. [The threat landscape in one page](#3-the-threat-landscape-in-one-page)
4. [The Master Lifecycle](#4-the-master-lifecycle)
5. [How to read this knowledge base](#5-how-to-read-this-knowledge-base)
6. [Conventions used everywhere](#6-conventions-used-everywhere)
7. [The Ten Perspectives](#7-the-ten-perspectives)
8. [Chapter map](#8-chapter-map)
9. [Judge Insights](#9-judge-insights)
10. [Interview Insights](#10-interview-insights)
11. [Cross-references](#11-cross-references)
12. [References](#12-references)

---

## 1. Why this knowledge base exists

Most security documentation fails in one of two ways. Academic papers explain *what*
something is with mathematical precision and never tell you what to type. Vendor blogs
tell you what to type and never tell you *why* it works, so the moment reality deviates
from the blog post you are stranded.

This knowledge base refuses both failure modes. Every concept here is explained three
times, in this order:

1. **Intuition** - what problem does this solve, explained the way a senior engineer
   explains it at a whiteboard.
2. **Implementation** - the actual bytes, the actual API, the actual command.
3. **Enterprise relevance** - why a bank's SOC cares, and what SUDARSHAN must do about it.

If you finish a section and cannot explain it to a colleague without looking at the page,
that section failed you. Open an issue.

### Who this is for

| Reader | What they get |
|---|---|
| New engineer on SUDARSHAN | Onboarding path: read Blocks A→B→E in order |
| Malware analyst | Chapters 10–16 are your daily reference |
| SOC analyst | Chapters 17–20 plus the cheat sheets in Ch 33 |
| Reverse engineer | Chapters 02, 03, 08, 10–12 |
| Android developer | Chapters 01–09 explain why the platform fights you |
| Hackathon presenter | Ch 32 (misconceptions), Ch 34 (judge prep), Quick Revision Guide |
| Interview candidate | Ch 35 plus the Interview Insights at every chapter end |

### The 95% bar

The stated goal is that an engineering student who has internalised this document can
confidently answer 95%+ of technical questions from cybersecurity experts, Android
engineers, malware researchers, enterprise architects, banking professionals, investors,
hackathon judges, and interviewers.

That bar is only reachable if you can answer the *follow-up*. Anyone can memorise
"APK signature scheme v2 signs the whole file." The follow-up is "so why does v1 still
exist?" and then "what specifically breaks if I only use v1?" and then "name the CVE."
Every chapter is written to survive three follow-ups deep. See
[§9 Judge Insights](#9-judge-insights) for how this is drilled.

---

## 2. What SUDARSHAN is

**SUDARSHAN is an AI-powered enterprise malware investigation platform for banks.**

A bank's fraud team receives an APK. Maybe a customer's phone was drained and the APK
was pulled off the device. Maybe a threat-intel feed flagged it. Maybe a smishing SMS
pointed at a download URL. The question is always the same, and it is always urgent:

> *Is this malicious, what does it do to our customers, is it part of a campaign we've
> seen before, and what do we do in the next thirty minutes?*

Today that question is answered by a human analyst with a laptop, `jadx`, a VirusTotal
tab, and eight browser tabs of vendor blogs. It takes hours. It does not scale. It is
not reproducible. It produces a Word document that nobody can audit six months later
when a regulator asks how the conclusion was reached.

SUDARSHAN's job is to compress that into minutes, with evidence, reproducibly, at scale.

```
        ┌─────────────────────────────────────────────────────────┐
        │                      SUDARSHAN                          │
        │                                                         │
        │  APK in  ──►  [ Intake ]                                │
        │                   │                                     │
        │                   ├──► [ Static Analysis ]              │
        │                   ├──► [ Dynamic Detonation ]           │
        │                   ├──► [ Threat-Intel Enrichment ]      │
        │                   ├──► [ Campaign Correlation ]         │
        │                   │                                     │
        │                   ▼                                     │
        │            [ Risk Scoring ]                             │
        │                   │                                     │
        │                   ▼                                     │
        │   Investigation Report  ──►  SOC + Fraud Team  ──► out  │
        └─────────────────────────────────────────────────────────┘
```

The design of each of those boxes is Chapters 22–30. But you cannot design them until
you understand what an APK *is* (Block A), how to pull it apart (Block B), and what the
adversary actually does (Block C). Hence the ordering of this document.

### Design principles, stated up front

These recur in every chapter. Learn them now:

1. **No single signal is a verdict.** Not a VirusTotal count, not a permission, not
   obfuscation. Ever. (Ch 32 is entirely about this.)
2. **Confidence and severity are different axes.** "Definitely a banking trojan" and
   "probably something bad" are different rows in a queue.
3. **Every score must be explainable.** A bank operates under regulators. "The model
   said 87" is not an answer. Every point of score traces to an evidence artifact.
4. **Static and dynamic are complements, never substitutes.** Packers kill static.
   Evasion kills dynamic. Only fusion survives.
5. **Identity is the signer, not the package name.** This single idea prevents more
   analytical errors than any other in this document.

---

## 3. The threat landscape in one page

The reason this platform is worth building, in numbers with dates attached.

| Figure | Source | Date |
|---|---|---|
| 34 active Android banking malware families tracked | Zimperium zLabs *Banking Heist Report* | Mar 19, 2026 |
| 1,243 financial institutions targeted across 90 countries | Zimperium zLabs | Mar 19, 2026 |
| Android malware-driven fraudulent transactions **+67% YoY** | Zimperium zLabs | Mar 19, 2026 |
| Anatsa alone targets **831 financial institutions** | Zscaler ThreatLabz | Aug 2025 |
| 2.36 M policy-violating apps blocked from Google Play | Google Security Blog | 2024 in review |
| 158,000 developer accounts banned | Google Security Blog | 2024 in review |
| ~200 billion apps scanned daily by Play Protect | Google Security Blog | 2024 in review |
| 13 M+ new malicious apps found **outside** Google Play | Google Security Blog | 2024 in review |
| India: 13.42 lakh UPI fraud cases, ₹1,087 crore (FY23-24), **+85% YoY** | Lok Sabha (MoS Finance) | Nov 25, 2024 |
| India: ₹1,750 crore lost to cybercrime in first 4 months | I4C | 2024 |

Two things should jump out.

**First**, the 13 million figure. Play Protect finds an order of magnitude more malware
*outside* Google Play than the 2.36 million it blocks inside it. The sideloading channel
is where banking malware lives. This is why Chapter 09 (Package Manager) matters so much - the install pipeline is the battlefield.

**Second**, the Indian numbers. UPI fraud is not a subset of global mobile fraud; it is a
distinct ecosystem with its own lures ("PM Surya Ghar: Muft Bijli Yojana" campaigns),
its own C2 patterns (Firebase Cloud Messaging, Telegram), and its own regulatory context
(RBI, CERT-In's six-hour incident reporting mandate, the DPDP Act 2023). SUDARSHAN is
built for Indian banks first. Chapter 14 covers this specifically.

### What the adversary actually does

Strip away the family names and the 2020–2026 landscape converges on a single playbook:

```
  Smishing / fake Play page / Play-hosted dropper
                    │
                    ▼
       Dropper installs payload  ◄── uses session-based install API
                    │                to dodge Android 13/15 restrictions
                    ▼
      "Enable Accessibility to continue"   ◄── THE hinge of the entire attack
                    │
                    ▼
   Accessibility auto-grants remaining permissions by injecting taps
                    │
        ┌───────────┼────────────┬──────────────┐
        ▼           ▼            ▼              ▼
   Overlay      Keylogging   SMS / Notif    Hidden VNC
   phishing     via a11y     OTP theft      screen control
        │           │            │              │
        └───────────┴────────────┴──────────────┘
                    │
                    ▼
        On-Device Fraud (ODF) / Device Takeover (DTO)
        Transaction initiated FROM the victim's own device,
        from the victim's own IP, on the victim's own
        already-authenticated banking session.
```

That last box is why traditional bank fraud controls fail. Device fingerprinting passes.
Geolocation passes. Behavioural biometrics *can* catch it but often don't. The
transaction is genuinely coming from the customer's phone - because the criminal is
driving the customer's phone.

**Accessibility Service abuse is the single highest-value detection target in this
entire document.** Everything in Block C orbits it.

---

## 4. The Master Lifecycle

Every chapter plugs into this spine. When you are lost, come back here and ask "which
box am I in?"

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                          THE MASTER LIFECYCLE                            │
 └──────────────────────────────────────────────────────────────────────────┘

   APK exists somewhere                                         [Ch 02, 08]
          │
          ▼
   Download (Play / sideload / dropper)                         [Ch 09]
          │
          ▼
   PackageInstaller session opened                              [Ch 09]
          │
          ▼
   Signature verification (v1/v2/v3/v3.1/v4)                    [Ch 07]
          │
          ▼
   Certificate / signer identity established                    [Ch 06]
          │
          ▼
   Installed: UID assigned, sandbox created, SELinux labels     [Ch 04]
          │
          ▼
   Permissions requested & granted                              [Ch 04]
          │
          ▼
   dexopt / ART compilation                                     [Ch 03]
          │
          ▼
   Execution: Zygote fork → process → components                [Ch 01, 03]
          │
          ▼
   Malicious behaviour (a11y, overlay, OTP, VNC, ATS)           [Ch 13, 14]
          │
   ═══════╪═══════════ investigation begins ═══════════════════════════════
          │
          ▼
   Static Analysis (unpack, decompile, signature, manifest)     [Ch 10, 11]
          │
          ▼
   Dynamic Analysis (detonate, hook, observe C2)                [Ch 12]
          │
          ▼
   Threat Intelligence enrichment                               [Ch 16, 30]
          │
          ▼
   IOC Extraction                                               [Ch 26]
          │
          ▼
   Campaign Correlation                                         [Ch 15, 28]
          │
          ▼
   Risk Scoring                                                 [Ch 27]
          │
          ▼
   Investigation Report                                         [Ch 29]
          │
          ▼
   SOC Response                                                 [Ch 19]
          │
          ▼
   Incident Response / fraud containment                        [Ch 20]
```

Notice the vertical line in the middle. Everything above it is the *adversary's*
lifecycle. Everything below is *ours*. A good analyst can point at any artifact and say
which box of the adversary's lifecycle produced it. That is the core skill this document
teaches.

---

## 5. How to read this knowledge base

### Reading paths

**Path 1 - New engineer onboarding (4–6 weeks).**
`00 → 01 → 02 → 03 → 04 → 06 → 07 → 08 → 09` then `10 → 11 → 12`, then `13 → 14`, then
`22 → 27`. Skip Blocks D and F on first pass.

**Path 2 - I have an APK on my desk right now.**
Ch 33 (Cheat Sheets) → Ch 11 (Static Analysis) → Ch 12 (Dynamic Analysis) →
Ch 26 (IOC Extraction) → Ch 29 (Report). Come back for theory later.

**Path 3 - I'm presenting to judges tomorrow.**
Quick Revision Guide, then Ch 32 (Misconceptions), then Ch 34 (Judge Prep). The
misconceptions chapter is the single highest-return-per-minute chapter in the document.

**Path 4 - I'm interviewing next week.**
Ch 35, plus the *Interview Insights* section at the end of every chapter. Those sections
are written from real question patterns, not invented.

### Block structure

| Block | Chapters | Theme |
|---|---|---|
| **A** | 00–09 | Foundations: Android, APK, runtime, security model, signing |
| **B** | 10–12 | Analysis craft: RE, static, dynamic |
| **C** | 13–16 | The adversary: malware, banking malware, infra, threat intel |
| **D** | 17–21 | Operations: forensics, hunting, SOC, IR, AI |
| **E** | 22–30 | Building SUDARSHAN |
| **F** | 31–37 | Reference: gaps, misconceptions, cheat sheets, prep, glossary |

---

## 6. Conventions used everywhere

### Chapter anatomy

Every chapter has the same skeleton, so you always know where to look:

```
Header block (ID, block, tags, version, last-updated)
Table of Contents
1..N  Body sections
      └─ each concept answers: WHAT / WHY / HOW / WHEN / WHERE / LIMITATIONS
Ten Perspectives table (where relevant)
Detection Logic (what SUDARSHAN should do)
Limitations & Edge Cases
False Positives / False Negatives
Engineering Tips
Judge Insights
Interview Insights
Cross-references
References
```

### Callout types

> **⚙️ Engineering Note** - a practical detail that will bite you in code.

> **🏛️ Enterprise Insight** - why a bank, regulator, or SOC lead cares.

> **⚖️ Judge Tip** - the thing that impresses in a five-minute demo Q&A.

> **🚨 Misconception** - a widely believed wrong thing. Full list in Ch 32.

> **🔬 Research Gap** - genuinely unsolved. Do not claim we solved it.

### Notation

- `API 33` means Android API level 33. Android *version* (13) and *API level* (33) are
  not the same number and are never used interchangeably in this document. See the
  mapping table in Ch 04.
- Version-gated behaviour is always written as **"Android 14 (API 34)+"**, never just
  "modern Android."
- Malware family names are given with the **naming vendor** on first use in a chapter,
  e.g. *Anatsa (ThreatFabric; also TeaBot per Cleafy; also Toddler)*. Vendor naming
  diverges and pretending otherwise causes real analytical errors.
- Commands are shown with a `$` prompt for host, `#` for on-device root shell.
- Hashes, C2 domains, and package names taken from published research are reproduced
  verbatim so they are greppable. They are **defanged** where they are live infrastructure
  (`dksu[.]top`).

### Cross-reference format

Inline references look like `[→ Ch 07 §3 APK Signature Scheme v2](../security/07-apk-signing.md#3-apk-signature-scheme-v2)`.
Every chapter ends with a Cross-references section listing both *upstream* (what you
should have read first) and *downstream* (what this enables).

### Versioning

Every file carries `Version: MAJOR.MINOR.PATCH` and `Last Updated`. Bump MINOR when
adding a section, PATCH for corrections, MAJOR when the chapter's structure changes.
Threat-intel content ages fastest - anything in Blocks C and D older than 12 months
should be treated as needing re-verification.

---

## 7. The Ten Perspectives

The same artifact means ten different things to ten different readers. Training yourself
to switch between these is what separates an analyst from a tool operator. This table
recurs throughout the document; here is the canonical version using a single example - **an app requesting `BIND_ACCESSIBILITY_SERVICE`**.

| Perspective | How it sees a11y request |
|---|---|
| **Android (the OS)** | A legitimate API for users with disabilities. Gated behind a settings toggle and, since Android 13, behind Restricted Settings for non-session-installed apps. |
| **Google (the platform owner)** | A policy-controlled surface. Play policy requires justification; misuse is grounds for removal and developer-account ban. |
| **An Antivirus** | A signature/heuristic input. On its own, near-worthless - thousands of legitimate apps use it. |
| **VirusTotal** | Not directly visible. VT reports *engine verdicts*, not capability. You must read the behavioural/details tabs. |
| **MobSF** | A flagged permission in the static report, contributing to the security score. Contributes noise if read alone. |
| **Malware Analyst** | The hinge. First question: what does the `accessibilityservice` XML config declare, and what does `onAccessibilityEvent` actually do? |
| **Reverse Engineer** | An entry point to trace. Find the service class, walk `onAccessibilityEvent`, look for `performGlobalAction`, `ACTION_CLICK` injection, and node-text harvesting. |
| **SOC Analyst** | An alert-triage attribute. Correlate with overlay permission, install source, and device telemetry before escalating. |
| **Enterprise Security Team** | A policy control point. MDM/UEM can block a11y-abusing apps; MTD can alert on them. |
| **SUDARSHAN** | A **high-weight cluster member**, never a standalone verdict. Scored only in combination with `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, dynamic code loading, and install-source anomalies. |

> **🚨 Misconception preview:** "The app requests accessibility, therefore it's malware."
> False, and it will generate a false-positive rate that gets your platform ignored.
> Password managers, screen readers, automation tools, and accessibility utilities all
> legitimately need it. The signal is the *cluster*, not the permission. → Ch 32.

---

## 8. Chapter map

### Block A - Foundations (this block)

| # | Chapter | One-line purpose |
|---|---|---|
| 00 | Introduction | You are here. Conventions and the master lifecycle. |
| 01 | [Android Internals](android/01-android-internals.md) | The stack, Zygote, Binder, components. |
| 02 | [APK Architecture](apk/02-apk-architecture.md) | What an APK *is*, conceptually and structurally. |
| 03 | [Android Runtime](android/03-android-runtime.md) | ART, dexopt, class loading, JNI, reflection. |
| 04 | [Android Security Model](security/04-android-security-model.md) | Sandbox, UID, SELinux, permissions, version gates. |
| 05 | [Android Cryptography](security/05-android-cryptography.md) | Keystore, TEE/StrongBox, attestation, crypto misuse. |
| 06 | [Certificates](security/06-certificates.md) | X.509, self-signed trust, fingerprints, identity. |
| 07 | [APK Signing](security/07-apk-signing.md) | v1→v4, rotation, Janus/Master Key/Fake ID. |
| 08 | [APK File Format](apk/08-apk-file-format.md) | Byte level: ZIP, AXML, resources.arsc, DEX. |
| 09 | [Package Manager](apk/09-package-manager.md) | Install pipeline, sessions, dropper abuse. |

### Blocks B–F - forthcoming

| # | Chapter | Block |
|---|---|---|
| 10–12 | Reverse Engineering · Static Analysis · Dynamic Analysis | B |
| 13–16 | Android Malware · Banking Malware · Malware Infrastructure · Threat Intelligence | C |
| 17–21 | Digital Forensics · Mobile Threat Hunting · Enterprise SOC · Incident Response · AI-assisted Analysis | D |
| 22–30 | Building SUDARSHAN · Detection Pipeline · Threat Intake · Investigation Engine · IOC Extraction · Risk Scoring · Campaign Correlation · Investigation Reports · TI Database | E |
| 31–37 | Future Research · Common Misconceptions · Cheat Sheets · Judge Prep · Interview Prep · Glossary · References | F |

---

## 9. Judge Insights

> **What judges ask first:** *"What does SUDARSHAN actually do that VirusTotal doesn't?"*

**Perfect answer:** VirusTotal tells you *whether* engines think a file is bad. It does
not tell you what the malware does to *our* customers, whether it belongs to a campaign
we've seen, or what the fraud team should do in the next thirty minutes. SUDARSHAN
produces an investigation, not a verdict - capability mapping to MITRE ATT&CK Mobile,
extracted C2 infrastructure, campaign linkage by signer fingerprint and code similarity,
and an explainable risk score a regulator can audit. Also: VirusTotal is a multi-engine
aggregator, not an antivirus, and treating its detection count as a verdict is one of the
most common errors in the field.

**Common mistake:** Saying "we use AI to detect malware." Judges hear this fifty times a
day. Say instead what the AI *specifically* does (triage summarisation of decompiled code,
IOC extraction, report drafting - always human-in-the-loop) and what it explicitly does
*not* do (produce the verdict autonomously, because banks operate under explainability
requirements).

**Likely follow-ups:**
- *"How do you avoid false positives?"* → Cluster-based scoring, confidence separated
  from severity, and the misconception list in Ch 32.
- *"What if the malware detects your sandbox?"* → That's why static and dynamic are
  fused; also real devices over emulators. → Ch 12.
- *"Isn't Google already solving this?"* → Play Protect found 13 M malicious apps
  *outside* Play in 2024 alone. The platform is a layer, not a solution, and banks carry
  the fraud loss regardless.

**Fact that impresses:** Anatsa reached the **#4 spot in Google Play's Top Free Tools
category** (ThreatFabric, June 2025) before pushing its malicious update - roughly six
weeks after a clean release. Droppers ship clean, then update. That is why one-time
store review cannot be the only control.

---

## 10. Interview Insights

**Q: "Walk me through what happens when a user installs an APK."**
This is the single most common Android-security screening question. The interviewer is
checking whether you know the pipeline or just the vocabulary. Answer using the Master
Lifecycle in §4: download → PackageInstaller session → signature verification →
certificate/signer identity → UID assignment and sandbox creation → permission grants →
dexopt → first launch via Zygote fork. Named stages beat vague description every time.

**Q: "How would you tell if an APK is malicious?"**
Beginner mistake: listing permissions. Senior answer: "No single indicator is sufficient.
I'd look for a capability *cluster* - accessibility service plus overlay plus SMS or
notification access plus dynamic code loading - then corroborate with signer reputation,
install-source, and C2 behaviour under detonation. Then I'd check whether the signer
certificate or the C2 infrastructure links to a known campaign."

**Q: "What's the difference between a certificate, a signature, and a hash?"**
Asked constantly, failed constantly. See Ch 06 and Ch 07. Short version: the **hash**
identifies exact bytes of one artifact; the **signature** proves those bytes weren't
modified after signing; the **certificate** identifies who did the signing. An attacker
controls the hash trivially (change one byte). They cannot forge the signer without the
private key. That's why *signer fingerprint* is the durable identifier, not the hash and
absolutely not the package name.

**Beginner mistake to avoid:** treating "obfuscated" as "malicious." Practically every
commercial banking app on the Play Store is obfuscated with R8 or DexGuard. Obfuscation
is a weighted signal in context, never a verdict.

---

## 11. Cross-references

**Downstream (this chapter enables):**
- [→ Ch 01 Android Internals](android/01-android-internals.md) - the stack the lifecycle runs on
- [→ Ch 32 Common Misconceptions](appendix/32-common-misconceptions.md) - the design principles of §2 in full
- [→ Ch 22 Building SUDARSHAN](sudarshan/22-building-sudarshan.md) - the architecture sketched in §2

**Related concepts:**
- Accessibility abuse → Ch 13 · Overlay attacks → Ch 13 · ODF/DTO → Ch 14
- Risk scoring philosophy → Ch 27 · Explainability requirements → Ch 21, Ch 29

---

## 12. References

1. Google Security Blog - *How we kept the Google Play & Android app ecosystems safe in 2024* (2025). https://security.googleblog.com/
2. Zimperium zLabs - *Banking Heist Report* (March 19, 2026).
3. Zscaler ThreatLabz - *Anatsa's Latest Updates* (August 2025).
4. ThreatFabric - Anatsa Google Play dropper campaign analysis (July 2025).
5. Lok Sabha, Ministry of Finance (MoS Pankaj Chaudhary) - UPI fraud statistics, winter session (disclosed Nov 25, 2024).
6. Indian Cyber Crime Coordination Centre (I4C) - cybercrime loss figures (2024).
7. Android Developers - *Platform Architecture*. https://developer.android.com/guide/platform
8. MITRE ATT&CK for Mobile. https://attack.mitre.org/matrices/mobile/
9. OWASP MASVS v2.1.0 (January 18, 2024). https://mas.owasp.org/MASVS/

### Further reading
- OWASP Mobile Application Security Testing Guide (MASTG)
- NIST SP 800-163 Rev.1 - *Vetting the Security of Mobile Applications*
- Google Project Zero blog - Android research archive

---

*Next: [Chapter 01 - Android Internals →](android/01-android-internals.md)*
