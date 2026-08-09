# 34 - Judge Preparation

> **Chapter ID:** `CH34` · **Block:** F (Reference) · **Status:** Stable
> **Tags:** `#judges` `#demo` `#presentation` `#qa` `#hackathon` `#pitch`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

> **This chapter synthesises.** Every chapter already carries its own *Judge Insights*. This one
> covers what those can't: **demo choreography, cross-cutting question patterns, judge archetypes,
> and failure recovery.**

---

## Table of Contents

1. [What judges are actually scoring](#1-what-judges-are-actually-scoring)
2. [The judge archetypes](#2-the-judge-archetypes)
3. [The five-minute demo](#3-the-five-minute-demo)
4. [The opening ninety seconds](#4-the-opening-ninety-seconds)
5. [Question patterns and how to handle them](#5-question-patterns-and-how-to-handle-them)
6. [The twelve facts that land](#6-the-twelve-facts-that-land)
7. [Things that lose the room](#7-things-that-lose-the-room)
8. [Recovering from a bad moment](#8-recovering-from-a-bad-moment)
9. [The one-page crib](#9-the-one-page-crib)

---

## 1. What judges are actually scoring

Rarely the thing teams optimise for.

| What teams optimise | What judges score |
|---|---|
| Feature count | **Does this solve a real problem?** |
| UI polish | Does the team understand the domain? |
| "We use AI" | Do they know what their system *can't* do? |
| Volume of slides | Can they answer three follow-ups deep? |
| Technical complexity | Is the technical claim *true*? |

### The scoring reality

```
   A team that says "we do X, Y, Z"          → sounds impressive, scores medium
   and can't survive a follow-up

   A team that says "we do X, here's the      → scores high
   evidence, and here's what we deliberately
   don't do and why"
```

> **⚖️ The single most useful preparation:** for every claim you plan to make, prepare the
> **three-follow-ups-deep answer**. Anyone can say "APK signature scheme v2 signs the whole file."
> The follow-ups are "so why does v1 still exist?", "what specifically breaks if I only use v1?",
> and "name the CVE." Depth is what separates a memorised pitch from understanding.

---

## 2. The judge archetypes

You will usually face two or three of these. Read the room early and adapt.

### 🔧 The Security Practitioner
*Works in security. Will find your overclaim.*

**Asks:** "How do you handle packed samples?" · "What's your false positive rate?" · "Isn't this
just MobSF plus VirusTotal?"

**Wins them by:** technical precision, volunteered limitations, correct version-gating.
**Loses them by:** claiming completeness, saying "exploit" for accessibility abuse, quoting
random-split ML accuracy.

### 🏦 The Domain Expert (banking / fraud)
*Understands fraud, not Android internals.*

**Asks:** "How does this change what my fraud team does?" · "What's the false positive cost to
customers?" · "Which of my controls actually fail?"

**Wins them by:** the ODF explanation, the "what NOT to rely on" list, the money clock.
**Loses them by:** ATT&CK technique IDs with no translation, no customer-impact framing.

### 💰 The Investor / Business Judge
*Assessing whether this is a company.*

**Asks:** "Who pays for this?" · "Why can't Google just fix it?" · "What's the moat?"

**Wins them by:** the 13-million-outside-Play number, the compounding-corpus argument, non-goals.
**Loses them by:** technical depth with no business translation, no market sizing.

### 🎓 The Academic
*Assessing rigour.*

**Asks:** "How did you evaluate?" · "What's your baseline?" · "Is that reproducible?"

**Wins them by:** temporal splits, hard-negative corpus, named research gaps, cited sources.
**Loses them by:** unevaluated claims, Drebin results presented as current.

> **⚖️ Judge Tip:** When you don't know the archetype, **lead with the problem and the numbers**
> (which works for all four), then let their first question tell you which register to use.

---

## 3. The five-minute demo

Choreographed so the strongest thing happens first and the technical depth is *shown*, not claimed.

```
 0:00 ─ 0:45  THE PROBLEM
              "A bank's fraud team has an APK and 30 minutes before the
               money is gone. Today that takes a human analyst hours."
              One number: UPI fraud +85% YoY, ₹1,087 crore FY23-24.

 0:45 ─ 1:45  ★ THE KILLER DEMO - signer impersonation
              Two APKs side by side. Same package name: com.clientbank.app.
              Different certificate fingerprints.
              → instant CRITICAL verdict, cryptographic justification, no ML.
              "Identity on Android is the signing key, not the package name.
               Anyone can type a package name; only the bank has the key."

 1:45 ─ 3:00  THE REAL CASE - a dropper
              Submit a clean-looking PDF reader. Static: benign.
              → detonate → package-list diff → NEW PACKAGE APPEARS
              → child artifact analysed → malicious
              → ★ score propagates UP: the dropper is now critical
              "Anatsa's dropper reached #4 in Play's Top Free Tools before
               turning malicious six weeks after a clean release."

 3:00 ─ 4:00  THE BANK-FACING OUTPUT
              Show the extracted overlay TARGET LIST containing the client's
              package. Show the affected-customer sweep by signer.
              "One submission tells four banks they're being targeted."

 4:00 ─ 4:30  EXPLAINABILITY
              Click any score line → file, line number, log offset, timestamp.
              "This is what we hand a regulator."

 4:30 ─ 5:00  WHAT WE DON'T DO
              Non-goals + the accessibility gap.
              "We don't claim to prevent this. We compress time-to-informed-
               response, and we never report clean on something we couldn't read."
```

### Why this order

| Slot | Purpose |
|---|---|
| Signer demo first | **Deterministic, instant, visually obvious, zero ML.** Establishes credibility before anything subjective. |
| Dropper second | Shows the hard case and proves the recursion design |
| Target list third | The business-value moment for a domain judge |
| Explainability fourth | The regulated-buyer moment |
| Non-goals last | Signals maturity; pre-empts the "what can't you do" question |

> **⚖️ Judge Tip:** Never open with architecture diagrams. Open with **two APKs and a verdict**.
> Judges have seen a hundred architecture slides that afternoon; they have not seen a
> cryptographic impersonation check fire in thirty seconds.

---

## 4. The opening ninety seconds

Rehearse this verbatim. Everything else can be adaptive; this cannot.

> "A bank's fraud team gets an APK - pulled off a customer's phone after a disputed transfer. They
> need to know four things: is it malicious, does it target *us*, which of our customers have it,
> and what do we do right now. Under UPI the money is through a mule chain in minutes, so a correct
> answer in four hours is correct and useless.
>
> Today a human analyst answers that with jadx and a VirusTotal tab, in hours, unreproducibly.
> SUDARSHAN answers it in minutes, with every claim traceable to a file and a line - because the
> bank has to defend that answer to RBI nine months later.
>
> Let me show you the simplest case first."
>
> *[two APKs, same package name, different fingerprint → critical]*

**Why it works:** states the problem in the customer's words, quantifies urgency, names the
incumbent (a human with tools), states the differentiator (speed + defensibility), and moves to
demo inside ninety seconds.

---

## 5. Question patterns and how to handle them

### Pattern A - "Isn't this just [existing tool]?"

*MobSF · VirusTotal · antivirus · a SIEM*

**Structure:** acknowledge what the tool does well → name the *different question* you answer →
one concrete example.

> "MobSF is genuinely good and we use it as a baseline. But it scores **security hygiene**, not
> maliciousness, and those are frequently anti-correlated - a hardened bank app with pinning and
> obfuscation grades badly, while a dropper with three permissions grades well because the payload
> isn't there yet. The bank's question isn't 'is this app well-built', it's 'is our package name in
> this malware's target list and which of our customers have it installed.'"

### Pattern B - "Why can't Google/Android just fix this?"

**Structure:** they have tried, repeatedly → name the specific changes with versions → explain the
structural reason it persists.

> "They have - Android 13 added Restricted Settings, Android 15 tied accessibility eligibility to
> the session-based install API. Malware adapted both times; droppers simply adopted the session
> API to look like a legitimate store. The structural problem is that accessibility genuinely needs
> read and write over every app's UI for assistive technology, and there's no shipped mechanism for
> scoped accessibility. Meanwhile Play Protect found 13 million malicious apps *outside* Play in
> 2024 - six times what it blocked inside - and the bank carries the fraud loss regardless."

### Pattern C - "How do you know it's accurate?" / "False positive rate?"

**Structure:** reject the single-number framing → explain per-action calibration → name your hard
negatives.

> "It depends on the action, deliberately. Critical triggers customer-visible containment, so we
> target under 1%. Medium just queues something, so 20% is fine. A single global threshold either
> drowns analysts or misses threats. And we calibrate against a hard-negative corpus that
> deliberately includes password managers, TeamViewer, MDM agents, and the client bank's own
> production app - because a scorer that flags the most-hardened app on the device is a predictable
> and embarrassing failure."

### Pattern D - "What about the AI?"

**Structure:** state where it doesn't decide → state what it does → give the regulatory reason.

> "The AI never produces the verdict. Deterministic rules do, with every point of score traced to a
> file and line. ML does similarity clustering and queue ordering. LLMs summarise decompiled code
> and draft reports, grounded with mandatory evidence citations. That's not caution for its own
> sake - a bank has to explain a held session to a regulator, and 'the model said 0.87' fails while
> 'the accessibility config declares canPerformGestures at line 6' survives."

### Pattern E - "What can't you do?"

**Never deflect.** This is a gift.

> "Three things. We can't detect a payload that doesn't exist yet - droppers are clean at analysis
> time, which we handle with installer attribution and detonation-time package diffing rather than
> pretending. We can't guarantee unpacking, so samples we couldn't read carry a confidence ceiling
> and are reported inconclusive, never clean. And we don't do actor attribution - family and
> campaign, yes; who the humans are, no. Anyone claiming that from an APK is overselling."

### Pattern F - the hostile technical probe

*"You said X. But actually Y, doesn't that break it?"*

**Structure:** if they're right, **concede immediately and precisely** → show you understand the
implication → say what you'd do.

> "You're right - Android 14 blocked loading from world-writable files specifically, not dynamic
> code loading generally. An app can still load DEX from its own private read-only storage or from
> memory. That's exactly why we hook the class loaders rather than relying on the platform
> restriction."

Conceding a point precisely scores **higher** than defending a wrong one. Judges are testing
whether you know the boundary.

---

## 6. The twelve facts that land

Deploy sparingly - one or two per answer, never a recital.

| # | Fact | Deploy when asked about |
|---|---|---|
| 1 | Anatsa's dropper reached **#4 in Play's Top Free Tools (June 29, 2025)** before turning malicious ~6 weeks after a clean May 7 release | Store review; droppers |
| 2 | Play Protect found **13M+ malicious apps outside Play** in 2024 vs 2.36M blocked inside | "Why isn't Google enough?" |
| 3 | **Android 14 blocks installing apps targeting below API 23** (`INSTALL_FAILED_DEPRECATED_SDK_VERSION`) because malware targeted API 22 to escape runtime permissions | Platform hardening |
| 4 | **Janus (CVE-2017-13156):** a file can be a valid ZIP *and* a valid DEX - ZIP parses from the end, DEX from the start. v1-only, Android 5.0–8.0, patched Dec 2017 | Why v2 exists |
| 5 | Crocodilus command **`TRU9MMRHBCRO`** adds a fake "Bank Support" contact so vishing calls show a trusted name | Social engineering sophistication |
| 6 | **ToxicPanda uses AES-ECB** - deterministic, so C2 traffic is fingerprintable *without the key* | Crypto; detection creativity |
| 7 | **ERMAC 3.0 source leaked** via an open directory (Hunt.io, Aug 2025) exposing a hardcoded JWT secret and default root credentials | Attribution; adversary opsec |
| 8 | Zscaler (Aug 2025): **Anatsa dropped remote DEX loading for direct install** - so class-loader-only detection misses it | Why two staging detections |
| 9 | **Vultur** (2021) was the first Android banker to drop overlays for VNC - an *economic* shift, not just technical | Technique evolution |
| 10 | **MobSF's formula** penalises high-severity findings regardless of context, so a hardened bank app grades worse than a clean dropper | Tooling limits |
| 11 | **Safe Mode** disables all third-party apps and their accessibility services - defeating uninstall interception, overlay obstruction, and watchdogs in one step | Remediation |
| 12 | **ART and Conscrypt are Mainline modules** updated via Play, so two "Android 14" devices can behave differently | Reproducibility |

---

## 7. Things that lose the room

| ❌ Never say | Why it costs you |
|---|---|
| "The malware exploits a vulnerability" | It abuses a documented API with consent. Signals you haven't read primary research. |
| "We use AI to detect malware" | Judges hear it fifty times. Say what it specifically does *and doesn't*. |
| "99% accuracy" | On a random split that measures memorisation. Say temporal split. |
| "We prevent mobile banking fraud" | You compress time-to-response. Overclaim invites disproof. |
| "VirusTotal shows 42/70, so it's Anatsa" | VT is an aggregator; labels are inconsistent. |
| "It's obfuscated, so it's suspicious" | Every Play app is. Including the client's. |
| "Medusa" (unqualified) | Three unrelated things share the name. |
| "Android blocks that now" | Version-gate it or don't say it. |
| "We're better than [named vendor]" | Reads as inexperience. Say what's *different*. |
| "That's a great question" (filler) | Costs two seconds of credibility. Just answer. |

---

## 8. Recovering from a bad moment

### You don't know the answer

> "I don't know. My instinct is [X] because [reason], but I'd want to check before telling you
> something wrong."

**This scores well.** Fabricating scores terribly, and technical judges detect it instantly.

### You were wrong and they caught it

> "You're right, I overstated that. What's actually true is [correction]. Thank you - that matters
> for [specific implication]."

Concede fully, immediately, and precisely. Do not partially defend.

### The demo breaks

> "That's the live path failing - let me show you the recorded run and explain what should happen."

Never debug on stage. Have a recorded fallback. Move on within fifteen seconds.

### A judge is aggressively sceptical

Don't match energy. Get concrete and specific:

> "Fair challenge. Let me be precise about what we actually claim: [narrow, defensible claim].
> What we don't claim is [the thing they're attacking]."

Narrowing to a defensible claim converts an attack into a demonstration of judgement.

---

## 9. The one-page crib

```
┌──────────────────────────────────────────────────────────────────────┐
│ THE PROBLEM                                                          │
│  Bank has an APK + 30 min before the money's gone.                   │
│  UPI fraud +85% YoY → 13.42 lakh cases / ₹1,087 cr (FY23-24).        │
├──────────────────────────────────────────────────────────────────────┤
│ THE ATTACK (one sentence)                                            │
│  Dropper installs payload via session API → user enables Accessibility│
│  → read+write over every app's UI → fraud from the victim's own       │
│  device, IP, and authenticated session. Every device control passes.  │
├──────────────────────────────────────────────────────────────────────┤
│ THE DIFFERENTIATOR (P3 + P4)                                         │
│  Every verdict is evidence-linked and reproducible, AND we never      │
│  claim "clean" on a sample we couldn't actually analyse.              │
├──────────────────────────────────────────────────────────────────────┤
│ DEMO ORDER                                                           │
│  1 signer impersonation (30s, deterministic, no ML)                  │
│  2 dropper → recursion → score propagates UP                          │
│  3 target list names the client bank                                  │
│  4 click any score line → file + line + timestamp                     │
│  5 non-goals                                                          │
├──────────────────────────────────────────────────────────────────────┤
│ NON-GOALS (volunteer these)                                          │
│  not a SIEM · not an AV · no on-device agent · no autonomous          │
│  containment · no actor attribution · no reportability assertions     │
├──────────────────────────────────────────────────────────────────────┤
│ THE THREE FACTS                                                      │
│  • Anatsa dropper hit #4 in Play Top Free Tools before turning bad    │
│  • 13M+ malicious apps found OUTSIDE Play in 2024 (vs 2.36M inside)   │
│  • Anatsa now installs directly, not via DEX loading → need 2 detects │
├──────────────────────────────────────────────────────────────────────┤
│ NEVER SAY                                                            │
│  "exploits a vulnerability" · "99% accuracy" · "we prevent fraud"     │
│  "obfuscated = suspicious" · unqualified "Medusa" · "Android blocks    │
│  that now" (without an API level)                                     │
├──────────────────────────────────────────────────────────────────────┤
│ IF YOU DON'T KNOW                                                    │
│  "I don't know. My instinct is X because Y, but I'd check first."     │
└──────────────────────────────────────────────────────────────────────┘
```

---

*Previous: [← Ch 33 Cheat Sheets](33-cheat-sheets.md) · Next: [Ch 35 Interview Preparation →](35-interview-preparation.md)*
