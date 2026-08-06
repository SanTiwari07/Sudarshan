# 35 — Interview Preparation

> **Chapter ID:** `CH35` · **Block:** F (Reference) · **Status:** Stable
> **Tags:** `#interview` `#questions` `#preparation` `#careers` `#answers`
> **Last Updated:** 2026-08-05 · **Version:** 1.0.0

> **This chapter synthesises.** Every chapter carries its own *Interview Insights*. This one covers
> what those can't: **role-specific tracks, answer frameworks, the questions that separate levels,
> and how to handle not knowing.**

---

## Table of Contents

1. [What interviewers are testing](#1-what-interviewers-are-testing)
2. [Role tracks](#2-role-tracks)
3. [Answer frameworks](#3-answer-frameworks)
4. [The ten questions you will definitely get](#4-the-ten-questions-you-will-definitely-get)
5. [Level-separating questions](#5-level-separating-questions)
6. [The practical exercise](#6-the-practical-exercise)
7. [System design questions](#7-system-design-questions)
8. [Handling what you don't know](#8-handling-what-you-dont-know)
9. [Questions to ask them](#9-questions-to-ask-them)
10. [The 48-hour revision plan](#10-the-48-hour-revision-plan)

---

## 1. What interviewers are testing

Four things, in roughly this order of weight:

| # | Testing for | Detected by |
|---|---|---|
| 1 | **Depth vs recall** | Follow-ups. Everyone knows the definition; few know *why*. |
| 2 | **Practical experience** | Details only hands-on work teaches (`-wal` files, inlining, `apktool -s`) |
| 3 | **Calibrated honesty** | Whether you say "I don't know" or invent |
| 4 | **Reasoning under uncertainty** | "The sandbox showed nothing — what do you conclude?" |

```
   Junior answer:  "Static analysis examines code without running it."
   Mid answer:     + "It's fast and scalable but can't see dynamic behaviour."
   Senior answer:  + "And specifically it's blind to droppers, because the
                     payload isn't in the file at analysis time — Anatsa's
                     Play droppers were genuinely clean at review. So the
                     architectural consequence is that you must escalate on
                     *inability to analyse*, not just on findings."
```

**The senior differentiator is always the same shape: definition → limitation → architectural
consequence.**

---

## 2. Role tracks

### 🔬 Malware Analyst / Reverse Engineer

**Core:** Ch 03, 08, 10, 12, 13, 14
**Must know cold:** smali basics · DEX header fields · unpacking ladder · Frida hook library ·
family lineages · accessibility abuse mechanics

**Signature questions:**
- "Walk me through reverse engineering an APK."
- "How would you unpack a packed sample?"
- "You decompile and the methods are empty. What's happening?"
- "Explain the difference between Anatsa and Hook."

### 🛡️ SOC Analyst / Detection Engineer

**Core:** Ch 11, 16, 18, 19, 20
**Must know cold:** the capability cluster · MITRE mapping · Sigma structure · alert fatigue ·
triage tree · the money clock

**Signature questions:**
- "How would you triage an alert about a suspicious app on a customer device?"
- "Write a detection rule for accessibility abuse."
- "How do you measure a detection's quality?"
- "What's your incident response sequence?"

### 📱 Android Security Engineer

**Core:** Ch 01–09
**Must know cold:** permission model evolution · signing schemes v1–v4 · Binder and
`getCallingUid()` · version gates by API level · Keystore and attestation

**Signature questions:**
- "Explain the Android security model."
- "How does Android enforce permissions?"
- "Walk me through installing an APK."
- "What changed in Android 14 and 15 for security?"

### 🏗️ Security Platform / Backend Engineer

**Core:** Ch 22–30
**Must know cold:** tiered pipeline economics · artifact graph and recursion · evidence ledger ·
two-axis scoring · multi-tenant isolation

**Signature questions:**
- "Design a malware analysis platform."
- "How do you scale dynamic analysis?"
- "How do you make an automated verdict auditable?"
- "How do you correlate across customers who compete?"

### 🧠 Threat Intelligence Analyst

**Core:** Ch 14, 15, 16, 28, 30
**Must know cold:** Pyramid of Pain · Diamond Model · IOC lifecycle and TTLs · attribution limits ·
the leaked-source problem · vendor naming divergence

**Signature questions:**
- "What's the difference between data, information, and intelligence?"
- "How confident can you be in attribution?"
- "Two vendors name the same malware differently. What do you do?"
- "How would you handle a DGA?"

---

## 3. Answer frameworks

### Framework 1 — WHAT / WHY / LIMIT

For any "explain X" question.

> **WHAT** it is (one sentence) → **WHY** it exists (the problem it solves) →
> **LIMIT** (where it breaks)

*"Certificate pinning makes an app refuse connections unless the server's key matches a pinned
value. It exists because the CA system is a weak link — a rogue or compromised CA, or a
user-installed CA, would otherwise be trusted. Its limit is that it protects data **in transit**;
accessibility-based malware reads the plaintext off the screen before TLS is involved, so pinning is
the wrong layer for that threat."*

### Framework 2 — DEFINITION → CONSEQUENCE

For "what's the difference between X and Y."

> Both definitions → the *operational* consequence of the difference

*"A hash identifies a specific file; a signer certificate identifies who signed it. The consequence
is that hashes are useless for identity — an adversary changes one byte, and Play itself produces
multiple hashes per version through split APKs — whereas the signer survives rebuilds because they
need that key to update their own victims."*

### Framework 3 — LAYERS

For "how does X work."

> Work through the stack, naming each layer

*"Permission enforcement: the app calls an SDK method, which is a Binder proxy. The kernel's Binder
driver records the caller's UID unspoofably. The system service receives the transaction and calls
`Binder.getCallingUid()`, then checks whether that UID holds the permission. That's why patching
your own client-side `checkSelfPermission()` achieves nothing — the check happens in the service,
not in your process."*

### Framework 4 — THE HONEST NEGATIVE

For "the analysis showed nothing" / "how do you know."

> State what you *can't* conclude → give the alternative explanations → state the action

*"I can't conclude it's clean. It could have detected the sandbox, been geofenced away from my
environment, been time-delayed, or its C2 could be offline. So I'd record it as inconclusive with a
confidence ceiling, requeue for re-detonation, and check whether the static analysis showed evasion
logic."*

---

## 4. The ten questions you will definitely get

### Q1. "Walk me through what happens when an APK is installed."
Session created (**installer recorded**) → parse manifest → **targetSdk gate** (A14: <API 23 blocked,
A15: <24) → signature verification (v3.1→v3→v2→v1; v1-only rejected from API 30) → **signer TOFU
check** → user confirmation → Play Protect scan → commit (UID, sandbox, SELinux label) → permission
grants → dexopt → register in `packages.xml` + broadcast.
*Naming the failure codes at each gate is the senior marker.* → [Ch 09](../apk/09-package-manager.md)

### Q2. "Certificate vs signature vs hash?"
Certificate = **who signed** (identity, survives rebuilds). Signature = **integrity of these bytes**
(new every build). Hash = **which file** (changes on any byte). Punchline: **identity is the
certificate; the hash is only an IOC.** → [Ch 06 §9](../security/06-certificates.md#9-certificate--signature--hash)

### Q3. "Static or dynamic analysis — which matters more?"
A trap. Neither, because the blind spots are **complementary**: static can't see droppers, packed
code, or conditional behaviour; dynamic can't see unexecuted paths, evaded runs, or anything if the
C2 is dead. Give one concrete example of each. → [Ch 12 §1](../dynamic-analysis/12-dynamic-analysis.md#1-why-dynamic-analysis-exists)

### Q4. "How does Android banking malware steal money?"
Don't say "phishing." Walk the chain: dropper installs payload via the **session API** to escape
Restricted Settings → user enables Accessibility → `canPerformGestures` self-grants the rest →
package enumeration finds target banks → overlay or Hidden VNC harvests credentials →
SMS/notification/screen-read captures the OTP → transfer initiated **on-device**. Land on **On-Device
Fraud**. → [Ch 13 §2](../malware/13-android-malware.md#2-the-unified-playbook)

### Q5. "An app has accessibility and overlay permissions. Malware?"
Insufficient. Password managers, screen readers, automation tools, and remote-support apps all
qualify. Ask for the **cluster**, the signer reputation, the installer, and the runtime behaviour.
→ [Ch 32 M9](32-common-misconceptions.md#-m9--a-dangerous-permission-means-malware)

### Q6. "Explain Janus."
A file can be a valid ZIP **and** a valid DEX — ZIP is parsed from the end, DEX from offset 0.
Prepend a malicious DEX to a v1-signed APK: the signature verifier sees the untouched archive and
passes; ART loads the prepended DEX. **CVE-2017-13156**, Android 5.0–8.0, **v1-only**, patched
December 2017, structurally impossible under v2's whole-file digest.
→ [Ch 07 §9](../security/07-apk-signing.md#9-the-three-classic-attacks)

### Q7. "How does Android enforce permissions?"
Not in the calling app — in the **service**, using `Binder.getCallingUid()`, which the kernel
supplies and the caller cannot spoof. → [Ch 01 §6](../android/01-android-internals.md#6-binder-ipc)

### Q8. "How would you unpack a packed APK?"
The principle: **the runtime must see plaintext DEX to execute it.** Hook `InMemoryDexClassLoader`
and `DexClassLoader` and dump at that moment; failing that, memory-scan for DEX magic and carve;
failing that, extract from `.vdex`; failing that, reverse the native unpacker at `JNI_OnLoad` —
checking `.init_array` first, because constructors run before it.
→ [Ch 10 §9](../reverse-engineering/10-reverse-engineering.md#9-unpacking-strategy)

### Q9. "The sandbox ran the sample and nothing happened. Conclusion?"
**Not clean.** Sandbox detection, geofencing (ERMAC excludes CIS nations), time delay, C2 offline,
no decoy target apps installed, or no user interaction simulated. Record **inconclusive** with a
confidence ceiling and requeue. *This question tests analytical honesty more than knowledge.*

### Q10. "How would you remove this from a customer's device?"
**Isolate → acquire → remediate**, never reordered. Airplane mode (BRATA and BingoMod wipe on
detection); acquire evidence; **Safe Mode** (disables third-party apps and their accessibility
services); revoke device admin; uninstall; verify; **then** credential reset — because resetting on
an infected device hands the attacker the new credentials.
→ [Ch 20 §10](../incident-response/20-incident-response.md#10-the-device-remediation-runbook)

---

## 5. Level-separating questions

These distinguish mid from senior. The junior answer isn't *wrong* — it's incomplete.

| Question | Junior | Senior |
|---|---|---|
| "Is obfuscation suspicious?" | "It can be." | "No — R8 is on by default, every Play app is obfuscated including the client's bank app. Discriminate on signer, capability cluster, and behaviour." |
| "How do you identify a malware family?" | "Hashes and signatures." | "Signer cert first, then DEX-level TLSH, then infrastructure. And after the Cerberus, Octo, SpyNote, and ERMAC leaks, code similarity means *lineage*, not actor." |
| "What's VirusTotal for?" | "Checking if a file is malicious." | "Enrichment — first-seen, submission geography, related samples, Retrohunt. It's an aggregator; fresh droppers score 0/70 and engines copy each other's labels." |
| "Why did your Frida hook not fire?" | "Maybe it detected Frida." | "Inlining first, then wrong overload, then a different process, then a different class loader — *then* Frida detection." |
| "How do you evaluate an ML malware model?" | "Accuracy on a test set." | "Temporal split, never random — a random split leaks same-family variants and measures memorisation. And check the hard-negative corpus." |
| "You pulled an app's database and it's empty." | "Maybe there's no data." | "You missed the `-wal` file. WAL means recent transactions live there until checkpointed." |
| "Does 2FA stop this?" | "It helps." | "Four routes past it: SMS interception, notification-listener reading, accessibility reading the authenticator code off screen, and tapping Approve. Per-transaction biometric is the control that holds." |
| "How fast should analysis be?" | "As fast as possible." | "Against the money clock, not a generic SLA — funds are through a mule chain in minutes, so we stream partial results and let containment act on medium confidence." |

---

## 6. The practical exercise

Many interviews hand you a sample or a scenario. The structure below works for almost any variant.

### "Here's an APK. Analyse it."

```
 SAY OUT LOUD AS YOU GO — they're scoring your process, not just your finding.

 1. "First, identity."      sha256 + apksigner --print-certs
                            → is the signer known? does it match the claimed package?
 2. "Now capability, cheaply."   apktool d -s → manifest + a11y config
                            → I'm looking for the cluster, not counting permissions
 3. "Is there an a11y service?"  read res/xml/*accessib*
                            → canRetrieveWindowContent + canPerformGestures = read+write over all UI
 4. "What's it targeting?"  grep package names in resources
 5. "Anything hidden?"      assets/ entropy, lib/ packer fingerprints, dex/so ratio
 6. "Strings."              const-string grep — if empty, strings are encrypted → go dynamic
 7. "Decide."               "I'd escalate to detonation because [cluster + staging machinery]"
```

**Do:** narrate reasoning · state what you'd check next and why · say what would change your mind
**Don't:** jump straight to jadx · count permissions · conclude from a single signal

### "The sandbox showed nothing. What now?"

Use **Framework 4** (§3). Then: check static for evasion logic, verify decoy apps were installed,
check locale/timezone matched the target region, confirm C2 reachability, and requeue.

---

## 7. System design questions

### "Design a malware analysis platform"

**Lead with constraints, not components.**

```
 1. CONSTRAINTS       response clock (minutes) · explainability (regulated buyer)
                      · cost gradient (10ms → hours) · complementary blind spots
 2. TIERED PIPELINE   T0-T2 on 100%, gate T3 (~20%), gate T4 (~5%), T5 (<1%)
                      ★ gates biased toward escalation; escalate on INABILITY to analyse
 3. DATA MODEL        graph — investigation is traversal (signer → samples → key → C2)
                      + separate columnar store for corpus hunting
 4. SCORING           two axes; cluster gate; confidence ceiling; evidence pointers
 5. RECURSION         dumped/installed artifacts re-enter the pipeline; score propagates UP
 6. OUTPUT            multi-audience; shared case ID with fraud ops
 7. NON-GOALS         not a SIEM, no autonomous containment, no actor attribution
```

**Follow-ups to expect:** "What's your bottleneck?" (device-bound T4, then humans) · "How many
devices?" (`samples × escalation_rate × minutes / (1440 × utilisation)`) · "How do you handle
multi-tenancy?" (share indicators, isolate submissions, enforce with RLS).

### "How would you detect [technique] at scale?"

Structure: **cheap static signal → escalation gate → dynamic confirmation → what would make it a
false positive → how you'd tune.** Always include the false-positive population — omitting it is the
most common failure in this question.

---

## 8. Handling what you don't know

### The formula

> "I don't know. My instinct is [X] because [reason]. I'd verify by [method]."

**Why it scores well:** it demonstrates reasoning, honesty, and a verification instinct — three
things the interview is actually testing. Fabricating fails all three and is usually detected.

### Adjacent recovery

If you don't know the specific thing, answer the adjacent thing you *do* know, and say so:

> "I haven't worked with Flutter reversing specifically. What I do know is that the logic lives in
> `libapp.so` as compiled Dart rather than in the DEX, so the general approach would be native RE
> plus a Dart-aware tool like reFlutter. I'd want to actually do it before claiming more."

### Never do this

| ❌ | Why |
|---|---|
| Invent a CVE number or a date | Trivially checked; ends the interview's credibility |
| "I'd have to look at the code" (as a dodge) | Fine once, evasive twice |
| Answer a different question and hope | Interviewers notice |
| "That's a great question" | Filler; costs credibility |

---

## 9. Questions to ask them

These signal seriousness and give you real information.

**Technical:**
- "What's your split between static and dynamic analysis in practice?"
- "How do you handle samples you can't unpack?"
- "What's your false-positive rate on hardened banking apps?"
- "Do you do temporal-split evaluation on any ML components?"

**Operational:**
- "How does the SOC hand off to the fraud team?"
- "What's your time from detection to containment action?"
- "How do you decide what gets human reverse engineering?"

**Honest:**
- "What's the thing your current detection misses most often?"
- "What would you change about the platform if you could start over?"

> **⚙️ The last two are the best questions in the list.** They get honest answers, they tell you
> whether the team is self-aware, and they signal that you think about limitations rather than
> features.

---

## 10. The 48-hour revision plan

### Day 1 — Foundations (6h)

| Block | Chapters | Focus |
|---|---|---|
| Morning (3h) | [Ch 33 Cheat Sheets](33-cheat-sheets.md) → [Ch 32 Misconceptions](32-common-misconceptions.md) | Highest return per minute |
| Afternoon (3h) | Ch 04, 06, 07, 09 | Security model, identity, signing, install |

**Must be able to recite:** the three-column certificate/signature/hash table · the capability
cluster · v1–v4 with API levels · the version gate table.

### Day 2 — Craft and operations (6h)

| Block | Chapters | Focus |
|---|---|---|
| Morning (3h) | Ch 10, 11, 12 | Analysis workflows; the unpacking ladder; the five Frida hooks |
| Afternoon (2h) | Ch 13, 14 | Playbook, ODF, lineage map, family fingerprints |
| Evening (1h) | Ch 20 §10 + [§4 above](#4-the-ten-questions-you-will-definitely-get) | Runbook + the ten questions out loud |

### The final hour

```
 ✓ Say the ten questions (§4) OUT LOUD. Silent reading isn't rehearsal.
 ✓ Draw the attack chain from memory: dropper → session install → a11y →
   self-escalation → enumeration → overlay/VNC → OTP → ODF
 ✓ Draw the lineage map from memory
 ✓ Recite the three-column cert/signature/hash table
 ✓ Rehearse "I don't know" out loud once — it's harder than it sounds
 ✓ Pick your three facts (Ch 34 §6) and know their dates and vendors
```

> **⚖️ Final advice.** The interviewer is not trying to catch you out; they're trying to find out
> how you think. **Reason out loud, state your uncertainty, and name the limitation.** A candidate
> who says "static analysis is fast and reproducible, and here's the specific case where it fails"
> outperforms one who lists five more tools.

---

*Previous: [← Ch 34 Judge Preparation](34-judge-preparation.md) · Next: [Ch 36 Glossary →](36-glossary.md)*
