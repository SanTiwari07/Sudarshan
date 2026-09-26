# SUDARSHAN — Official Recordly Demo Teleprompter & Interactive Screenplay
**Target Case:** SBI YONO Fake KYC Attack (`BASE-01-SBI`)
**Total Video Target:** 5 Minutes (300 Seconds)
**Narration Pace:** ~135 WPM (Crisp, authoritative, zero overlapping)
**Audio Track Directory:** `video_recording/audio/`

---

## Pre-Recording Checklist in Recordly
1. **Launch Recordly:** Open from Start Menu or `C:\Users\SHAMBHAVI PATIL\AppData\Local\Programs\Recordly\Recordly.exe`.
2. **Recording Mode:** Select **"Single App Window"** (select Google Chrome / Edge running `http://localhost:5173`).
3. **Canvas Styling:**
   - Background: Dark Gradient (`#0B1120` to `#1E293B`)
   - Frame Padding: `32px`
   - Frame Corners: Rounded (`16px`)
   - Window Shadow: `Large / Soft`
4. **Cursor Settings:**
   - Cursor Smoothing: **Enabled (Spring / Smooth)**
   - Click Effect: **Translucent Ripple (Amber / Blue)**
   - Cursor Size: `1.1x`
5. **Audio Source:**
   - Either record live with microphone, OR
   - Drop the pre-generated audio files from `video_recording/audio/` onto the Recordly timeline!

---

## Scene-by-Scene Teleprompter & On-Screen Choreography

### Act 1: The Threat — The 90-Second Fraud Crisis (0:00 – 0:45)
* **Audio Track:** `01_Act1_TheThreat_90Seconds.mp3` (Duration: ~42s)
* **Screen:** Visual Intro / Presentation Slide or Static Diagram
* **On-Screen Action:**
  - `0:00 - 0:15`: Show title graphic: *"SUDARSHAN: Securing Indian Digital Banking"*.
  - `0:15 - 0:30`: Transition to graphic of fake WhatsApp message: *"Urgent: Your SBI YONO KYC has expired. Update now: sbi-kyc.apk"*.
  - `0:30 - 0:45`: Display 4-step attack timeline: (1) Sideload $\rightarrow$ (2) Accessibility Coercion $\rightarrow$ (3) Overlay Phishing $\rightarrow$ (4) ATS Money Exfiltration.
* **Narration:**
  > *"Across India, digital banking and UPI handle billions of transactions every single day. But right now, millions of citizens are being targeted by sophisticated on-device fraud campaigns. A victim receives an urgent WhatsApp notification impersonating their bank: 'Update your SBI KYC within 24 hours to prevent account freeze.' Attached is a sideloaded APK. Once installed, the victim is tricked into enabling Android Accessibility permissions. Within 90 seconds, the trojan launches an invisible overlay, steals banking credentials, intercepts SMS OTPs, and executes Automated Transfer Systems to drain accounts. Traditional antivirus fails because attackers alter code hashes daily. Manual reverse engineering takes 4 to 8 hours per APK. That is why we built SUDARSHAN."*

---

### Act 2: Enter SUDARSHAN & The VIDE Breakthrough (0:45 – 1:30)
* **Audio Track:** `02_Act2_Sudarshan_VIDE_Breakthrough.mp3` (Duration: ~43s)
* **Screen:** SUDARSHAN Homepage / Dashboard (`http://localhost:5173/`)
* **On-Screen Action:**
  - `0:45 - 1:05`: Wide camera on SUDARSHAN Dashboard. Cursor slowly glides across the top navigation bar (`Upload`, `History`, `Discovery`).
  - `1:05 - 1:30`: Recordly zooms in (1.25x) to center. Hover briefly over the protected banking institution emblems, highlighting State Bank of India.
* **Narration:**
  > *"SUDARSHAN is an autonomous Android banking malware and fraud intelligence platform, engineered from the ground up to take suspicious APKs from infiltration to complete containment in minutes. Our foundational breakthrough is VIDE, the Visual Impersonation Detection Engine. Here is our core insight: an adversary can easily obfuscate package names or encrypt payloads, but they cannot alter the visual interface. They must mimic the bank's UI perfectly to trick the user! VIDE treats the frontend visual interface as the ultimate Indicator of Compromise. Across 10 major Indian banking baselines, VIDE extracts Layout ASTs, CIEDE2000 color palettes, and digital signing certificates to unmask clones instantly."*

---

### Act 3 Part 1: Ingestion & Corrupted AXML Repair (1:30 – 1:55)
* **Audio Track:** `03_Act3_Part1_Upload_AXMLRepair.mp3` (Duration: ~23s)
* **Screen:** Upload Screen (`http://localhost:5173/`)
* **On-Screen Action:**
  - `1:30 - 1:40`: Cursor drags `video_recording/assets/sbi_yono_sample.apk` onto the upload dropzone.
  - `1:40 - 1:55`: Recordly zooms in (1.4x) onto the analysis status indicator showing: *"AXML Header Repaired"*, SHA-256 computation, and static extraction.
* **Narration:**
  > *"Let's run a live analysis. We drag and drop an active in-the-wild sample targeting State Bank of India customers. Modern trojans intentionally corrupt their binary XML headers to crash standard decompilers like MobSF and JADX. SUDARSHAN's intake pipeline instantly detects the anomaly, repairs the string tables with our built-in recovery engine, and dispatches parallel static and dynamic workers."*

---

### Act 3 Part 2: The Executive Fraud Card & VIDE SBI Attribution (1:55 – 2:35)
* **Audio Track:** `04_Act3_Part2_FraudCard_SBI_Attribution.mp3` (Duration: ~39s)
* **Screen:** Executive Fraud Card (`/case/<sha256>`)
* **On-Screen Action:**
  - `1:55 - 2:05`: Seamless transition to Fraud Card. Recordly camera zooms in (1.45x) onto the circular **Fraud Risk Score Gauge (95/100 CRITICAL)**.
  - `2:05 - 2:15`: Pan right to the **Targeted Bank** card displaying the SBI logo and "State Bank of India (YONO SBI)".
  - `2:15 - 2:35`: **CLICK ACTION:** Click the **Target analysis drawer** button. The side drawer slides smoothly open. Scroll down 250px inside the drawer showing the baseline tokens and captured overlay screenshots.
* **Narration:**
  > *"Analysis complete. We land on the Executive Fraud Card, purpose-built for rapid triage. At a glance, our Fraud Risk Score reads 95 out of 100, CRITICAL. Notice the Targeted Bank panel: without relying on package names, VIDE has identified this sample as an impersonation of State Bank of India's YONO app with 92 percent confidence. Clicking into the Target Analysis Drawer reveals the forensic proof. VIDE verified the UI against our official SBI baseline. Notice the digital signer verification: the official SBI release key is completely absent. This triggers our CH27 On-Device Fraud Triad: high visual similarity plus developer signer mismatch immediately locks the verdict as fraudulent."*

---

### Act 3 Part 3: Dynamic Sandbox & Runtime Frida Instrumentation (2:35 – 3:10)
* **Audio Track:** `05_Act3_Part3_Runtime_Frida_Sandbox.mp3` (Duration: ~34s)
* **Screen:** Technical View (`/case/<sha256>/evidence?section=dynamic`)
* **On-Screen Action:**
  - `2:35 - 2:45`: **CLICK ACTION:** Click on the top navigation tab **"Evidence"** $\rightarrow$ Click **"Runtime"** subtab.
  - `2:45 - 2:58`: Smooth scroll down 400px to the **Dangerous APIs** and **MITRE ATT&CK** table.
  - `2:58 - 3:10`: Hover cursor over Frida hooks: `AccessibilityNodeInfo`, `SmsManager.sendTextMessage`, and `WindowManager.addView`.
* **Narration:**
  > *"Now, let's drill down into the Technical SOC View. Under the Runtime tab, we see the real-time telemetry from our isolated Android dynamic sandbox. Using our pre-compiled Frida hook bundle, SUDARSHAN instrumented the process at exact PID spawn. Look at these events: the sample hijacked Android Accessibility to scrape on-screen PIN entries, monitored SMS broadcasts to steal two-factor OTP tokens, and attempted outbound socket connections to an offshore C2 server. SUDARSHAN captured the exact exfiltration IPs and ports for immediate network blacklisting."*

---

### Act 3 Part 4: Visual Diff & Overlay Inspection (3:10 – 3:30)
* **Audio Track:** `06_Act3_Part4_VisualDiff_ColorAST.mp3` (Duration: ~18s)
* **Screen:** Visual Evidence Tab (`/case/<sha256>/evidence?section=visual`)
* **On-Screen Action:**
  - `3:10 - 3:18`: **CLICK ACTION:** Click **"Visual"** subtab. Recordly zooms in (1.35x) on the **VisualDiffViewer**.
  - `3:18 - 3:30`: Scroll down to the side-by-side color swatches. Cursor points to official SBI Royal Blue (`#1B4AA0`) compared side-by-side with suspect palette ($\Delta E < 1.8$).
* **Narration:**
  > *"Under the Visual Evidence tab, our side-by-side AST and color comparator proves that the trojan reproduced SBI's exact brand color tokens, hex 1B4AA0, with a perceptual delta-E under 1.8. It also replicated critical strings like 'Enter MPIN' and 'Forgot Password' within an identical layout hierarchy."*

---

### Act 3 Part 5: Grounded AI Copilot (Gemini RAG) & Export (3:30 – 4:00)
* **Audio Track:** `07_Act3_Part5_GroundedAI_Copilot.mp3` (Duration: ~34s)
* **Screen:** Ask SUDARSHAN (`/case/<sha256>/ask`)
* **On-Screen Action:**
  - `3:30 - 3:40`: **CLICK ACTION:** Click **"Ask SUDARSHAN"** in top nav.
  - `3:40 - 3:52`: **CLICK ACTION:** Click prompt: *"Generate executive containment playbook for this SBI campaign."* The structured 7-section answer streams in.
  - `3:52 - 4:00`: Scroll down through the containment steps, highlighting verified evidence citation chips `[EV-01]`. Cursor moves to "Export Report" button.
* **Narration:**
  > *"For fraud operations leads, SUDARSHAN features a Grounded AI Copilot powered by Google Gemini RAG. It indexes 22 forensic sections of the sample into an in-memory graph. Asking for a containment playbook generates an immediate, hallucination-free response complete with verified evidence citations: revoking active mobile sessions, blacklisting C2 infrastructure, and updating SIEM correlation rules. With one click, we can export this as an Executive PDF or OASIS STIX 2.1 threat feed."*

---

### Act 4: Mathematical Determinism & Defense Standards (4:00 – 4:30)
* **Audio Track:** `08_Act4_Mathematical_Determinism.mp3` (Duration: ~33s)
* **Screen:** Technical View / Explainability Formula (`/case/<sha256>/evidence?section=overview`)
* **On-Screen Action:**
  - `4:00 - 4:15`: Zoom in on the Explainability Breakdown card showing formula weights: $\text{FRS} = 0.25 \times \text{STEI} + 0.35 \times \text{BFCI} + 0.20 \times \text{Corr} + 0.20 \times \text{Impact}$.
  - `4:15 - 4:30`: Highlight test badge: **2,840+ Automated Unit & Integration Tests Passing**.
* **Narration:**
  > *"Why can financial institutions and defense teams trust SUDARSHAN? Because of our non-negotiable architectural invariant: Deterministic Detection, Grounded AI Intelligence. Generative AI never calculates, alters, or inflates our Fraud Risk Score. The numerical score is computed strictly by our deterministic mathematical engine. Identical inputs yield identical, auditable scores every time. Every rule, safety floor, and sandbox boundary is verified by an enterprise test suite of over 2,800 automated tests, ensuring absolute reliability in hostile production environments."*

---

### Act 5: National Ecosystem Vision & Closing Call to Action (4:30 – 5:00)
* **Audio Track:** `09_Act5_National_Ecosystem_Vision.mp3` (Duration: ~38s)
* **Screen:** Closing Vision Slide / Summary Deck
* **On-Screen Action:**
  - `4:30 - 4:45`: Display 3 strategic pillars:
    1. **Public & Private Bank SOCs** (SBI, HDFC, ICICI, Kotak, Axis)
    2. **National Agencies** (RBI, CERT-In, I4C / 1930 Portal)
    3. **Citizen Protection** (Telecom & WhatsApp Gateways)
  - `4:45 - 5:00`: Fade slowly into the SUDARSHAN Crest and Tagline: *"Autonomous Android Banking Malware & Fraud Intelligence Platform. Securing Every Transaction, Protecting Every Citizen."*
* **Narration:**
  > *"Looking to the future, SUDARSHAN is designed to integrate seamlessly into India's national cyber defense fabric. First, for Public and Private Banks, our API plugs into fraud investigation pipelines, detecting brand-impersonation campaigns before funds leave customer accounts. Second, for Government Agencies like CERT-In, RBI, and the I4C 1930 portal, SUDARSHAN automates the triage of citizen-reported APKs and expedites nationwide C2 infrastructure takedowns. And third, with Telecom and Messaging Platforms, SUDARSHAN's lightweight inspection engine can scan APK payloads before they are ever installed on citizen devices. As India leads the world in digital financial innovation, SUDARSHAN stands as an intelligent shield, turning 90 seconds of vulnerability into immediate, verifiable defense. Thank you."*
