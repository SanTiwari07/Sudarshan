# Step-by-Step Operator Guide: Creating the Demo Video in Recordly

Welcome to the **SUDARSHAN Premium Demo Studio**. Everything required to produce a studio-grade 5-minute video has been pre-configured in your workspace under `c:\Projects\Sudarshan\video_recording\`.

---

## What We Have Built & Downloaded For You

All assets are cleanly organized inside `video_recording/`:

| Folder / File | Purpose |
| :--- | :--- |
| **`video_recording/Recordly-windows-x64.exe`** | The official Recordly installer package (installed and ready). |
| **`video_recording/audio/`** | **9 neural voiceover tracks** (`.mp3`) + 1 Master continuous track (`00_SUDARSHAN_MASTER_VOICEOVER.mp3`). Zero overlap, paced for human narration. |
| **`video_recording/assets/sbi_yono_sample.apk`** | The live test APK targeting State Bank of India YONO for dropzone upload. |
| **`video_recording/assets/sbi_fingerprints.json`** | Canonical brand tokens & layout AST fingerprints for State Bank of India. |
| **`video_recording/scripts/DEMO_RECORDLY_TELEPROMPTER.md`** | Word-for-word teleprompter synchronized with mouse actions, zooms, and drawer clicks. |

---

## Step 1: Launch SUDARSHAN (Backend & Frontend)

Before starting the recording, ensure SUDARSHAN is running in your browser:

1. In PowerShell, start the platform:
   ```powershell
   cd c:\Projects\Sudarshan
   .\start.ps1
   ```
2. Open your browser to:
   ```
   http://localhost:5173
   ```
3. Set your browser window to a clean 16:9 ratio (recommended: **1920×1080** or maximized on a 1080p/1440p monitor).
4. Hide your browser bookmarks bar (`Ctrl + Shift + B`) for a clean presentation.

---

## Step 2: Launch Recordly

Recordly is already installed on your PC. You can launch it by:
* Searching **Recordly** in the Windows Start Menu, or
* Running:
  ```powershell
  Start-Process "$env:LOCALAPPDATA\Programs\Recordly\Recordly.exe"
  ```

---

## Step 3: Configure Recordly Canvas & Frame Settings

To get the signature premium "Screen Studio" look:

1. **Target Capture:**
   * In Recordly, click **Record**.
   * Select **"Window"** mode and choose the browser window running SUDARSHAN (`localhost:5173`).
2. **Frame Styling:**
   * **Background:** Select **Gradient** or **Dark Slate Wallpaper** (e.g., `#0F172A` to `#1E293B`).
   * **Padding:** Set to **32px** (gives that elegant framed floating window effect).
   * **Border Radius:** Set to **16px** (smooth rounded window corners).
   * **Shadow:** Set to **Soft / High Elevation**.
3. **Cursor Polish:**
   * **Cursor Smoothing:** Toggle **ON** (Recordly will smooth out jerky mouse twitches into fluid cinematic arcs).
   * **Click Ripple:** Toggle **ON** with color set to subtle Amber or Cyan.
   * **Scale:** Set cursor size to **1.1x**.

---

## Step 4: Add the Zero-Overlap Voiceover Track

You have two easy choices for sound:

### Option A: Import Pre-Generated Studio Audio (Recommended)
Because we already generated all speech using neural natural voices with calibrated pauses, there is **zero voice overlapping**:
1. In Recordly, go to the **Audio** tab or timeline.
2. Click **"Add Audio Track"** and select:
   `c:\Projects\Sudarshan\video_recording\audio\00_SUDARSHAN_MASTER_VOICEOVER.mp3`
3. Hit Play! As the voice speaks each section, simply perform the corresponding mouse movement and click as described in `DEMO_RECORDLY_TELEPROMPTER.md`.

### Option B: Modular Scene Clips
If you prefer to edit scene-by-scene:
* Drag each numbered file from `video_recording/audio/` (`01_...`, `02_...`, etc.) directly into its corresponding section on the Recordly timeline.

---

## Step 5: Perform the Interactive Actions (Summary Checklist)

Follow the on-screen steps from `DEMO_RECORDLY_TELEPROMPTER.md`:

1. **0:00 – 0:45 (Act 1):** Intro slide / problem statement on fake SBI YONO KYC attacks.
2. **0:45 – 1:30 (Act 2):** SUDARSHAN home page, hover over protected banking badges.
3. **1:30 – 1:55 (Act 3.1):** Drag & drop `video_recording/assets/sbi_yono_sample.apk` onto upload zone.
4. **1:55 – 2:35 (Act 3.2):** Land on **Fraud Card**. Zoom into **95/100 CRITICAL** gauge. Click **"Target analysis drawer"** $\rightarrow$ side drawer slides open showing SBI YONO 92% match.
5. **2:35 – 3:10 (Act 3.3):** Click **Evidence** tab $\rightarrow$ click **Runtime** subtab. Scroll down to Frida hook timeline (`SmsManager`, `AccessibilityNodeInfo`).
6. **3:10 – 3:30 (Act 3.4):** Click **Visual** subtab. Scroll to color swatches comparing official `#1B4AA0` vs clone palette.
7. **3:30 – 4:00 (Act 3.5):** Click **Ask SUDARSHAN**. Click *"Generate executive containment playbook"*. Watch structured 7-section answer stream in with citation chips.
8. **4:00 – 4:30 (Act 4):** Show Explainability formula card ($0.25 \times \text{STEI} + 0.35 \times \text{BFCI} + \dots$) and the 2,800+ test suite badge.
9. **4:30 – 5:00 (Act 5):** Closing vision slide (Banks, CERT-In/RBI/I4C, Telecom).

---

## Step 6: Export the Video

1. In Recordly, click **Export**.
2. Select:
   * **Format:** MP4 (H.264)
   * **Resolution:** 1080p (1920×1080) or 1440p (2560×1440)
   * **Frame Rate:** 60 FPS
3. Save the exported video directly into `c:\Projects\Sudarshan\video_recording\SUDARSHAN_PREMIUM_DEMO.mp4`.
