# SUDARSHAN Demo Recovery Guide

Use this guide to troubleshoot and recover a live demonstration of Sudarshan. Do not invent recovery commands; stick to those officially supported by the repository.

## 1. ADB Disconnected / Emulator Unavailable
- **Symptom:** The console reports `ADB Device Connected | [FAIL]`.
- **Check:** Run `adb devices`. If it says "offline" or is empty.
- **Recovery:**
  ```powershell
  adb kill-server
  adb start-server
  ```
  Restart the emulator from Android Studio.
- **Fallback Demo:** Run the offline pipeline check: `.\.venv\Scripts\python.exe scripts\verify_runtime_pipeline.py`

## 2. APK Installation Failure
- **Symptom:** Analysis gets stuck at the start; emulator screen doesn't change.
- **Check:** Look at the backend logs for `INSTALL_FAILED`.
- **Recovery:**
  Manually wipe the app:
  ```powershell
  adb uninstall com.android.insecurebankv2
  ```
  Restart the analysis job from the UI.
- **Fallback Demo:** Show static analysis results instead.

## 3. UI Explorer Stuck
- **Symptom:** The emulator is on a system dialogue (e.g., "Google Play Services") and AgenticExplorer is not moving.
- **Check:** Check the console for `State unchanged` or `Out of scope`.
- **Recovery:**
  AgenticExplorer has a native recovery mechanism and will eventually issue a back command. To speed it up manually:
  ```powershell
  adb shell input keyevent 4
  ```
- **Fallback Demo:** Proceed to wait; the max action attempt budget will terminate the loop automatically and yield the final report.

## 4. Jev Unavailable
- **Symptom:** Real Jev API is timing out or throwing HTTP 500.
- **Check:** Look for `JEV_NETWORK_ERROR` in the backend logs.
- **Recovery:**
  Ensure `.env` sets `SUDARSHAN_JEV_PROVIDER=mock`. Restart the backend.
- **Fallback Demo:** The `HybridPlanner` will natively fall back to `Gemini`. Point out this architectural resilience during the demo.

## 5. Gemini Unavailable
- **Symptom:** Gemini API throws quota or connection errors during narrative generation or fallback.
- **Check:** Look for `Gemini fallback failed`.
- **Recovery:**
  Verify `.env` has a valid Google AI Studio key.
- **Fallback Demo:** The system will use deterministic fallbacks for UI exploration. The final report will lack the plain English narrative, but the FRS and evidence timeline will still be generated accurately.

## 6. Frida Unavailable
- **Symptom:** Live dynamic hooks are not firing.
- **Check:** Expected behavior on non-rooted emulator. 
- **Recovery:** Cannot be recovered without a rooted device.
- **Fallback Demo:** Execute `.\.venv\Scripts\python.exe scripts\verify_runtime_pipeline.py` to demonstrate the offline Pub/Sub and Risk engine logic processing synthetic Frida events successfully.
