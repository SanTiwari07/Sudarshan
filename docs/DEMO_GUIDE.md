# SUDARSHAN Demo Guide

This guide details how to run a reproducible demonstration of the Sudarshan Hybrid Dynamic Analysis Engine.

## Prerequisites
1. Windows OS
2. Python 3.11+
3. Android Studio (Emulator running)
4. Configured `.env` file (with `SUDARSHAN_JEV_PROVIDER=mock` for deterministic runs).

## Demo Procedure

### 1. Start the Backend
Open a terminal in the project root:
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
**Expected:** FastAPI startup logs indicating the server is ready.

### 2. Start the Frontend
Open a second terminal:
```powershell
cd frontend
npm run dev
```
**Expected:** Vite server starts at `http://localhost:5173`.

### 3. Ensure the Emulator is Running
Open a third terminal:
```powershell
adb devices
```
**Expected:** `emulator-5554` (or similar) is listed as `device`.

### 4. Prepare the Safe Demo APK
Ensure `InsecureBankv2.apk` is available in your test directory.

### 5. Upload APK
Navigate to `http://localhost:5173`.
- Login as `admin`.
- Drag and drop `InsecureBankv2.apk` into the upload zone.
- Click "Analyze".

### 6. Static Analysis
**Expected:** The pipeline will immediately parse the AndroidManifest.xml and extract hardcoded IPs/URLs. STEI base risk score is calculated.

### 7. Dynamic Analysis
**Expected:** The dashboard transitions to the Dynamic Execution phase. The emulator will automatically install the APK and launch it.

### 8. UI Exploration
**Expected:**
- The emulator screen displays the login form.
- The AgenticExplorer (using mock Jev in deterministic mode) clicks the username field and types a synthetic credential.
- It clicks the password field and types a synthetic password.
- It clicks "Submit".
- A "Credentials Failed" or "Welcome" popup appears.

### 9. Evidence Collection
**Expected:** The backend logs show screenshots being collected. The `EvidenceStore` records the "submit" button click.

### 10. Risk Aggregation
**Expected:** The dashboard displays the final risk score. If anti-analysis was detected, it is flagged.

### 11. SOC Dashboard
**Expected:** The final report displays the FRS, Evidence trace, and AI Explanation in plain English.
