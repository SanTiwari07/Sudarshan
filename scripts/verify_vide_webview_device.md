# Live VIDE WebView verification (device / emulator)

## Prerequisites

- Genymotion (or device) on ADB: `adb devices` shows `device`
- **frida-server** on guest matching host Frida (`frida --version` → **17.16.4**)
- **ADB forward** to guest loopback Frida port (default **27042**):

```powershell
adb -s 192.168.56.101:5555 forward tcp:27042 tcp:27042
```

- Non-privileged test app (Settings cannot host WebView). This repo uses **InsecureBankv2** lab APK: `backend/test_sample.apk` → `com.android.insecurebankv2`

## Frida client on Windows (Cursor / non-TTY)

`frida-ps -H 127.0.0.1:27042` may hang without a console. Use the **Python Frida API**:

```powershell
python -c "import frida; d=frida.get_device_manager().add_remote_device('127.0.0.1:27042'); print(len(d.enumerate_processes()))"
```

## Automated live probe (recommended)

Builds a minimal agent with the same `WebView.loadData` hook + emit schema as `banking_trojan.js`:

```powershell
cd shared\sudarshan_core\engines\frida_hooks
npx frida-compile vide_live_probe.js -o vide_live_probe.bundle.js
copy vide_live_probe.bundle.js ..\..\..\..\scripts\vide_live_probe.bundle.js

adb -s 192.168.56.101:5555 install -r backend\test_sample.apk
$env:PYTHONPATH = "backend;shared"
python -u scripts\live_vide_webview_verify.py
```

Pass criteria:

- `HOOK WebView.loadData` with `html_len` > 0
- `collect_webview_html_from_frida_events()` returns snippets
- `run_vide_analysis()` runs (VIDE-F001 only if confidence ≥ 0.20 and a discriminating axis - text or palette - carries evidence)

## Production Sudarshan bundle

`banking_trojan.bundle.js` is selected by `frida_sandbox._select_hooks_script()`. Confirm hooks:

```powershell
python -u -c "import frida,subprocess,time; from pathlib import Path; ..."
# spawn com.android.insecurebankv2, load banking_trojan.bundle.js, check hook_installed WebView.loadData
```

Full `run_frida_analysis()` on InsecureBankv2 does **not** guarantee a `loadData` call unless the app opens a WebView during exploration.

## Recorded result (2026-08-08, Genymotion 192.168.56.101:5555)

- `WebView.loadData` hook fired, `html_preview` length **175**
- VIDE matched strings (e.g. `enter upi pin`, `mpin`, `login`) but **confidence ~0.15** → **VIDE-F001 not fired** (expected; threshold unchanged)
