# SUDARSHAN DEVICE COMPATIBILITY MATRIX

This document tracks the verified device environments for the SUDARSHAN dynamic analysis platform.
The architecture is designed to be device-agnostic, with runtime discovery of capabilities (ABI, Android Version, Screen Resolution) rather than hardcoded assumptions.

| Environment | Android | API | ABI | ADB | Install | Launch | Frida | Hooks | UI Explorer | Network | Overall |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AVD (emulator-5554) | 13.0 / 14.0 | 33 / 34 | x86_64 | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| Genymotion | 11.0 / 12.0 | 30 / 31 | x86 / x86_64 | PASS | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| Physical Device | 10.0+ | 29+ | arm64-v8a | UNTESTED | UNTESTED | UNTESTED | UNTESTED | UNTESTED | UNTESTED | UNTESTED | UNTESTED |

## Portability Features Verified
- **ABI-Aware Frida:** The engine dynamically checks `ro.product.cpu.abi` and fetches the strictly matching Frida server binary (`x86`, `x86_64`, `arm`, `arm64`).
- **Screen Coordinate Agnosticism:** UI explorer relies on semantic XML bounds `[x1,y1][x2,y2]` to compute dynamic screen coordinates. Absolute fallback coordinates have been replaced with screen-relative dimensions (`wm size`).
- **Dynamic Device Selection:** The `ADB_SERVER_SOCKET` and `auto.py` provider dynamically bridge container networking to the host's ADB daemon, allowing discovery of Genymotion or Android Studio emulators without hardcoding.
