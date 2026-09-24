# SUDARSHAN — Troubleshooting & Diagnostic Guide

> **Classification:** OPERATIONAL  

---

## 1. Common Operational Issues

### 1.1 "JWT_SECRET_KEY is not set"
- **Cause:** Security control refuses to run with default empty secret.
- **Solution:** Add `JWT_SECRET_KEY=<random_string_32_chars>` to your `.env` file.

### 1.2 "Frida connection failed / No device attached"
- **Cause:** ADB emulator is offline or `frida-server` is not running.
- **Solution:** Run `adb devices`. If using Genymotion, verify VM is started and reachable at `ADB_HOST`.

### 1.3 Container Out Of Memory (OOM Exit 137)
- **Cause:** Androguard at DEBUG level retains DEX parse trees in memory.
- **Solution:** Androguard logging level is hard-locked to `WARNING` in production code. Do not set `LOG_LEVEL=DEBUG` globally.
