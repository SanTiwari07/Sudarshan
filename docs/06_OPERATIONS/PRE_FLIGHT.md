# SUDARSHAN — Pre-Flight Checklist

> **Classification:** OPERATIONAL  

---

Before starting an analysis session:
1. **Docker Engine Running:** `docker info` confirms Docker is active.
2. **Environment Variables:** Verify `.env` has a secure `JWT_SECRET_KEY`.
3. **Android Sandbox Connected (if testing dynamic):**
   - Check device connection: `adb devices`
   - Test Frida server: `frida-ps -U` or `frida-ps -H <ip>:27055`
4. **Port Availability:** Ports `5173`, `8000`, `8008`, `8085` are free.
