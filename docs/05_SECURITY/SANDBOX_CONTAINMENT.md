# SUDARSHAN — Sandbox Containment & Network Isolation

> **Classification:** AUTHORITATIVE  
> **Source Module:** `shared/sudarshan_core/security/sandbox_containment.py`  

---

## 1. Sandbox Isolation Principles

Dynamic analysis executes live Android malware. Hostile binaries must be contained within dedicated Android guest environments with zero exposure to internal enterprise networks:

1. **Target Boundary:** Dynamic analysis communicates exclusively over ADB TCP (`host.docker.internal:5037` or direct VM IP).
2. **Host LAN Leak Prevention:** In production, `CONTAINMENT_STRICT=true` audits ADB connection endpoints. Any attempt to bridge local subnets (`192.168.x.x`, `10.x.x.x`) without explicit whitelisting causes the container startup to fail closed.
3. **mitmproxy Traffic Sink:** All sandbox HTTP/HTTPS egress is routed through `mitmproxy` loopback on port `8085`.
