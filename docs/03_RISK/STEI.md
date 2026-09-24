# SUDARSHAN — Static Threat Evaluation Index (STEI)

> **Classification:** AUTHORITATIVE  
> **Formula Anchor:** `shared/sudarshan_core/engines/risk_engine.py`  

---

## 1. 5-Axis STEI Formula

$$\text{STEI} = 0.60 \times \text{CT} + 0.20 \times \text{BT} + 0.10 \times \text{PR} + 0.05 \times \text{OB} + 0.05 \times \text{IR}$$

Where:
- **CT (Credential Theft, 60%):**
  - Accessibility service declaration: `+40`
  - SMS interception permissions (`READ_SMS`, `RECEIVE_SMS`): `+35`
  - Overlay permission (`SYSTEM_ALERT_WINDOW`): `+25`
  - Maximum: `100.0`.
- **BT (Banking Targeting, 20%):**
  - Target Indian banking package names detected: `+30` per package.
  - VIDE visual clone detection active: `+35` to `+85` based on clone confidence.
  - Maximum: `100.0`.
- **PR (Permission Risk, 10%):**
  - Dangerous permissions count normalized against typical banking profile baselines.
- **OB (Obfuscation Axis, 5%):**
  - High DEX entropy, reflection usage, and dynamic class loaders.
- **IR (Infrastructure Risk, 5%):**
  - Hardcoded non-standard ports, suspicious IP addresses, and URL counts.
