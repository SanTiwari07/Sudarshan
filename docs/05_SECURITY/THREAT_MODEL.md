# SUDARSHAN — Threat Model & Attack Surface

> **Classification:** AUTHORITATIVE  
> **Reference:** `docs/99_HISTORY/INCIDENTS/P0_RED_TEAM_PENETRATION_REPORT.md`  

---

## 1. Attacker Personas & Vectors

| Persona | Attack Vector | Mitigation in SUDARSHAN |
| :--- | :--- | :--- |
| **Malware Author** | Evasion via emulator fingerprinting | Evasion safety floor; anti-evasion state-warping. |
| **Malware Author** | Malformed AXML crash injection | `apk_repair.py` automatically reconstructs AXML string tables. |
| **Adversary** | Prompt injection via APK strings | `sanitizer.py` neutralizes LLM prompt overrides. |
| **Malicious Insider** | Escalating role or reading unassigned cases | 3-tier RBAC enforced at FastAPI route dependency layer. |
| **External Attacker** | Uploading non-APK files or web shells | ZIP magic verification (`_ZIP_MAGIC`), extension check, size bounds. |
