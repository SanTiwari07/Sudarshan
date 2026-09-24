# SUDARSHAN — STIX 2.1 Threat Intelligence Serialization

> **Classification:** AUTHORITATIVE  
> **Standard:** OASIS STIX 2.1  

---

SUDARSHAN serializes malware indicators into standard STIX 2.1 bundles:
- `indicator`: File SHA-256 hashes, C2 IP addresses, domains.
- `malware`: Identified banking trojan family (`Drinik`, `Xenomorph`, `SOVA`, etc.).
- `attack-pattern`: MITRE ATT&CK Mobile techniques (e.g. `T1418`, `T1417`, `T1437`).
- `relationship`: Links between malware objects and observed indicators.
