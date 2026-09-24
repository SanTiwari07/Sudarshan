# SUDARSHAN — Security Model & Access Control

> **Classification:** AUTHORITATIVE  
> **Source Modules:** `backend/app/auth/auth.py`, `backend/app/case_access.py`  

---

## 1. Authentication & RBAC

- **JWT Tokens:** Issued via `/api/v1/auth/login` signed with `JWT_SECRET_KEY` (HMAC-SHA256). Expiry configurable (`ACCESS_TOKEN_EXPIRE_MINUTES`).
- **3-Tier RBAC:**
  - `analyst`: Read/write access to own investigations.
  - `soc_lead`: Full access across tenant cases, audit log viewing, batch prioritization.
  - `admin`: User administration, key configuration, active session revocation.

---

## 2. Hardening Measures
- **Session Revocation:** Immediate token invalidation via JWT ID (`jti`) blacklisting in the database.
- **Account Lockout:** Locks accounts and IPs after 5 failed login attempts within 15 minutes.
- **Path Traversal Defense:** All upload paths are resolved and checked with `is_relative_to(UPLOADS_DIR)`.
- **Export Ledger:** Every PDF report or STIX bundle exported is logged in an append-only audit trail.
