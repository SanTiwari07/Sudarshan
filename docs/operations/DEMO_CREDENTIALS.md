# Demo account configuration

How to configure the demonstration accounts SUDARSHAN seeds at startup, for showing the three RBAC tiers without hand-creating users.

Verified against `backend/app/demo_seed.py` and `backend/app/auth/auth.py` on **2026-08-27**.

> **No credential values are published here, and none should be added.** Configure every password in your local `.env`, which is listed in `.gitignore` and must never be committed.

---

## Setup

```bash
cp .env.example .env
```

Then set, at minimum:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<choose a strong password>

SUDARSHAN_SEED_DEMO_USERS=true
DEMO_SOCLEAD_USERNAME=soclead
DEMO_SOCLEAD_PASSWORD=<choose a strong password>
DEMO_ANALYST_USERNAME=analyst1
DEMO_ANALYST_PASSWORD=<choose a strong password>
```

Demo seeding runs only when `SUDARSHAN_SEED_DEMO_USERS` is truthy (`1`, `true`, `yes`, `on`).

If `admin` already exists in the database with a different password, delete `sudarshan.db` or reset the `dbdata` volume before changing `ADMIN_PASSWORD` — seeding does not overwrite an existing account.

> **Set every `DEMO_*_PASSWORD` explicitly.** `backend/app/demo_seed.py` falls back to hardcoded default passwords when these variables are unset. Those defaults are in the public source tree, so any instance seeded without them has publicly known credentials for a SOC-lead and an analyst account. This is a demonstration convenience and is unsafe on anything reachable beyond localhost.

---

## Accounts after startup

| Role | Username source | Password source | Case visibility |
| :--- | :--- | :--- | :--- |
| `admin` | `ADMIN_USERNAME` (default `admin`) | `ADMIN_PASSWORD` | All cases, plus role and account administration |
| `soc_lead` | `DEMO_SOCLEAD_USERNAME` (default `soclead`) | `DEMO_SOCLEAD_PASSWORD` | All cases, verdict override, case assignment, audit log |
| `analyst` | `DEMO_ANALYST_USERNAME` (default `analyst1`) | `DEMO_ANALYST_PASSWORD` | Own cases only |

Sign in at `http://localhost:5173/login`.

> If `ADMIN_PASSWORD` is left blank on first boot, a random password is generated and printed **once** to the backend startup log. Capture it from there; it is not shown again.

---

## Optional alias accounts

```env
DEMO_SEED_BOI_ALIASES=true
```

Seeds three additional accounts alongside the ones above:

| Account | Username variable (default) | Password variable |
| :--- | :--- | :--- |
| Admin alias | `DEMO_BOI_ADMIN_USERNAME` (`boi_admin`) | `DEMO_BOI_ADMIN_PASSWORD` |
| SOC lead alias | `DEMO_BOI_SOCLEAD_USERNAME` (`boi_soclead`) | `DEMO_BOI_SOCLEAD_PASSWORD` |
| Analyst alias | `DEMO_BOI_ANALYST_USERNAME` (`boi_analyst`) | `DEMO_BOI_ANALYST_PASSWORD` |

The same warning applies: each of these has a hardcoded default password in `demo_seed.py`. Set all three explicitly or leave `DEMO_SEED_BOI_ALIASES` off.

---

## Promoting a user manually

Roles are never self-assigned. Registration always produces an `analyst`; elevation is an admin operation:

```http
PATCH /api/v1/auth/users/{user_id}/role
Authorization: Bearer <admin token>
Content-Type: application/json

{"role": "soc_lead"}
```

Assignable roles: `analyst`, `soc_lead`, `admin`. The change is recorded in the audit log with the previous and new role.

Related administrative routes: `PATCH /api/v1/auth/users/{user_id}/active` to deactivate an account, and `POST /api/v1/auth/users/{user_id}/revoke-sessions` to invalidate its tokens. Full reference: [api/ENDPOINTS.md](api/ENDPOINTS.md).

---

## Before any non-local deployment

- Turn demo seeding off: `SUDARSHAN_SEED_DEMO_USERS` unset or false, `DEMO_SEED_BOI_ALIASES` off.
- Set a real `JWT_SECRET_KEY`; the backend refuses to start without one.
- Set `SUDARSHAN_ENV=production` and `SANDBOX_CONTAINMENT_STRICT=true` so startup validation fails closed.
- Control self-registration with `SUDARSHAN_ALLOW_REGISTRATION`.
- Review the lockout policy: `AUTH_ACCOUNT_LOCK_THRESHOLD`, `AUTH_IP_LOCK_THRESHOLD`, `AUTH_LOCKOUT_WINDOW_MINUTES`.
