# BOI Hackathon — Demo Login Credential Configuration

> [!IMPORTANT]
> **Do not commit `.env` files.** All passwords must be configured in your local `.env` file only. `.env` is listed in `.gitignore` and must never be pushed to version control.
> This document does not publish credential values. Configure them locally.

---

## Recommended Demo Setup

Copy `.env.example` to `.env` and set the following variables:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<choose a strong password>

SUDARSHAN_SEED_DEMO_USERS=true
DEMO_SOCLEAD_USERNAME=soclead
DEMO_SOCLEAD_PASSWORD=<choose a strong password>
DEMO_ANALYST_USERNAME=analyst1
DEMO_ANALYST_PASSWORD=<choose a strong password>
```

**Fresh database:** Delete `sudarshan.db` (or reset the Docker volume) if `admin` was already created with a different password.

---

## Accounts After Startup

| Role | Username (default) | Password | Case Visibility |
|------|----------|----------|--------------------|
| Admin | `admin` (from `ADMIN_USERNAME`) | Set in `ADMIN_PASSWORD` | All cases |
| SOC Lead | `soclead` (from `DEMO_SOCLEAD_USERNAME`) | Set in `DEMO_SOCLEAD_PASSWORD` | All cases |
| Analyst | `analyst1` (from `DEMO_ANALYST_USERNAME`) | Set in `DEMO_ANALYST_PASSWORD` | Own cases only |

Login page: `http://localhost:5173/login`

> [!NOTE]
> If `ADMIN_PASSWORD` is left blank on first boot, a random password is **generated and printed once** to the backend startup log. Capture it from there — it is not shown again.

---

## Optional Alternate Usernames

Add to `.env`:

```env
DEMO_SEED_BOI_ALIASES=true
```

This seeds additional alias accounts (`boi_admin`, `boi_soclead`, `boi_analyst`) with passwords specified via the corresponding `DEMO_BOI_*_PASSWORD` environment variables.

---

## Manual Role Promotion (Admin Only)

```http
PATCH /api/v1/users/{user_id}/role
Authorization: Bearer <admin token>
Content-Type: application/json

{"role": "soc_lead"}
```

Assignable roles: `analyst`, `soc_lead`, `admin`.
