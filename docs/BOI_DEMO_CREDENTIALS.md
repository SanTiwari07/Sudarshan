# BOI Hackathon — Demo login credentials

Set these in your **local `.env`** (never commit `.env`). Restart the backend after changes.

## Recommended demo setup

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=BOI@Admin2026!

SUDARSHAN_SEED_DEMO_USERS=true
DEMO_SOCLEAD_USERNAME=soclead
DEMO_SOCLEAD_PASSWORD=Sudarshan@SOC2026
DEMO_ANALYST_USERNAME=analyst1
DEMO_ANALYST_PASSWORD=Sudarshan@Analyst2026
```

**Fresh database:** delete `sudarshan.db` (or reset the Docker volume) if `admin` was already created with a different password.

## Accounts after startup

| Role | Username | Password | Case visibility |
|------|----------|----------|-----------------|
| Admin | `admin` | `BOI@Admin2026!` (from `.env`) | All cases |
| SOC Lead | `soclead` | `Sudarshan@SOC2026` | All cases |
| Analyst | `analyst1` | `Sudarshan@Analyst2026` | Own cases only |

Login: `http://localhost:5173/login`

## Alternate usernames (optional)

Add to `.env`:

```env
DEMO_SEED_BOI_ALIASES=true
```

| Role | Username | Password |
|------|----------|----------|
| Admin | `boi_admin` | `Sudarshan@Admin2026` |
| SOC Lead | `boi_soclead` | `Sudarshan@SOC2026` |
| Analyst | `boi_analyst` | `Sudarshan@Analyst2026` |

## Manual role promotion (if needed)

Admin only:

```http
PATCH /api/v1/auth/users/{user_id}/role
Authorization: Bearer <admin token>
Content-Type: application/json

{"role": "soc_lead"}
```
