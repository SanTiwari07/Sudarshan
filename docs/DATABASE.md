# Database

SQLite, accessed with `aiosqlite` from the gateway. No ORM, no migration
framework, raw SQL throughout. That is deliberate and is not changing here.

---

## 1. One authoritative database

The gateway owns application persistence:

```
Frontend  →  FastAPI Gateway  →  sudarshan.db   (authoritative)
                    ↓
             Analysis Engine   (performs analysis, returns results, stores none)
```

The path comes from **`SUDARSHAN_DB_PATH`**. Set it. Compose sets
`/app/data/sudarshan.db`, backed by the `dbdata` volume.

Resolution order (`backend/app/db/paths.py`):

1. `SUDARSHAN_DB_PATH` — explicit always wins.
2. A legacy `./sudarshan.db` in the working directory, **if it already exists** —
   a compatibility clause so existing installs keep working. Logged as a warning.
3. `<cwd>/data/sudarshan.db` — the default for a new install.

### Why rule 2 exists

The path used to be a bare relative `"sudarshan.db"`, resolved against each
process's working directory. That produced three unrelated database files:

| File | Created by | Contents |
|---|---|---|
| `backend/sudarshan.db` | uvicorn (CWD=backend) | the real data |
| `sudarshan.db` (repo root) | pytest | test spill |
| `analysis-engine/sudarshan.db` | `AnalysisHistory()` defaulting to its own CWD | placeholder rows only |

Changing the default without rule 2 would point a running install at an empty
file and every existing case would vanish from the UI. Adoption is therefore
explicit — see §5.

It also broke production outright: `docker-compose.hardened.yml` sets
`read_only: true` and removes the `./backend:/app` bind-mount, so the path
resolved to `/app/sudarshan.db` on an unwritable filesystem and `init_db()`
raised out of the startup event. The hardened overlay could not boot. Both
compose files now mount `dbdata:/app/data`.

### The per-session evidence store is *not* part of this

`shared/sudarshan_core/engines/evidence_store.py` writes one WAL SQLite file per
analysis under `artifacts/evidence/<case>.evidence.db`. That is intentional: it
is a forensic sidecar with crash recovery, holding full event payloads. The
gateway indexes it (`runtime_events.payload_ref`) rather than absorbing it.

---

## 2. Schema

Managed by `backend/app/db/migrations.py`, tracked in `schema_migrations`.

| Table | Purpose |
|---|---|
| `users` | accounts, roles, `is_active`, `last_login_at` |
| `sessions` | JWT **jti** → revocation state. Makes logout real |
| `login_attempts` | durable authentication history, drives lockout |
| `audit_events` | who did what, to which object, when, from where |
| `cases` | analysis results + `raw_result` + analyst lifecycle fields |
| `case_notes` | analyst commentary |
| `case_iocs` | indicator ↔ case, the cross-case pivot |
| `analysis_runs` | trending history, real scores |
| `chat_messages` | authoritative investigation conversations |
| `export_events` | export ledger (reference only, never the payload) |
| `runtime_events` | runtime evidence index → evidence store |
| `ioc_cache` | reputation cache, 24h TTL |
| `analysis_jobs` | durable async-poll state |
| `analysis_batches`, `analysis_batch_jobs` | enterprise batch scan |
| `discovery_sessions`, `discovery_candidates` | URL crawl |

Every connection sets `journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`.

### Adding a migration

Append to `MIGRATIONS` in `backend/app/db/migrations.py`. Two rules:

1. **Never destructive.** No DROP, no DELETE, no type rewrites. This database
   holds forensic evidence.
2. **Independently idempotent.** Do not rely on the ledger alone — re-check the
   real schema. Existing installs have `cases.raw_result` from the previous
   mechanism with no ledger row, which is why `0001` is a guarded no-op there.

Never renumber or edit an applied version in place.

Order inside `init_db()` is **CREATE → migrate → index**. An index can reference
a column a migration is about to add, and on a pre-existing table the CREATE was
a no-op that did not add it. Getting this backwards fails with
`no such column: sha256` on `analysis_runs` — a real failure caught in testing.

---

## 3. The engine's verdict is immutable

An analyst's decision is stored in its **own** columns and never overwrites what
the pipeline measured:

```
final_risk_score = 94.0            risk_band = CRITICAL      ← engine, unchanged
frs_breakdown.stei = 71.2          dynamic_result.bfci       ← engine, unchanged

analyst_verdict  = FALSE_POSITIVE                            ← analyst
verdict_reason   = "Known internal test APK"
verdict_set_by   = <user id>       verdict_set_at = <ts>
```

Both halves stay readable. `PATCH /cases/{sha}/verdict` returns both, and the
audit event records the engine values the analyst was overruling.

---

## 4. Retention

`backend/app/workers/retention.py`, daily. `RETENTION_ENABLED=false` disables it.

**Deleted** — operational state only:

| Table | Window | Why it is safe |
|---|---|---|
| `sessions` | 7d past expiry | authorises nothing; the login is in `login_attempts` |
| `login_attempts` | 90d | a quarter of review history |
| `ioc_cache` | 7d past expiry | it is a cache |
| `analysis_jobs` | 30d after completion | carries `result_json`; the case row is permanent |
| `runtime_events` | 30d | the index only — evidence files untouched |

**Never deleted**: `audit_events`, `cases`, `case_notes`, `case_iocs`,
`analysis_runs`, `chat_messages`, `export_events`, `users`. The audit trail in
particular is evidence, and a trail with a rolling window has a hole exactly
where an incident review needs to look.

Preview before trusting it:

```bash
python scripts/db_admin.py prune
```

---

## 5. Operations

All via `scripts/db_admin.py`. Set `SUDARSHAN_DB_PATH` first, or run it where
the app runs.

### Which database am I using?

```bash
python scripts/db_admin.py locate
```

Prints the resolved path, *why* it was chosen, and every other candidate found
on the machine with its case and user counts.

### Backup

```bash
python scripts/db_admin.py backup
```

**Do not `cp` a live WAL database.** The file on disk is only part of the state —
recent transactions live in `-wal`, and copying the three files with three
separate reads can capture them at three different points. The result opens
without complaint and is silently short of data, or corrupt.

This uses `sqlite3.Connection.backup()`, which takes a consistent snapshot while
writers continue and produces one self-contained file. It runs `integrity_check`
on the result before reporting success.

Under Compose:

```bash
docker compose exec backend python /opt/sudarshan-scripts/db_admin.py backup
```

### Verify

```bash
python scripts/db_admin.py verify           # integrity_check + foreign_key_check
python scripts/db_admin.py inspect          # tables, counts, schema version
```

### Restore

```bash
python scripts/db_admin.py restore backups/sudarshan-20260826T061226Z.db
docker compose restart backend
```

Refuses a backup that fails `integrity_check`, preserves the current database as
`sudarshan.pre-restore-<ts>.db` first, and removes stale `-wal`/`-shm` — which
would otherwise be replayed on top of the restored file.

### Adopting an existing database

Moving an existing install onto the volume:

```bash
SUDARSHAN_DB_PATH=/app/data/sudarshan.db \
  python scripts/db_admin.py adopt backend/sudarshan.db
```

Refuses to overwrite a non-empty destination without `--force`, always keeps a
copy of whatever it replaces, and never deletes the source. Inspect both first.

---

## 6. Authentication notes

- **Tokens carry a `jti`; sessions are server-side.** `get_current_user` checks
  signature → expiry → jti present → session live → user exists → account active.
  A token with no session row is rejected, which includes any token minted before
  this change.
- **`POST /auth/logout` is real.** Previously logout was
  `localStorage.removeItem('sudarshan_token')` and the token stayed valid for its
  full `JWT_EXPIRE_HOURS` window.
- **Disabling an account revokes its sessions**, otherwise the account stays
  usable until its tokens expire — the exact window an admin is closing.
- **Lockout is temporary and self-healing.** A permanent lock triggered by failed
  passwords would hand any anonymous caller a denial-of-service against a named
  analyst. Per-account threshold is high (10/15min); the per-IP threshold
  (25/15min) is what actually blunts spraying.
- **`TRUST_PROXY_HEADERS` is off by default.** `X-Forwarded-For` is
  attacker-controlled unless a proxy you control rewrites it, and the recorded
  client IP is precisely the field an attacker would want to forge.
- **Tests must use `tests/auth_helpers.py`.** `create_access_token()` alone
  produces a token with no session, which is correctly rejected.
