# Phase 5 Durable Queue Implementation

## 1. Problem
The original async execution architecture relied heavily on an in-memory `asyncio.Queue` and local Python `OrderedDict` arrays to maintain job status, analysis progress, and lifecycle tracking. This fundamentally broke resilience across service boundaries. If a Uvicorn backend process restarted, the queue dropped all pending requests, creating permanently "stuck" analyses in the database. 

Furthermore, `analysis_queue.py` had no concept of global deduplication. The exact same `sha256` payload uploaded by 1,000 users concurrently would dispatch 1,000 Android emulation executions, rapidly draining system resources.

## 2. Architecture Before
```text
FastAPI
 ↓
PostgreSQL (Tracks Job Existence)
 ↓
asyncio.Queue (Volatile)
 ↓
Worker (In-Memory Progress tracking)
```

## 3. Architecture After
```text
                    ┌──────────────┐
                    │   FastAPI    │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
       ┌──────────────┐        ┌────────────────┐
       │ PostgreSQL   │        │ PostgreSQL     │
       │ analysis_jobs│        │ canon_analyses │
       │ User Ticket  │        │ Atomic Queue   │
       └──────┬───────┘        └───────┬────────┘
              │                        │
              │                        ▼
              │                 ┌──────────────┐
              │                 │   Workers    │
              │                 └──────────────┘
```

## 4. Queue Technology
**Technology Chosen:** PostgreSQL-backed explicit claim queue using `FOR UPDATE SKIP LOCKED`.
**Reason:** 
1. `SKIP LOCKED` natively leverages Postgres row-level locking capabilities, meaning workers atomically claim the exact same table without colliding, providing lock-free concurrency identical to Redis, but without requiring an entirely new networking daemon stack.
2. Simplifies backend architecture footprint for future low-cost scalable GCP deployments (Cloud SQL provides this implicitly).

## 5. Job Lifecycle
1. `QUEUED` - Initially created via API.
2. `PROCESSING` - Worker successfully runs `claim_next_canonical_job`.
3. `RETRYING` - A worker exception triggers a job reset.
4. `COMPLETED` - Analysis successful.
5. `FAILED` - Fatal error or retry exhaustion.
6. `CANCELLED` - User manual override.

## 6. Atomic Claiming
Workers query the database selecting `LIMIT 1 FOR UPDATE SKIP LOCKED`. Any concurrently spinning worker immediately bypasses locked rows to grab the next available, eliminating deadlocks.

## 7. Lease
When a worker claims an analysis, it generates a `lease_expires_at` column matching `time.now() + 15 minutes`. The worker spins up a lightweight async routine to fire `last_heartbeat_at` updates every 60 seconds against the database. 

## 8. Recovery
If a worker hard-crashes (SIGKILL/OOM), its heartbeat dies. When `lease_expires_at < time.now()` evaluates as true, the next worker searching the atomic queue is legally permitted to override the lock and claim the orphaned task, recovering seamlessly.

## 9. Retry
The system natively tracks `attempt_count`. If a worker crashes or raises an intentional `Exception` during Androguard/Frida phases, the lease simply fails back. The system permits 3 maximum retries.

## 10. Deduplication
We have abstracted the workload from User requests into Canonical Execution contexts.
The Canonical Fingerprint is `sha256` + `sudarshan_core.__version__`.
Multiple jobs mapping to the exact same fingerprint bind to the exact same `canonical_analyses` record natively via SQL joins, meaning a thousand duplicate API calls will immediately reuse the same `COMPLETED` result or gracefully wait for a single underlying `PROCESSING` run to finish.

## 11. Idempotency
Because duplicate hashes coalesce to Canonical records via UPSERT mechanisms, accidental multi-post frontend API retries seamlessly merge without duplicating executions.

## 12. Batch Compatibility
Enterprise Batch API continues to leverage `enqueue`, which naturally falls through to the new Canonical queue deduplication without modifying batch execution semantics.

## 13. Security
By maintaining `analysis_jobs` mapped back to user identifiers, multiple analysts correctly observe the results without exposing ownership or sharing non-RBAC access keys. 

## 14. Failure Matrix
| Failure                       | Expected Behavior                  | Verified |
| ----------------------------- | ---------------------------------- | -------- |
| FastAPI restart               | Jobs remain recoverable in DB      | YES      |
| Worker crash                  | Lease expires and job is recovered | YES      |
| PostgreSQL restart            | Connections recover/retry          | YES      |
| Queue failure                 | Job remains authoritative in DB    | YES      |
| Duplicate APK                 | Existing canonical analysis reused | YES      |
| Same APK + new engine version | New analysis                       | N/A      |
| Duplicate request             | Idempotent behavior                | YES      |

## 15. Remaining Limitations
1. **Local Disk Storage**: Because payload `.apk` binaries are held in local `/app/uploads` `/tmp` volumes, a worker retrieving an orphaned DB claim on a *different* container will fail stating `Payload missing`. This perfectly highlights why **Phase 3 (GCS Storage)** is explicitly the next scalable requirement.

---
# Phase 5 Final Acceptance

## Result
PASS WITH KNOWN LIMITATIONS

## Verified
- **Database Durability:** Jobs survive backend restarts natively via PostgreSQL.
- **Atomic Claiming:** `FOR UPDATE SKIP LOCKED` successfully prevents double-claims.
- **Lease Expiration & Recovery:** Checked via `test_queue.py` where a simulated 1.5s expiry organically transferred the locked job to `worker-test2` after `worker-test1` failed to heartbeat.
- **Split-Brain Double Execution:** Heartbeat task tracks consecutive failures, cancelling local Python `asyncio.Task` pipelines before lease expires to prevent duplicate dynamic sandbox execution.
- **Deduplication:** Proved via `test_dedup.py` that 5 concurrent jobs map exactly to 1 canonical execution.
- **Idempotency:** Re-issuing the same `job_id` maps identically without error.
- **Concurrent Insert Race:** PostgreSQL `ON CONFLICT (fingerprint) DO UPDATE` successfully serializes overlapping job creation.
- **Batch Analysis:** `batch_worker.py` loops natively defer to the durable deduplicated canonical queue without retaining volatile state.
- **SQLite Compatibility:** Provided `BEGIN IMMEDIATE` fallback for sqlite dev workflows.

## Not Verified
- **GCP Cloud SQL Native Performance:** We proved this against `postgres:15-alpine` locally, not Cloud SQL.
- **Scale above 100 Workers:** Concurrency load tested up to 100 overlaps. 

## Blockers
- None.

## Known Limitations
- **Local /tmp File Storage:** Recovery is mathematically bound to the same physical node because the `.apk` resides in `/tmp`. If Node A dies, Node B will claim the job from the DB, but fail finding the file. Phase 3 (GCS) resolves this natively.

## Phase 3 Readiness
READY
