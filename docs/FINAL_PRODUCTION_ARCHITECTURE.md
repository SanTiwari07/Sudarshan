# Final Production Architecture

## Scalability Implementation Complete
Sudarshan is now ready to support multi-node scaling and high volume ingestion safely.

### 1. Database & State
* **PostgreSQL:** Primary store. Connection pool tuned for high throughput with bounds (min=5, max=20, 	imeout=60s).
* **Durable Queue:** Asynchronous workers coordinate tasks across nodes. Lease recovery built-in.

### 2. Distributed Storage
* **GCS Integration:** Active via GCSArtifactStorage. Files seamlessly persist between worker stages without host filesystem boundaries.
* **Worker Fetch:** Nodes claim tasks via fingerprint and fetch required evidence direct from distributed storage automatically.

### 3. Backpressure & Quotas
* **Queue Depth:** System limits job queues dynamically via MAX_QUEUE_DEPTH, responding with HTTP 429 backpressure.
* **User Quotas:** Per-day submission constraints per analyst via USER_QUOTA_PER_DAY.
* **API Limits:** Endpoint ingestion regulated automatically at 10 requests / minute.

### 4. Concurrency Model
* **Static Limits:** Multi-node STATIC_MAX_CONCURRENCY defines generic background task workers processing APKs.
* **Dynamic Budget:** DYNAMIC_MAX_CONCURRENCY segregates Frida processing budgets without stalling overall pipeline execution.

## Verification
Multi-node object recovery, deterministic queue claiming, idempotency, deduplication, and local state recovery are fully verified by automated tests running against the production execution branches.
