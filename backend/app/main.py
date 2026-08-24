import os
import logging
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from root .env file
_env_path = Path(__file__).resolve().parents[2] / ".env"
if not _env_path.exists():
    _env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=_env_path)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.rate_limit import limiter

from app.routes import (
    upload, report, intelligence, screenshots, discovery, baselines, resilience, batch,
)
from app.routes.runtime_api import router as runtime_router
from app.routes.cases import router as cases_router
from app.auth.auth import router as auth_router
from app.db.database import init_db
from app.workers.analysis_queue import start_workers, stop_workers
from app.workers.batch_worker import start_batch_worker, stop_batch_worker
from app.workers.baseline_refresh import start_baseline_refresh, stop_baseline_refresh
from app.auth.auth import hash_password, username_exists, create_user

# ─── Structured Logging Configuration ────────────────────────────────────────
# Androguard at DEBUG level produces tens of thousands of log records per
# analysis, each holding DEX parse-tree references that inflate memory to 2-3 GB.
# Must be WARNING in production to prevent OOM kills (exit 137).
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
for _noisy in ("androguard", "androguard.core", "androguard.core.analysis",
               "androguard.core.bytecodes", "androguard.core.analysis.analysis",
               "androguard.core.axml"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

try:
    import loguru
    loguru.logger.disable("androguard")
except ImportError:
    pass

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sudarshan Enterprise Banking Threat Intelligence Platform",
    version="2.1.0",
    description=(
        "APK malware analysis engine with Androguard/MobSF static analysis, "
        "Frida dynamic behavioral sandbox, RAG-grounded Gemini Flash intelligence, "
        "threat correlation (VT/OTX/AbuseIPDB), 5-axis STEI scoring, "
        "JWT auth, persistent SQLite case store, and async job queue."
    ),
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# allow_origins=["*"] together with allow_credentials=True is invalid per the
# Fetch standard; Starlette resolves it by reflecting the caller's Origin, which
# means every site on the internet becomes a trusted origin. Use an explicit
# allow-list instead - override with CORS_ALLOW_ORIGINS (comma-separated).
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"
CORS_ALLOW_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ALLOW_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ─── Routers ─────────────────────────────────────────────────────────────────

app.include_router(auth_router,          prefix="/api/v1",         tags=["Authentication"])
app.include_router(upload.router,        prefix="/api/v1",         tags=["Analysis"])
app.include_router(batch.router,         prefix="/api/v1",         tags=["Enterprise Batch Scan"])
app.include_router(discovery.router,     prefix="/api/v1",         tags=["APK Discovery"])
app.include_router(report.router,        prefix="/api/v1",         tags=["Reports & Export"])
app.include_router(cases_router,         prefix="/api/v1",         tags=["Case History"])
app.include_router(intelligence.router,  prefix="/api/v1",         tags=["Threat Intelligence"])
app.include_router(screenshots.router,   prefix="/api/v1",         tags=["Screenshots"])
app.include_router(baselines.router,     prefix="/api/v1",         tags=["VIDE Baselines"])
app.include_router(resilience.router,    prefix="/api/v1",         tags=["Investigation Resilience"])
app.include_router(runtime_router,       prefix="/api",            tags=["Runtime Telemetry"])


# ─── Startup / Shutdown ───────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    from sudarshan_core.security.sandbox_containment import validate_backend_production_config
    from app.startup_validation import validate_production_environment

    validate_backend_production_config()
    validate_production_environment()
    # 1. Initialize SQLite tables
    await init_db()
    logger.info("[Startup] Database initialized")

    # 2. Seed the admin user if none exists.
    #    No hardcoded default password: a known credential in a public repo is a
    #    published credential. If ADMIN_PASSWORD is unset we mint a random one
    #    and print it exactly once, on first boot only.
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD")

    if not await username_exists(admin_user):
        generated = False
        if not admin_pass:
            admin_pass = secrets.token_urlsafe(18)
            generated = True

        hashed = hash_password(admin_pass)
        await create_user(admin_user, hashed, role="admin")

        if generated:
            logger.warning(
                "[Startup] ADMIN_PASSWORD was not set. Seeded admin '%s' with a "
                "generated password: %s - store it now; it is not recoverable "
                "and will not be shown again.",
                admin_user, admin_pass,
            )
        else:
            logger.info(f"[Startup] Seeded admin user: {admin_user}")

    # 2b. Optional BOI hackathon demo accounts (soclead, analyst1, optional boi_*).
    try:
        from app.demo_seed import seed_demo_users
        await seed_demo_users()
    except Exception as e:
        logger.warning(f"[Startup] Demo user seed skipped ({e})")

    # 3. Install the persistent IOC reputation cache.
    #    The ioc_cache table and its 24h-TTL accessors already existed and were
    #    never called, so every analysis re-queried VirusTotal / OTX / AbuseIPDB
    #    from scratch - up to 14 requests against a 4-req/min free tier.
    #    sudarshan_core cannot import app.db (the analysis engine has no such
    #    package), so the accessors are injected here instead.
    try:
        from sudarshan_core.services.threat_correlator import configure_ioc_cache
        from app.db.database import get_cached_ioc, save_ioc_cache
        configure_ioc_cache(get_cached_ioc, save_ioc_cache)
        logger.info("[Startup] IOC reputation cache wired (24h TTL)")
    except Exception as e:
        logger.warning(f"[Startup] IOC cache not wired ({e}); correlation will run uncached")

    # 4. Register the runtime-telemetry sink on the shared event bus.
    #    sudarshan_core used to import this module directly, which fails in the
    #    analysis engine (no app package) and was swallowed - so all hook and
    #    event telemetry from the delegated path went nowhere. Registering a
    #    sink keeps the dependency pointing downward.
    try:
        from sudarshan_core.engines.event_bus import register_telemetry_sink
        from app.routes.runtime_api import record_event
        register_telemetry_sink(record_event)
        logger.info("[Startup] Runtime telemetry sink registered")
    except Exception as e:
        logger.warning(f"[Startup] Telemetry sink not registered ({e})")

    # 5. Warm the VIDE baseline corpus and schedule periodic re-ingestion.
    #    Loading is cached in-process so static analysis does not re-read the
    #    ~40 corpus files per sample; the admin refresh endpoint and this
    #    worker are the two ways the cache is invalidated.
    await start_baseline_refresh()

    # 6. Start async analysis worker pool
    await start_workers()
    logger.info("[Startup] Analysis worker pool started")

    # 7. Start enterprise batch scan worker
    await start_batch_worker()
    logger.info("[Startup] Enterprise batch scan worker started")


@app.on_event("shutdown")
async def shutdown():
    await stop_batch_worker()
    await stop_baseline_refresh()
    await stop_workers()
    logger.info("[Shutdown] Analysis workers stopped")


# ─── Root Endpoints ───────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return {
        "status": "Sudarshan Enterprise Banking Threat Intelligence Platform Online",
        "version": "2.1.0",
        "engines": ["androguard", "mobsf (if configured)", "frida (if emulator connected)"],
        "scoring": [
            "5-axis STEI (CT×0.60 + BT×0.20 + PR×0.10 + OB×0.05 + IR×0.05)",
            "BFCI (frida dynamic behavioral formula)",
            "FRS = 0.25×STEI + 0.35×BFCI + 0.20×Correlation + 0.20×BankingImpact",
        ],
        "intelligence": ["rag", "gemini-2.5-flash", "virustotal", "otx", "abuseipdb"],
        "export": ["stix-2.1", "ioc-csv"],
        "auth": "JWT Bearer",
        "storage": "SQLite (persistent case store + IOC cache)",
        "queue": "asyncio worker pool",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
