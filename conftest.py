"""
Repository-wide pytest isolation.

Without this the suite wrote into whatever database the working directory
resolved to - `data/sudarshan.db` from the repo root, the same file a local
backend uses - so rows left by one run (e.g. QUEUED canonical jobs) were
claimed by tests in the next, and a developer's cases were mixed with test
fixtures. Each session now gets a throwaway SQLite file.

An explicit SUDARSHAN_TEST_DB_PATH still wins, for debugging a run's state.
"""

import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="sudarshan-pytest-"))
os.environ["SUDARSHAN_DB_PATH"] = os.getenv(
    "SUDARSHAN_TEST_DB_PATH", str(_tmp / "sudarshan.db")
)
# The Compose default points at Postgres; unit tests exercise the SQLite path.
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("JWT_SECRET_KEY", "pytest-only-secret-key-not-for-production")

# Keep the developer's real provider keys out of the suite. Several modules
# fill unset variables from the repo .env, which made unit tests issue live
# VirusTotal / OTX / AbuseIPDB / Gemini requests against real quotas. An empty
# value counts as "set", so the .env loaders leave it alone.
if not os.getenv("SUDARSHAN_TEST_USE_REAL_KEYS"):
    for _key in (
        "VIRUSTOTAL_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY",
        "GEMINI_API_KEY", "GEMINI_PRIMARY_API_KEY", "GEMINI_FALLBACK_API_KEY", "GOOGLE_API_KEY",
    ):
        os.environ[_key] = ""
