"""
Authoritative database path resolution.
=======================================

The gateway owns application persistence. Exactly one SQLite file is the source
of truth, and this module is the only place that decides which one.

Why this exists
---------------
`DB_PATH` used to be `os.getenv("SUDARSHAN_DB_PATH", "sudarshan.db")` - a
*relative* path resolved against the process CWD. Three consequences, all
observed in this repo:

  * `backend/sudarshan.db`        - the real one (uvicorn runs with CWD=backend)
  * `sudarshan.db`                - test spill (pytest runs from the repo root)
  * `analysis-engine/sudarshan.db` - AnalysisHistory() defaulting to its own CWD

and a fourth, worse one: under `docker-compose.hardened.yml` the backend gets
`read_only: true` with the dev bind-mount removed, so the path resolved to
`/app/sudarshan.db` on a read-only filesystem and `init_db()` raised
`unable to open database file` out of the startup event. The hardened overlay
could not boot.

Resolution order
----------------
1. ``SUDARSHAN_DB_PATH``      - explicit wins, always. This is what Compose sets.
2. A legacy ``./sudarshan.db`` next to the process CWD, **if it already exists**.
   Existing installs keep working untouched; we only warn.
3. ``<cwd>/data/sudarshan.db`` - the new default, in a directory that can be
   backed by a volume.

Rule 2 is the compatibility clause. Without it, deploying this change would
point a running install at an empty database and every existing case would
disappear from the UI. It is deliberately a warning, not silent behaviour.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_DB_PATH = "SUDARSHAN_DB_PATH"

LEGACY_BASENAME = "sudarshan.db"
DEFAULT_SUBDIR = "data"


def legacy_db_path() -> Path:
    """The pre-change location: `sudarshan.db` relative to the process CWD."""
    return Path.cwd() / LEGACY_BASENAME


def default_db_path() -> Path:
    """The new default: a `data/` directory that a volume can be mounted over."""
    return Path.cwd() / DEFAULT_SUBDIR / LEGACY_BASENAME


def resolve_db_path() -> Path:
    """
    Decide the authoritative database file. Pure - no filesystem writes.

    Read on every connection rather than frozen at import, so that setting
    SUDARSHAN_DB_PATH after import (which is what the test-suite does) is
    honoured.
    """
    explicit = os.getenv(ENV_DB_PATH, "").strip()
    if explicit:
        return Path(explicit).expanduser()

    legacy = legacy_db_path()
    if legacy.exists():
        return legacy

    return default_db_path()


def resolution_reason() -> str:
    """Human-readable explanation of *why* the current path was chosen."""
    if os.getenv(ENV_DB_PATH, "").strip():
        return f"{ENV_DB_PATH} is set"
    if legacy_db_path().exists():
        return (
            f"{ENV_DB_PATH} is unset and a legacy {LEGACY_BASENAME} exists in the "
            f"working directory - using it for backward compatibility"
        )
    return f"{ENV_DB_PATH} is unset - using the default location"


def ensure_parent(path: Path) -> None:
    """
    Create the containing directory.

    A read-only rootfs raises OSError here rather than deeper inside aiosqlite,
    where the error message does not say which directory was unwritable.
    """
    parent = path.parent
    if parent and not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OSError(
                f"Cannot create the database directory {parent}: {exc}. "
                f"Set {ENV_DB_PATH} to a writable location, and make sure that "
                f"location is a mounted volume if the container filesystem is "
                f"read-only."
            ) from exc
