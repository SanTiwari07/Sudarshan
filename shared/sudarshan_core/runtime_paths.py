"""Portable filesystem locations for runtime artifacts.

Every writable location Sudarshan uses at runtime is resolved here, so no module
has to guess where the project root is or hardcode a platform's temp directory.

Two rules hold everywhere:

* an environment variable always wins, so a container, a CI runner and a SOC
  workstation can each point the engine somewhere appropriate without a code
  change, and
* the fallback is derived from this file's own location with
  :class:`pathlib.Path`, never from the process working directory - analysis
  runs are launched from the backend, the analysis engine and test harnesses
  alike, and each has a different cwd.

The previous ``Path(f"/tmp/sudarshan_{session_id}")`` in the session manager is
what this replaces: it is not a valid path on Windows, so a checkpoint written
there was unreadable on the machines most of this project is developed on.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Optional

# runtime_paths.py -> sudarshan_core -> shared -> <repo root>
_PACKAGE_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_ROOT.parents[1]

#: Environment variables, in the order each location consults them.
ENV_ARTIFACTS_DIR = "SUDARSHAN_ARTIFACTS_DIR"
ENV_CHECKPOINT_DIR = "SUDARSHAN_CHECKPOINT_DIR"
ENV_SESSION_DIR = "SUDARSHAN_SESSION_DIR"
ENV_PERSONA_DIR = "SUDARSHAN_PERSONA_DIR"


def repo_root() -> Path:
    """Project root, derived from this module's location."""
    return _REPO_ROOT


def package_root() -> Path:
    """Root of the installed ``sudarshan_core`` package."""
    return _PACKAGE_ROOT


def _from_env(var: str, default: Path, *, create: bool) -> Path:
    raw = os.getenv(var, "").strip()
    path = Path(raw).expanduser() if raw else default
    if create:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            # A read-only or non-existent configured root must not take the
            # process down - fall back to the OS temp area, which is writable
            # by definition, and let the caller proceed.
            path = Path(tempfile.gettempdir()) / "sudarshan" / default.name
            path.mkdir(parents=True, exist_ok=True)
    return path


def artifacts_dir(*, create: bool = True) -> Path:
    """Root for all generated forensic artifacts."""
    return _from_env(
        ENV_ARTIFACTS_DIR, _REPO_ROOT / "sudarshan_artifacts", create=create
    )


def checkpoint_dir(*, create: bool = True) -> Path:
    """Where session checkpoint snapshots are written."""
    raw = os.getenv(ENV_CHECKPOINT_DIR, "").strip()
    if raw:
        return _from_env(ENV_CHECKPOINT_DIR, Path(raw), create=create)
    # Derived from the artifacts root so relocating artifacts relocates
    # checkpoints with them, which is what an operator setting one variable
    # expects.
    return _from_env(
        ENV_CHECKPOINT_DIR, artifacts_dir(create=create) / "checkpoints", create=create
    )


def session_dir(session_id: str, *, create: bool = True) -> Path:
    """Per-session working directory for one dynamic analysis run."""
    raw = os.getenv(ENV_SESSION_DIR, "").strip()
    base = Path(raw).expanduser() if raw else artifacts_dir(create=create) / "sessions"
    path = base / safe_component(session_id)
    if create:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            path = Path(tempfile.gettempdir()) / "sudarshan" / safe_component(session_id)
            path.mkdir(parents=True, exist_ok=True)
    return path


def persona_dir(*, create: bool = False) -> Path:
    """Directory holding persona JSON templates.

    Ships inside the package so a pip-installed copy still has the defaults;
    override the environment variable to point at an operator-maintained set.
    """
    return _from_env(
        ENV_PERSONA_DIR, _PACKAGE_ROOT / "config" / "personas", create=create
    )


_UNSAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]")


def safe_component(value: str, *, fallback: str = "unnamed", limit: int = 96) -> str:
    """
    Sanitise a string for use as a single path component.

    Session ids and persona names reach this from request payloads, so
    separators and traversal sequences have to be stripped rather than trusted:
    a ``session_id`` of ``../../etc`` would otherwise escape the artifacts root.
    """
    cleaned = _UNSAFE_COMPONENT.sub("_", (value or "").strip())
    cleaned = cleaned.strip("._") or fallback
    return cleaned[:limit]
