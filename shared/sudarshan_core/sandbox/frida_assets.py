"""
Frida server asset resolution by device ABI.

Never silently push an x86_64 binary onto an arm64 device. Locate the matching
host-side frida-server and report actionable errors when it is missing.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Frida release arch suffix ← Android ABI
_ABI_TO_FRIDA_ARCH: Dict[str, str] = {
    "x86_64": "x86_64",
    "x86": "x86",
    "arm64-v8a": "arm64",
    "arm64": "arm64",
    "aarch64": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "arm": "arm",
}

DEFAULT_FRIDA_VERSION = "17.16.4"


@dataclass(frozen=True)
class FridaBinarySpec:
    """Resolved (or missing) Frida server binary for a device ABI."""

    abi: str
    frida_arch: str
    version: str
    expected_name: str
    path: Optional[Path]
    search_dirs: Tuple[Path, ...]

    @property
    def found(self) -> bool:
        return self.path is not None and self.path.is_file()


def normalize_abi(abi: str) -> str:
    a = (abi or "").strip().lower()
    if not a:
        return ""
    # Prefer the first entry when abilist is passed accidentally
    if "," in a:
        a = a.split(",", 1)[0].strip()
    return a


def frida_arch_for_abi(abi: str) -> Optional[str]:
    a = normalize_abi(abi)
    if not a:
        return None
    if a in _ABI_TO_FRIDA_ARCH:
        return _ABI_TO_FRIDA_ARCH[a]
    # Soft match prefixes
    for key, arch in _ABI_TO_FRIDA_ARCH.items():
        if a.startswith(key):
            return arch
    return None


def pick_primary_abi(abi: str = "", abilist: str = "") -> str:
    """Choose the primary ABI for Frida binary selection."""
    primary = normalize_abi(abi)
    if primary:
        return primary
    if abilist:
        first = abilist.split(",")[0].strip()
        return normalize_abi(first)
    return ""


def default_frida_version() -> str:
    return (
        os.getenv("FRIDA_VERSION")
        or os.getenv("SUDARSHAN_FRIDA_VERSION")
        or DEFAULT_FRIDA_VERSION
    ).strip() or DEFAULT_FRIDA_VERSION


# Files that only ever exist at the top of a Sudarshan checkout.
_REPO_MARKERS = ("docker-compose.yml", ".env.example", ".git")


def detect_repo_root(start: Optional[Path] = None) -> Path:
    """
    Locate the repository root, or the best stand-in for it.

    ``parents[3]`` is correct only for the on-disk layout
    (``shared/sudarshan_core/sandbox/frida_assets.py`` → repo root). Inside the
    containers ``shared/`` is bind-mounted at ``/opt/sudarshan-core``, so the
    same arithmetic yields **/opt** - which is why the frida-server cache landed
    in the container's writable layer and was discarded on every rebuild.

    Resolution order:
      1. ``SUDARSHAN_REPO_ROOT`` - explicit override (set it in a container)
      2. the nearest ancestor holding a repo marker
      3. ``parents[3]`` - the host layout, unchanged
    """
    env_root = (os.getenv("SUDARSHAN_REPO_ROOT") or "").strip()
    if env_root:
        return Path(env_root).expanduser()

    here = (start or Path(__file__)).resolve()
    for parent in here.parents:
        if any((parent / marker).exists() for marker in _REPO_MARKERS):
            return parent

    return here.parents[3] if len(here.parents) > 3 else here.parent


def frida_server_search_dirs(repo_root: Optional[Path] = None) -> List[Path]:
    """Ordered directories that may contain frida-server binaries."""
    roots: List[Path] = []
    env_dir = (
        os.getenv("FRIDA_SERVER_DIR")
        or os.getenv("SUDARSHAN_FRIDA_SERVER_DIR")
        or ""
    ).strip()
    if env_dir:
        roots.append(Path(env_dir).expanduser())

    if repo_root is None:
        repo_root = detect_repo_root()

    version = default_frida_version()
    roots.extend(
        [
            repo_root / f"frida-server-{version}-android-x86_64",
            repo_root / f"frida-server-{version}-android-x86",
            repo_root / f"frida-server-{version}-android-arm64",
            repo_root / f"frida-server-{version}-android-arm",
            repo_root / "frida-server",
            repo_root / "bin" / "frida-server",
            # auto_download_dir() caches into tools/, so it MUST be searched -
            # without it a downloaded or hand-placed binary is invisible to
            # locate_frida_server() and only the download short-circuit finds it.
            repo_root / "tools",
            repo_root / "tools" / "frida-server",
            repo_root,
        ]
    )
    # Deduplicate while preserving order
    seen = set()
    out: List[Path] = []
    for p in roots:
        key = str(p.resolve()) if p.exists() else str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def expected_binary_name(version: str, frida_arch: str) -> str:
    return f"frida-server-{version}-android-{frida_arch}"


def _candidate_names(version: str, frida_arch: str) -> List[str]:
    return [
        expected_binary_name(version, frida_arch),
        f"frida-server-android-{frida_arch}",
        "frida-server",
    ]


def locate_frida_server(
    abi: str,
    *,
    abilist: str = "",
    version: Optional[str] = None,
    search_dirs: Optional[Sequence[Path]] = None,
    repo_root: Optional[Path] = None,
) -> FridaBinarySpec:
    """
    Locate a host-side frida-server matching the device ABI.

    Returns a FridaBinarySpec even when missing so callers can print actionable
    errors (detected ABI, expected name, search directories).
    """
    primary = pick_primary_abi(abi, abilist)
    ver = (version or default_frida_version()).strip()
    dirs = list(search_dirs) if search_dirs is not None else frida_server_search_dirs(repo_root)
    arch = frida_arch_for_abi(primary) or ""
    expected = expected_binary_name(ver, arch) if arch else f"frida-server-{ver}-android-<arch>"

    if not arch:
        return FridaBinarySpec(
            abi=primary,
            frida_arch="",
            version=ver,
            expected_name=expected,
            path=None,
            search_dirs=tuple(dirs),
        )

    names = _candidate_names(ver, arch)
    # Also accept version-agnostic patterns in search dirs
    name_patterns = [
        re.compile(rf"^frida-server-{re.escape(ver)}-android-{re.escape(arch)}$"),
        re.compile(rf"^frida-server-.*-android-{re.escape(arch)}$"),
        re.compile(r"^frida-server$"),
    ]

    for directory in dirs:
        if not directory.exists():
            continue
        # Exact filenames first
        for name in names:
            candidate = directory / name
            if candidate.is_file() and candidate.stat().st_size > 100_000:
                return FridaBinarySpec(
                    abi=primary,
                    frida_arch=arch,
                    version=ver,
                    expected_name=expected,
                    path=candidate,
                    search_dirs=tuple(dirs),
                )
        # Directory itself may be the arch-specific folder
        if directory.is_dir():
            for child in directory.iterdir():
                if not child.is_file() or child.stat().st_size <= 100_000:
                    continue
                if child.suffix.lower() in (".xz", ".md", ".txt", ".sha256"):
                    continue
                if any(p.match(child.name) for p in name_patterns):
                    # Prefer arch match in filename when present
                    if arch in child.name or child.name == "frida-server":
                        return FridaBinarySpec(
                            abi=primary,
                            frida_arch=arch,
                            version=ver,
                            expected_name=expected,
                            path=child,
                            search_dirs=tuple(dirs),
                        )

    return FridaBinarySpec(
        abi=primary,
        frida_arch=arch,
        version=ver,
        expected_name=expected,
        path=None,
        search_dirs=tuple(dirs),
    )


def auto_download_dir(repo_root: Optional[Path] = None) -> Path:
    """Where auto-downloaded frida-server binaries are cached."""
    env_dir = (
        os.getenv("FRIDA_SERVER_DIR")
        or os.getenv("SUDARSHAN_FRIDA_SERVER_DIR")
        or ""
    ).strip()
    if env_dir:
        return Path(env_dir).expanduser()
    if repo_root is None:
        repo_root = detect_repo_root()
    return repo_root / "tools"


def auto_download_enabled() -> bool:
    return os.getenv(
        "SUDARSHAN_FRIDA_AUTO_DOWNLOAD", "1"
    ).strip().lower() not in ("0", "false", "no")


def download_frida_server(
    version: str,
    frida_arch: str,
    dest_dir: Optional[Path] = None,
    *,
    timeout: int = 300,
) -> Tuple[bool, str, Optional[Path]]:
    """
    Fetch frida-server from the official GitHub release and cache it.

    `tools/` is gitignored - the binary is ~106 MB, over GitHub's file limit -
    so a fresh clone has no frida-server and dynamic analysis fails on every new
    machine until somebody downloads one by hand. That manual step is the reason
    this setup "works on one laptop but not another"; fetching it on demand
    removes it.

    Returns (ok, message, path).
    """
    import lzma
    import urllib.error
    import urllib.request

    if not version or not frida_arch:
        return False, "version and frida_arch are required", None

    dest_dir = Path(dest_dir) if dest_dir else auto_download_dir()
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"cannot create {dest_dir}: {exc}", None

    binary_name = expected_binary_name(version, frida_arch)
    final_path = dest_dir / binary_name
    if final_path.is_file() and final_path.stat().st_size > 100_000:
        return True, f"already cached: {final_path}", final_path

    archive_name = f"{binary_name}.xz"
    url = (
        f"https://github.com/frida/frida/releases/download/{version}/{archive_name}"
    )
    archive_path = dest_dir / archive_name

    logger.info("[FridaAssets] Downloading %s", url)
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "sudarshan-frida-provisioner"}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
        archive_path.write_bytes(payload)
    except urllib.error.HTTPError as exc:
        return False, (
            f"HTTP {exc.code} fetching {url}. Check that frida {version} publishes "
            f"an android-{frida_arch} build."
        ), None
    except Exception as exc:
        return False, f"download failed ({exc}). Offline? Set FRIDA_SERVER_DIR to a local copy.", None

    try:
        with lzma.open(archive_path) as compressed:
            final_path.write_bytes(compressed.read())
    except Exception as exc:
        return False, f"could not decompress {archive_path}: {exc}", None
    finally:
        try:
            archive_path.unlink()
        except OSError:
            pass

    try:
        final_path.chmod(0o755)
    except OSError:
        pass

    size_mb = final_path.stat().st_size / (1024 * 1024)
    logger.info(
        "[FridaAssets] Cached %s (%.1f MB)", final_path, size_mb
    )
    return True, f"downloaded {binary_name} ({size_mb:.1f} MB)", final_path


def ensure_frida_server(
    abi: str,
    *,
    abilist: str = "",
    version: Optional[str] = None,
    repo_root: Optional[Path] = None,
) -> FridaBinarySpec:
    """
    Locate the matching frida-server, downloading it when absent.

    Idempotent and safe to call before every run: a cached binary short-circuits
    immediately. Honours SUDARSHAN_FRIDA_AUTO_DOWNLOAD=0 for air-gapped hosts,
    which then get the usual actionable "place it here" message.
    """
    spec = locate_frida_server(
        abi, abilist=abilist, version=version, repo_root=repo_root
    )
    if spec.path is not None:
        return spec
    if not spec.frida_arch:
        return spec          # unknown ABI - nothing to download
    if not auto_download_enabled():
        logger.warning(
            "[FridaAssets] %s missing and auto-download disabled.",
            spec.expected_name,
        )
        return spec

    ok, message, path = download_frida_server(
        spec.version, spec.frida_arch, auto_download_dir(repo_root)
    )
    if not ok:
        logger.error("[FridaAssets] Auto-download failed: %s", message)
        return spec

    return FridaBinarySpec(
        abi=spec.abi,
        frida_arch=spec.frida_arch,
        version=spec.version,
        expected_name=spec.expected_name,
        path=path,
        search_dirs=spec.search_dirs,
    )


def missing_binary_message(spec: FridaBinarySpec) -> str:
    """Actionable error text when the required Frida binary is absent."""
    places = "\n".join(f"  - {d}" for d in spec.search_dirs[:6])
    return (
        "Frida startup failed\n"
        f"ABI: {spec.abi or '(unknown)'}\n"
        f"Expected binary: {spec.expected_name}\n"
        f"Binary found: no\n"
        f"Place the matching Frida server in one of:\n{places}\n"
        f"Download: https://github.com/frida/frida/releases/tag/{spec.version}"
    )


def supported_host_abis(repo_root: Optional[Path] = None) -> List[str]:
    """Return Android ABIs for which a host Frida binary is present."""
    supported: List[str] = []
    for abi in ("x86_64", "x86", "arm64-v8a", "armeabi-v7a"):
        spec = locate_frida_server(abi, repo_root=repo_root)
        if spec.found:
            supported.append(abi)
    return supported
