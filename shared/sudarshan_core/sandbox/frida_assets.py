"""
Frida server asset resolution by device ABI.

Never silently push an x86_64 binary onto an arm64 device. Locate the matching
host-side frida-server and report actionable errors when it is missing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

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
        # shared/sudarshan_core/sandbox/frida_assets.py → repo root
        repo_root = Path(__file__).resolve().parents[3]

    version = default_frida_version()
    roots.extend(
        [
            repo_root / f"frida-server-{version}-android-x86_64",
            repo_root / f"frida-server-{version}-android-x86",
            repo_root / f"frida-server-{version}-android-arm64",
            repo_root / f"frida-server-{version}-android-arm",
            repo_root / "frida-server",
            repo_root / "bin" / "frida-server",
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
