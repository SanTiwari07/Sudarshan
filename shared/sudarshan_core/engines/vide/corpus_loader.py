"""Load the ``apk_details`` banking baseline corpus into VIDE baselines.

The corpus ships one self-contained package per protected institution::

    apk_details/
      baselines_index.json                     master registry (10 banks)
      baseline-library/<BASE-ID>/
        design.md                  brand + design schema (colour tokens, type)
        fingerprints.json          per-screen structural signature + strings
        app.meta.json              identity / screen inventory
        navigation.manifest.json   screen transition graph

``design.md`` is the design-schema source: it carries the colour system table
that lets VIDE answer "is this suspect app dressed as this bank?" rather than
only "does it share some strings".

Corpus JSON is written by a PowerShell producer and carries a UTF-8 BOM, so
every read here goes through ``utf-8-sig``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.vide.ui_profile import UIProfile

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_CORPUS_DIR = _REPO_ROOT / "apk_details"

# `| primary | `#1B4AA0` (deep blue) | ...`  and the combined states row
# `| success `#178C4E` / warning `#E8A100` / error `#ED232A` | ... |`
_TOKEN_COLOR_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9_-]*)\s*\|?\s*`?(#[0-9A-Fa-f]{6,8})`?"
)
_HEX_RE = re.compile(r"#[0-9A-Fa-f]{6,8}")
_BACKTICKED = re.compile(r"`([^`]+)`")
_PKG_RE = re.compile(r"`((?:com|in)\.[a-z0-9_]+(?:\.[a-z0-9_]+)+)`")

# Colour tokens that actually carry brand identity. Neutral surfaces/text are
# shared by every banking app on earth and would create false matches.
_BRAND_TOKENS = ("primary", "secondary", "accent")
_NEUTRAL_COLORS = frozenset(
    {"#ffffff", "#000000", "#fff", "#000", "#f5f5f5", "#fafafa"}
)


@dataclass
class BaselineScreen:
    """One screen's structural fingerprint from ``fingerprints.json``."""

    screen_id: str
    structural_signature: str = ""
    region_order: List[str] = field(default_factory=list)
    exact_strings: List[str] = field(default_factory=list)
    brand_tokens: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "screen_id": self.screen_id,
            "structural_signature": self.structural_signature,
            "region_order": list(self.region_order),
            "exact_strings": list(self.exact_strings),
            "brand_tokens": dict(self.brand_tokens),
        }


@dataclass
class DesignProfile:
    """Design schema parsed from ``design.md``."""

    color_tokens: Dict[str, str] = field(default_factory=dict)
    brand_palette: List[str] = field(default_factory=list)
    full_palette: List[str] = field(default_factory=list)
    typography: str = ""
    must_implement_screens: List[str] = field(default_factory=list)
    referenced_packages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "color_tokens": dict(self.color_tokens),
            "brand_palette": list(self.brand_palette),
            "full_palette": list(self.full_palette),
            "typography": self.typography,
            "must_implement_screens": list(self.must_implement_screens),
            "referenced_packages": list(self.referenced_packages),
        }


def read_corpus_json(path: Path) -> Dict[str, Any]:
    """Read corpus JSON, tolerating the UTF-8 BOM the producer emits."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[VIDE] corpus file unreadable %s: %s", path.name, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _section(md: str, heading: str) -> str:
    """Return the body of a markdown section, up to the next heading."""
    pattern = re.compile(
        rf"^#{{1,4}}\s*{re.escape(heading)}\s*$(.*?)(?=^#{{1,4}}\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(md)
    return match.group(1) if match else ""


def parse_design_md(md: str) -> DesignProfile:
    """Extract the design schema (colour system, type, screens) from design.md."""
    profile = DesignProfile()
    if not md:
        return profile

    color_section = _section(md, "Color System")
    seen: List[str] = []
    for row in color_section.splitlines():
        if not row.lstrip().startswith("|"):
            continue
        # Skip the header/separator rows of the markdown table.
        if re.match(r"^\s*\|[\s|:-]*\|\s*$", row) or "| Token |" in row:
            continue
        for token, hex_value in _TOKEN_COLOR_RE.findall(row):
            key = token.strip().lower()
            value = hex_value.lower()
            if key in ("token", "value", "confidence", "evidence"):
                continue
            profile.color_tokens.setdefault(key, value)
        for hex_value in _HEX_RE.findall(row):
            low = hex_value.lower()
            if low not in seen:
                seen.append(low)

    profile.full_palette = seen
    profile.brand_palette = [
        profile.color_tokens[t]
        for t in _BRAND_TOKENS
        if t in profile.color_tokens and profile.color_tokens[t] not in _NEUTRAL_COLORS
    ]

    typography = _section(md, "Typography").strip()
    profile.typography = re.sub(r"\s+", " ", typography)[:400]

    inventory = _section(md, "SCREEN INVENTORY")
    must = re.search(r"\*\*MUST IMPLEMENT[^:]*:\*\*(.*?)(?:\*\*|\Z)", inventory, re.DOTALL)
    if must:
        profile.must_implement_screens = [
            s.strip().upper() for s in _BACKTICKED.findall(must.group(1)) if s.strip()
        ]

    profile.referenced_packages = sorted({m for m in _PKG_RE.findall(md)})
    return profile


def parse_fingerprints(data: Dict[str, Any]) -> List[BaselineScreen]:
    """Parse ``fingerprints.json`` into structural screen fingerprints."""
    screens: List[BaselineScreen] = []
    for entry in data.get("screens") or []:
        if not isinstance(entry, dict):
            continue
        screen_id = str(entry.get("screenId") or entry.get("screen_id") or "").strip()
        if not screen_id:
            continue
        brand_tokens = entry.get("brandTokens") or entry.get("brand_tokens") or {}
        screens.append(
            BaselineScreen(
                screen_id=screen_id,
                structural_signature=str(
                    entry.get("structuralSignature")
                    or entry.get("structural_signature")
                    or ""
                ),
                region_order=[
                    str(r) for r in (entry.get("regionOrder") or entry.get("region_order") or [])
                ],
                exact_strings=[
                    str(s) for s in (entry.get("exactStrings") or entry.get("exact_strings") or [])
                ],
                brand_tokens={
                    str(k): str(v).lower()
                    for k, v in brand_tokens.items()
                    if isinstance(v, str)
                },
            )
        )
    return screens


def find_corpus_root(explicit: Optional[Path] = None) -> Optional[Path]:
    """Locate the ``apk_details`` corpus: explicit > env > repo default."""
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_dir = os.environ.get("VIDE_CORPUS_DIR")
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.append(_DEFAULT_CORPUS_DIR)

    for candidate in candidates:
        if (candidate / "baselines_index.json").is_file():
            return candidate
    return None
