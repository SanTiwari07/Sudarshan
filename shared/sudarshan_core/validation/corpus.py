"""Load validation APK corpus from tests/apks/corpus.manifest.json."""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_MANIFEST = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "apks" / "corpus.manifest.json"
CORPUS_ROOT = DEFAULT_MANIFEST.parent


@dataclass
class CorpusEntry:
    id: str
    category: str
    label: str
    apk_path: Path
    optional: bool = False
    package_hint: str = ""
    fetch_url: str = ""
    notes: str = ""
    missing: bool = False
    missing_reason: str = ""


def _resolve_apk_path(entry: Dict[str, Any], root: Path) -> Path:
    rel = entry.get("relative_path", "")
    path = root / rel
    if path.is_file():
        return path.resolve()
    alias = entry.get("alias_of")
    if alias:
        alias_path = root / alias
        if alias_path.is_file():
            return alias_path.resolve()
    return path.resolve()


def load_corpus(manifest_path: Optional[Path] = None) -> List[CorpusEntry]:
    manifest_path = manifest_path or DEFAULT_MANIFEST
    root = manifest_path.parent
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries: List[CorpusEntry] = []
    for raw in data.get("samples", []):
        apk = _resolve_apk_path(raw, root)
        missing = not apk.is_file()
        reason = ""
        if missing:
            reason = f"APK not found at {apk}"
        entries.append(
            CorpusEntry(
                id=raw["id"],
                category=raw.get("category", raw["id"]),
                label=raw.get("label", raw["id"]),
                apk_path=apk,
                optional=bool(raw.get("optional")),
                package_hint=raw.get("package_hint", ""),
                fetch_url=raw.get("fetch_url", ""),
                notes=raw.get("notes", ""),
                missing=missing,
                missing_reason=reason,
            )
        )
    return entries


def fetch_entry(entry: CorpusEntry) -> bool:
    if not entry.fetch_url or entry.apk_path.is_file():
        return entry.apk_path.is_file()
    entry.apk_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        logger.info("Fetching %s from %s", entry.id, entry.fetch_url)
        urllib.request.urlretrieve(entry.fetch_url, entry.apk_path)
        entry.missing = False
        entry.missing_reason = ""
        return True
    except Exception as exc:
        logger.error("Fetch failed for %s: %s", entry.id, exc)
        return False


def fetch_all(manifest_path: Optional[Path] = None) -> int:
    ok = 0
    for entry in load_corpus(manifest_path):
        if entry.fetch_url and fetch_entry(entry):
            ok += 1
    return ok
