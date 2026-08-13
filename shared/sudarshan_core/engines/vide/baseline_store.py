"""Load and index institution UI baselines.

Two baseline sources are merged:

* the ``apk_details`` corpus (10 Indian retail banks, the production set), and
* the legacy hand-written lab baselines in ``data/ui_baselines/*.json``.

Baselines are cached in-memory behind :func:`get_baselines` because Tier 1/2
static analysis looks them up per-sample and re-reading ~40 files each time is
pure overhead. :func:`refresh_baselines` invalidates the cache for the admin
refresh endpoint and the periodic background worker.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.vide.corpus_loader import (
    BaselineScreen,
    DesignProfile,
    find_corpus_root,
    parse_design_md,
    parse_fingerprints,
    read_corpus_json,
)
from sudarshan_core.engines.vide.ui_profile import UIProfile

logger = logging.getLogger(__name__)

_DEFAULT_BASELINES_DIR = (
    Path(__file__).resolve().parents[2] / "data" / "ui_baselines"
)

SOURCE_CORPUS = "corpus"
SOURCE_LAB = "lab"


@dataclass
class InstitutionBaseline:
    institution_id: str
    display_name: str
    package_names: List[str]
    allowed_signers_sha256: List[str]
    profile: UIProfile
    version: str = "1.0.0"
    # Corpus-only enrichment. Empty for legacy lab baselines.
    source: str = SOURCE_LAB
    bank: str = ""
    app_name: str = ""
    screens: List[BaselineScreen] = field(default_factory=list)
    design: Optional[DesignProfile] = None
    navigation: Dict[str, Any] = field(default_factory=dict)
    corpus_packages: List[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "InstitutionBaseline":
        prof = UIProfile.from_dict(data.get("profile") or data)
        return cls(
            institution_id=str(data.get("institution_id", "")),
            display_name=str(data.get("display_name", data.get("institution_id", ""))),
            package_names=list(data.get("package_names") or []),
            allowed_signers_sha256=list(data.get("allowed_signers_sha256") or []),
            profile=prof,
            version=str(data.get("version", "1.0.0")),
            source=SOURCE_LAB,
        )

    def summary(self) -> Dict[str, Any]:
        """Lightweight description for the /baselines API."""
        return {
            "institution_id": self.institution_id,
            "display_name": self.display_name,
            "bank": self.bank,
            "app_name": self.app_name,
            "source": self.source,
            "version": self.version,
            "package_names": list(self.package_names),
            "screen_count": len(self.screens),
            "string_count": len(self.profile.strings),
            "brand_palette": list(self.design.brand_palette) if self.design else [],
        }


# ─────────────────────────────── corpus ────────────────────────────────────


def _build_corpus_baseline(
    entry: Dict[str, Any],
    corpus_root: Path,
) -> Optional[InstitutionBaseline]:
    """Assemble one InstitutionBaseline from a baselines_index.json entry."""
    baseline_id = str(entry.get("id") or "").strip()
    if not baseline_id:
        return None

    def _resolve(key: str) -> Optional[Path]:
        rel = entry.get(key)
        if not isinstance(rel, str) or not rel:
            return None
        path = corpus_root / rel
        return path if path.is_file() else None

    fingerprint_path = _resolve("fingerprints")
    design_path = _resolve("design")
    meta_path = _resolve("meta")
    nav_path = _resolve("navigation")

    screens: List[BaselineScreen] = []
    if fingerprint_path:
        screens = parse_fingerprints(read_corpus_json(fingerprint_path))

    design: Optional[DesignProfile] = None
    if design_path:
        try:
            design = parse_design_md(design_path.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            logger.warning("[VIDE] design.md unreadable for %s: %s", baseline_id, exc)

    meta = read_corpus_json(meta_path) if meta_path else {}
    navigation = read_corpus_json(nav_path) if nav_path else {}

    if not screens and not design:
        logger.warning("[VIDE] corpus entry %s has no usable profile", baseline_id)
        return None

    # Aggregate profile for the deterministic comparer.
    strings: List[str] = []
    for screen in screens:
        for value in screen.exact_strings:
            if value not in strings:
                strings.append(value)

    # Only identity-carrying colours: neutral surfaces would match every app.
    colors: List[str] = []
    if design:
        colors.extend(design.brand_palette)
    for screen in screens:
        for value in screen.brand_tokens.values():
            if value not in colors:
                colors.append(value)

    region_sequence: List[str] = []
    for screen in screens:
        region_sequence.extend(screen.region_order)

    package_names = list(design.referenced_packages) if design else []

    return InstitutionBaseline(
        institution_id=baseline_id,
        display_name=str(entry.get("appName") or meta.get("appName") or baseline_id),
        package_names=package_names,
        allowed_signers_sha256=[],
        profile=UIProfile(
            source="corpus_baseline",
            strings=strings,
            view_sequence=region_sequence,
            colors=[c for c in dict.fromkeys(colors)],
            asset_hashes=[],
        ),
        version=str(meta.get("corpusVersion") or "1.0"),
        source=SOURCE_CORPUS,
        bank=str(entry.get("bank") or meta.get("bank") or ""),
        app_name=str(entry.get("appName") or meta.get("appName") or ""),
        screens=screens,
        design=design,
        navigation=navigation,
    )


def load_corpus_baselines(corpus_root: Optional[Path] = None) -> List[InstitutionBaseline]:
    """Parse ``apk_details/baselines_index.json`` into baselines."""
    root = find_corpus_root(corpus_root)
    if root is None:
        logger.info("[VIDE] baseline corpus not found; using lab baselines only")
        return []

    index = read_corpus_json(root / "baselines_index.json")
    entries = index.get("baselines") or []
    out: List[InstitutionBaseline] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            baseline = _build_corpus_baseline(entry, root)
        except Exception as exc:  # never let one bad entry kill ingestion
            logger.warning("[VIDE] corpus entry failed: %s", exc, exc_info=True)
            continue
        if baseline:
            out.append(baseline)
    logger.info(
        "[VIDE] ingested %d/%d corpus baselines (version %s)",
        len(out),
        len(entries),
        index.get("corpusVersion", "?"),
    )
    return out


# ──────────────────────────────── lab ──────────────────────────────────────


def load_lab_baselines(directory: Optional[Path] = None) -> List[InstitutionBaseline]:
    base_dir = directory or _DEFAULT_BASELINES_DIR
    if not base_dir.is_dir():
        logger.warning("[VIDE] Baseline directory missing: %s", base_dir)
        return []
    out: List[InstitutionBaseline] = []
    for path in sorted(base_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            bl = InstitutionBaseline.from_json(data)
            if bl.institution_id:
                out.append(bl)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("[VIDE] Skip baseline %s: %s", path.name, e)
    return out


def load_baselines(directory: Optional[Path] = None) -> List[InstitutionBaseline]:
    """All baselines: lab set first (explicit dir keeps legacy behaviour)."""
    if directory is not None:
        return load_lab_baselines(directory)
    return load_lab_baselines() + load_corpus_baselines()


# ──────────────────────────────── cache ────────────────────────────────────


@dataclass
class _CacheState:
    baselines: List[InstitutionBaseline] = field(default_factory=list)
    loaded_at: float = 0.0
    generation: int = 0


_cache = _CacheState()
_cache_lock = threading.Lock()
_CACHE_TTL_SECONDS = 15 * 60


def get_baselines(force_refresh: bool = False) -> List[InstitutionBaseline]:
    """Cached baseline lookup used by the analysis hot path."""
    now = time.time()
    with _cache_lock:
        fresh = (
            _cache.baselines
            and not force_refresh
            and (now - _cache.loaded_at) < _CACHE_TTL_SECONDS
        )
        if fresh:
            return _cache.baselines
        loaded = load_baselines()
        _cache.baselines = loaded
        _cache.loaded_at = now
        _cache.generation += 1
        return loaded


def refresh_baselines() -> Dict[str, Any]:
    """Invalidate and reload the cache. Returns a report for the admin API."""
    started = time.time()
    baselines = get_baselines(force_refresh=True)
    corpus = [b for b in baselines if b.source == SOURCE_CORPUS]
    return {
        "refreshed": True,
        "total": len(baselines),
        "corpus_baselines": len(corpus),
        "lab_baselines": len(baselines) - len(corpus),
        "generation": _cache.generation,
        "duration_ms": round((time.time() - started) * 1000, 2),
        "institutions": [b.institution_id for b in corpus],
    }


def cache_status() -> Dict[str, Any]:
    with _cache_lock:
        return {
            "loaded": bool(_cache.baselines),
            "count": len(_cache.baselines),
            "generation": _cache.generation,
            "age_seconds": (
                round(time.time() - _cache.loaded_at, 2) if _cache.loaded_at else None
            ),
            "ttl_seconds": _CACHE_TTL_SECONDS,
        }


# ───────────────────────────── shortlisting ────────────────────────────────


def shortlist_baselines(
    suspect: UIProfile,
    baselines: List[InstitutionBaseline],
    top_k: int = 5,
    min_string_overlap: int = 1,
) -> List[InstitutionBaseline]:
    """
    Cheap pre-filter before deterministic full compare.

  Rule: a baseline is a candidate only if it shares at least
  ``min_string_overlap`` normalized strings with the suspect.
  If none qualify, return [] (do not compare arbitrary banks).
    """
    if not baselines:
        return []
    suspect_strings = {s.lower().strip() for s in suspect.strings if s.strip()}
    if not suspect_strings and not suspect.view_sequence:
        return []

    scored: List[tuple[float, int, InstitutionBaseline]] = []
    for bl in baselines:
        base_strings = {s.lower().strip() for s in bl.profile.strings if s.strip()}
        if not base_strings:
            continue
        overlap = len(suspect_strings & base_strings)
        if overlap < min_string_overlap:
            continue
        score = overlap / max(len(base_strings), 1)
        scored.append((score, overlap, bl))

    scored.sort(key=lambda x: (-x[0], -x[1], x[2].institution_id))
    return [b for _, _, b in scored[:top_k]]
