"""
Locating the labelled malware corpus.

The corpus is 17 APKs organised by category - 8 real banking trojans plus 9
non-malware controls. It is deliberately gitignored (`.gitignore:136`): the
Malware/ folder holds live banking trojans that must not be committed. Every
consumer therefore has to locate it at run time and degrade cleanly when it is
absent, rather than assuming a path.

Path resolution follows the same discipline as
``engines/vide/corpus_loader.find_corpus_root``: explicit argument, then
environment, then in-repo defaults, and a candidate only counts if it actually
carries the expected marker - so a stale environment variable pointing at a
deleted directory falls through instead of silently disabling detection.

One wrinkle this module exists to absorb: the in-repo corpus currently lives at
``test apk/test apk/`` - the folder is nested inside another of the same name.
Two callers hardcoded the un-nested path and have been silently pointing at
nothing (``scripts/health_check.py``, ``tests/integration/test_pipeline.py``).
The descent below is written generically - check a candidate, then check its
immediate subdirectories - rather than special-casing that one layout, so
flattening the directory later does not re-break every caller.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# Category directory -> label used for precision/recall.
#
# "Vulnerable" (InsecureBankv2) counts as benign on purpose: it is deliberately
# INSECURE, not malicious. Scoring it as malware would inflate recall by
# rewarding the engine for flagging a training app. This labelling call is
# reported in the harness output rather than left implicit.
CATEGORY_LABELS: Dict[str, str] = {
    "Malware": "malware",
    "Safe": "benign",
    "Vulnerable": "benign",
    "MAS Crackmes": "benign",
}

CORPUS_ENV_VARS = ("SUDARSHAN_LABELLED_CORPUS_DIR",)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_CORPUS_DIRS: List[Path] = [
    _REPO_ROOT / "test apk",
    _REPO_ROOT / "tests" / "apks" / "labelled",
]

# How deep to descend looking for the category directories. 1 covers the
# current double-nesting; more would start trawling unrelated trees.
_MAX_DESCENT = 1


@dataclass(frozen=True)
class LabelledSample:
    """One APK in the corpus, with the label its containing folder implies."""

    path: Path
    category: str          # "Malware" | "Safe" | "Vulnerable" | "MAS Crackmes"
    label: str             # "malware" | "benign"
    display_name: str      # file stem, e.g. "Amaze File Manager"

    @property
    def file_name(self) -> str:
        return self.path.name


def _is_corpus_root(candidate: Path) -> bool:
    """True when `candidate` directly contains a category folder holding APKs."""
    try:
        return any(
            (candidate / category).is_dir() and any((candidate / category).glob("*.apk"))
            for category in CATEGORY_LABELS
        )
    except OSError:
        return False


def _descend(candidate: Path, depth: int = _MAX_DESCENT) -> Optional[Path]:
    """Return `candidate` if it is a corpus root, else search its subdirectories."""
    if _is_corpus_root(candidate):
        return candidate
    if depth <= 0:
        return None
    try:
        children = sorted(p for p in candidate.iterdir() if p.is_dir())
    except OSError:
        return None
    for child in children:
        found = _descend(child, depth - 1)
        if found is not None:
            return found
    return None


def corpus_search_order(explicit: Optional[Path] = None) -> List[Path]:
    """
    The candidate directories that will be tried, in order.

    Exposed so a failure message can show what was actually looked at. "Corpus
    not found" without the search order is the kind of error that costs an hour.
    """
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    for var in CORPUS_ENV_VARS:
        env_dir = os.environ.get(var)
        if env_dir and env_dir.strip():
            candidates.append(Path(env_dir.strip()))
    candidates.extend(_DEFAULT_CORPUS_DIRS)

    seen: List[Path] = []
    for c in candidates:
        if c not in seen:
            seen.append(c)
    return seen


def find_labelled_corpus_root(explicit: Optional[Path] = None) -> Optional[Path]:
    """
    Locate the labelled corpus root, or None when it is not present.

    None is an ordinary outcome, not an error: the corpus is gitignored, so a
    fresh clone legitimately has none. Callers should report that and exit
    distinguishably rather than raising.
    """
    for candidate in corpus_search_order(explicit):
        found = _descend(candidate)
        if found is not None:
            return found
    return None


def load_labelled_samples(root: Path) -> List[LabelledSample]:
    """
    Every APK under `root`, sorted by (category, file name) for stable output.

    Sorting here rather than relying on filesystem order keeps the generated
    results table diffable across machines.
    """
    samples: List[LabelledSample] = []
    for category, label in CATEGORY_LABELS.items():
        category_dir = root / category
        if not category_dir.is_dir():
            continue
        for apk in sorted(category_dir.glob("*.apk")):
            samples.append(
                LabelledSample(
                    path=apk,
                    category=category,
                    label=label,
                    display_name=apk.stem,
                )
            )
    return sorted(samples, key=lambda s: (s.category, s.file_name))


def resolve_sample(relative: str, explicit: Optional[Path] = None) -> Optional[Path]:
    """
    Resolve one known sample, e.g. ``"Vulnerable/InsecureBankv2.apk"``.

    For the several callers that want a single fixture APK and should not be
    rebuilding corpus paths by hand.
    """
    root = find_labelled_corpus_root(explicit)
    if root is None:
        return None
    candidate = root / relative
    return candidate if candidate.is_file() else None
