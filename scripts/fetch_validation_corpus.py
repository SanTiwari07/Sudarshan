#!/usr/bin/env python3
"""Fetch OSS validation APKs listed in corpus.manifest.json."""

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

from sudarshan_core.validation.corpus import fetch_all, load_corpus, fetch_entry

logging.basicConfig(level=logging.INFO, format="%(message)s")


def main() -> int:
    n = fetch_all()
    present = sum(1 for e in load_corpus() if e.apk_path.is_file())
    print(f"Fetched {n} URL(s); {present} APK(s) present on disk.")
    return 0 if present > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
