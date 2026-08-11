#!/usr/bin/env python3
"""
Ingest an APK: compute SHA256 (case ID) and write ingestion_record.json.

Usage:
    PYTHONPATH=backend;shared python scripts/apk_ingest.py path/to/sample.apk
    PYTHONPATH=backend;shared python scripts/apk_ingest.py --drinik
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sudarshan_core.ingest.apk_record import (
    build_apk_record,
    resolve_drinik_apk_path,
    write_ingestion_record,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest APK and compute case SHA256")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    parser.add_argument("--drinik", action="store_true", help="Resolve Drinik APK from env/corpus paths")
    parser.add_argument("-o", "--output-dir", help="Directory for ingestion_record.json")
    args = parser.parse_args(argv)

    apk_path = args.apk
    if args.drinik:
        resolved = resolve_drinik_apk_path(apk_path)
        if not resolved:
            print(
                "No Drinik APK found. Place sample at tests/apks/categories/drinik.apk "
                "or set DRINIK_APK_PATH.",
                file=sys.stderr,
            )
            return 2
        apk_path = str(resolved)

    if not apk_path:
        parser.error("Provide apk path or --drinik")

    record = write_ingestion_record(apk_path, output_dir=args.output_dir)
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
