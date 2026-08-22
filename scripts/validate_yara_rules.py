#!/usr/bin/env python3
"""
Measure the YARA ruleset against the labelled corpus.

    python scripts/validate_yara_rules.py
    python scripts/validate_yara_rules.py --rules <dir> --corpus <dir>

Two passes, because the two scanner entry points see very different data:

  apk      - rules.match(<apk path>), what YARAScanner.scan_file() does. Only
             ZIP entry names and container structure are visible; entry content
             is deflated.
  strings  - rules.match(data=<decompressed entries>), which APPROXIMATES what
             YARAScanner.scan_strings() sees once Frida has recovered runtime
             strings from a decrypted payload.

The second pass is an approximation and is labelled as one. Decompressing an
APK is not the same as running it: a packed sample's second stage stays
encrypted on disk, so this pass under-reports what a live run would find. It is
still the more honest of the two for behaviour rules, and it catches a rule that
would fire on a benign app's plaintext.

The number that matters is FALSE POSITIVES on the 9 benign controls. A rule that
fires on VLC is worse than a rule that misses a trojan, because an analyst who
learns to ignore the ruleset gets nothing from any of it.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

try:
    import yara
except ImportError:
    print("yara-python is not installed. pip install yara-python", file=sys.stderr)
    raise SystemExit(2)

from sudarshan_core.validation.labelled_corpus import (  # noqa: E402
    find_labelled_corpus_root,
    load_labelled_samples,
)

DEFAULT_RULES_DIR = _ROOT / "shared" / "sudarshan_core" / "engines" / "yara_rules"

#: Cap on decompressed bytes per sample for the strings pass. VLC alone expands
#: past 100 MB and the tail adds nothing but wall-clock.
MAX_DECOMPRESSED_BYTES = 180 * 1024 * 1024


def decompressed(path: Path, cap: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Every entry concatenated, so plaintext inside the ZIP is matchable."""
    out = bytearray()
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if len(out) >= cap:
                    break
                try:
                    out += archive.read(info)
                except Exception:
                    continue      # one unreadable entry must not lose the rest
    except Exception:
        return b""
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", default=str(DEFAULT_RULES_DIR))
    parser.add_argument("--corpus")
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    filepaths = {
        f.name: str(f)
        for f in sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
    }
    if not filepaths:
        print(f"No .yar/.yara files in {rules_dir}", file=sys.stderr)
        return 2
    try:
        rules = yara.compile(filepaths=filepaths)
    except yara.Error as exc:
        print(f"Rules do not compile: {exc}", file=sys.stderr)
        return 1
    print(f"compiled {len(filepaths)} ruleset(s) from {rules_dir}")

    root = find_labelled_corpus_root(Path(args.corpus) if args.corpus else None)
    if root is None:
        print("Labelled corpus not found.", file=sys.stderr)
        return 2
    samples = load_labelled_samples(root)
    print(f"corpus: {root}  ({len(samples)} samples)\n")

    # rule -> label -> [sample names]
    fired: Dict[str, Dict[str, List[str]]] = defaultdict(
        lambda: {"malware": [], "benign": []}
    )
    per_sample: Dict[str, List[str]] = {}

    for sample in samples:
        names = set()
        for match in rules.match(str(sample.path)):
            names.add(match.rule)
        blob = decompressed(sample.path)
        if blob:
            for match in rules.match(data=blob):
                names.add(match.rule)
        per_sample[sample.display_name] = sorted(names)
        for rule_name in names:
            fired[rule_name][sample.label].append(sample.display_name)
        print(
            f"  {sample.label:8} {sample.display_name[:30]:30} "
            f"{', '.join(sorted(names)) or '-'}",
            flush=True,
        )

    n_mal = sum(1 for s in samples if s.label == "malware")
    n_ben = sum(1 for s in samples if s.label == "benign")

    all_rules = sorted({r.identifier for r in rules})
    header = f"\n{'rule':45} {'malware':>9} {'benign':>8}   false positives"
    print(header)
    print("-" * len(header))
    false_positives = 0
    for rule_name in all_rules:
        hits = fired.get(rule_name, {"malware": [], "benign": []})
        mal, ben = len(hits["malware"]), len(hits["benign"])
        false_positives += ben
        print(
            f"{rule_name:45} {mal:>4}/{n_mal:<4} {ben:>3}/{n_ben:<4}   "
            f"{', '.join(hits['benign']) if ben else '-'}"
        )

    detected = sum(
        1 for s in samples if s.label == "malware" and per_sample[s.display_name]
    )
    clean = sum(
        1 for s in samples if s.label == "benign" and not per_sample[s.display_name]
    )
    print(f"\nmalware with at least one rule hit : {detected}/{n_mal}")
    print(f"benign with no rule hit at all     : {clean}/{n_ben}")
    print(f"total false-positive rule hits     : {false_positives}")

    if false_positives:
        print(
            "\nFAIL: a rule fired on a benign control. Tighten it or drop it - "
            "a noisy ruleset is one an analyst learns to ignore."
        )
        return 1
    print("\nOK: no rule fired on any benign control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
