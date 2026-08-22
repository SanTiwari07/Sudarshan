#!/usr/bin/env python3
"""
Score the labelled corpus with Sudarshan's static engine and compare to VirusTotal.

    python scripts/virustotal_crosscheck.py
    python scripts/virustotal_crosscheck.py --json out.json --rate 4

Requires VIRUSTOTAL_API_KEY in the environment or .env. Hashes are looked up;
sample files are never uploaded.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

# Load .env without overwriting anything already exported.
_env = _ROOT / ".env"
if _env.is_file():
    for line in _env.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")

from sudarshan_core.validation.labelled_corpus import (  # noqa: E402
    find_labelled_corpus_root,
    load_labelled_samples,
)
from sudarshan_core.validation.static_scoring import score_apk_static  # noqa: E402
from sudarshan_core.validation.virustotal_crosscheck import (  # noqa: E402
    CrossCheckRow,
    CrossCheckSummary,
    VTResult,
    lookup_many,
    vt_api_key,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write the full result set here")
    parser.add_argument("--rate", type=int, help="VT requests per minute")
    parser.add_argument("--corpus", help="explicit corpus root")
    args = parser.parse_args()

    key = vt_api_key()
    if not key:
        print("VIRUSTOTAL_API_KEY is not set - cannot cross-check.", file=sys.stderr)
        return 2

    root = find_labelled_corpus_root(Path(args.corpus) if args.corpus else None)
    if root is None:
        print("Labelled corpus not found.", file=sys.stderr)
        return 2
    samples = load_labelled_samples(root)
    print(f"corpus: {root}  ({len(samples)} samples)\n")

    # ---- Sudarshan static pass --------------------------------------------
    scored: List[Dict] = []
    for sample in samples:
        digest = _sha256(sample.path)
        record = {
            "name": sample.display_name,
            "sha256": digest,
            "label": sample.label,
            "category": sample.category,
            "band": "",
            "frs": 0.0,
            "family": "",
            "error": "",
        }
        try:
            result = score_apk_static(sample.path)
            record.update(
                band=result.band,
                frs=round(result.frs, 2),
                family=result.family,
            )
        except Exception as exc:  # a broken sample must not abort the corpus
            record["error"] = f"{type(exc).__name__}: {exc}"
        print(
            f"  scored {record['name'][:34]:34} "
            f"frs={record['frs']:>6} band={record['band'] or 'ERROR'}",
            flush=True,
        )
        scored.append(record)

    # ---- VirusTotal pass ---------------------------------------------------
    hashes = [r["sha256"] for r in scored]
    print(f"\nquerying VirusTotal for {len(hashes)} hashes...", flush=True)
    vt: Dict[str, VTResult] = asyncio.run(lookup_many(hashes, key, per_min=args.rate))

    rows = [
        CrossCheckRow(
            name=r["name"],
            sha256=r["sha256"],
            corpus_label=r["label"],
            sudarshan_band=r["band"],
            sudarshan_frs=r["frs"],
            sudarshan_family=r["family"],
            vt=vt.get(r["sha256"], VTResult(r["sha256"], "error", detail="no result")),
        )
        for r in scored
    ]
    summary = CrossCheckSummary(rows)

    # ---- Report ------------------------------------------------------------
    header = (
        f"\n{'sample':34} {'truth':8} {'sudarshan':10} {'frs':>6} "
        f"{'VT':>7} {'vt verdict':13} {'agree':6} vt family"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        agree = "-" if not row.comparable else ("yes" if row.agrees else "NO")
        print(
            f"{row.name[:34]:34} {row.corpus_label:8} "
            f"{row.sudarshan_band or 'ERROR':10} {row.sudarshan_frs:>6} "
            f"{row.vt.ratio_text:>7} {row.vt.verdict:13} {agree:6} "
            f"{row.vt.family[:30]}"
        )

    matrix = summary.confusion()
    rate = summary.agreement_rate
    print("\n-- agreement with VirusTotal --")
    print(f"  comparable samples     : {len(summary.comparable_rows)}/{len(rows)}")
    print(f"  agreement rate         : {'n/a' if rate is None else f'{rate:.1%}'}")
    print(f"  both say malware       : {matrix['both_malware']}")
    print(f"  both say benign        : {matrix['both_benign']}")
    print(f"  Sudarshan only malware : {matrix['sudarshan_only_malware']}  (possible FP)")
    print(f"  VT only malware        : {matrix['vt_only_malware']}  (possible miss)")

    if summary.excluded:
        print("\n-- excluded (VT expressed no usable opinion) --")
        for row in summary.excluded:
            print(f"  {row.name[:34]:34} {row.vt.verdict:13} {row.vt.detail}")

    if summary.disagreements:
        print("\n-- disagreements to investigate --")
        for row in summary.disagreements:
            print(
                f"  {row.name[:34]:34} sudarshan={row.sudarshan_band} "
                f"({row.sudarshan_frs}) vt={row.vt.ratio_text} {row.vt.family}"
            )

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "corpus_root": str(root),
                    "agreement_rate": rate,
                    "confusion": matrix,
                    "rows": [
                        {
                            "name": r.name,
                            "sha256": r.sha256,
                            "corpus_label": r.corpus_label,
                            "sudarshan_band": r.sudarshan_band,
                            "sudarshan_frs": r.sudarshan_frs,
                            "sudarshan_family": r.sudarshan_family,
                            "vt_verdict": r.vt.verdict,
                            "vt_malicious": r.vt.malicious,
                            "vt_total": r.vt.total,
                            "vt_family": r.vt.family,
                            "vt_vendors": r.vt.vendors,
                            "vt_detail": r.vt.detail,
                            "agrees": r.agrees if r.comparable else None,
                        }
                        for r in rows
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
