"""Summarise the corpus run: did every sample get a scoreable runtime axis?"""
import glob
import json
import os

OUT = "/app/uploads/corpus_results"

timings = {}
tp = os.path.join(OUT, "timings.txt")
if os.path.exists(tp):
    for line in open(tp):
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("elapsed="):
            timings[parts[0]] = parts[1].split("=", 1)[1]

rows = []
for path in sorted(glob.glob(os.path.join(OUT, "*.json"))):
    name = os.path.basename(path)[:-5]
    try:
        d = json.load(open(path))
    except Exception as e:
        rows.append((name, "PARSE_FAIL", str(e)[:30], "", "", "", timings.get(name, "?")))
        continue
    dy = d.get("dynamic_result") or {}
    frs = d.get("frs_breakdown") or {}
    excluded = frs.get("axes_excluded") or []
    rows.append((
        name,
        "INCLUDED" if "dynamic" not in excluded else "EXCLUDED",
        (frs.get("dynamic_exclusion_reason") or "-"),
        str(dy.get("dynamic_status") or "-"),
        str(dy.get("evidence_record_count") or 0),
        f"{d.get('final_risk_score')}/{d.get('risk_band')}",
        timings.get(name, "?"),
    ))

hdr = ("SAMPLE", "AXIS", "REASON", "STATUS", "EVID", "SCORE", "TIME")
w = [max(len(str(r[i])) for r in ([hdr] + rows)) for i in range(len(hdr))]
print("  ".join(h.ljust(w[i]) for i, h in enumerate(hdr)))
print("  ".join("-" * w[i] for i in range(len(hdr))))
for r in rows:
    print("  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)))

inc = sum(1 for r in rows if r[1] == "INCLUDED")
print(f"\nruntime available: {inc}/{len(rows)}")
over = [r[0] for r in rows if r[6].rstrip("s").isdigit() and int(r[6].rstrip("s")) > 300]
print(f"over 5 minutes   : {over or 'none'}")
