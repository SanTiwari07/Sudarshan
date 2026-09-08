#!/bin/sh
# Run every corpus sample through the full pipeline, one at a time, recording
# wall-clock and the dynamic-axis outcome for each.
#
# The device is wiped between samples: a payload left behind by the previous
# run would be "already installed" for the next one, which changes both the
# dropper's behaviour and the secondary-payload detection that depends on
# "absent at session start".
OUT=/app/uploads/corpus_results
mkdir -p "$OUT"

for APK in "$@"; do
  NAME=$(basename "$APK" .apk)
  echo "=== $NAME ==="

  # wipe third-party packages
  for p in $(adb -s emulator-5554 shell "pm list packages -3" | sed 's/package://' | tr -d '\r'); do
    adb -s emulator-5554 uninstall "$p" >/dev/null 2>&1
  done

  START=$(date +%s)
  curl -s -m 600 -X POST http://127.0.0.1:8001/api/v1/analyze \
    -H "Content-Type: application/json" \
    -d "{\"file_path\": \"$APK\"}" \
    -o "$OUT/$NAME.json" -w "http=%{http_code}\n"
  END=$(date +%s)
  echo "$NAME elapsed=$((END-START))s" >> "$OUT/timings.txt"
  echo "$NAME done in $((END-START))s"
done
echo "CORPUS_RUN_COMPLETE"
