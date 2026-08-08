#!/bin/sh
# Remove Cursor agent trailers from a commit message file ($1).
MSG_FILE="$1"
[ -n "$MSG_FILE" ] && [ -f "$MSG_FILE" ] || exit 0
TMP="${MSG_FILE}.cursor-strip.$$"
# Co-authored-by / Made-with / noreply GitHub bot identity
grep -viE 'cursoragent@cursor\.com|199161495\+cursoragent@users\.noreply\.github\.com' "$MSG_FILE" \
  | grep -viE '^co-authored-by:[[:space:]]*cursor' \
  | grep -viE '^made-with:[[:space:]]*cursor' \
  | grep -viE '^made with cursor' \
  > "$TMP" || true
mv "$TMP" "$MSG_FILE"
