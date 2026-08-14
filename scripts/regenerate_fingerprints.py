#!/usr/bin/env python3
"""
Regenerate ``exactStrings`` in each baseline's ``fingerprints.json`` from the
strings the built APK actually ships.

Why this exists
---------------
The corpus fingerprints were authored from the design specification, not from
the compiled apps, so they drifted: the spec says ``"User ID"`` and
``"Account Balance"`` while the React builds render ``"Username"`` and
``"Available Balance"``, and ``"Quick Transfer"`` / ``"Pay Bills"`` are absent
entirely. VIDE's string axis carries 40% of the confidence score, so that drift
costs real detection sensitivity - a baseline APK failed to string-match its own
baseline entry.

How it works
------------
Screen attribution comes from the React source (``app/src/screens/Login.tsx``
maps to screen id ``*-LOGIN``), because a minified bundle no longer says which
screen a label belongs to. Every candidate is then **verified against the built
APK** before being written, so nothing lands in the fingerprints that the
shipped artifact does not actually contain.

Strings are also collected from components the screen imports directly (one
level), since a label like the app title is rendered through ``<Header
title="..."/>``.

Usage
-----
    python scripts/regenerate_fingerprints.py              # dry run: show diff
    python scripts/regenerate_fingerprints.py --write      # apply
    python scripts/regenerate_fingerprints.py --baseline BASE-01-SBI
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "shared"))

from sudarshan_core.engines.vide.corpus_loader import find_corpus_root  # noqa: E402
from sudarshan_core.engines.vide.js_bundle import iter_string_literals  # noqa: E402

# Resolved rather than hardcoded: the corpus is a separate repository, so its
# checkout location varies (see BANKING_BASELINE_CORPUS_DIR).
CORPUS = find_corpus_root() or (REPO_ROOT / "banking-baseline-corpus")
LIBRARY = CORPUS / "baseline-library"
APK_DIR = CORPUS / "built_apks"

# Screen-id suffix -> React source file basename.
SCREEN_FILES = {
    "LOGIN": "Login",
    "MPIN": "MPIN",
    "HOME": "Home",
    "ACCOUNTS": "Accounts",
    "TRANSFER": "Transfer",
    "SERVICES": "Services",
    "PROFILE": "Profile",
    "SPLASH": "Splash",
    "RECEIPT": "Receipt",
    "REVIEW": "Review",
    "AMOUNT": "Amount",
    "CONFIRM": "Confirm",
}

# Props whose string value is rendered to the user.
_TEXT_PROPS = (
    "title", "label", "placeholder", "alt", "aria-label",
    "heading", "subtitle", "text", "cta", "buttonText",
)
_PROP_RE = re.compile(
    r'\b(?:' + "|".join(p.replace("-", r"\-") for p in _TEXT_PROPS) + r')\s*=\s*"([^"]{2,60})"'
)
_PROP_BRACE_RE = re.compile(
    r'\b(?:' + "|".join(p.replace("-", r"\-") for p in _TEXT_PROPS) + r")\s*=\s*\{\s*'([^']{2,60})'\s*\}"
)
# JSX text between tags. Must span newlines: prettier-formatted JSX puts the
# text on its own line (`<h1>\n  Welcome back\n</h1>`), and a newline-excluding
# pattern silently drops most of a well-formatted screen's labels.
# The negated class still cannot cross a tag boundary, so this stays anchored.
_JSX_TEXT_RE = re.compile(r">([^<>{}]{2,200})<")

# Prototype mock data. A real clone renders the victim's own account number and
# timestamp, so these can never match and only dilute the fingerprint.
_MOCK_DATA_RE = re.compile(
    r"[X*]{4,}"                                    # masked identifiers
    r"|\b\d{1,2}:\d{2}\b"                          # clock times
    r"|\b\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b"
    r"|\b(19|20)\d{2}\b"                           # years
    r"|^[₹$]\s?[\d,]+",                            # literal amounts
    re.IGNORECASE,
)
# "Good Morning, Rahul" - the greeting is real UI, the name is mock.
_GREETING_WITH_NAME_RE = re.compile(
    r"^(good\s+(morning|afternoon|evening)|welcome\s+back|hi|hello)\s*,\s*\S+",
    re.IGNORECASE,
)
_LOCAL_IMPORT_RE = re.compile(r"""^\s*import\s+.*?from\s+['"](\.[^'"]+)['"]""", re.MULTILINE)
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)

_MAX_PER_SCREEN = 12


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _is_ui_label(text: str) -> bool:
    """Reject code, styling and punctuation-only fragments."""
    if not (2 <= len(text) <= 60):
        return False
    if not re.search(r"[A-Za-z]{2,}", text):
        return False
    # Style values, identifiers, expressions, paths.
    if re.search(r"[{}()\[\];<>$\\|=]", text):
        return False
    if re.match(r"^[./#@]", text):
        return False
    if re.match(r"^\d+(px|rem|em|%|vh|vw|s|ms)$", text):
        return False
    if re.match(r"^[a-z-]+$", text) and " " not in text:
        # bare lowercase css-ish token: "flex", "column", "space-between"
        return False
    if _MOCK_DATA_RE.search(text) or _GREETING_WITH_NAME_RE.match(text):
        return False
    return True


def extract_source_strings(path: Path) -> List[str]:
    """User-visible strings from one .tsx file, in source order."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    source = _COMMENT_RE.sub(" ", source)

    found: List[str] = []
    seen: Set[str] = set()

    def _add(raw: str) -> None:
        text = _clean(raw)
        if not _is_ui_label(text):
            return
        key = text.lower()
        if key in seen:
            return
        seen.add(key)
        found.append(text)

    for match in _PROP_RE.finditer(source):
        _add(match.group(1))
    for match in _PROP_BRACE_RE.finditer(source):
        _add(match.group(1))
    for match in _JSX_TEXT_RE.finditer(source):
        _add(match.group(1))

    return found


def resolve_local_imports(screen_path: Path) -> List[Path]:
    """Components the screen imports directly (one level, local paths only)."""
    try:
        source = screen_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: List[Path] = []
    for rel in _LOCAL_IMPORT_RE.findall(source):
        candidate = (screen_path.parent / rel).resolve()
        for suffix in (".tsx", ".ts"):
            target = candidate.with_suffix(suffix)
            if target.is_file():
                out.append(target)
                break
    return out


def apk_literal_set(apk_path: Path) -> Set[str]:
    """Every string literal present in the APK's JS bundles, lowercased."""
    literals: Set[str] = set()
    if not apk_path.is_file():
        return literals
    with zipfile.ZipFile(apk_path) as archive:
        for name in archive.namelist():
            if not name.startswith("assets/") or not name.endswith(".js"):
                continue
            if Path(name).name in ("cordova.js", "cordova_plugins.js", "native-bridge.js"):
                continue
            try:
                text = archive.read(name).decode("utf-8", errors="replace")
            except (OSError, zipfile.BadZipFile):
                continue
            for literal in iter_string_literals(text):
                cleaned = _clean(literal)
                if cleaned:
                    literals.add(cleaned.lower())
    return literals


def build_screen_strings(
    baseline_dir: Path,
    screen_id: str,
    shipped: Set[str],
) -> Tuple[List[str], List[str]]:
    """
    (verified strings for this screen, candidates rejected as not shipped).

    Screen-file strings come first; imported-component strings fill the tail.
    """
    suffix = screen_id.rsplit("-", 1)[-1].upper()
    basename = SCREEN_FILES.get(suffix)
    if not basename:
        return [], []

    screens_dir = baseline_dir / "app" / "src" / "screens"
    screen_path = screens_dir / f"{basename}.tsx"
    if not screen_path.is_file():
        return [], []

    candidates = extract_source_strings(screen_path)
    for component in resolve_local_imports(screen_path):
        for value in extract_source_strings(component):
            if value.lower() not in {c.lower() for c in candidates}:
                candidates.append(value)

    verified: List[str] = []
    rejected: List[str] = []
    for value in candidates:
        if value.lower() in shipped:
            if len(verified) < _MAX_PER_SCREEN:
                verified.append(value)
        else:
            rejected.append(value)
    return verified, rejected


def process_baseline(
    baseline_id: str,
    write: bool,
) -> Optional[Dict[str, object]]:
    baseline_dir = LIBRARY / baseline_id
    fingerprints_path = baseline_dir / "fingerprints.json"
    apk_path = APK_DIR / f"{baseline_id}.apk"

    if not fingerprints_path.is_file():
        print(f"  {baseline_id}: fingerprints.json missing - skipped", file=sys.stderr)
        return None
    if not apk_path.is_file():
        print(f"  {baseline_id}: {apk_path.name} missing - skipped", file=sys.stderr)
        return None

    raw = fingerprints_path.read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    shipped = apk_literal_set(apk_path)

    report: Dict[str, object] = {"baseline": baseline_id, "screens": []}
    changed = False

    for screen in data.get("screens") or []:
        screen_id = str(screen.get("screenId") or "")
        old = list(screen.get("exactStrings") or [])
        new, rejected = build_screen_strings(baseline_dir, screen_id, shipped)

        if not new:
            # Never blank a screen's fingerprint because extraction came up
            # empty - that would silently disable matching for it.
            report["screens"].append(
                {"screen": screen_id, "status": "kept", "old": old, "new": old}
            )
            continue

        kept_old = [s for s in old if s.lower() in shipped]
        merged: List[str] = []
        for value in kept_old + new:
            if value.lower() not in {m.lower() for m in merged}:
                merged.append(value)
        merged = merged[:_MAX_PER_SCREEN]

        if [s.lower() for s in merged] != [s.lower() for s in old]:
            changed = True
        screen["exactStrings"] = merged
        report["screens"].append(
            {
                "screen": screen_id,
                "status": "updated",
                "old": old,
                "new": merged,
                "dropped": [s for s in old if s.lower() not in shipped],
                "rejected_not_shipped": rejected[:6],
            }
        )

    if write and changed:
        # Keep the BOM the corpus producer emits so nothing downstream that
        # assumes it breaks.
        fingerprints_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8-sig",
        )
    report["changed"] = changed
    return report


def main() -> int:
    # Banking UI strings contain the rupee sign; a cp1252 console would crash
    # the report before it finished printing.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="apply changes (default: dry run)")
    parser.add_argument("--baseline", help="only this baseline id, e.g. BASE-01-SBI")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args()

    if not LIBRARY.is_dir():
        print(f"Baseline library not found: {LIBRARY}", file=sys.stderr)
        return 2

    ids = (
        [args.baseline]
        if args.baseline
        else sorted(d.name for d in LIBRARY.iterdir() if d.is_dir())
    )

    reports = []
    for baseline_id in ids:
        report = process_baseline(baseline_id, args.write)
        if report:
            reports.append(report)

    if args.json:
        print(json.dumps(reports, indent=2, ensure_ascii=False))
        return 0

    for report in reports:
        print(f"\n{report['baseline']}  {'[UPDATED]' if report['changed'] else '[no change]'}")
        for screen in report["screens"]:  # type: ignore[index]
            if screen["status"] == "kept":
                print(f"  {screen['screen']:18} kept (no source strings resolved)")
                continue
            dropped = screen.get("dropped") or []
            print(f"  {screen['screen']:18} {len(screen['old'])} -> {len(screen['new'])} strings")
            if dropped:
                print(f"    dropped (not in APK): {', '.join(repr(d) for d in dropped)}")
            print(f"    now: {', '.join(repr(s) for s in screen['new'])}")

    if not args.write:
        print("\nDry run - nothing written. Re-run with --write to apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
