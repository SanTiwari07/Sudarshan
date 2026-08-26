"""
SUDARSHAN - Brand assets for the report renderers
=================================================
The mark and the wordmark, in the forms the two report renderers need them.

There is one mark file, in black line art on transparency, in two sizes: a
512px master for the title-page masthead and a 96px version for the running
head that repeats on every page. The frontend also ships a colour version of
the mark - a neon gradient with ragged edges - and it is deliberately not used
here. A filed forensic document is set in one ink; a glowing gradient in the
masthead is the first thing that would undo the rest of the redesign, and it
would photocopy to grey mush besides.

Everything is resolved from disk at import time rather than hard-coded as a
literal, so replacing the mark is a matter of replacing the PNG.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent

MARK_FILE = "sudarshan-mark.png"
MARK_SMALL_FILE = "sudarshan-mark-sm.png"

# The wordmark and the descriptor that sits under it. Both renderers set these
# in type rather than as artwork, so they stay searchable, selectable and
# legible at any size.
WORDMARK = "SUDARSHAN"
DESCRIPTOR = "Banking Malware Intelligence"
DESCRIPTOR_LONG = "Automated mobile-malware analysis and fraud-risk assessment"


def mark_path(small: bool = False) -> Optional[Path]:
    """
    Absolute path to the mark, or None if the asset is missing.

    Returns None rather than raising: a missing brand asset must degrade to a
    wordmark-only masthead, never fail a report export. A dossier without its
    logo is still a dossier; a dossier that would not render is not.
    """
    path = _HERE / (MARK_SMALL_FILE if small else MARK_FILE)
    return path if path.is_file() else None


@lru_cache(maxsize=2)
def mark_bytes(small: bool = False) -> Optional[bytes]:
    path = mark_path(small=small)
    if path is None:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


@lru_cache(maxsize=2)
def mark_data_uri(small: bool = True) -> Optional[str]:
    """
    The mark as a ``data:`` URI, for the single-file HTML export.

    That export has to survive being emailed as one file with no network, so
    every asset in it is inlined. The small mark is the default: the masthead
    displays it at about 44px, and the 96px file covers a 2x display without
    carrying the master's weight into every report.
    """
    raw = mark_bytes(small=small)
    if raw is None:
        return None
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
