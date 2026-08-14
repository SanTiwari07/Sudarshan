"""Mine UI strings from the DEX constant pool.

Last-resort extraction. When an APK is packed, obfuscated, or simply built with
a toolkit VIDE has no parser for, ``apktool`` yields empty layouts and there is
no web bundle either - the earlier extractors return nothing and the string axis
reads zero, which is indistinguishable from "this app has no banking UI".

Every string a compiled Android app can display still exists verbatim in a DEX
string table, because that is where the constant pool lives. Obfuscators rename
*identifiers*; they do not rewrite the literal a user reads on screen, since the
app has to render it. So this pass recovers the labels even when everything
structural has been stripped.

The parse is deliberately dependency-free and header-driven rather than a blind
scan for printable runs: ``string_ids`` gives exact string boundaries, so what
comes out is the real literal set, not fragments of adjacent bytecode. A
printable-run fallback is kept for a DEX whose header does not parse (truncated
or deliberately corrupted containers), where fragments still beat nothing.

Reference: Dalvik executable format, ``string_id_item`` / ``string_data_item``.
"""

from __future__ import annotations

import logging
import re
import struct
from pathlib import Path
from typing import Iterable, List, Set

logger = logging.getLogger(__name__)

_DEX_MAGIC = b"dex\n"

# Offsets into header_item.
_OFF_STRING_IDS_SIZE = 0x38
_OFF_STRING_IDS_OFF = 0x3C

_MAX_DEX_BYTES = 64 * 1024 * 1024
_MAX_STRINGS_PER_DEX = 400_000

# What a banking UI says, split by how much a hit is worth.
#
# STRONG terms occur in banking UIs and essentially nowhere else, so a hit is
# self-justifying. WEAK terms ("account", "transaction", "verify") are also
# ordinary framework vocabulary - AndroidX alone ships "FragmentTransaction",
# "Cert byte array cannot be null when verifying" and dozens more - so on their
# own they are evidence of nothing and are only kept once the noise filter below
# has had its say.
# Word boundaries are load-bearing, not decoration: without them ``m-?pin``
# matches inside "du(mpin)g" and every AndroidX exception message about a
# fragment being dumped scores as a banking label.
_STRONG_BANKING_RE = re.compile(
    r"(\bm-?pin\b|\bupi\b|\bifsc\b|\botp\b|net\s*banking|user\s*id|customer\s*id|"
    r"\bbeneficiary\b|\bpayee\b|\bpassbook\b|available\s+balance|account\s+balance|"
    r"account\s+number|card\s+number|\bcvv\b|\bimps\b|\bneft\b|\brtgs\b|"
    r"mobile\s*banking|internet\s*banking|fund\s*transfer|quick\s*transfer|"
    r"pay\s*bills?|mini\s*statement|date\s+of\s+birth|registered\s+mobile)",
    re.IGNORECASE,
)
_WEAK_BANKING_RE = re.compile(
    r"(\bpin\b|\bpasscode\b|\bpassword\b|\blogin\b|\blog\s*in\b|\bsign\s*in\b|"
    r"\bbalance\b|\baccount\b|\btransfer\b|\bdebit\b|\bcredit\b|\bstatement\b|"
    r"\btransaction\b|\bremit\b|\bbank\b|mobile\s*number|\bdeposit\b|"
    r"\bwithdraw\b|\bpayment\b)",
    re.IGNORECASE,
)

#: Any string matching this is banking-relevant enough to keep.
BANKING_STRING_RE = re.compile(
    f"{_STRONG_BANKING_RE.pattern}|{_WEAK_BANKING_RE.pattern}", re.IGNORECASE
)

# Java/Android identifiers and machine strings that pass a naive prose filter.
_NOT_UI = re.compile(
    r"^\s*$"
    r"|^[\[(]"                              # type descriptors: [B, (I)V
    r"|^L[a-z]+/"                           # Lcom/example/Foo;
    r"|^(android|java|javax|kotlin|okhttp3|com/|org/|dalvik)"
    r"|[<>{};$\\]"                          # code punctuation and inner classes
    r"|^[a-z]+\.[a-z]+\."                   # dotted package paths
    r"|^%[sd]"                              # format strings
    r"|^(https?|content|file|data|blob):"
    r"|^\.[a-zA-Z]"                         # file extensions / selectors
    r"|^#[0-9A-Fa-f]{3,8}$"                 # colours are handled elsewhere
)

# Framework and library literals that survive `_NOT_UI` because they are plain
# English sentences. These are the strings that flooded an unfiltered mine: an
# exception message about a "FragmentTransaction" is not a banking label.
_FRAMEWORK_VOCAB = re.compile(
    r"\b(fragment|lifecycle|listener|handler|receiver|observer|dispatcher|"
    r"executor|callback|viewmodel|savedstate|parcel|binder|intent|"
    r"activity|classloader|serializ|deserializ|superclass|"
    r"nullpointer|illegalstate|illegalargument|unsupportedoperation|"
    r"exception|stacktrace|debuggable|proguard|okhttp|retrofit|gson|"
    r"sqlite|cursor|contentprovider|webviewclient|renderer|"
    r"must\s+(be|call|not)|cannot\s+be|failed\s+to|unable\s+to|"
    r"already\s+(been|registered|executing)|not\s+supported|"
    r"\.java\b|\.kt\b|\(\)|getter|setter)",
    re.IGNORECASE,
)
# Machine identifiers that read as prose to the filters above: Binder
# transaction constants (``TRANSACTION_notify``) and HTTP header names
# (``Content-Transfer-Encoding: binary``).
_MACHINE_IDENT = re.compile(
    r"^[A-Z][A-Z0-9]{2,}_"
    r"|^[A-Z][a-z]+(?:-[A-Za-z]+)+\s*:"
)
# Log/exception fragments read as a clause, not a label: they open lowercase or
# with punctuation. A real UI string starts with a capital, a digit or a symbol
# a designer chose.
_CLAUSE_FRAGMENT = re.compile(r"^[a-z',.\-]")

# Source identifiers with no whitespace: ``ACCOUNT_STATUS_API``,
# ``AccountMetadataColumns``, ``changepassword``. Applied only to strings that
# are not themselves a distinctive banking acronym, since "MPIN", "OTP", "UPI"
# and "IFSC" are simultaneously SCREAMING_CASE and genuine on-screen labels.
_IDENTIFIER = re.compile(
    r"^[A-Z0-9_]+$"                       # SCREAMING_SNAKE
    r"|^[a-z]+[A-Z]"                      # camelCase
    r"|^(?:[A-Z][a-z0-9]+){2,}$"          # PascalCase
    r"|_"                                 # any snake_case remnant
    r"|/"                                 # route / path fragments
)
_HAS_SPACE = re.compile(r"\s")

_HAS_LETTERS = re.compile(r"[A-Za-z]{2,}")
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,64}")


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """ULEB128 at ``offset`` -> (value, next_offset)."""
    result = 0
    shift = 0
    for _ in range(5):
        if offset >= len(data):
            return result, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return result, offset


def iter_dex_strings(blob: bytes) -> Iterable[str]:
    """Every literal in a DEX string table, in constant-pool order."""
    if len(blob) < 0x70 or not blob.startswith(_DEX_MAGIC):
        yield from _iter_printable_runs(blob)
        return
    try:
        (count,) = struct.unpack_from("<I", blob, _OFF_STRING_IDS_SIZE)
        (table_off,) = struct.unpack_from("<I", blob, _OFF_STRING_IDS_OFF)
    except struct.error:
        yield from _iter_printable_runs(blob)
        return

    if count == 0 or count > _MAX_STRINGS_PER_DEX:
        yield from _iter_printable_runs(blob)
        return
    if table_off + 4 * count > len(blob):
        yield from _iter_printable_runs(blob)
        return

    for index in range(count):
        try:
            (data_off,) = struct.unpack_from("<I", blob, table_off + 4 * index)
        except struct.error:
            break
        if data_off >= len(blob):
            continue
        # string_data_item: uleb128 utf16_size, then NUL-terminated MUTF-8.
        _, cursor = _read_uleb128(blob, data_off)
        end = blob.find(b"\x00", cursor)
        if end < 0:
            continue
        raw = blob[cursor:end]
        if not raw or len(raw) > 512:
            continue
        try:
            yield raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # MUTF-8 encodes U+0000 and supplementary planes differently from
            # UTF-8; those literals are not UI labels, so skipping is correct.
            continue


def _iter_printable_runs(blob: bytes) -> Iterable[str]:
    for match in _PRINTABLE_RUN.finditer(blob):
        yield match.group(0).decode("ascii", errors="ignore")


def is_ui_string(value: str) -> bool:
    """Does this constant-pool entry look like something a user would read?"""
    text = value.strip()
    # A displayed label is short. Anything longer is a log line or a legal
    # paragraph, neither of which discriminates between banks.
    if len(text) < 3 or len(text) > 48:
        return False
    if not _HAS_LETTERS.search(text):
        return False
    if _NOT_UI.search(text) or _MACHINE_IDENT.match(text):
        return False
    if _FRAMEWORK_VOCAB.search(text) or _CLAUSE_FRAGMENT.match(text):
        return False
    # A single token with no spaces is an identifier unless it is one of the
    # banking acronyms a real screen prints on its own.
    if not _HAS_SPACE.search(text) and _IDENTIFIER.search(text):
        return len(text) <= 8 and bool(_STRONG_BANKING_RE.fullmatch(text))
    return True


def score_banking_string(value: str) -> int:
    """0 = not banking, 1 = generic banking term, 2 = distinctive banking term."""
    if _STRONG_BANKING_RE.search(value):
        return 2
    if _WEAK_BANKING_RE.search(value):
        return 1
    return 0


def mine_banking_strings(
    dex_paths: Iterable[Path],
    limit: int = 120,
) -> List[str]:
    """
    Banking-relevant UI labels from the given DEX files, strongest first.

    A DEX constant pool holds tens of thousands of entries, so the ``limit``
    is what actually decides the output. Returning the first N matches in
    pool order fills the budget with whatever library happens to be linked
    earliest; ranking by evidence strength means the budget goes to the labels
    that identify the app.
    """
    scored: List[tuple[int, int, str]] = []
    seen: Set[str] = set()
    order = 0
    for path in dex_paths:
        try:
            if path.stat().st_size > _MAX_DEX_BYTES:
                logger.debug("[VIDE] skipping oversized dex %s", path.name)
                continue
            blob = path.read_bytes()
        except OSError as exc:
            logger.debug("[VIDE] dex unreadable %s: %s", path, exc)
            continue
        for candidate in iter_dex_strings(blob):
            text = candidate.strip()
            key = text.lower()
            if key in seen or not is_ui_string(text):
                continue
            strength = score_banking_string(text)
            if not strength:
                continue
            seen.add(key)
            scored.append((-strength, order, text))
            order += 1

    scored.sort()
    return [text for _, _, text in scored[:limit]]


def find_dex_files(decode_dir: Path) -> List[Path]:
    """
    ``classes.dex``, ``classes2.dex``, ... in an extracted or decoded APK.

    One level of nesting is searched as well: a plain unzip puts them at the
    root, while ``apktool -s`` and several unpackers leave them in a
    subdirectory. Sorted shortest-name-first so ``classes.dex`` - which holds
    the application's own code - is mined before the library overflow files.
    """
    if not decode_dir.is_dir():
        return []
    found = {
        p.resolve()
        for pattern in ("*.dex", "*/*.dex")
        for p in decode_dir.glob(pattern)
        if p.is_file()
    }
    return sorted(found, key=lambda p: (len(p.name), str(p)))


def mine_from_decode_dir(decode_dir: Path, limit: int = 120) -> List[str]:
    """Banking strings from every DEX in a decoded APK directory."""
    return mine_banking_strings(find_dex_files(decode_dir), limit=limit)
