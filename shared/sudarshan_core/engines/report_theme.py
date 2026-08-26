"""
SUDARSHAN - Report Theme Tokens
===============================
Single source of truth for the palette, type scale, rule weights and page
geometry used by every report renderer: the single-file HTML export
(report_generator.py) and the ReportLab PDF (pdf_generator.py).

Design basis
------------
This palette follows the conventions of published forensic, audit and
regulatory documents rather than those of a product dashboard. The reference
set is NIST SP 800, ISO/IEC standards, Big-4 assurance reports, CERT-In
advisories and the Mandiant APT1 dossier. Those documents establish authority
by subtraction: one dark ink, a neutral grey ramp, hierarchy carried by type
and white space, and colour admitted only where it carries information.

Three rules govern everything below.

1.  One institutional ink. ``INK_STRONG`` is the document's only voice colour:
    body text, headings and every table rule are drawn in it or in a grey
    derived from it. Dark navy-charcoal is the historical choice for printed
    records because it survives photocopying and greyscale reproduction with
    its contrast intact.

2.  Severity is never carried by hue alone. WCAG 2.2 SC 1.4.1 forbids it and a
    photocopied dossier defeats it anyway. Every band therefore travels as
    colour *plus* a printed word *plus* an ordinal (1 of 4 .. 4 of 4) - see
    ``band_label``. The four band hues are drawn from the Okabe-Ito and Paul
    Tol colour-universal-design families and separate monotonically in
    luminance, so they remain distinguishable in greyscale and under
    deuteranopia and protanopia.

3.  Text inks and fill inks are different values of the same hue. The ``RISK_*``
    tokens are darkened to clear 4.5:1 against paper (WCAG SC 1.4.3) because
    they are set as type; the ``FILL_*`` tokens carry the CUD reference hue and
    are used only for bars, plates and rules, which need only 3:1 (SC 1.4.11).

Nothing here computes a verdict. These are presentation tokens only.
"""

from __future__ import annotations

from typing import Dict, Tuple

# ---------------------------------------------------------------------------
# Institutional ink and the neutral ramp
#
# Six steps, from the primary ink down to the palest ground. Every neutral in
# either renderer resolves to one of these; there are no one-off greys.
# ---------------------------------------------------------------------------

GREY_900 = "#1A2332"   # primary ink - body text, headings, principal rules
GREY_700 = "#3D4655"   # secondary text, captions, footnotes
GREY_500 = "#6B7280"   # null / "not examined" / disabled text
GREY_300 = "#B9C0CA"   # hairlines, mid-weight table rules
GREY_150 = "#E2E6EB"   # table header band, optional zebra fill
GREY_050 = "#F4F6F8"   # evidence-string ground, callout of last resort

INK = GREY_900            # primary body text
INK_STRONG = GREY_900     # headings, figures - same ink, weight carries emphasis
INK_MUTED = GREY_700      # secondary text, table body
INK_FAINT = GREY_500      # captions, labels, meta
INK_DISABLED = GREY_500   # absent-data notes

PAPER = "#FFFFFF"          # page ground
SURFACE = "#FFFFFF"        # no tinted cards: a fill must earn its place
SURFACE_INSET = GREY_150   # table head band
SURFACE_SUNK = GREY_150    # meter / bar tracks

BORDER = GREY_300          # hairline rules
BORDER_STRONG = GREY_900   # principal table rules (top and bottom)
RULE_HAIR = GREY_150       # inner row separators

ACCENT = GREY_900          # the institutional ink is the accent
ACCENT_SOFT = GREY_050     # accent tint

# ---------------------------------------------------------------------------
# Rule weights (points)
#
# Formal tables carry horizontal rules only, at three weights: a heavy rule
# top and bottom, a lighter rule under the header, and an optional hairline
# between body rows. Vertical rules and double rules are not used anywhere in
# the document - see `booktabs`, "The layout of formal tables".
# ---------------------------------------------------------------------------

RULE_W_STRONG = 1.0    # table top rule, table bottom rule, total rows
RULE_W_MID = 0.5       # header separator
RULE_W_HAIR = 0.25     # body row separator, used sparingly

CELL_PAD = 4.0         # minimum vertical padding inside a table cell, points

# ---------------------------------------------------------------------------
# Severity bands
#
# Four bands, ordinal 1..4. Hues follow Okabe-Ito / Paul Tol; the ink values
# are darkened for type contrast, the fill values keep the reference hue.
# ---------------------------------------------------------------------------

RISK_CRITICAL = "#8B1A1A"      # deep maroon      - band 4, lowest luminance
RISK_HIGH = "#B4470B"          # vermilion        - band 3
RISK_SUSPICIOUS = "#8A5F00"    # ochre, darkened  - band 2
RISK_SAFE = "#0B7A4B"          # green            - band 1
RISK_NEUTRAL = GREY_500        # unknown / not scored

FILL_CRITICAL = "#8B1A1A"
FILL_HIGH = "#CC5500"
FILL_SUSPICIOUS = "#DDAA33"
FILL_SAFE = "#0B7A4B"
FILL_NEUTRAL = GREY_300

# Tints are near-neutral by design. A band is announced by its word and its
# ordinal; the tint only groups the row, it does not shout.
TINT_CRITICAL = "#F6EEEE"
TINT_HIGH = "#F8F1EA"
TINT_SUSPICIOUS = "#F9F4E6"
TINT_SAFE = "#EDF4F0"
TINT_NEUTRAL = GREY_050

EDGE_CRITICAL = "#D9C0C0"
EDGE_HIGH = "#DFCBB8"
EDGE_SUSPICIOUS = "#E2D6B4"
EDGE_SAFE = "#C2D8CD"
EDGE_NEUTRAL = GREY_300

# ---------------------------------------------------------------------------
# Typography
#
# Serif for body text - the document is printed, filed and signed. Sans is
# reserved for headings, table headers and micro-labels, where its larger
# x-height reads better at small sizes. Mono carries hashes, package names and
# permission strings; both stacks below disambiguate 0/O and 1/l/I.
#
# Numerals in every table are set with tabular lining figures so that columns
# align on the decimal point and a score ledger can be checked by eye.
# ---------------------------------------------------------------------------

FONT_SANS = ('"IBM Plex Sans","Source Sans 3",-apple-system,BlinkMacSystemFont,'
             '"Segoe UI",Helvetica,Arial,sans-serif')
FONT_SERIF = ('"IBM Plex Serif","Source Serif 4",Charter,"Charis SIL",Georgia,'
              '"Times New Roman",Times,serif')
FONT_MONO = ('"IBM Plex Mono","JetBrains Mono","SFMono-Regular",Consolas,'
             '"Liberation Mono",Menlo,"Courier New",monospace')

# Point sizes. The printed document is the reference; the screen edition
# converts these to rem at 16px = 12pt.
PT_BODY = 10.5
PT_BODY_LEADING = 13.0     # 124% of body size
PT_SMALL = 9.0             # captions, table body
PT_SMALL_LEADING = 11.0
PT_FINE = 8.0              # footnotes, running head/foot
PT_FINE_LEADING = 10.0
PT_H3 = 10.5               # clause heading, bold
PT_H2 = 13.0
PT_H1 = 17.0
PT_PART = 22.0

# ---------------------------------------------------------------------------
# Page geometry (millimetres, A4)
#
# Asymmetric margins leave a binding gutter. The text block is 162mm wide,
# which is too wide for continuous prose at 10.5pt, so prose is held to a
# 90-character measure by indent and only tables and evidence blocks are set
# to the full width.
# ---------------------------------------------------------------------------

PAGE_MARGIN_TOP_MM = 25.0
PAGE_MARGIN_BOTTOM_MM = 22.0
PAGE_MARGIN_INSIDE_MM = 28.0
PAGE_MARGIN_OUTSIDE_MM = 20.0
PROSE_MEASURE_CH = 90

# ---------------------------------------------------------------------------
# Band resolution
# ---------------------------------------------------------------------------

_BAND_ORDER: Tuple[str, ...] = ("critical", "high", "suspicious", "safe", "neutral")

_BAND_INK: Dict[str, str] = {
    "critical": RISK_CRITICAL,
    "high": RISK_HIGH,
    "suspicious": RISK_SUSPICIOUS,
    "safe": RISK_SAFE,
    "neutral": RISK_NEUTRAL,
}

_BAND_FILL: Dict[str, str] = {
    "critical": FILL_CRITICAL,
    "high": FILL_HIGH,
    "suspicious": FILL_SUSPICIOUS,
    "safe": FILL_SAFE,
    "neutral": FILL_NEUTRAL,
}

_BAND_TINT: Dict[str, str] = {
    "critical": TINT_CRITICAL,
    "high": TINT_HIGH,
    "suspicious": TINT_SUSPICIOUS,
    "safe": TINT_SAFE,
    "neutral": TINT_NEUTRAL,
}

_BAND_EDGE: Dict[str, str] = {
    "critical": EDGE_CRITICAL,
    "high": EDGE_HIGH,
    "suspicious": EDGE_SUSPICIOUS,
    "safe": EDGE_SAFE,
    "neutral": EDGE_NEUTRAL,
}

# Ordinal position of each band on the four-step scale. Printed alongside the
# band word so severity survives greyscale, photocopying and colour blindness.
_BAND_ORDINAL: Dict[str, int] = {
    "safe": 1,
    "suspicious": 2,
    "high": 3,
    "critical": 4,
    "neutral": 0,
}

BAND_SCALE_STEPS = 4


def band_key(band: str) -> str:
    """Normalise any band / severity / verdict string to a palette key."""
    b = str(band or "").strip().lower()
    if not b:
        return "neutral"
    if "critical" in b:
        return "critical"
    if "high" in b:
        return "high"
    if "suspicious" in b or "medium" in b or "med" == b or "moderate" in b:
        return "suspicious"
    if "safe" in b or "low" in b or "clean" in b or "benign" in b or "info" in b:
        return "safe"
    return "neutral"


def band_ink(band: str) -> str:
    return _BAND_INK[band_key(band)]


def band_fill(band: str) -> str:
    return _BAND_FILL[band_key(band)]


def band_tint(band: str) -> str:
    return _BAND_TINT[band_key(band)]


def band_edge(band: str) -> str:
    return _BAND_EDGE[band_key(band)]


def band_ordinal(band: str) -> int:
    """1..4 up the severity scale, 0 for an unscored band."""
    return _BAND_ORDINAL[band_key(band)]


def band_label(band: str, upper: bool = True) -> str:
    """
    The band as it must appear anywhere in the document: word plus ordinal.

    'HIGH (3 of 4)'. The parenthetical is not decoration - it is what carries
    severity when the page is photocopied, printed in greyscale, or read by
    someone who cannot separate the four hues.
    """
    key = band_key(band)
    word = str(band or "").strip() or key
    if upper:
        word = word.upper()
    ordinal = _BAND_ORDINAL[key]
    if not ordinal:
        return f"{word} (not scored)"
    return f"{word} ({ordinal} of {BAND_SCALE_STEPS})"


def score_key(score: float) -> str:
    """Map an FRS 0..100 onto a palette key using the platform's own bands."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "neutral"
    if s >= 85:
        return "critical"
    if s >= 60:
        return "high"
    if s >= 30:
        return "suspicious"
    return "safe"


def score_ink(score: float) -> str:
    return _BAND_INK[score_key(score)]


def score_fill(score: float) -> str:
    return _BAND_FILL[score_key(score)]


# ---------------------------------------------------------------------------
# Null conventions
#
# A forensic report must distinguish "we did not look" from "we looked and it
# was not there". A blank cell conflates the two and is never acceptable.
# ---------------------------------------------------------------------------

NULL_NOT_APPLICABLE = "—"          # em dash: the field does not apply here
NULL_NOT_TESTED = "Not tested"          # examinable, but this run did not examine it
NULL_NOT_PRESENT = "Not present"        # examined, and absent
NULL_NOT_RECORDED = "Not recorded"      # the pipeline did not capture the value


def null_cell(value: object, absent: str = NULL_NOT_RECORDED) -> str:
    """Render a possibly-absent value, never as an ambiguous blank."""
    text = "" if value is None else str(value).strip()
    return text if text else absent
