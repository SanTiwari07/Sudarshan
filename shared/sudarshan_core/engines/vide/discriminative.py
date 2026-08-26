"""
Corpus-wide feature weighting: what actually separates one bank from another.

The banking baseline corpus is built to a *shared* schema. ``APP_CORPUS_SCHEMA``
mandates one component vocabulary, one set of design-token names and one
structural-signature vocabulary across all ten baselines, so that cross-app
structural comparison is meaningful. That is the right decision for the corpus
and a trap for a matcher: the features the schema shares are, by construction,
the features that carry no attribution.

Measured against the shipped corpus, the trap is total rather than partial:

* all ten baselines' ``fingerprints.json`` ship the **same ten** ``exactStrings``
  ("User ID", "Password", "Login", "Enter 6-Digit MPIN", ...);
* all ten ship the **same three** structural signatures; and
* the brand palettes collide across banks at ΔE₂₀₀₀ ≈ 0 - BOI ``#f26522`` is
  *bit-identical* to BOB's, ICICI ``#f37021`` sits 0.0 from BOI's orange, PNB
  and INDUS agree to ΔE 0.5, BOI's blue is 0.6 from BOB's.

A matcher that scores those axes at face value gives every bank the same number
and then names whichever one wins by a rounding error. That is precisely how a
BOI clone came to rank behind Union Bank and ICICI.

The fix is to score each feature by *how much it narrows the field*, computed
from the corpus itself rather than from a hand-kept list of "generic" terms
that would drift the moment an eleventh bank is registered.

Weighting
---------
For a feature carried by ``df`` of the corpus's ``n`` baselines::

    weight = (1/df - 1/n) / (1 - 1/n)

``1/df`` is the chance of naming the right bank when that feature is all the
evidence there is. Rescaling it so chance level maps to zero makes the weight
readable as "how much better than a coin-flip does this feature leave you":

===  ==========  =======================================================
df   weight      reading (n = 10)
===  ==========  =======================================================
1    1.00        exclusive to one bank - attribution evidence on its own
2    0.44        halves the field
3    0.26        weak
5    0.11        nearly worthless
10   0.00        shared by every baseline - *no* attribution value
===  ==========  =======================================================

The df = n row is the one that matters: a universally shared feature is worth
exactly nothing, so the corpus's shared template strings and shared structural
signatures drop out of attribution *arithmetically* instead of having to be
excluded by name. They still prove the app is a banking UI, which is a separate
question answered by the shape gate in :mod:`corpus_compare`.

Colour df is counted over ΔE₂₀₀₀ neighbourhoods, not hex equality. Two banks
whose oranges differ in the last hex digit share that orange in every sense a
victim or a comparer cares about, and counting them as distinct would hand a
shared colour a weight of 1.0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sudarshan_core.engines.vide.color_match import (
    IDENTICAL_DELTA_E,
    color_distance,
    is_brand_color,
)

#: ΔE₂₀₀₀ bounds for the *attribution* colour curve, deliberately tighter than
#: :data:`color_match.IDENTICAL_DELTA_E` / :data:`color_match.MAX_MATCH_DELTA_E`.
#:
#: Those constants answer "would a victim see the same colour", and 18.0 is the
#: right answer to that. Attribution asks a harder question - "which of ten
#: banks is this" - and the corpus's own palettes sit ΔE 4-6 apart, so a
#: tolerance of 18 is three times wider than the gaps between the classes it is
#: being asked to separate. Measured on the reference apps, that flatness let
#: HDFC score 0.73 against the SBI app on ΔE-4 near-misses while SBI scored 1.00
#: on its own colours at ΔE 0.0, and the two ranked within 8% of each other.
#:
#: 2.3 is the ΔE at which a non-expert observer reliably calls two swatches
#: different - the point past which the suspect is no longer wearing *this*
#: bank's colour but one near it.
ATTRIBUTION_IDENTICAL_DELTA_E = 2.3
ATTRIBUTION_MAX_DELTA_E = 8.0


def attribution_color_score(distance: float) -> float:
    """Graded 1.0 -> 0.0 colour agreement on the attribution curve."""
    if distance <= ATTRIBUTION_IDENTICAL_DELTA_E:
        return 1.0
    if distance >= ATTRIBUTION_MAX_DELTA_E:
        return 0.0
    span = ATTRIBUTION_MAX_DELTA_E - ATTRIBUTION_IDENTICAL_DELTA_E
    return 1.0 - ((distance - ATTRIBUTION_IDENTICAL_DELTA_E) / span)
from sudarshan_core.engines.vide.fuzzy import normalize

#: Below this, a feature is too widely shared to be worth reporting as
#: attribution evidence. Set at the df = 3 weight for n = 10: a feature three of
#: ten banks carry leaves the field wide open.
MIN_ATTRIBUTION_WEIGHT = 0.26

#: A feature carried by exactly one baseline. The corroboration requirement in
#: :mod:`corpus_compare` is expressed in these.
EXCLUSIVE_DF = 1

_WORD_RE = re.compile(r"[a-z0-9]+")


def discriminative_weight(df: int, corpus_size: int) -> float:
    """
    Attribution value of a feature carried by ``df`` of ``corpus_size`` banks.

    See the module docstring for the derivation. Returns 0.0 for a feature every
    baseline carries and 1.0 for one only a single baseline carries.
    """
    if df <= 0 or corpus_size <= 1:
        return 0.0
    if df >= corpus_size:
        return 0.0
    chance = 1.0 / corpus_size
    return max(0.0, ((1.0 / df) - chance) / (1.0 - chance))


def _phrase_key(value: str) -> str:
    """Normalised form used for identity-phrase matching."""
    return normalize(value)


@dataclass(frozen=True)
class IdentityPhrase:
    """One name a bank is known by, and how strongly it names *that* bank."""

    #: Normalised phrase as matched against suspect text ("bank of india").
    key: str
    #: Human-readable original, for evidence lines ("Bank of India").
    display: str
    #: Where it came from: ``app_name`` | ``bank`` | ``shortcode`` | ``package``.
    origin: str
    weight: float = 1.0
    #: How many distinct suspect strings carried this phrase. Zero on a phrase
    #: that came from the corpus rather than from a match.
    mentions: int = 0

    @property
    def token_count(self) -> int:
        return len(self.key.split())

    @property
    def is_ui_name(self) -> bool:
        """
        Whether a user could read this name off the screen.

        Package segments ("snapwork", "csam", "lotusintouch") are real identity
        evidence when a suspect leaks one, but no clone renders them, so they
        must not sit in the denominator of a coverage score - a bank with four
        package aliases would otherwise be structurally harder to attribute to
        than one with none.
        """
        return self.origin != "package"


@dataclass
class BaselineDiscriminators:
    """The evidence that distinguishes one baseline from the other nine."""

    institution_id: str
    #: Identity phrases, longest first so the longest match wins (see
    #: :meth:`CorpusDiscriminators.identity_hits`).
    identity: List[IdentityPhrase] = field(default_factory=list)
    #: Normalised label -> attribution weight, universal labels already dropped.
    label_weights: Dict[str, float] = field(default_factory=dict)
    #: Original-cased labels, keyed by normalised form, for evidence lines.
    label_display: Dict[str, str] = field(default_factory=dict)
    #: Brand colour -> attribution weight, colours shared corpus-wide dropped.
    color_weights: Dict[str, float] = field(default_factory=dict)
    #: Structural signature -> attribution weight. Empty for the shipped corpus,
    #: which gives all ten baselines the same three signatures.
    signature_weights: Dict[str, float] = field(default_factory=dict)

    def exclusive_labels(self) -> List[str]:
        return sorted(k for k, w in self.label_weights.items() if w >= 1.0)

    def exclusive_colors(self) -> List[str]:
        return sorted(k for k, w in self.color_weights.items() if w >= 1.0)

    def has_discriminative_evidence(self) -> bool:
        """Whether this baseline can be told apart from its peers at all."""
        return bool(
            self.identity
            or any(w >= MIN_ATTRIBUTION_WEIGHT for w in self.label_weights.values())
            or any(w >= MIN_ATTRIBUTION_WEIGHT for w in self.color_weights.values())
        )


class CorpusDiscriminators:
    """
    Feature weights derived from a whole baseline set.

    Built once per baseline generation and read per comparison, because the
    weights are a property of the corpus rather than of the suspect.
    """

    def __init__(self, baselines: Sequence["object"]) -> None:
        self._size = len(baselines)
        self._by_institution: Dict[str, BaselineDiscriminators] = {}
        self._build(baselines)

    # ── construction ───────────────────────────────────────────────────────

    def _build(self, baselines: Sequence["object"]) -> None:
        if not baselines:
            return

        label_sets: Dict[str, Dict[str, str]] = {}
        color_sets: Dict[str, List[str]] = {}
        signature_sets: Dict[str, List[str]] = {}

        for baseline in baselines:
            institution = getattr(baseline, "institution_id", "") or ""
            if not institution:
                continue
            labels: Dict[str, str] = {}
            for value in getattr(baseline, "profile").strings:
                key = _phrase_key(value)
                if key:
                    labels.setdefault(key, value)
            label_sets[institution] = labels
            color_sets[institution] = [
                c.lower()
                for c in getattr(baseline, "profile").colors
                if is_brand_color(c)
            ]
            signature_sets[institution] = [
                s.structural_signature
                for s in getattr(baseline, "screens", [])
                if getattr(s, "structural_signature", "")
            ]

        label_df = _document_frequency(
            {k: set(v) for k, v in label_sets.items()}
        )
        signature_df = _document_frequency(
            {k: set(v) for k, v in signature_sets.items()}
        )
        color_df = _color_document_frequency(color_sets)
        identity_df = _identity_document_frequency(baselines)

        for baseline in baselines:
            institution = getattr(baseline, "institution_id", "") or ""
            if not institution:
                continue
            labels = label_sets.get(institution, {})
            entry = BaselineDiscriminators(
                institution_id=institution,
                identity=_identity_phrases(baseline, identity_df, self._size),
                label_weights={
                    key: discriminative_weight(label_df.get(key, 1), self._size)
                    for key in labels
                    if discriminative_weight(label_df.get(key, 1), self._size) > 0.0
                },
                label_display=dict(labels),
                color_weights={
                    color: discriminative_weight(color_df.get(color, 1), self._size)
                    for color in color_sets.get(institution, [])
                    if discriminative_weight(color_df.get(color, 1), self._size) > 0.0
                },
                signature_weights={
                    signature: discriminative_weight(
                        signature_df.get(signature, 1), self._size
                    )
                    for signature in signature_sets.get(institution, [])
                    if discriminative_weight(signature_df.get(signature, 1), self._size)
                    > 0.0
                },
            )
            self._by_institution[institution] = entry

    # ── lookup ─────────────────────────────────────────────────────────────

    @property
    def corpus_size(self) -> int:
        return self._size

    def for_institution(self, institution_id: str) -> BaselineDiscriminators:
        return self._by_institution.get(
            institution_id, BaselineDiscriminators(institution_id=institution_id)
        )

    def degenerate_institutions(self) -> List[str]:
        """
        Baselines that nothing in the corpus can distinguish from their peers.

        A corpus-quality signal, not a scoring input: a baseline listed here can
        never be attributed to, and the operator should know that rather than
        discover it as a permanently ambiguous verdict.
        """
        return sorted(
            institution
            for institution, entry in self._by_institution.items()
            if not entry.has_discriminative_evidence()
        )

    def identity_hits(
        self,
        suspect_strings: Sequence[str],
    ) -> Dict[str, List[IdentityPhrase]]:
        """
        Which banks the suspect *names*, resolving overlapping names.

        "Bank of India" is a substring of "Union Bank of India", so a Vyom clone
        would otherwise hand Bank of India a perfect identity match. Each suspect
        string is therefore credited to the longest phrase it contains, and only
        to that phrase's owner.

        Returned phrases carry a ``mentions`` count, because *how often* an app
        says a bank's name separates wearing it from referring to it: a clone
        puts the name on its splash, its header and its welcome copy, while mock
        payee data names an unrelated bank once.
        """
        candidates: List[Tuple[str, IdentityPhrase]] = [
            (institution, phrase)
            for institution, entry in self._by_institution.items()
            for phrase in entry.identity
        ]
        # Longest phrase first: "union bank of india" is tested before "bank of
        # india", and the shorter one never sees the string.
        candidates.sort(key=lambda pair: (-len(pair[1].key), pair[0], pair[1].key))

        counts: Dict[str, Dict[str, int]] = {}
        found: Dict[str, Dict[str, IdentityPhrase]] = {}
        for value in suspect_strings:
            haystack = _phrase_key(value)
            if not haystack:
                continue
            padded = f" {haystack} "
            for institution, phrase in candidates:
                if f" {phrase.key} " not in padded:
                    continue
                counts.setdefault(institution, {})
                counts[institution][phrase.key] = (
                    counts[institution].get(phrase.key, 0) + 1
                )
                found.setdefault(institution, {})[phrase.key] = phrase
                # A string names one bank. Stop at the longest phrase it carries.
                break

        hits: Dict[str, List[IdentityPhrase]] = {}
        for institution, phrases in found.items():
            hits[institution] = [
                IdentityPhrase(
                    key=phrase.key,
                    display=phrase.display,
                    origin=phrase.origin,
                    weight=phrase.weight,
                    mentions=counts[institution][key],
                )
                for key, phrase in sorted(phrases.items())
            ]
        return hits


# ── document frequency ─────────────────────────────────────────────────────


def _document_frequency(sets: Dict[str, set]) -> Dict[str, int]:
    """How many baselines carry each feature."""
    frequency: Dict[str, int] = {}
    for values in sets.values():
        for value in values:
            frequency[value] = frequency.get(value, 0) + 1
    return frequency


def _color_document_frequency(color_sets: Dict[str, List[str]]) -> Dict[str, int]:
    """
    How many baselines carry each colour, counted perceptually.

    A colour's df is the number of baselines holding *some* colour within
    :data:`IDENTICAL_DELTA_E` of it - the same threshold at which
    :mod:`color_match` calls two swatches the same brand colour. Without this,
    BOI's ``#f26522`` and ICICI's ``#f37021`` are two "unique" oranges with
    weight 1.0 apiece, and each attributes a suspect to its own bank while
    sitting ΔE 0.0 apart.
    """
    frequency: Dict[str, int] = {}
    for owner, colors in color_sets.items():
        for color in colors:
            if color in frequency:
                continue
            count = 0
            for other, other_colors in color_sets.items():
                if any(
                    color_distance(color, candidate) <= IDENTICAL_DELTA_E
                    for candidate in other_colors
                ):
                    count += 1
            frequency[color] = max(count, 1)
    return frequency


def _identity_document_frequency(baselines: Sequence["object"]) -> Dict[str, int]:
    """df over identity phrases, so a name two banks share is down-weighted."""
    frequency: Dict[str, int] = {}
    for baseline in baselines:
        for key in {p for p in _raw_identity_keys(baseline)}:
            frequency[key] = frequency.get(key, 0) + 1
    return frequency


# ── identity phrases ───────────────────────────────────────────────────────

#: Words that name the *sector*, not the institution. A phrase made only of
#: these ("Mobile Banking", "Bank") identifies nothing and is dropped before df
#: is even consulted, because with ten banks in the corpus a term nine of them
#: use would still clear the weight floor on the tenth.
_GENERIC_IDENTITY_WORDS = frozenset(
    {
        "app",
        "application",
        "bank",
        "banking",
        "digital",
        "finance",
        "financial",
        "india",
        "indian",
        "limited",
        "ltd",
        "mobile",
        "net",
        "online",
        "pay",
        "payment",
        "payments",
        "the",
        "of",
        "and",
    }
)

#: Shortest identity phrase that may stand alone. Two characters ("in", "sb")
#: collide with ordinary words; three is the length of the corpus shortcodes
#: ("SBI", "PNB", "BOI") that genuinely name a bank.
_MIN_SHORTCODE_CHARS = 3


def _raw_identity_keys(baseline: "object") -> List[str]:
    """Candidate identity phrases for one baseline, before weighting."""
    keys: List[str] = []
    for value in _identity_sources(baseline):
        key = _phrase_key(value)
        if key and _is_identifying(key):
            keys.append(key)
    return keys


def _identity_sources(baseline: "object") -> List[str]:
    """
    Where a bank's names come from.

    All four are corpus-supplied rather than hardcoded here: ``app.meta.json``
    carries ``appName`` and ``bank``, the baseline id carries the shortcode, and
    the package registry carries the identifiers a genuine app is entitled to.
    Registering an eleventh bank therefore needs no change to this module.
    """
    sources: List[str] = []
    for attribute in ("app_name", "bank", "display_name"):
        value = getattr(baseline, attribute, "") or ""
        if value:
            sources.append(str(value))

    baseline_id = str(getattr(baseline, "baseline_id", "") or getattr(baseline, "institution_id", "") or "")
    shortcode = baseline_id.rsplit("-", 1)[-1] if "-" in baseline_id else ""
    if len(shortcode) >= _MIN_SHORTCODE_CHARS:
        sources.append(shortcode)

    # The distinctive segment of an official package name: "com.pnb.pnbone" ->
    # "pnb", "pnbone". A clone that keeps a resource path or a deep-link host
    # from the app it copies leaks these even when it renames the package.
    for package in getattr(baseline, "package_names", []) or []:
        for segment in str(package).split("."):
            if len(segment) >= _MIN_SHORTCODE_CHARS and segment not in ("com", "android"):
                sources.append(segment)
    return sources


def _is_identifying(key: str) -> bool:
    """Whether a normalised phrase names an institution rather than a sector."""
    words = _WORD_RE.findall(key)
    if not words:
        return False
    if all(word in _GENERIC_IDENTITY_WORDS for word in words):
        return False
    if len(words) == 1 and len(words[0]) < _MIN_SHORTCODE_CHARS:
        return False
    return True


def _identity_phrases(
    baseline: "object",
    identity_df: Dict[str, int],
    corpus_size: int,
) -> List[IdentityPhrase]:
    """Weighted identity phrases for one baseline, longest first."""
    origins = [
        ("app_name", getattr(baseline, "app_name", "") or ""),
        ("bank", getattr(baseline, "bank", "") or ""),
        ("display_name", getattr(baseline, "display_name", "") or ""),
    ]
    baseline_id = str(
        getattr(baseline, "baseline_id", "") or getattr(baseline, "institution_id", "") or ""
    )
    if "-" in baseline_id:
        origins.append(("shortcode", baseline_id.rsplit("-", 1)[-1]))
    for package in getattr(baseline, "package_names", []) or []:
        for segment in str(package).split("."):
            if len(segment) >= _MIN_SHORTCODE_CHARS and segment not in ("com", "android"):
                origins.append(("package", segment))

    phrases: Dict[str, IdentityPhrase] = {}
    for origin, value in origins:
        key = _phrase_key(value)
        if not key or not _is_identifying(key):
            continue
        weight = discriminative_weight(identity_df.get(key, 1), corpus_size)
        if weight < MIN_ATTRIBUTION_WEIGHT:
            continue
        existing = phrases.get(key)
        if existing is None or weight > existing.weight:
            phrases[key] = IdentityPhrase(
                key=key, display=str(value), origin=origin, weight=weight
            )

    return sorted(phrases.values(), key=lambda p: (-len(p.key), p.key))


# ── suspect-side scoring ───────────────────────────────────────────────────


def weighted_label_containment(
    suspect_strings: Sequence[str],
    weights: Dict[str, float],
    display: Optional[Dict[str, str]] = None,
) -> Tuple[float, List[str]]:
    """
    Share of a bank's *discriminative* label mass the suspect reproduces.

    Returns ``(score, matched_labels)`` with the score already normalised by the
    available weight, so a bank whose labels are all generic scores 0.0 rather
    than an undefined 0/0.
    """
    available = sum(weights.values())
    if available <= 0.0:
        return 0.0, []

    haystack = {normalize(s) for s in suspect_strings if s and s.strip()}
    if not haystack:
        return 0.0, []
    blob = " | ".join(sorted(haystack))

    earned = 0.0
    matched: List[str] = []
    for key, weight in weights.items():
        if key in haystack or f" {key} " in f" {blob} ":
            earned += weight
            matched.append((display or {}).get(key, key))
    return earned / available, sorted(matched)


def _closest(color: str, palette: Sequence[str]) -> Tuple[Optional[str], float]:
    """Nearest palette entry to ``color`` and its raw ΔE₂₀₀₀."""
    best: Optional[str] = None
    best_distance = float("inf")
    for candidate in palette:
        distance = color_distance(color, candidate)
        if distance < best_distance:
            best_distance = distance
            best = candidate
    if best is None or best_distance == float("inf"):
        return None, float("inf")
    return best, best_distance


def weighted_palette_match(
    suspect_colors: Sequence[str],
    weights: Dict[str, float],
) -> Tuple[float, List[Dict[str, object]]]:
    """
    Share of a bank's *discriminative* palette mass the suspect reproduces.

    Same shape as :func:`color_match.palette_similarity`, with two differences
    that both exist to stop one bank's palette scoring against another's:

    * each baseline colour contributes in proportion to how few other banks
      share it, so the orange BOI, BOB and ICICI all use scores near zero
      against all three rather than arbitrarily winning one of them; and
    * agreement is graded on :func:`attribution_color_score`, which reaches zero
      at ΔE 8 rather than 18, because the corpus palettes are themselves only
      ΔE 4-6 apart.
    """
    available = sum(weights.values())
    if available <= 0.0:
        return 0.0, []

    suspect_brand = [c for c in suspect_colors if is_brand_color(c)]
    if not suspect_brand:
        return 0.0, []

    from sudarshan_core.engines.vide.color_match import describe_delta_e

    earned = 0.0
    matches: List[Dict[str, object]] = []
    for target, weight in weights.items():
        found, raw_distance = _closest(target, suspect_brand)
        if found is None:
            continue
        score = attribution_color_score(raw_distance)
        if score <= 0.0:
            continue
        earned += weight * score
        distance = round(raw_distance, 2)
        matches.append(
            {
                "baseline": target,
                "suspect": found,
                "score": round(score, 4),
                "distance": distance,
                "delta_e": distance,
                "verdict": describe_delta_e(distance),
                "attribution_weight": round(weight, 4),
            }
        )

    matches.sort(
        key=lambda m: (
            -float(m["attribution_weight"]) * float(m["score"]),
            str(m["baseline"]),
        )
    )
    return earned / available, matches


#: Built discriminator indexes, keyed by the corpus they were derived from.
#:
#: Colour df is quadratic in the corpus palette - ten banks of five colours is
#: 2500 ΔE₂₀₀₀ evaluations - and the weights depend only on the baseline set,
#: not on the suspect. Rebuilding them per comparison would put that cost in
#: the per-sample hot path for an answer that cannot have changed.
_INDEX_CACHE: Dict[Tuple, "CorpusDiscriminators"] = {}
_INDEX_CACHE_LIMIT = 4


def _corpus_key(baselines: Sequence["object"]) -> Tuple:
    """Identity of a baseline set, cheap enough to compute per comparison."""
    return tuple(
        (
            getattr(b, "institution_id", ""),
            getattr(b, "version", ""),
            len(getattr(b, "profile").strings),
            len(getattr(b, "profile").colors),
        )
        for b in baselines
    )


def discriminators_for(baselines: Sequence["object"]) -> "CorpusDiscriminators":
    """Cached :class:`CorpusDiscriminators` for a baseline set."""
    key = _corpus_key(baselines)
    cached = _INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    index = CorpusDiscriminators(baselines)
    if len(_INDEX_CACHE) >= _INDEX_CACHE_LIMIT:
        _INDEX_CACHE.clear()
    _INDEX_CACHE[key] = index
    return index


def reset_discriminator_cache() -> None:
    """Drop cached indexes. Paired with the baseline cache refresh."""
    _INDEX_CACHE.clear()


#: Distinct strings naming a bank at which the app is judged to be *wearing*
#: that name rather than referring to it. A clone renders the name on its
#: splash, its header and its welcome copy; mock payee data names an unrelated
#: bank once. Three is the point at which the reference apps' own branding
#: saturates, so a genuine wearer is not penalised for having only three.
_MENTION_SATURATION = 3

#: Floor of the mention factor. A single mention is real evidence and must not
#: be scored at zero - it is halved, not discarded.
_SINGLE_MENTION_FACTOR = 0.5


def identity_coverage(
    hits: Iterable[IdentityPhrase],
    entry: BaselineDiscriminators,
) -> float:
    """
    How strongly the suspect wears this bank's identity, in [0, 1].

    Two factors, because coverage alone cannot separate the two ways a bank's
    name appears in an app:

    * **Coverage** of the bank's readable names - a suspect reproducing both
      "bob World" and "Bank of Baroda" is stronger evidence than one reproducing
      either. The denominator counts only names a user could read off the
      screen; package aliases are counted when found but never dilute it, or a
      bank with four package names would be harder to attribute to than one
      with none.
    * **Repetition** - how many distinct strings carry the name. This is what
      distinguishes a clone from an app that merely mentions a bank, and it is
      not hypothetical: the Union Bank reference app names "ICICI Bank" once in
      its mock payee list, which under coverage alone matched ICICI exactly as
      strongly as ICICI's own app does.
    """
    matched = list(hits)
    available = sum(p.weight for p in entry.identity if p.is_ui_name)
    if available <= 0.0:
        return 0.0

    coverage = min(1.0, sum(p.weight for p in matched) / available)
    if coverage <= 0.0:
        return 0.0

    mentions = sum(max(p.mentions, 1) for p in matched)
    factor = _SINGLE_MENTION_FACTOR + (1.0 - _SINGLE_MENTION_FACTOR) * min(
        1.0, mentions / _MENTION_SATURATION
    )
    return min(1.0, coverage * factor)
