"""
Cross-checking Sudarshan's verdict against VirusTotal, sample by sample.

This is a *pipeline* check, not a scoreboard. Sudarshan's FRS and VT's
detection ratio are computed by unrelated methods and are not expected to
correlate numerically; what must hold is that the two agree on the coarse
question an analyst actually asks - is this sample malicious or not. A
disagreement is a lead to investigate in the static/dynamic engines, which is
why this module reports the disagreeing samples individually rather than
collapsing everything into a single accuracy figure.

Three deliberate choices:

* **Hash lookup only.** The sample file is never uploaded. Submitting a file to
  VT publishes it to every VT Enterprise subscriber, which is not a decision a
  validation harness gets to make on the operator's behalf. A hash that VT has
  never seen simply comes back NOT_FOUND.

* **NOT_FOUND is not benign.** VT returning 404 means "no opinion", and folding
  that into the benign bucket would let an unknown sample silently count as
  agreement. It gets its own verdict so it can be excluded from the confusion
  matrix and reported as coverage instead - the same discipline
  ``static_scoring`` applies to axes it cannot run.

* **A vendor threshold, not "malicious > 0".** Single-vendor hits on Android
  APKs are dominated by heuristic adware/PUP flags that fire on ad SDKs present
  in plenty of legitimate apps. VT_MALICIOUS_VENDOR_THRESHOLD is the number of
  independent engines required before VT is treated as saying "malware".
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a runtime dep of the backend
    httpx = None  # type: ignore[assignment]

VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"

#: Independent engines that must call a sample malicious before VT is read as
#: "malware". Below this it is reported as LOW_DETECTION rather than benign,
#: because a 2/70 hit is genuinely ambiguous and hiding it in either bucket
#: would misrepresent the comparison.
VT_MALICIOUS_VENDOR_THRESHOLD: int = 5

#: Public VT API keys allow 4 requests/minute. Overridable for premium keys.
ENV_VT_KEY = "VIRUSTOTAL_API_KEY"
ENV_VT_RATE = "VIRUSTOTAL_RATE_LIMIT_PER_MIN"
DEFAULT_RATE_LIMIT_PER_MIN: int = 4

# Verdict vocabulary, shared by both sides of the comparison.
MALWARE = "malware"
BENIGN = "benign"
NOT_FOUND = "not_found"
LOW_DETECTION = "low_detection"
ERROR = "error"

#: Sudarshan risk bands that constitute a malicious call. "Suspicious" counts:
#: the band exists precisely because a floor refused to certify the sample as
#: safe, and treating a refusal-to-certify as a clean verdict would erase the
#: signal the floors were built to preserve.
MALICIOUS_BANDS = frozenset({"Suspicious", "High Risk", "Critical"})


def vt_api_key(explicit: Optional[str] = None) -> str:
    """The VT key from an explicit argument or the environment; "" if unset."""
    return (explicit or os.environ.get(ENV_VT_KEY) or "").strip()


def rate_limit_per_min() -> int:
    """Requests/minute budget, from the environment, floored at 1."""
    raw = os.environ.get(ENV_VT_RATE, "")
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_RATE_LIMIT_PER_MIN


@dataclass
class VTResult:
    """What VirusTotal knows about one hash."""

    sha256: str
    verdict: str                       # MALWARE | BENIGN | LOW_DETECTION | NOT_FOUND | ERROR
    malicious: int = 0
    total: int = 0
    family: str = ""
    vendors: List[str] = field(default_factory=list)
    detail: str = ""

    @property
    def ratio_text(self) -> str:
        return f"{self.malicious}/{self.total}" if self.total else "-"


def classify_vt(malicious: int, total: int) -> str:
    """
    Map a VT detection count onto this module's verdict vocabulary.

    ``total == 0`` means VT returned a record with no completed analyses, which
    is not the same as a clean scan and so is not BENIGN.
    """
    if total <= 0:
        return NOT_FOUND
    if malicious >= VT_MALICIOUS_VENDOR_THRESHOLD:
        return MALWARE
    if malicious > 0:
        return LOW_DETECTION
    return BENIGN


def sudarshan_verdict(band: str) -> str:
    """Collapse a Sudarshan risk band onto MALWARE / BENIGN."""
    return MALWARE if (band or "") in MALICIOUS_BANDS else BENIGN


async def lookup_hash(sha256: str, api_key: str, client: Any) -> VTResult:
    """
    Query VT for one hash. Never raises - transport and parse failures become
    an ERROR verdict so one dead lookup cannot abort a corpus run.
    """
    try:
        response = await client.get(
            VT_FILE_ENDPOINT.format(sha256=sha256),
            headers={"x-apikey": api_key},
        )
    except Exception as exc:
        return VTResult(sha256, ERROR, detail=f"{type(exc).__name__}: {exc}")

    if response.status_code == 404:
        return VTResult(sha256, NOT_FOUND, detail="not present in VT corpus")
    if response.status_code == 429:
        return VTResult(sha256, ERROR, detail="rate limited (HTTP 429)")
    if response.status_code != 200:
        return VTResult(sha256, ERROR, detail=f"HTTP {response.status_code}")

    try:
        attrs = response.json().get("data", {}).get("attributes", {})
    except Exception as exc:
        return VTResult(sha256, ERROR, detail=f"unparseable response: {exc}")

    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    # Only engines that actually returned a verdict count toward the
    # denominator; "timeout" and "type-unsupported" are non-answers.
    total = sum(
        int(stats.get(key, 0) or 0)
        for key in ("malicious", "suspicious", "undetected", "harmless")
    )
    vendors = [v for v, r in results.items() if r.get("category") == "malicious"]

    # VT's own classification only. A missing label means no known family -
    # never fall back to uploader-supplied filenames (see threat_correlator).
    family = (
        (attrs.get("popular_threat_classification") or {}).get(
            "suggested_threat_label"
        )
        or ""
    )

    return VTResult(
        sha256=sha256,
        verdict=classify_vt(malicious, total),
        malicious=malicious,
        total=total,
        family=family,
        vendors=sorted(vendors)[:8],
    )


async def lookup_many(
    hashes: List[str],
    api_key: str,
    per_min: Optional[int] = None,
    client: Any = None,
) -> Dict[str, VTResult]:
    """
    Look up every hash, pacing requests to stay inside the key's quota.

    The sleep is placed *between* requests rather than before each one, so a
    single-hash run does not pay the rate-limit delay for nothing.
    """
    budget = per_min or rate_limit_per_min()
    interval = 60.0 / float(budget)
    owns_client = client is None
    if owns_client:
        if httpx is None:
            raise RuntimeError("httpx is required for VirusTotal cross-checking")
        client = httpx.AsyncClient(timeout=30.0)

    out: Dict[str, VTResult] = {}
    try:
        for index, digest in enumerate(hashes):
            if index:
                await asyncio.sleep(interval)
            out[digest] = await lookup_hash(digest, api_key, client)
    finally:
        if owns_client:
            await client.aclose()
    return out


@dataclass
class CrossCheckRow:
    """One sample, as seen by both systems."""

    name: str
    sha256: str
    corpus_label: str        # ground truth from the corpus directory
    sudarshan_band: str
    sudarshan_frs: float
    sudarshan_family: str
    vt: VTResult

    @property
    def sudarshan(self) -> str:
        return sudarshan_verdict(self.sudarshan_band)

    @property
    def comparable(self) -> bool:
        """Whether VT expressed an opinion this row can be scored against."""
        return self.vt.verdict in (MALWARE, BENIGN)

    @property
    def agrees(self) -> bool:
        return self.comparable and self.sudarshan == self.vt.verdict


@dataclass
class CrossCheckSummary:
    """Aggregate agreement, with non-comparable rows kept visible."""

    rows: List[CrossCheckRow]

    @property
    def comparable_rows(self) -> List[CrossCheckRow]:
        return [r for r in self.rows if r.comparable]

    @property
    def disagreements(self) -> List[CrossCheckRow]:
        return [r for r in self.comparable_rows if not r.agrees]

    @property
    def excluded(self) -> List[CrossCheckRow]:
        return [r for r in self.rows if not r.comparable]

    @property
    def agreement_rate(self) -> Optional[float]:
        """None rather than 1.0 when nothing was comparable."""
        comparable = self.comparable_rows
        if not comparable:
            return None
        return sum(1 for r in comparable if r.agrees) / len(comparable)

    def confusion(self) -> Dict[str, int]:
        """Sudarshan vs VT over comparable rows only."""
        matrix = {
            "both_malware": 0,
            "both_benign": 0,
            "sudarshan_only_malware": 0,   # VT says benign - possible false positive
            "vt_only_malware": 0,          # VT says malware - possible miss
        }
        for row in self.comparable_rows:
            if row.sudarshan == MALWARE and row.vt.verdict == MALWARE:
                matrix["both_malware"] += 1
            elif row.sudarshan == BENIGN and row.vt.verdict == BENIGN:
                matrix["both_benign"] += 1
            elif row.sudarshan == MALWARE:
                matrix["sudarshan_only_malware"] += 1
            else:
                matrix["vt_only_malware"] += 1
        return matrix
