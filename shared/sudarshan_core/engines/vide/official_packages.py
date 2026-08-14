"""Canonical Play Store package names for the ten protected institutions.

The corpus baselines are *prototypes*: ``BASE-07-BOI.apk`` is built as
``com.boi.baseline.test``, not as the real ``com.boi.mobile``. So the corpus
cannot tell VIDE which package a genuine app is allowed to claim, and the
CH06 signer rule needs exactly that.

This module is therefore the single source of truth for "which package names
belong to which bank", shared by:

* :mod:`baseline_store` - so a matched baseline knows the identity a clone
  would have to forge, and
* ``data/bank_signer_registry.json`` - which keys the CH06 rule off the same
  list.

``design.md`` also names packages, but it names *observed* ones with varying
confidence (BOI's spec cites ``com.boi.ua.android`` from a Play listing). Those
are merged in as additional protected identities rather than replacing this
table.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# baseline id -> (display name, official package names)
#
# Ordered as the corpus registry orders them (BASE-01 .. BASE-10).
OFFICIAL_PACKAGES: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "BASE-01-SBI": ("YONO SBI", ("com.sbi.lotus", "com.sbi.lotusintouch")),
    "BASE-02-HDFC": ("HDFC Bank MobileBanking", ("com.snapwork.hdfc", "com.hdfc.bank")),
    "BASE-03-ICICI": ("iMobile Pay", ("com.csam.icici.bank.imobile",)),
    "BASE-04-AXIS": ("Axis Mobile", ("com.axis.mobile",)),
    "BASE-05-BOB": ("bob World", ("com.mconnect",)),
    "BASE-06-PNB": ("PNB ONE", ("com.pnb.pnbone",)),
    "BASE-07-BOI": ("BOI Mobile", ("com.boi.mobile",)),
    "BASE-08-KOTAK": ("Kotak811", ("com.msf.k8",)),
    "BASE-09-INDUS": ("IndusMobile", ("com.indusind.indusmobile",)),
    "BASE-10-UNION": ("Vyom", ("com.infrasofttech.uboi",)),
}


def packages_for(baseline_id: str) -> List[str]:
    """Official package names for a baseline id, or ``[]`` if unregistered."""
    entry = OFFICIAL_PACKAGES.get((baseline_id or "").strip().upper())
    return list(entry[1]) if entry else []


def display_name_for(baseline_id: str) -> str:
    entry = OFFICIAL_PACKAGES.get((baseline_id or "").strip().upper())
    return entry[0] if entry else ""


def all_official_packages() -> List[str]:
    """Every protected package name across the ten institutions."""
    out: List[str] = []
    for _, packages in OFFICIAL_PACKAGES.values():
        out.extend(packages)
    return out


def baseline_id_for_package(package_name: str) -> str:
    """Reverse lookup: which institution owns this package name."""
    needle = (package_name or "").strip().lower()
    if not needle:
        return ""
    for baseline_id, (_, packages) in OFFICIAL_PACKAGES.items():
        if needle in {p.lower() for p in packages}:
            return baseline_id
    return ""


def merge_packages(baseline_id: str, extra: List[str]) -> List[str]:
    """Official packages first, then any additional ones, de-duplicated."""
    merged = packages_for(baseline_id)
    seen = {p.lower() for p in merged}
    for candidate in extra:
        value = (candidate or "").strip()
        if value and value.lower() not in seen:
            seen.add(value.lower())
            merged.append(value)
    return merged
