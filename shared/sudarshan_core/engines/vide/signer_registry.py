"""CH06 canonical signer registry impersonation check.

A package name is an identity claim. ``com.sbi.lotus`` says "I am YONO SBI",
and Android will happily install anything that says so - the only thing that
makes the claim true is the signing certificate.

This module enforces that: it holds, per protected bank package, the
certificate fingerprints that are allowed to make the claim. Anything else
signed under that package name is impersonation, which is rule
``CH06-SIGNER-IMPERSONATION``.

An **empty** allowlist means no canonical fingerprint has been provisioned yet.
Until fingerprints are provisioned, the identity claim cannot be verified but
also cannot be disproved, so the check returns ``undetermined`` - not a
finding. Only non-empty registries (or a self-evidently debug-signed APK) make
a conclusive impersonation finding.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "data" / "bank_signer_registry.json"
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# Certificate subjects Android's own debug keystore emits. Any APK signed with
# one of these was never through a release pipeline, so a debug-signed APK
# claiming a bank package is the strongest form of the finding.
_DEBUG_SUBJECT_RE = re.compile(
    r"(CN\s*=\s*Android\s*Debug|O\s*=\s*Android\b|CN\s*=\s*(test|debug|example)\b)",
    re.IGNORECASE,
)


@dataclass
class SignerImpersonationResult:
    detected: bool = False
    package_name: str = ""
    signer_sha256: str = ""
    rule_id: str = "CH06-SIGNER-IMPERSONATION"
    institution_id: str = ""
    debug_signed: bool = False
    evidence_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "rule_id": self.rule_id,
            "package_name": self.package_name,
            "signer_sha256": self.signer_sha256,
            "institution_id": self.institution_id,
            "debug_signed": self.debug_signed,
            "evidence_lines": self.evidence_lines,
        }


def _normalize_sha256(value: str) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", value or "").lower()


def _registry_entries(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Package map from either registry layout.

    v2 nests the packages under ``"packages"`` so the file can also carry
    schema metadata; v1 was a flat package -> entry mapping. Both are read so an
    older registry (or a test fixture built by hand) keeps working.
    """
    packages = raw.get("packages")
    if isinstance(packages, dict):
        return packages
    return {k: v for k, v in raw.items() if not str(k).startswith("_")}


def load_signer_registry(path: Optional[Path] = None) -> Dict[str, List[str]]:
    """Protected package -> allowed signer fingerprints.

    Packages with **no** allowed fingerprints are kept with an empty list.
    Dropping them - as this once did - silently disabled the rule for exactly
    the packages whose canonical signer is unknown, which is where an
    impersonation claim cannot be checked any other way.
    """
    reg_path = path or _REGISTRY_PATH
    if not reg_path.is_file():
        logger.warning("[VIDE] Signer registry missing: %s", reg_path)
        return {}
    try:
        raw = json.loads(reg_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("[VIDE] Signer registry unreadable: %s", e)
        return {}
    if not isinstance(raw, dict):
        return {}

    out: Dict[str, List[str]] = {}
    for pkg, entry in _registry_entries(raw).items():
        if isinstance(entry, dict):
            allowed = entry.get("allowed_signers_sha256") or entry.get("allowed") or []
        elif isinstance(entry, list):
            allowed = entry
        else:
            continue
        out[str(pkg)] = [
            _normalize_sha256(a)
            for a in allowed
            if _SHA256_RE.match(_normalize_sha256(a))
        ]
    return out


def load_signer_registry_metadata(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Package -> ``{display_name, bank, baseline_id}`` for evidence lines."""
    reg_path = path or _REGISTRY_PATH
    if not reg_path.is_file():
        return {}
    try:
        raw = json.loads(reg_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for pkg, entry in _registry_entries(raw).items():
        if isinstance(entry, dict):
            out[str(pkg)] = {
                "display_name": str(entry.get("display_name") or ""),
                "bank": str(entry.get("bank") or ""),
                "baseline_id": str(entry.get("baseline_id") or ""),
            }
    return out


def is_debug_signed(certificate: Dict[str, Any]) -> bool:
    """Was this APK signed with a debug/test keystore rather than a release key?"""
    if not certificate:
        return False
    for key, value in certificate.items():
        if isinstance(value, str) and _DEBUG_SUBJECT_RE.search(value):
            return True
        if isinstance(value, dict) and is_debug_signed(value):
            return True
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and _DEBUG_SUBJECT_RE.search(item):
                    return True
                if isinstance(item, dict) and is_debug_signed(item):
                    return True
        # MobSF reports this as an explicit boolean when it can determine it.
        if key in ("apk_is_debuggable", "is_debug", "debug_certificate") and value is True:
            return True
    return False


def extract_signer_sha256(certificate: Dict[str, Any]) -> str:
    """MobSF-style certificate dict → SHA-256 fingerprint."""
    if not certificate:
        return ""
    for key in (
        "certificate_sha256",
        "sha256",
        "sha256_fingerprint",
        "certificate_fingerprint",
        "fingerprint",
    ):
        val = certificate.get(key)
        if isinstance(val, str):
            norm = _normalize_sha256(val)
            if len(norm) == 64:
                return norm
    # Nested analysis blocks
    for block in certificate.values():
        if isinstance(block, dict):
            nested = extract_signer_sha256(block)
            if nested:
                return nested
    return ""


def check_signer_impersonation(
    package_name: str,
    certificate: Dict[str, Any],
    registry: Optional[Dict[str, List[str]]] = None,
    metadata: Optional[Dict[str, Dict[str, Any]]] = None,
) -> SignerImpersonationResult:
    """
    Does this APK claim a protected bank package it is not entitled to?

    Fires when the package name is one of the ten protected institutions and
    the signing certificate is not one the genuine app is signed with -
    including the case where no genuine fingerprint is on file at all, since an
    identity claim that cannot be verified is not one that can be honoured.
    """
    reg = registry if registry is not None else load_signer_registry()
    meta = metadata if metadata is not None else load_signer_registry_metadata()
    result = SignerImpersonationResult(package_name=package_name or "")
    if not package_name or package_name not in reg:
        return result

    entry = meta.get(package_name, {})
    result.institution_id = str(entry.get("baseline_id") or "")
    identity = entry.get("display_name") or entry.get("bank") or "a protected bank"

    signer = extract_signer_sha256(certificate)
    result.signer_sha256 = signer
    result.debug_signed = is_debug_signed(certificate)

    allowed = reg[package_name]
    if signer and signer in allowed:
        return result

    # ── Empty allowlist: no fingerprints provisioned yet ─────────────────────
    # We cannot confirm the signer is genuine, but we also cannot prove it is
    # not - an unverifiable claim is undetermined, not impersonation. The rule
    # fires only once real fingerprints are in the registry.
    # Exception: a debug-signed APK is conclusive regardless - it provably did
    # not come from the bank's release pipeline.
    if not allowed:
        if not result.debug_signed:
            result.evidence_lines.append(
                f"Package {package_name} claims {identity} but no canonical "
                f"signing certificate is provisioned for this package - "
                f"CH06 undetermined (provision fingerprints to enable the rule)"
            )
            return result
        # Fall through to the detection block: debug-signed is conclusive.

    if not signer:
        # Non-empty allowlist but no fingerprint to compare. Say so rather than
        # asserting a finding on absent evidence - unless the certificate itself
        # is self-evidently a debug key, which is conclusive without a
        # fingerprint.
        if not result.debug_signed:
            result.evidence_lines.append(
                f"Package {package_name} claims {identity} but no signer "
                f"fingerprint could be extracted - CH06 undetermined"
            )
            return result

    result.detected = True
    result.evidence_lines = [
        f"CH06: package {package_name} claims the identity of {identity}"
        + (f" ({result.institution_id})" if result.institution_id else ""),
    ]
    if signer:
        result.evidence_lines.append(
            f"Signer SHA-256 {signer[:16]}… is not a certificate this package "
            f"may be signed with"
        )
    if allowed:
        result.evidence_lines.append(
            f"{len(allowed)} canonical signing certificate(s) on file for this package"
        )
    else:
        result.evidence_lines.append(
            "APK is signed with a debug/test keystore - it did not come from "
            "the bank's release pipeline (no canonical certificate provisioned yet)"
        )
    if result.debug_signed:
        result.evidence_lines.append(
            "APK is signed with a debug/test keystore - it did not come from "
            "the bank's release pipeline"
        )
    return result
