"""CH06 canonical signer registry impersonation check."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "data" / "bank_signer_registry.json"
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@dataclass
class SignerImpersonationResult:
    detected: bool = False
    package_name: str = ""
    signer_sha256: str = ""
    rule_id: str = "CH06-SIGNER-IMPERSONATION"
    evidence_lines: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.evidence_lines is None:
            self.evidence_lines = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "rule_id": self.rule_id,
            "package_name": self.package_name,
            "signer_sha256": self.signer_sha256,
            "evidence_lines": self.evidence_lines,
        }


def _normalize_sha256(value: str) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", value or "").lower()


def load_signer_registry(path: Optional[Path] = None) -> Dict[str, List[str]]:
    reg_path = path or _REGISTRY_PATH
    if not reg_path.is_file():
        return {}
    try:
        raw = json.loads(reg_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("[VIDE] Signer registry unreadable: %s", e)
        return {}
    out: Dict[str, List[str]] = {}
    for pkg, entry in raw.items():
        if isinstance(entry, dict):
            allowed = entry.get("allowed_signers_sha256") or entry.get("allowed") or []
        elif isinstance(entry, list):
            allowed = entry
        else:
            continue
        normalized = [_normalize_sha256(a) for a in allowed if _normalize_sha256(a)]
        if normalized:
            out[str(pkg)] = normalized
    return out


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
) -> SignerImpersonationResult:
    reg = registry if registry is not None else load_signer_registry()
    result = SignerImpersonationResult(package_name=package_name or "")
    if not package_name or package_name not in reg:
        return result
    signer = extract_signer_sha256(certificate)
    result.signer_sha256 = signer
    if not signer:
        result.evidence_lines.append(
            f"Package {package_name} is in bank registry but signer fingerprint unavailable"
        )
        return result
    allowed = reg[package_name]
    if signer in allowed:
        return result
    result.detected = True
    result.evidence_lines = [
        f"CH06: package {package_name} claims protected bank identity",
        f"Signer SHA-256 {signer[:16]}… not in canonical registry ({len(allowed)} known)",
    ]
    return result
