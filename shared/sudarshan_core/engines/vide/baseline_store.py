"""Load and index institution UI baselines."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.vide.ui_profile import UIProfile

logger = logging.getLogger(__name__)

_DEFAULT_BASELINES_DIR = (
    Path(__file__).resolve().parents[2] / "data" / "ui_baselines"
)


@dataclass
class InstitutionBaseline:
    institution_id: str
    display_name: str
    package_names: List[str]
    allowed_signers_sha256: List[str]
    profile: UIProfile
    version: str = "1.0.0"

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "InstitutionBaseline":
        prof = UIProfile.from_dict(data.get("profile") or data)
        return cls(
            institution_id=str(data.get("institution_id", "")),
            display_name=str(data.get("display_name", data.get("institution_id", ""))),
            package_names=list(data.get("package_names") or []),
            allowed_signers_sha256=list(data.get("allowed_signers_sha256") or []),
            profile=prof,
            version=str(data.get("version", "1.0.0")),
        )


def load_baselines(directory: Optional[Path] = None) -> List[InstitutionBaseline]:
    base_dir = directory or _DEFAULT_BASELINES_DIR
    if not base_dir.is_dir():
        logger.warning("[VIDE] Baseline directory missing: %s", base_dir)
        return []
    out: List[InstitutionBaseline] = []
    for path in sorted(base_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            bl = InstitutionBaseline.from_json(data)
            if bl.institution_id:
                out.append(bl)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("[VIDE] Skip baseline %s: %s", path.name, e)
    return out


def shortlist_baselines(
    suspect: UIProfile,
    baselines: List[InstitutionBaseline],
    top_k: int = 5,
    min_string_overlap: int = 1,
) -> List[InstitutionBaseline]:
    """
    Cheap pre-filter before deterministic full compare.

  Rule: a baseline is a candidate only if it shares at least
  ``min_string_overlap`` normalized strings with the suspect.
  If none qualify, return [] (do not compare arbitrary banks).
    """
    if not baselines:
        return []
    suspect_strings = {s.lower().strip() for s in suspect.strings if s.strip()}
    if not suspect_strings and not suspect.view_sequence:
        return []

    scored: List[tuple[float, int, InstitutionBaseline]] = []
    for bl in baselines:
        base_strings = {s.lower().strip() for s in bl.profile.strings if s.strip()}
        if not base_strings:
            continue
        overlap = len(suspect_strings & base_strings)
        if overlap < min_string_overlap:
            continue
        score = overlap / max(len(base_strings), 1)
        scored.append((score, overlap, bl))

    scored.sort(key=lambda x: (-x[0], -x[1], x[2].institution_id))
    return [b for _, _, b in scored[:top_k]]
