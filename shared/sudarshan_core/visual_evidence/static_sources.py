"""Load static corroboration flags from artifact-side investigation manifest."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_STATIC_FLAG_KEYS = (
    "has_accessibility_abuse",
    "has_system_alert_window",
    "has_sms_read_write",
    "targets_indian_banks",
    "has_dynamic_code_loading",
    "has_device_admin",
)


def load_static_flags_from_artifact(artifact_dir: Path) -> Dict[str, bool]:
    """Read capability_flags from investigation manifest.json (artifact root)."""
    path = Path(artifact_dir) / "manifest.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[VisualEvidence] Could not read investigation manifest: %s", exc)
        return {}

    caps = data.get("capability_flags")
    if not isinstance(caps, dict):
        if data.get("screenshots") is not None:
            return {}
        return {}

    out: Dict[str, bool] = {}
    for key in _STATIC_FLAG_KEYS:
        if key in caps:
            out[key] = bool(caps.get(key))
    return out


def merge_static_flags(
    artifact_dir: Path,
    overrides: Optional[Dict[str, bool]] = None,
) -> Dict[str, bool]:
    merged = load_static_flags_from_artifact(artifact_dir)
    if overrides:
        for key, val in overrides.items():
            if key in _STATIC_FLAG_KEYS:
                merged[key] = bool(val)
    return merged
