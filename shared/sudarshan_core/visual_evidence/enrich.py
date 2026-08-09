"""Post-dynamic visual evidence enrichment (static, VIDE, workflow)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from sudarshan_core.visual_evidence.linker import write_visual_evidence_artifact
from sudarshan_core.visual_evidence.static_sources import merge_static_flags

logger = logging.getLogger(__name__)


def enrich_visual_evidence_artifact(
    artifact_dir: Path,
    *,
    analysis_id: str,
    package_name: str,
    vide_result: Optional[Dict[str, Any]] = None,
    static_flags: Optional[Dict[str, bool]] = None,
    session_metadata: Optional[Dict[str, Any]] = None,
) -> int:
    """
    Deterministic re-link after Frida, static intel, VIDE, and workflow are final.

    Regenerates visual_evidence.json from artifacts (no re-capture, no VIDE re-run).
    """
    flags = merge_static_flags(artifact_dir, static_flags)
    return write_visual_evidence_artifact(
        artifact_dir,
        analysis_id=analysis_id,
        package_name=package_name,
        static_flags=flags,
        vide_result=vide_result or {},
        session_metadata=session_metadata or {},
    )
