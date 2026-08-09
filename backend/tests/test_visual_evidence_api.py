"""API tests for visual evidence manifest merge."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.visual_evidence.api_merge import (
    merge_entry_with_visual_evidence,
    build_visual_evidence_index,
)


def test_merge_entry_includes_visual_fields():
    ver = {
        "screenshot_id": "SCR-001",
        "investigative_claim": "UI observed during analysis.",
        "claim_type": "anti_analysis_ui",
        "quality": "B",
        "correlation_status": "causal",
        "linked_evidence_ids": ["EVID-001"],
        "linked_finding_keys": ["obfuscation"],
        "timeline_eligible": True,
        "report_tier": "technical",
    }
    out = merge_entry_with_visual_evidence(
        {"screenshot_id": "SCR-001", "filename": "screenshots/a.png"},
        ver,
        sha256="a" * 64,
    )
    assert out["correlation_status"] == "causal"
    assert "/a.png" in out["png_url"]
    assert out["visual_evidence"]["linked_evidence_ids"] == ["EVID-001"]


def test_index_by_finding_key():
    idx = build_visual_evidence_index([
        {"screenshot_id": "SCR-001", "linked_finding_keys": ["overlay_capability"], "linked_evidence_ids": []},
    ])
    assert idx["by_finding_key"]["overlay_capability"] == ["SCR-001"]
