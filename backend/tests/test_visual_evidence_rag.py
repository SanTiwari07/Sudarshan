"""RAG index includes deterministic visual evidence chunks."""

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test_secret_key_for_pytest_minimum_length_32")

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND.parent / "shared"))
sys.path.insert(0, str(BACKEND))

from app.ai import gemini_rag as rag  # noqa: E402


def test_build_investigation_index_visual_evidence(tmp_path, monkeypatch):
    import json

    art = tmp_path / "case_artifacts"
    art.mkdir()
    (art / "visual_evidence.json").write_text(
        json.dumps(
            {
                "records": [
                    {
                        "screenshot_id": "SCR-004",
                        "investigative_claim": "Banking credential UI observed.",
                        "quality": "A",
                        "correlation_status": "causal",
                        "linked_evidence_ids": ["EVID-019"],
                        "linked_finding_keys": ["overlay_capability"],
                        "workflow_stage_label": "Phishing Overlay Deployment",
                        "timestamp_ms": 1000,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    sha = "c" * 64
    report = {
        "sha256": sha,
        "dynamic_result": {"artifact_dir": str(art)},
        "final_risk_score": 50,
        "risk_band": "MEDIUM",
        "family_classification": "Unknown",
        "matched_rule": "none",
        "action": "REVIEW",
    }

    monkeypatch.setattr(
        "app.artifact_resolve.resolve_artifact_dir",
        lambda _report, sha256=None: art,
    )

    rag._investigation_index.clear()
    rag.build_investigation_index(sha, report)

    idx = rag._investigation_index[sha]
    chunks = idx["visual_evidence"]
    assert any("SCR-004" in c for c in chunks)
    assert any("EVID-019" in c for c in chunks)
    assert any("overlay_capability" in c for c in chunks)


def test_overlay_intent_includes_visual_evidence():
    sections = rag.INTENT_SECTION_MAP.get("overlay", [])
    assert "visual_evidence" in sections


def test_visual_intent_maps_to_ver():
    assert "visual_evidence" in rag.INTENT_SECTION_MAP.get("visual", [])
