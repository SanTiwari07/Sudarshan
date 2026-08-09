"""VIDE - normalized UI profile for static/dynamic comparison."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class UIProfile:
    """Structural fingerprint of a screen (layout XML, HTML, or uiautomator)."""

    source: str  # apktool_layout | assets_html | webview_dump | uiautomator
    strings: List[str] = field(default_factory=list)
    view_sequence: List[str] = field(default_factory=list)
    colors: List[str] = field(default_factory=list)
    asset_hashes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "strings": self.strings,
            "view_sequence": self.view_sequence,
            "colors": self.colors,
            "asset_hashes": self.asset_hashes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UIProfile":
        return cls(
            source=str(data.get("source", "unknown")),
            strings=list(data.get("strings") or []),
            view_sequence=list(data.get("view_sequence") or []),
            colors=list(data.get("colors") or []),
            asset_hashes=list(data.get("asset_hashes") or []),
        )


@dataclass
class VIDECompareResult:
    """Deterministic VIDE output (CH21: verdict source, not LLM)."""

    rule_id: str = ""
    detected: bool = False
    institution_id: str = ""
    institution_display: str = ""
    confidence: float = 0.0
    string_jaccard: float = 0.0
    tree_similarity: float = 0.0
    color_match: float = 0.0
    matched_strings: List[str] = field(default_factory=list)
    evidence_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "detected": self.detected,
            "capability": "visual_impersonation" if self.detected else "",
            "institution_id": self.institution_id,
            "institution_display": self.institution_display,
            "confidence": round(self.confidence, 4),
            "scores": {
                "string_jaccard": round(self.string_jaccard, 4),
                "tree_similarity": round(self.tree_similarity, 4),
                "color_match": round(self.color_match, 4),
            },
            "matched_strings": self.matched_strings[:20],
            "evidence_lines": self.evidence_lines,
        }
