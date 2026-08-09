"""Visual evidence record and artifact envelope models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VisualEvidenceRecord:
  screenshot_id: str
  filename: str
  png_sha256: str
  timestamp_ms: int
  capture_trigger: str
  claim_type: str
  investigative_claim: str
  quality: str
  report_tier: str
  correlation_status: str
  linked_evidence_ids: List[str] = field(default_factory=list)
  linked_finding_keys: List[str] = field(default_factory=list)
  workflow_stage_label: str = ""
  timeline_eligible: bool = False
  priority: str = "P2"
  corroboration_summary: str = ""
  vide_rule_id: str = ""
  vide_baseline_id: str = ""
  negative_proof: bool = False
  analyst_note: str = ""

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)

  @classmethod
  def from_dict(cls, data: Dict[str, Any]) -> "VisualEvidenceRecord":
    return cls(
      screenshot_id=str(data.get("screenshot_id") or ""),
      filename=str(data.get("filename") or ""),
      png_sha256=str(data.get("png_sha256") or ""),
      timestamp_ms=int(data.get("timestamp_ms") or 0),
      capture_trigger=str(data.get("capture_trigger") or ""),
      claim_type=str(data.get("claim_type") or ""),
      investigative_claim=str(data.get("investigative_claim") or ""),
      quality=str(data.get("quality") or ""),
      report_tier=str(data.get("report_tier") or ""),
      correlation_status=str(data.get("correlation_status") or ""),
      linked_evidence_ids=list(data.get("linked_evidence_ids") or []),
      linked_finding_keys=list(data.get("linked_finding_keys") or []),
      workflow_stage_label=str(data.get("workflow_stage_label") or ""),
      timeline_eligible=bool(data.get("timeline_eligible")),
      priority=str(data.get("priority") or "P2"),
      corroboration_summary=str(data.get("corroboration_summary") or ""),
      vide_rule_id=str(data.get("vide_rule_id") or ""),
      vide_baseline_id=str(data.get("vide_baseline_id") or ""),
      negative_proof=bool(data.get("negative_proof")),
      analyst_note=str(data.get("analyst_note") or ""),
    )


@dataclass
class VisualEvidenceArtifact:
  schema_version: int
  generated_at: str
  analysis_id: str
  package_name: str
  records: List[VisualEvidenceRecord]

  def to_dict(self) -> Dict[str, Any]:
    return {
      "schema_version": self.schema_version,
      "generated_at": self.generated_at,
      "analysis_id": self.analysis_id,
      "package_name": self.package_name,
      "records": [r.to_dict() for r in self.records],
    }
