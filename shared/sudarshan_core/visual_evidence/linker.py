"""Deterministic visual evidence linker and artifact writer."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sudarshan_core.visual_evidence.claim_templates import render_investigative_claim
from sudarshan_core.visual_evidence.constants import (
    ACCESSIBILITY_SCRAPE_MARKERS,
    ACCESSIBILITY_SETTINGS_MARKERS,
    BANKING_DETECTION_MARKERS,
    CAPTURE_REASON_TO_CLAIM,
    CAPTURE_REASON_TO_WORKFLOW,
    CLAIM_ACCESSIBILITY_GUIDANCE,
    CLAIM_ANTI_ANALYSIS_UI,
    CLAIM_BANKING_TARGET_UI,
    CLAIM_CREDENTIAL_COLLECTION_UI,
    CLAIM_DROPPER_UI,
    CLAIM_FAKE_LOGIN_UI,
    CLAIM_FINAL_STATE,
    CLAIM_INCONCLUSIVE_VISUAL,
    CLAIM_LAUNCH_CONTEXT,
    CLAIM_OTP_UI,
    CLAIM_OVERLAY_OBSERVED,
    CLAIM_VISUAL_IMPERSONATION,
    CORRELATION_CAUSAL,
    CORRELATION_LINKED,
    CORRELATION_NOT_APPLICABLE,
    CORRELATION_STRENGTH_ORDER,
    CORRELATION_TEMPORAL,
    CORRELATION_UNRESOLVED,
    DEX_INSTALL_MARKERS,
    EVIDENCE_MOMENT_CAPTURE_REASONS,
    LIFECYCLE_REASON,
    OVERLAY_API_MARKERS,
    SCHEMA_VERSION,
    SMS_API_MARKERS,
    SUSPICIOUS_UI_REASONS,
    VISUAL_LINK_DELTA_MS_CRITICAL,
    VISUAL_LINK_DELTA_MS_DEFAULT,
    VISUAL_LINK_DELTA_MS_VIDE,
    VISUAL_LINK_MAX_EVID_PER_SCR,
)
from sudarshan_core.visual_evidence.static_sources import merge_static_flags
from sudarshan_core.visual_evidence.models import VisualEvidenceArtifact, VisualEvidenceRecord
from sudarshan_core.visual_evidence.quality import (
    apply_executive_key_cap,
    assign_priority,
    assign_quality,
    assign_report_tier,
    timeline_eligible,
)

logger = logging.getLogger(__name__)

# Workflow stage labels (must match workflow_reconstructor._STAGE_RULES labels)
STAGE_OVERLAY = "Phishing Overlay Deployment"
STAGE_ACCESSIBILITY = "Accessibility Service Activation"
STAGE_CREDENTIAL_SCRAPE = "UI Credential Scraping"
STAGE_BANKING = "Banking App Detection"
STAGE_SMS = "SMS / OTP Interception"
STAGE_ANTI_ANALYSIS = "Anti-Analysis Evasion"
STAGE_DEX = "Dynamic Code Loading"

_CLAIM_FINDING_KEYS: Dict[str, List[str]] = {
    CLAIM_OVERLAY_OBSERVED: ["overlay_capability"],
    CLAIM_FAKE_LOGIN_UI: ["overlay_capability"],
    CLAIM_VISUAL_IMPERSONATION: ["visual_impersonation"],
    CLAIM_ACCESSIBILITY_GUIDANCE: ["accessibility_abuse"],
    CLAIM_CREDENTIAL_COLLECTION_UI: ["accessibility_abuse"],
    CLAIM_OTP_UI: ["sms_otp_interception"],
    CLAIM_BANKING_TARGET_UI: ["banking_targeting"],
    CLAIM_ANTI_ANALYSIS_UI: ["obfuscation"],
    CLAIM_DROPPER_UI: ["runtime_code_loading"],
}

# Visual claim from capture reason must not inherit incompatible hook claims.
_INCOMPATIBLE_HOOK_CLAIMS: Dict[str, frozenset] = {
    CAPTURE_REASON_TO_CLAIM["VPN_REQUEST"]: frozenset({
        CLAIM_ACCESSIBILITY_GUIDANCE,
        CLAIM_CREDENTIAL_COLLECTION_UI,
        CLAIM_ANTI_ANALYSIS_UI,
        CLAIM_BANKING_TARGET_UI,
    }),
    CAPTURE_REASON_TO_CLAIM["UPDATE_PROMPT"]: frozenset({
        CLAIM_ANTI_ANALYSIS_UI,
        CLAIM_ACCESSIBILITY_GUIDANCE,
    }),
    CAPTURE_REASON_TO_CLAIM["EXTERNAL_APK"]: frozenset({
        CLAIM_ACCESSIBILITY_GUIDANCE,
        CLAIM_ANTI_ANALYSIS_UI,
    }),
    CAPTURE_REASON_TO_CLAIM["DOWNLOAD_PROMPT"]: frozenset({
        CLAIM_ACCESSIBILITY_GUIDANCE,
        CLAIM_ANTI_ANALYSIS_UI,
    }),
}

_CLAIM_WORKFLOW_STAGE: Dict[str, str] = {
    CLAIM_OVERLAY_OBSERVED: STAGE_OVERLAY,
    CLAIM_FAKE_LOGIN_UI: STAGE_OVERLAY,
    CLAIM_ACCESSIBILITY_GUIDANCE: STAGE_ACCESSIBILITY,
    CLAIM_CREDENTIAL_COLLECTION_UI: STAGE_CREDENTIAL_SCRAPE,
    CLAIM_BANKING_TARGET_UI: STAGE_BANKING,
    CLAIM_OTP_UI: STAGE_SMS,
    CLAIM_ANTI_ANALYSIS_UI: STAGE_ANTI_ANALYSIS,
    CLAIM_DROPPER_UI: STAGE_DEX,
    CLAIM_VISUAL_IMPERSONATION: STAGE_BANKING,
}


def _sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.warning("[VisualEvidence] PNG hash failed %s: %s", path, exc)
        return None


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[VisualEvidence] Could not read %s: %s", path, exc)
        return None


def _load_evidence_records(artifact_dir: Path) -> List[Dict[str, Any]]:
    data = _load_json(artifact_dir / "evidence.json")
    if not data:
        return []
    if isinstance(data, list):
        return data
    return list(data.get("records") or [])


def _load_manifest_shots(artifact_dir: Path) -> List[Dict[str, Any]]:
    for rel in (
        artifact_dir / "screenshots" / "manifest.json",
        artifact_dir / "screenshots.json",
    ):
        data = _load_json(rel)
        if isinstance(data, dict) and data.get("screenshots"):
            return list(data["screenshots"])
    return []


def _api_matches(api: str, markers: Tuple[str, ...]) -> bool:
    api = api or ""
    return any(m in api for m in markers)


def _event_claim_type(ev: Dict[str, Any]) -> Optional[str]:
    """Map hook evidence to a visual claim type. SMS hooks never produce visual claims."""
    api = str(ev.get("api") or "")
    category = str(ev.get("category") or "").lower()

    if _api_matches(api, SMS_API_MARKERS) or category == "sms":
        return None

    if _api_matches(api, OVERLAY_API_MARKERS) or category == "overlay":
        return CLAIM_OVERLAY_OBSERVED

    if _api_matches(api, ACCESSIBILITY_SETTINGS_MARKERS):
        return CLAIM_ACCESSIBILITY_GUIDANCE

    if _api_matches(api, ACCESSIBILITY_SCRAPE_MARKERS) or category == "accessibility":
        if _api_matches(api, ACCESSIBILITY_SCRAPE_MARKERS):
            return CLAIM_CREDENTIAL_COLLECTION_UI
        return CLAIM_ACCESSIBILITY_GUIDANCE

    if _api_matches(api, BANKING_DETECTION_MARKERS) or category == "banking":
        return CLAIM_BANKING_TARGET_UI

    if category == "anti_analysis":
        return CLAIM_ANTI_ANALYSIS_UI

    if _api_matches(api, DEX_INSTALL_MARKERS) or category in ("dangerous_apis", "persistence"):
        if _api_matches(api, DEX_INSTALL_MARKERS):
            return CLAIM_DROPPER_UI

    return None


def _delta_for_event(ev: Dict[str, Any]) -> int:
    sev = str(ev.get("severity") or "").upper()
    category = str(ev.get("category") or "").lower()
    if sev == "CRITICAL" or category in ("overlay", "anti_analysis"):
        return VISUAL_LINK_DELTA_MS_CRITICAL
    return VISUAL_LINK_DELTA_MS_DEFAULT


def _scr_path(artifact_dir: Path, filename: str) -> Path:
    rel = filename.replace("\\", "/").lstrip("/")
    return artifact_dir / rel if rel.startswith("screenshots/") else artifact_dir / "screenshots" / Path(rel).name


def _is_lifecycle_launch(shot: Dict[str, Any]) -> bool:
    reason = str(shot.get("reason") or "")
    label = str(shot.get("label") or "").lower()
    if reason == LIFECYCLE_REASON and "01_app_opened" in label:
        return True
    return "app_opened" in label or label.startswith("01_")


def _is_lifecycle_final(shot: Dict[str, Any]) -> bool:
    reason = str(shot.get("reason") or "")
    label = str(shot.get("label") or "").lower()
    if reason == LIFECYCLE_REASON and "99_final" in label:
        return True
    return "final_screen" in label or label.startswith("99_")


def _suspicious_ui_shot(shot: Dict[str, Any]) -> bool:
    reason = str(shot.get("reason") or "")
    return reason in SUSPICIOUS_UI_REASONS or "perception" in str(shot.get("label") or "").lower()


def _load_workflow(artifact_dir: Path) -> Dict[str, Any]:
    data = _load_json(artifact_dir / "workflow.json")
    return data if isinstance(data, dict) else {}


def _strongest_correlation(statuses: List[str]) -> str:
    for status in CORRELATION_STRENGTH_ORDER:
        if status in statuses:
            return status
    return CORRELATION_UNRESOLVED


def _hook_evidence_record(ev: Dict[str, Any]) -> bool:
    return str(ev.get("category") or "").upper() != "SCREENSHOT"


def _resolve_workflow_stage(
    linked_finding_ids: List[str],
    evidence_by_finding: Dict[str, Dict[str, Any]],
    workflow: Dict[str, Any],
) -> str:
    stages = workflow.get("stages") or []
    if not stages or not linked_finding_ids:
        return ""

    resolved: List[str] = []
    for fid in linked_finding_ids:
        ev = evidence_by_finding.get(fid)
        if not ev:
            continue
        api = str(ev.get("api") or "")
        ts = int(ev.get("timestamp_ms") or 0)
        stage_labels: List[str] = []
        for st in stages:
            hooks = st.get("hook_names") or []
            if not hooks:
                continue
            hook_match = api in hooks or any(h in api for h in hooks if h)
            if not hook_match:
                continue
            start_ms = int(st.get("start_ms") or 0)
            end_ms = int(st.get("end_ms") or 0)
            if ts and end_ms and not (start_ms <= ts <= end_ms):
                continue
            label = str(st.get("label") or "")
            if label:
                stage_labels.append(label)
        if len(stage_labels) == 1:
            resolved.append(stage_labels[0])

    unique = list(dict.fromkeys(resolved))
    if len(unique) == 1:
        return unique[0]
    return ""


class _ShotLinks:
    """Per-screenshot EVID links with correlation tier."""

    def __init__(self) -> None:
        self.finding_ids: List[str] = []
        self.tiers: Dict[str, str] = {}
        self.claim_hints: Dict[str, str] = {}

    def add(self, finding_id: str, tier: str, claim_hint: Optional[str]) -> bool:
        if finding_id in self.finding_ids:
            return False
        if len(self.finding_ids) >= VISUAL_LINK_MAX_EVID_PER_SCR:
            return False
        self.finding_ids.append(finding_id)
        self.tiers[finding_id] = tier
        if claim_hint:
            self.claim_hints.setdefault(finding_id, claim_hint)
        return True

    def correlation_status(self) -> str:
        if not self.finding_ids:
            return CORRELATION_UNRESOLVED
        return _strongest_correlation(list(self.tiers.values()))

    def primary_claim_hint(self) -> Optional[str]:
        for fid in self.finding_ids:
            if self.tiers.get(fid) == CORRELATION_CAUSAL:
                return self.claim_hints.get(fid)
        for fid in self.finding_ids:
            hint = self.claim_hints.get(fid)
            if hint:
                return hint
        return None


def _is_evidence_moment_shot(shot: Dict[str, Any]) -> bool:
    """True when screenshot was captured for a UI evidence moment (not a hook)."""
    if str(shot.get("evidence_moment_id") or "").strip():
        return True
    reason = str(shot.get("reason") or "")
    if reason in EVIDENCE_MOMENT_CAPTURE_REASONS:
        return True
    if str(shot.get("category") or "") == "evidence_moment":
        return True
    return False


def _reason_claim_type(shot: Dict[str, Any]) -> Optional[str]:
    reason = str(shot.get("reason") or shot.get("capture_trigger") or "")
    return CAPTURE_REASON_TO_CLAIM.get(reason)


def _claims_compatible(visual_claim: Optional[str], hook_claim: Optional[str]) -> bool:
    if not visual_claim or not hook_claim:
        return True
    if visual_claim == hook_claim:
        return True
    for base_claim, blocked in _INCOMPATIBLE_HOOK_CLAIMS.items():
        if visual_claim == base_claim and hook_claim in blocked:
            return False
    return True


def _build_shot_links(
    shot: Dict[str, Any],
    evidence: List[Dict[str, Any]],
    evidence_by_uuid: Dict[str, Dict[str, Any]],
) -> _ShotLinks:
    out = _ShotLinks()
    trigger_uuid = str(shot.get("trigger_event") or "").strip()
    sh_hash = str(shot.get("screen_hash") or "")
    shot_ts = int(shot.get("timestamp_ms") or 0)
    visual_claim = _reason_claim_type(shot)
    moment_shot = _is_evidence_moment_shot(shot)

    if trigger_uuid and trigger_uuid in evidence_by_uuid:
        ev = evidence_by_uuid[trigger_uuid]
        if _hook_evidence_record(ev):
            fid = str(ev.get("finding_id") or "")
            hint = _event_claim_type(ev)
            if fid and hint is not None and _claims_compatible(visual_claim, hint):
                out.add(fid, CORRELATION_CAUSAL, hint)

    for ev in evidence:
        fid = str(ev.get("finding_id") or "")
        if not fid or fid in out.finding_ids:
            continue
        if not _hook_evidence_record(ev):
            continue
        hint = _event_claim_type(ev)
        if hint is None:
            continue
        if not _claims_compatible(visual_claim, hint):
            continue
        ev_hash = str((ev.get("extra") or {}).get("screen_hash") or "")
        if ev_hash and sh_hash and ev_hash == sh_hash:
            out.add(fid, CORRELATION_LINKED, hint)

    # Evidence-moment captures are visually self-describing; never attach
    # unrelated runtime hooks by timestamp proximity alone.
    if moment_shot:
        return out

    for ev in sorted(evidence, key=lambda e: int(e.get("timestamp_ms") or 0)):
        fid = str(ev.get("finding_id") or "")
        if not fid or fid in out.finding_ids:
            continue
        if not _hook_evidence_record(ev):
            continue
        hint = _event_claim_type(ev)
        if hint is None:
            continue
        if not _claims_compatible(visual_claim, hint):
            continue
        event_ms = int(ev.get("timestamp_ms") or 0)
        if shot_ts <= 0 or event_ms <= 0:
            continue
        if abs(shot_ts - event_ms) > _delta_for_event(ev):
            continue
        out.add(fid, CORRELATION_TEMPORAL, hint)

    return out


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


class VisualEvidenceLinker:
    """Build VisualEvidenceRecord list from manifest + evidence + session context."""

    def __init__(
        self,
        artifact_dir: Path,
        *,
        analysis_id: str = "",
        package_name: str = "",
        static_flags: Optional[Dict[str, bool]] = None,
        vide_result: Optional[Dict[str, Any]] = None,
        session_metadata: Optional[Dict[str, Any]] = None,
    ):
        self.artifact_dir = Path(artifact_dir)
        self.analysis_id = analysis_id
        self.package_name = package_name
        self.static_flags = static_flags or {}
        self.vide_result = vide_result or {}
        self.session_metadata = session_metadata or {}

    def link(self) -> List[VisualEvidenceRecord]:
        shots = _load_manifest_shots(self.artifact_dir)
        shots.sort(key=lambda s: int(s.get("timestamp_ms") or 0))
        evidence = _load_evidence_records(self.artifact_dir)
        if not self.static_flags:
            self.static_flags = merge_static_flags(self.artifact_dir, None)

        evidence_by_finding: Dict[str, Dict[str, Any]] = {}
        evidence_by_uuid: Dict[str, Dict[str, Any]] = {}
        for ev in evidence:
            fid = str(ev.get("finding_id") or "")
            if fid:
                evidence_by_finding[fid] = ev
            uid = str(ev.get("id") or "")
            if uid:
                evidence_by_uuid[uid] = ev

        workflow = _load_workflow(self.artifact_dir)

        vide_detected = bool(
            self.vide_result.get("visual_impersonation_detected")
            or (self.vide_result.get("vide_compare") or {}).get("detected")
        )
        baseline_name = str(
            (self.vide_result.get("vide_compare") or {}).get("baseline_name")
            or self.vide_result.get("matched_baseline")
            or "reference"
        )
        vide_rule_id = str(self.vide_result.get("rule_id") or "VIDE-F001")
        vide_baseline_id = str(
            (self.vide_result.get("vide_compare") or {}).get("baseline_id")
            or self.vide_result.get("baseline_id")
            or ""
        )

        seen_screen_hash: Set[str] = set()
        records: List[VisualEvidenceRecord] = []

        for shot in shots:
            sid = str(shot.get("screenshot_id") or "")
            if not sid:
                continue
            filename = str(shot.get("filename") or "")
            ts = int(shot.get("timestamp_ms") or 0)
            capture_trigger = str(shot.get("reason") or shot.get("source") or "")
            png_path = _scr_path(self.artifact_dir, filename)
            png_sha = _sha256_file(png_path) or ""
            png_missing = not png_sha

            screen_hash = str(shot.get("screen_hash") or "")
            is_duplicate = bool(screen_hash and screen_hash in seen_screen_hash)
            if screen_hash:
                seen_screen_hash.add(screen_hash)

            shot_links = _build_shot_links(shot, evidence, evidence_by_uuid)
            linked = shot_links.finding_ids[:VISUAL_LINK_MAX_EVID_PER_SCR]
            correlation = CORRELATION_UNRESOLVED
            claim_type: Optional[str] = None
            reason_claim = _reason_claim_type(shot)
            moment_shot = _is_evidence_moment_shot(shot)

            if _is_lifecycle_launch(shot):
                claim_type = CLAIM_LAUNCH_CONTEXT
                correlation = CORRELATION_NOT_APPLICABLE
            elif _is_lifecycle_final(shot):
                claim_type = CLAIM_FINAL_STATE
                correlation = CORRELATION_NOT_APPLICABLE
            elif reason_claim and moment_shot:
                claim_type = reason_claim
                causal_links = [
                    fid for fid in linked
                    if shot_links.tiers.get(fid) == CORRELATION_CAUSAL
                ]
                if causal_links:
                    correlation = CORRELATION_CAUSAL
                    linked = causal_links
                elif linked:
                    correlation = shot_links.correlation_status()
                else:
                    correlation = CORRELATION_CAUSAL
                    linked = []
            elif linked:
                claim_type = shot_links.primary_claim_hint() or CLAIM_INCONCLUSIVE_VISUAL
                correlation = shot_links.correlation_status()
                if claim_type == CLAIM_OVERLAY_OBSERVED and _suspicious_ui_shot(shot):
                    claim_type = CLAIM_FAKE_LOGIN_UI
            elif reason_claim:
                claim_type = reason_claim
                correlation = CORRELATION_CAUSAL
            else:
                claim_type = CLAIM_INCONCLUSIVE_VISUAL
                correlation = CORRELATION_UNRESOLVED

            params: Dict[str, Any] = {}
            if claim_type == CLAIM_VISUAL_IMPERSONATION:
                params = {"baseline_name": baseline_name, "rule_id": vide_rule_id}

            investigative_claim = render_investigative_claim(claim_type, params)

            quality = assign_quality(
                claim_type=claim_type,
                correlation_status=correlation,
                linked_evidence_ids=linked,
                evidence_by_finding_id=evidence_by_finding,
                static_flags=self.static_flags,
                vide_detected=vide_detected and claim_type == CLAIM_VISUAL_IMPERSONATION,
                is_duplicate=is_duplicate,
                png_missing=png_missing,
            )
            report_tier = assign_report_tier(claim_type, quality)
            priority = assign_priority(claim_type, quality)
            tl_eligible = timeline_eligible(quality, correlation, claim_type)

            finding_keys = list(_CLAIM_FINDING_KEYS.get(claim_type, []))
            if claim_type == CLAIM_OTP_UI and linked:
                finding_keys = list(dict.fromkeys(finding_keys + ["sms_otp_interception"]))

            workflow_label = _resolve_workflow_stage(linked, evidence_by_finding, workflow)
            if not workflow_label and reason_claim:
                reason_key = str(shot.get("reason") or shot.get("capture_trigger") or "")
                workflow_label = CAPTURE_REASON_TO_WORKFLOW.get(reason_key, "")

            corroboration = ""
            if linked and correlation in (CORRELATION_CAUSAL, CORRELATION_LINKED):
                corroboration = f"Linked runtime evidence: {', '.join(linked)} ({correlation})"
            elif linked and correlation == CORRELATION_TEMPORAL:
                corroboration = (
                    f"Runtime hooks observed near capture: {', '.join(linked)} "
                    f"(temporal; visual claim from capture reason)"
                )
            elif moment_shot and reason_claim:
                corroboration = "Visual evidence captured from observed UI state."
            elif correlation == CORRELATION_NOT_APPLICABLE:
                corroboration = "Lifecycle capture without hook correlation."

            records.append(
                VisualEvidenceRecord(
                    screenshot_id=sid,
                    filename=filename,
                    png_sha256=png_sha,
                    timestamp_ms=ts,
                    capture_trigger=capture_trigger,
                    claim_type=claim_type,
                    investigative_claim=investigative_claim,
                    quality=quality,
                    report_tier=report_tier,
                    correlation_status=correlation,
                    linked_evidence_ids=linked,
                    linked_finding_keys=finding_keys,
                    workflow_stage_label=workflow_label,
                    timeline_eligible=tl_eligible,
                    priority=priority,
                    corroboration_summary=corroboration,
                    vide_rule_id=vide_rule_id if claim_type == CLAIM_VISUAL_IMPERSONATION else "",
                    vide_baseline_id=vide_baseline_id if claim_type == CLAIM_VISUAL_IMPERSONATION else "",
                    negative_proof=False,
                    analyst_note="",
                )
            )

        if vide_detected and records:
            has_vide_scr = any(
                r.claim_type == CLAIM_VISUAL_IMPERSONATION
                and r.correlation_status in (CORRELATION_LINKED, CORRELATION_CAUSAL)
                for r in records
            )
            if not has_vide_scr:
                vide_ms = int(self.vide_result.get("timestamp_ms") or 0)
                best: Optional[VisualEvidenceRecord] = None
                best_d = 10**18
                for rec in records:
                    if rec.timestamp_ms <= 0:
                        continue
                    d = abs(rec.timestamp_ms - vide_ms) if vide_ms else 0
                    if vide_ms and d > VISUAL_LINK_DELTA_MS_VIDE:
                        continue
                    if d < best_d:
                        best, best_d = rec, d
                if best is None and records:
                    best = records[0]
                if best and best.claim_type == CLAIM_INCONCLUSIVE_VISUAL:
                    best.claim_type = CLAIM_VISUAL_IMPERSONATION
                    best.investigative_claim = render_investigative_claim(
                        CLAIM_VISUAL_IMPERSONATION,
                        {"baseline_name": baseline_name, "rule_id": vide_rule_id},
                    )
                    best.correlation_status = CORRELATION_LINKED
                    best.vide_rule_id = vide_rule_id
                    best.vide_baseline_id = vide_baseline_id
                    best.linked_finding_keys = ["visual_impersonation"]
                    best.workflow_stage_label = _resolve_workflow_stage(
                        best.linked_evidence_ids, evidence_by_finding, workflow
                    )
                    best.quality = assign_quality(
                        claim_type=best.claim_type,
                        correlation_status=best.correlation_status,
                        linked_evidence_ids=best.linked_evidence_ids,
                        evidence_by_finding_id=evidence_by_finding,
                        static_flags=self.static_flags,
                        vide_detected=True,
                        is_duplicate=False,
                        png_missing=not best.png_sha256,
                    )
                    best.report_tier = assign_report_tier(best.claim_type, best.quality)
                    best.priority = assign_priority(best.claim_type, best.quality)
                    best.timeline_eligible = timeline_eligible(
                        best.quality, best.correlation_status, best.claim_type
                    )

        records.sort(key=lambda r: r.timestamp_ms)
        apply_executive_key_cap(records)
        return records


def write_visual_evidence_artifact(
    artifact_dir: Path,
    *,
    analysis_id: str,
    package_name: str,
    static_flags: Optional[Dict[str, bool]] = None,
    vide_result: Optional[Dict[str, Any]] = None,
    session_metadata: Optional[Dict[str, Any]] = None,
) -> int:
    """Run linker and write visual_evidence.json. Returns record count."""
    merged_flags = merge_static_flags(Path(artifact_dir), static_flags)
    linker = VisualEvidenceLinker(
        artifact_dir,
        analysis_id=analysis_id,
        package_name=package_name,
        static_flags=merged_flags,
        vide_result=vide_result,
        session_metadata=session_metadata,
    )
    records = linker.link()
    artifact = VisualEvidenceArtifact(
        schema_version=SCHEMA_VERSION,
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        analysis_id=analysis_id,
        package_name=package_name,
        records=records,
    )
    out_path = Path(artifact_dir) / "visual_evidence.json"
    _atomic_write_json(out_path, artifact.to_dict())
    logger.info("[VisualEvidence] Wrote %d record(s) -> %s", len(records), out_path)
    apply_evidence_screenshot_links(artifact_dir, records)
    return len(records)


def apply_evidence_screenshot_links(
    artifact_dir: Path,
    records: List[VisualEvidenceRecord],
) -> None:
    """Update evidence.json screenshot_ref / screenshot_id for linked EVID rows."""
    path = Path(artifact_dir) / "evidence.json"
    data = _load_json(path)
    if not data or not isinstance(data, dict):
        return
    recs = data.get("records")
    if not isinstance(recs, list):
        return

    by_evid: Dict[str, VisualEvidenceRecord] = {}
    link_statuses = frozenset({
        CORRELATION_CAUSAL,
        CORRELATION_LINKED,
        CORRELATION_TEMPORAL,
    })
    for ver in records:
        if ver.correlation_status not in link_statuses:
            continue
        for eid in ver.linked_evidence_ids:
            if eid and eid not in by_evid:
                by_evid[eid] = ver

    changed = False
    for ev in recs:
        fid = str(ev.get("finding_id") or "")
        ver = by_evid.get(fid)
        if not ver:
            continue
        if ev.get("screenshot_ref") != ver.filename:
            ev["screenshot_ref"] = ver.filename
            changed = True
        if ev.get("screenshot_id") != ver.screenshot_id:
            ev["screenshot_id"] = ver.screenshot_id
            changed = True

    if changed:
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("[VisualEvidence] Updated evidence.json screenshot links")
        except OSError as exc:
            logger.warning("[VisualEvidence] Could not update evidence.json: %s", exc)
