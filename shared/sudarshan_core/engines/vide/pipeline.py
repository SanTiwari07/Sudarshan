"""VIDE orchestration - static + dynamic profile merge and compare."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline, load_baselines
from sudarshan_core.engines.vide.compare import RULE_ID, compare_against_baselines
from sudarshan_core.engines.vide.html_profile import profile_from_html
from sudarshan_core.engines.vide.layout_extractor import extract_from_decode_dir
from sudarshan_core.engines.vide.signer_registry import (
    SignerImpersonationResult,
    check_signer_impersonation,
    extract_signer_sha256,
)
from sudarshan_core.engines.vide.ui_profile import UIProfile, VIDECompareResult

logger = logging.getLogger(__name__)


def _merge_profiles(primary: UIProfile, extra: UIProfile) -> UIProfile:
    return UIProfile(
        source=primary.source,
        strings=sorted(set(primary.strings) | set(extra.strings))[:150],
        view_sequence=(primary.view_sequence + extra.view_sequence)[:220],
        colors=sorted(set(primary.colors) | set(extra.colors))[:40],
        asset_hashes=list(dict.fromkeys(primary.asset_hashes + extra.asset_hashes))[:25],
    )


def extract_html_from_assets(decode_dir: Path) -> List[str]:
    snippets: List[str] = []
    assets = decode_dir / "assets"
    if not assets.is_dir():
        return snippets
    for path in assets.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".html", ".htm", ".xhtml"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if len(text) > 50:
                snippets.append(text[:50000])
        except OSError:
            continue
    return snippets[:10]


def profile_from_dynamic_result(dynamic_result: Optional[Dict[str, Any]]) -> UIProfile:
    if not dynamic_result:
        return UIProfile(source="dynamic_empty")
    merged = UIProfile(source="dynamic")
    for event in dynamic_result.get("vide_webview_html") or []:
        if isinstance(event, str) and event:
            merged = _merge_profiles(merged, profile_from_html(event, "webview_dump"))
    for event in dynamic_result.get("network_logs") or []:
        if isinstance(event, str) and "<html" in event.lower():
            merged = _merge_profiles(merged, profile_from_html(event, "network_html"))
    ui_xml = dynamic_result.get("ui_hierarchy_xml")
    if isinstance(ui_xml, str) and ui_xml:
        merged = _merge_profiles(merged, _profile_from_uiautomator_xml(ui_xml))
    return merged


def _profile_from_uiautomator_xml(xml: str) -> UIProfile:
    import xml.etree.ElementTree as ET

    strings: List[str] = []
    seq: List[str] = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return UIProfile(source="uiautomator")
    for node in root.iter():
        cls = node.attrib.get("class", "")
        if cls:
            short = cls.rsplit(".", 1)[-1]
            seq.append(short)
        for attr in ("text", "content-desc", "hint"):
            val = node.attrib.get(attr, "").strip()
            if val:
                strings.append(val)
    return UIProfile(source="uiautomator", strings=strings[:80], view_sequence=seq[:120])


def collect_webview_html_from_frida_events(dynamic_result: Dict[str, Any]) -> List[str]:
    """Parse Frida session payloads for WebView HTML (loadData hooks)."""
    html_snippets: List[str] = []
    events_map = dynamic_result.get("frida_events") or {}
    for category in ("network", "banking", "overlay"):
        for wrapper in events_map.get(category, []):
            if not isinstance(wrapper, dict):
                continue
            data = wrapper.get("data") if isinstance(wrapper.get("data"), dict) else wrapper
            hook = str(data.get("hook") or wrapper.get("hook") or "")
            if "loadData" in hook or "loadDataWithBaseURL" in hook:
                html = data.get("html_preview") or data.get("data_preview") or ""
                if html:
                    html_snippets.append(str(html))
            script = data.get("script_preview") or ""
            if script and len(script) > 40 and "<" in script:
                html_snippets.append(str(script))
    return html_snippets


def _empty_vide_payload(
    *,
    status: str,
    available: bool,
    error: str = "",
) -> Dict[str, Any]:
    return {
        "available": available,
        "status": status,
        "error": error,
        "vide_compare": {
            "rule_id": RULE_ID,
            "detected": False,
            "capability": "",
            "institution_id": "",
            "institution_display": "",
            "confidence": 0.0,
            "scores": {"string_jaccard": 0.0, "tree_similarity": 0.0, "color_match": 0.0},
            "matched_strings": [],
            "evidence_lines": [],
        },
        "signer_impersonation": {
            "detected": False,
            "rule_id": "CH06-SIGNER-IMPERSONATION",
            "package_name": "",
            "signer_sha256": "",
            "evidence_lines": [],
        },
        "suspect_profile_summary": {
            "string_count": 0,
            "view_node_count": 0,
            "sources": "",
        },
        "critical_visual_cluster": False,
        "visual_impersonation_detected": False,
        "visual_impersonation_institution": "",
        "visual_impersonation_confidence": 0.0,
        "ui_hierarchy_integrated": False,
    }


def safe_run_vide_analysis(
    *,
    decode_dir: Optional[Path] = None,
    suspect_profile: Optional[UIProfile] = None,
    dynamic_result: Optional[Dict[str, Any]] = None,
    package_name: str = "",
    certificate: Optional[Dict[str, Any]] = None,
    baselines: Optional[List[InstitutionBaseline]] = None,
    apktool_available: bool = True,
) -> Dict[str, Any]:
    """Run VIDE; never raise - distinguish UNAVAILABLE / ERROR / OK."""
    has_static = bool(
        suspect_profile
        and (suspect_profile.strings or suspect_profile.view_sequence)
    )
    has_dynamic = bool(
        dynamic_result
        and (
            dynamic_result.get("frida_events")
            or dynamic_result.get("ui_hierarchy_xml")
            or dynamic_result.get("vide_webview_html")
        )
    )
    if not has_static and not has_dynamic and not apktool_available:
        out = _empty_vide_payload(status="UNAVAILABLE", available=False)
        out["vide_compare"]["evidence_lines"] = [
            "VIDE: static UI profile unavailable (apktool missing or failed)"
        ]
        out["signer_impersonation"] = check_signer_impersonation(
            package_name, certificate or {}
        ).to_dict()
        return out

    try:
        result = run_vide_analysis(
            decode_dir=decode_dir,
            suspect_profile=suspect_profile,
            dynamic_result=dynamic_result,
            package_name=package_name,
            certificate=certificate,
            baselines=baselines,
        )
        result["available"] = True
        result["status"] = "OK"
        result["error"] = ""
        result["ui_hierarchy_integrated"] = bool(
            dynamic_result and dynamic_result.get("ui_hierarchy_xml")
        )
        return result
    except Exception as exc:
        logger.warning("[VIDE] run_vide_analysis failed: %s", exc, exc_info=True)
        out = _empty_vide_payload(status="ERROR", available=False, error=str(exc))
        try:
            out["signer_impersonation"] = check_signer_impersonation(
                package_name, certificate or {}
            ).to_dict()
        except Exception:
            pass
        return out


def run_vide_analysis(
    *,
    decode_dir: Optional[Path] = None,
    suspect_profile: Optional[UIProfile] = None,
    dynamic_result: Optional[Dict[str, Any]] = None,
    package_name: str = "",
    certificate: Optional[Dict[str, Any]] = None,
    baselines: Optional[List[InstitutionBaseline]] = None,
) -> Dict[str, Any]:
    """
    Full VIDE pass: build suspect profile, compare to baselines, CH06 signer check.
    """
    bl = baselines if baselines is not None else load_baselines()
    suspect = suspect_profile or UIProfile(source="empty")

    if decode_dir and decode_dir.is_dir():
        static_prof = extract_from_decode_dir(decode_dir)
        suspect = _merge_profiles(suspect, static_prof)
        for html in extract_html_from_assets(decode_dir):
            suspect = _merge_profiles(suspect, profile_from_html(html, "assets_html"))

    if dynamic_result:
        dyn_prof = profile_from_dynamic_result(dynamic_result)
        for html in collect_webview_html_from_frida_events(dynamic_result):
            dyn_prof = _merge_profiles(dyn_prof, profile_from_html(html, "webview_dump"))
        suspect = _merge_profiles(suspect, dyn_prof)

    vide_compare: VIDECompareResult = compare_against_baselines(suspect, bl)
    signer_check: SignerImpersonationResult = check_signer_impersonation(
        package_name, certificate or {}
    )

    # Allowlist: same institution baseline signer → suppress visual FP
    if vide_compare.detected and package_name:
        for bl_entry in bl:
            if bl_entry.institution_id != vide_compare.institution_id:
                continue
            if package_name in bl_entry.package_names:
                signer = extract_signer_sha256(certificate or {})
                allowed = bl_entry.allowed_signers_sha256
                if allowed and signer and signer.lower() in [a.lower() for a in allowed]:
                    vide_compare = VIDECompareResult(
                        rule_id=vide_compare.rule_id,
                        detected=False,
                        evidence_lines=[
                            "VIDE suppressed: package matches allowlisted legitimate app signer"
                        ],
                    )
                break

    cluster_support = bool(
        dynamic_result and dynamic_result.get("has_high_risk_capabilities")
    )
    critical_cluster = (
        vide_compare.detected
        and cluster_support
        and vide_compare.confidence >= 0.80
    )

    return {
        "vide_compare": vide_compare.to_dict(),
        "signer_impersonation": signer_check.to_dict(),
        "suspect_profile_summary": {
            "string_count": len(suspect.strings),
            "view_node_count": len(suspect.view_sequence),
            "sources": suspect.source,
        },
        "critical_visual_cluster": critical_cluster,
        "visual_impersonation_detected": vide_compare.detected,
        "visual_impersonation_institution": vide_compare.institution_display,
        "visual_impersonation_confidence": vide_compare.confidence,
    }
