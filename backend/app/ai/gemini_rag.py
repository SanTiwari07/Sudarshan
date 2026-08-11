# backend/app/ai/gemini_rag.py
"""
Sudarshan Investigation Assistant - Gemini RAG Engine
======================================================
Implements the Evidence-Aware Investigation Assistant for Sudarshan.

Architecture:
  1. Investigation Graph Builder - indexes all evidence sections per SHA256
  2. Intent Detector - classifies the question type
  3. Hybrid Retriever - keyword + section-aware + intent retrieval
  4. Context Builder - compresses evidence into a focused prompt
  5. Gemini Streamer - streams structured 7-section response

Design Rules:
  - Gemini NEVER receives raw APK data or full reports
  - Gemini NEVER decides risk - it only explains deterministic engine output
  - Every statement in the response traces back to indexed evidence
  - If evidence is absent, the assistant says so explicitly
"""

from __future__ import annotations

import json
import logging
import os
import re
import asyncio
from collections import OrderedDict
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from sudarshan_core.engines.agentic.sanitizer import sanitize, sanitize_block

logger = logging.getLogger(__name__)


def _apk_str(value: Any) -> str:
    """Sanitize one APK-derived field before it is concatenated into chunk text."""
    return sanitize(value)


def _sanitize_chunk_text(text: str) -> str:
    """Sanitize a completed evidence chunk (multi-line safe)."""
    return sanitize_block(text)

def _get_gemini_api_key() -> str:
    key = os.getenv("GEMINI_API_KEY", "")
    if not key:
        try:
            from pathlib import Path
            from dotenv import load_dotenv
            curr = Path(__file__).resolve().parent
            for _ in range(5):
                env_file = curr / ".env"
                if env_file.exists():
                    load_dotenv(dotenv_path=env_file, override=True)
                    key = os.getenv("GEMINI_API_KEY", "")
                    break
                curr = curr.parent
        except Exception:
            pass
    return key

MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# ─── Investigation Graph (in-memory per SHA256) ───────────────────────────────
# Structure: { sha256: { section_name: [chunk_str, ...] } }
#
# BOUNDED (LRU). This grew for the process lifetime - one entry per analysed
# sample, each holding ~20 sections of formatted evidence chunks - with nothing
# ever evicting. An index that falls out is rebuilt on demand from the database
# by the /chat endpoint, so eviction costs a rebuild, not the conversation.
_INDEX_MAX_ENTRIES = int(os.getenv("SUDARSHAN_RAG_INDEX_MAX", "128"))
_investigation_index: "OrderedDict[str, Dict[str, List[str]]]" = OrderedDict()


# ─── Section Definitions ──────────────────────────────────────────────────────

SECTION_NAMES = [
    "metadata", "manifest", "permissions", "activities", "services",
    "receivers", "components", "static_findings", "dynamic_findings",
    "runtime_events", "timeline", "network", "files", "apis",
    "mitre", "malware_family", "threat_intelligence", "risk_engine",
    "recommendations", "verdict", "fraud_workflow", "visual_evidence",
    # MobSF enrichment sections
    "binary_analysis", "crypto_findings", "webview_findings",
    "ssl_findings", "anti_analysis", "secrets", "trackers",
    "exported_components", "network_security",
]

# Intent → relevant sections mapping
INTENT_SECTION_MAP: Dict[str, List[str]] = {
    "safe":              ["verdict", "risk_engine", "static_findings", "dynamic_findings", "threat_intelligence"],
    "score":             ["risk_engine", "verdict", "static_findings"],
    "otp":               ["dynamic_findings", "runtime_events", "permissions", "static_findings", "threat_intelligence"],
    "sms":               ["dynamic_findings", "runtime_events", "permissions", "static_findings"],
    "accessibility":     ["dynamic_findings", "runtime_events", "static_findings", "permissions"],
    "overlay":           ["visual_evidence", "dynamic_findings", "runtime_events", "permissions", "static_findings"],
    "permissions":       ["permissions", "static_findings", "manifest"],
    "network":           ["network", "threat_intelligence", "dynamic_findings", "static_findings", "network_security"],
    "mitre":             ["mitre", "static_findings", "dynamic_findings"],
    "malware":           ["malware_family", "threat_intelligence", "static_findings"],
    "manifest":          ["manifest", "components", "activities", "services", "receivers", "exported_components"],
    "certificate":       ["metadata", "static_findings"],
    "virustotal":        ["threat_intelligence"],
    "dynamic":           ["visual_evidence", "dynamic_findings", "runtime_events", "timeline", "network", "files"],
    "timeline":          ["visual_evidence", "timeline", "dynamic_findings", "runtime_events"],
    "recommend":         ["recommendations", "verdict", "risk_engine"],
    "report":            ["visual_evidence", "verdict", "risk_engine", "static_findings", "dynamic_findings", "threat_intelligence", "mitre", "recommendations"],
    "compare":           ["malware_family", "threat_intelligence", "mitre", "static_findings"],
    "executive":         ["visual_evidence", "verdict", "risk_engine", "recommendations", "threat_intelligence"],
    "workflow":          ["visual_evidence", "fraud_workflow", "dynamic_findings", "runtime_events", "timeline"],
    "chain":             ["fraud_workflow", "dynamic_findings", "runtime_events"],
    "sequence":          ["fraud_workflow", "dynamic_findings", "runtime_events"],
    # New intents for enriched MobSF data
    "crypto":            ["crypto_findings", "static_findings", "ssl_findings"],
    "webview":           ["webview_findings", "static_findings", "network"],
    "ssl":               ["ssl_findings", "network_security", "static_findings", "network"],
    "secrets":           ["secrets", "static_findings", "threat_intelligence"],
    "obfuscation":       ["static_findings", "anti_analysis", "risk_engine"],
    "native":            ["binary_analysis", "static_findings"],
    "sdk":               ["trackers", "static_findings"],
    "exported":          ["exported_components", "manifest", "components"],
    "anti":              ["visual_evidence", "anti_analysis", "static_findings", "dynamic_findings"],
    "visual":            ["visual_evidence", "dynamic_findings", "runtime_events", "fraud_workflow"],
    "default":           ["verdict", "risk_engine", "fraud_workflow", "static_findings", "dynamic_findings", "threat_intelligence"],
}


# ─── 1. Investigation Graph Builder ──────────────────────────────────────────

def build_investigation_index(sha256: str, report: Dict[str, Any]) -> None:
    """
    Chunks all evidence sections from a completed analysis report and indexes
    them in the in-memory investigation graph.

    This should be called immediately after analysis completes.
    """
    idx: Dict[str, List[str]] = {}

    # ── Metadata ──────────────────────────────────────────────────────────────
    idx["metadata"] = [
        f"SHA256: {sha256}",
        f"Package: {_apk_str(report.get('package_name', 'Unknown'))}",
        f"App Name: {_apk_str(report.get('app_name', 'Unknown'))}",
        f"Analysis Mode: {_apk_str(report.get('analysis_mode', 'Unknown'))}",
        f"Certificate: {json.dumps(report.get('certificate', {}))[:300]}",
    ]

    # ── Verdict & Risk Engine ─────────────────────────────────────────────────
    score = report.get("final_risk_score", 0)
    band = report.get("risk_band", "Unknown")
    confidence = report.get("confidence", 70)
    action = report.get("recommended_action", "Manual Review")
    frs = report.get("frs_breakdown", {})

    idx["verdict"] = [
        f"Final Risk Score: {score:.1f}/100",
        f"Risk Band: {band}",
        f"Confidence: {confidence:.0f}%",
        f"Recommended Action: {action}",
        f"Family Classification: {_apk_str(report.get('family_classification', 'Unknown'))}",
    ]

    idx["risk_engine"] = [
        f"FRS Formula: {frs.get('formula_used', 'static_only_frs')}",
        f"STEI Score: {frs.get('stei', 0):.1f}/100",
        f"Dynamic Score: {frs.get('dynamic', 0):.1f}/100",
        f"Correlation Score: {frs.get('correlation', 0):.1f}/100",
        f"Banking Impact Score: {frs.get('banking_impact', 0):.1f}/100",
        f"Dynamic Analysis Available: {frs.get('dynamic_available', False)}",
    ]

    stei_axes = frs.get("stei_axes", {})
    if stei_axes:
        idx["risk_engine"].append(
            f"STEI Axes - CT (Credential Theft): {stei_axes.get('ct', 0):.1f}, "
            f"BT (Banking Targeting): {stei_axes.get('bt', 0):.1f}, "
            f"PR (Permission Risk): {stei_axes.get('pr', 0):.1f}, "
            f"OB (Obfuscation): {stei_axes.get('ob', 0):.1f}, "
            f"IR (Infrastructure Risk): {stei_axes.get('ir', 0):.1f}"
        )

    # Include evidence chain from risk engine
    evidence_chain = report.get("evidence", [])
    for ev in evidence_chain[:10]:
        idx["risk_engine"].append(f"Risk Evidence: {_apk_str(ev)}")

    # ── Permissions ───────────────────────────────────────────────────────────
    all_perms = report.get("all_permissions", [])
    idx["permissions"] = [f"Total Permissions: {len(all_perms)}"]

    dangerous_perms = report.get("dangerous_perms", [])
    for perm in dangerous_perms:
        if isinstance(perm, dict):
            idx["permissions"].append(
                f"DANGEROUS: {_apk_str(perm.get('permission', ''))} - "
                f"{_apk_str(perm.get('info', ''))} - {_apk_str(perm.get('description', ''))}"
            )
        elif isinstance(perm, str):
            idx["permissions"].append(f"DANGEROUS: {_apk_str(perm)}")

    # Key behavioral flags
    idx["permissions"].append(
        f"Accessibility Abuse: {report.get('has_accessibility_abuse', False)}"
    )
    idx["permissions"].append(
        f"SMS Interception: {report.get('has_sms_read_write', False)}"
    )
    idx["permissions"].append(
        f"Overlay Capability: {report.get('has_system_alert_window', False)}"
    )
    idx["permissions"].append(
        f"Targets Indian Banks: {report.get('targets_indian_banks', False)}"
    )

    # ── Manifest ──────────────────────────────────────────────────────────────
    idx["manifest"] = []
    for finding in report.get("manifest_findings", [])[:15]:
        if isinstance(finding, dict):
            idx["manifest"].append(
                f"[{_apk_str(finding.get('severity', 'INFO'))}] {_apk_str(finding.get('title', ''))}: "
                f"{_apk_str(finding.get('description', ''))} - Component: {_apk_str(finding.get('component', ''))}"
            )

    # ── Activities / Services / Receivers ─────────────────────────────────────
    activities = report.get("activities", [])
    idx["activities"] = [f"Activity: {_apk_str(a)}" for a in activities[:20]]
    idx["activities"].append(f"Total Activities: {len(activities)}")

    services = report.get("services_list", [])
    idx["services"] = [f"Service: {_apk_str(s)}" for s in services[:20]]
    idx["services"].append(f"Total Services: {len(services)}")

    receivers = report.get("receivers", [])
    idx["receivers"] = [f"Receiver: {_apk_str(r)}" for r in receivers[:20]]
    idx["receivers"].append(f"Total Receivers: {len(receivers)}")

    idx["components"] = [
        f"Exported Components - check manifest section for exported=true details",
        f"Activities: {len(activities)}, Services: {len(services)}, Receivers: {len(receivers)}",
    ]

    # ── Static Findings ───────────────────────────────────────────────────────
    idx["static_findings"] = []

    for finding in report.get("code_findings", [])[:15]:
        if isinstance(finding, dict):
            idx["static_findings"].append(
                f"[{_apk_str(finding.get('severity', 'INFO'))}] {_apk_str(finding.get('title', ''))}: "
                f"{_apk_str(finding.get('description', ''))}"
            )

    urls = report.get("hardcoded_urls_ips", [])
    if urls:
        idx["static_findings"].append(
            f"Hardcoded URLs/IPs ({len(urls)}): {', '.join(_apk_str(u) for u in urls[:10])}"
        )

    secrets = report.get("hardcoded_secrets", [])
    if secrets:
        idx["static_findings"].append(
            f"Hardcoded Secrets ({len(secrets)}): {', '.join(_apk_str(s) for s in secrets[:5])}"
        )

    obf_score = report.get("obfuscation_score", 0)
    idx["static_findings"].append(f"Obfuscation Score: {obf_score:.1f}")
    idx["static_findings"].append(f"Has Reflection: {report.get('has_reflection', False)}")
    idx["static_findings"].append(f"Suspicious Strings count: {len(report.get('suspicious_strings', []))}")
    idx["static_findings"].append(f"AppSec Score (MobSF): {report.get('appsec_score', 'N/A')}")

    # ── APIs ──────────────────────────────────────────────────────────────────
    dangerous_apis = report.get("dangerous_apis_found_raw", [])
    idx["apis"] = [f"Dangerous API: {_apk_str(api)}" for api in dangerous_apis[:20]]
    idx["apis"].append(f"Total Dangerous APIs: {len(dangerous_apis)}")

    # ── Dynamic Findings ──────────────────────────────────────────────────────
    dyn = report.get("dynamic_result", {}) or {}
    dyn_available = dyn.get("available", False)

    idx["dynamic_findings"] = [f"Dynamic Analysis Available: {dyn_available}"]

    if dyn_available:
        api_calls = dyn.get("api_calls", [])
        idx["dynamic_findings"].extend([f"Runtime API Call: {_apk_str(c)}" for c in api_calls[:15]])
        idx["dynamic_findings"].append(f"Total Runtime API Calls: {len(api_calls)}")

        network_logs = dyn.get("network_logs", [])
        idx["dynamic_findings"].append(f"Network Connections Observed: {len(network_logs)}")
        for net in network_logs[:10]:
            idx["dynamic_findings"].append(f"Network: {_apk_str(net)}")

        files = dyn.get("files_accessed", [])
        idx["dynamic_findings"].extend([f"File Accessed: {_apk_str(f)}" for f in files[:10]])

        # YARA matches
        yara = dyn.get("yara_matches", [])
        if yara:
            idx["dynamic_findings"].append(f"YARA Matches: {json.dumps(yara[:5])}")

        # Anti-analysis events
        anti = dyn.get("anti_analysis_events", [])
        if anti:
            idx["dynamic_findings"].append(f"Anti-Analysis Events: {json.dumps(anti[:5])}")

    # ── Runtime Events & Timeline ─────────────────────────────────────────────
    if dyn_available:
        timeline = dyn.get("attack_timeline", [])
        idx["timeline"] = [f"Timeline Event: {json.dumps(ev)[:200]}" for ev in timeline[:20]]
        idx["timeline"].append(f"Total Timeline Events: {len(timeline)}")

        idx["runtime_events"] = [
            f"Activities Triggered: {', '.join(dyn.get('activities_triggered', [])[:10])}",
            f"Logcat Lines: {len(dyn.get('logcat', '').splitlines())}",
        ]

        coverage = dyn.get("coverage_metrics", {})
        if coverage:
            idx["runtime_events"].append(f"Coverage Metrics: {json.dumps(coverage)[:300]}")

        multi_stage = dyn.get("multi_stage_summary", {})
        if multi_stage:
            idx["runtime_events"].append(f"Multi-stage Analysis: {json.dumps(multi_stage)[:300]}")
    else:
        idx["timeline"] = ["Dynamic analysis was not performed for this APK."]
        idx["runtime_events"] = ["Dynamic analysis was not performed for this APK."]

    # ── Fraud Workflow ────────────────────────────────────────────────────────
    workflow = report.get("fraud_workflow") or (dyn.get("fraud_workflow") if dyn_available and isinstance(dyn, dict) else None)
    idx["fraud_workflow"] = []
    if workflow and isinstance(workflow, dict) and workflow.get("stages"):
        seq_label = workflow.get("sequence_label", "NONE")
        chain_conf = workflow.get("chain_confidence", 0.0)
        stages = workflow.get("stages", [])
        idx["fraud_workflow"].append(
            f"Fraud Sequence Detected: {workflow.get('fraud_sequence_detected', False)}"
        )
        idx["fraud_workflow"].append(
            f"Sequence Label: {seq_label} (Chain Confidence: {chain_conf:.0%})"
        )
        idx["fraud_workflow"].append(f"Workflow Stage Count: {len(stages)}")
        for i, stg in enumerate(stages, 1):
            if isinstance(stg, dict):
                conf = stg.get('confidence', 0.0)
                idx["fraud_workflow"].append(
                    f"  Stage {i}: {_apk_str(stg.get('label', ''))} [{_apk_str(stg.get('technique_id', ''))}] "
                    f" - {_apk_str(stg.get('description', ''))} (confidence={conf:.0%})"
                )
    else:
        idx["fraud_workflow"] = ["No fraud workflow was reconstructed from dynamic evidence."]

    # ── Visual investigation evidence (deterministic VER artifact) ─────────────
    idx["visual_evidence"] = []
    try:
        from app.artifact_resolve import resolve_artifact_dir
        from sudarshan_core.visual_evidence.api_merge import load_visual_evidence_records

        art_dir = resolve_artifact_dir(report, sha256=sha256)
        for ver in load_visual_evidence_records(art_dir):
            sid = ver.get("screenshot_id", "")
            claim = ver.get("investigative_claim", "")
            idx["visual_evidence"].append(
                f"{_apk_str(sid)}\n"
                f"Claim: {_apk_str(claim)}\n"
                f"Quality: {_apk_str(ver.get('quality', ''))}\n"
                f"Correlation: {_apk_str(ver.get('correlation_status', ''))}\n"
                f"Evidence: {', '.join(_apk_str(x) for x in (ver.get('linked_evidence_ids') or []))}\n"
                f"Finding: {', '.join(_apk_str(x) for x in (ver.get('linked_finding_keys') or []))}\n"
                f"Workflow: {_apk_str(ver.get('workflow_stage_label', ''))}\n"
                f"Timestamp_ms: {ver.get('timestamp_ms', '')}"
            )
    except Exception as exc:
        logger.debug("[RAG] visual_evidence index skip: %s", exc)
    if not idx["visual_evidence"]:
        idx["visual_evidence"] = ["No visual_evidence.json artifact indexed for this case."]

    # ── Network ───────────────────────────────────────────────────────────────
    idx["network"] = []
    if urls:
        idx["network"].extend([f"Hardcoded URL/IP: {_apk_str(u)}" for u in urls[:15]])
    corr = report.get("threat_correlation", {}) or {}
    suspicious_domains = corr.get("suspicious_domains", [])
    malicious_ips = corr.get("malicious_ips", [])
    if suspicious_domains:
        idx["network"].extend([f"Suspicious Domain (VT): {_apk_str(d)}" for d in suspicious_domains[:10]])
    if malicious_ips:
        idx["network"].extend([f"Malicious IP (VT): {_apk_str(ip)}" for ip in malicious_ips[:10]])
    if not idx["network"]:
        idx["network"] = ["No suspicious network indicators found."]

    # ── Threat Intelligence ───────────────────────────────────────────────────
    corr = report.get("threat_correlation", {}) or {}
    idx["threat_intelligence"] = []

    if corr.get("available"):
        vt_ratio = corr.get("vt_detection_ratio", 0)
        vt_detections = corr.get("sha256_detections", 0)
        vt_total = corr.get("sha256_total", 0)
        idx["threat_intelligence"].append(
            f"VirusTotal: {vt_detections}/{vt_total} engines flagged this APK "
            f"({vt_ratio:.0%} detection rate)"
        )
        vendors = corr.get("vt_malicious_vendors", [])
        if vendors:
            idx["threat_intelligence"].append(
                f"Flagged by: {', '.join(_apk_str(v) for v in vendors[:5])}"
            )

        known_family = corr.get("known_family")
        if known_family:
            idx["threat_intelligence"].append(f"Known Malware Family (VT): {_apk_str(known_family)}")

        campaign = corr.get("campaign")
        if campaign:
            idx["threat_intelligence"].append(f"Campaign Attribution: {_apk_str(campaign)}")

        threat_score = corr.get("threat_score", 0)
        idx["threat_intelligence"].append(f"Threat Intelligence Score: {threat_score:.1f}/100")

        ioc_reps = corr.get("ioc_reputation", [])
        for ioc in ioc_reps[:8]:
            if isinstance(ioc, dict):
                idx["threat_intelligence"].append(
                    f"IOC [{_apk_str(ioc.get('type', ''))}] {_apk_str(ioc.get('indicator', ''))} - "
                    f"Reputation: {_apk_str(ioc.get('reputation', ''))} (Source: {_apk_str(ioc.get('source', ''))})"
                )
    else:
        idx["threat_intelligence"].append(
            "Threat intelligence correlation was not available or could not be retrieved."
        )

    # ── Malware Family ────────────────────────────────────────────────────────
    family = report.get("family_classification", "Unknown")
    idx["malware_family"] = [
        f"Classified Family: {_apk_str(family)}",
        f"Matched Rule: {_apk_str(report.get('matched_rule', 'No rule matched'))}",
    ]
    if corr.get("known_family"):
        idx["malware_family"].append(f"VirusTotal Family: {_apk_str(corr.get('known_family'))}")
    if family == "Unknown":
        idx["malware_family"].append(
            "No known malware family was matched. The APK does not match any known banking trojan signature."
        )

    # ── MITRE Mapping ─────────────────────────────────────────────────────────
    intel = report.get("intelligence_report", {}) or {}
    mitre_techs = intel.get("mitre_techniques_used", [])
    idx["mitre"] = [f"MITRE Technique: {_apk_str(t)}" for t in mitre_techs[:15]]
    if not mitre_techs:
        idx["mitre"] = ["No MITRE ATT&CK for Mobile techniques were mapped for this APK."]

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = intel.get("recommended_actions", [])
    cert_recs = intel.get("cert_in_recommendations", [])
    idx["recommendations"] = [f"Action: {_apk_str(r)}" for r in recs[:8]]
    idx["recommendations"].extend([f"CERT-In: {_apk_str(r)}" for r in cert_recs[:5]])
    if action:
        idx["recommendations"].append(f"Deterministic Recommendation: {action}")

    # ── Exported Components ───────────────────────────────────────────────────
    exported_acts = report.get("exported_activities", [])
    exported_svcs = report.get("exported_services", [])
    exported_rcvs = report.get("exported_receivers", [])
    idx["exported_components"] = []
    for a in exported_acts[:20]:
        idx["exported_components"].append(f"Exported Activity: {_apk_str(a)}")
    for s in exported_svcs[:10]:
        idx["exported_components"].append(f"Exported Service: {_apk_str(s)}")
    for r_ in exported_rcvs[:10]:
        idx["exported_components"].append(f"Exported Receiver: {_apk_str(r_)}")
    if not idx["exported_components"]:
        idx["exported_components"] = ["No exported components detected in this APK."]

    # ── Binary Analysis (native SO security) ──────────────────────────────────
    bin_analysis = report.get("binary_analysis", [])
    idx["binary_analysis"] = []
    for so in bin_analysis[:15]:
        if isinstance(so, dict):
            name = so.get("name", "unknown.so")
            flags = []
            if so.get("nx") == "True":  flags.append("NX=enabled")
            elif so.get("nx"):          flags.append(f"NX={so['nx']}")
            if so.get("stack_canary") == "True":  flags.append("StackCanary=enabled")
            elif so.get("stack_canary"): flags.append(f"StackCanary={so['stack_canary']}")
            if so.get("relro"):         flags.append(f"RELRO={so['relro']}")
            if so.get("rpath") not in (None, "False", ""):
                flags.append(f"RPATH={so['rpath']} (dangerous)")
            idx["binary_analysis"].append(
                f"Native Library: {_apk_str(name)} - {', '.join(flags) if flags else 'no security flags'}"
            )
    if not idx["binary_analysis"]:
        idx["binary_analysis"] = ["No native binary analysis data available (MobSF mode required)."]

    # ── Code Findings - categorized by topic ──────────────────────────────────
    all_code_findings = report.get("code_findings", [])
    # We need the raw dicts for categorization - handle both ManifestFinding objs and dicts
    code_finding_dicts = []
    for f_ in all_code_findings:
        if isinstance(f_, dict):
            code_finding_dicts.append(f_)
        elif hasattr(f_, "model_dump"):
            code_finding_dicts.append(f_.model_dump())
        elif hasattr(f_, "dict"):
            code_finding_dicts.append(f_.dict())

    _CRYPTO_KEYWORDS = {"crypto", "cipher", "des", "md5", "sha1", "ecb", "aes", "rsa", "rc4",
                        "weakkey", "hardcoded_key", "encryption", "digest", "random", "prng"}
    _WEBVIEW_KEYWORDS = {"webview", "javascript", "addjavascriptinterface", "loadurl",
                         "evaluatejavascript", "setjavascrip", "allowfileaccess"}
    _SSL_KEYWORDS = {"ssl", "tls", "trustmanager", "hostname", "pinning", "hostnamevalidator",
                     "x509", "certificate", "cleartext", "http_"}
    _ANTI_KEYWORDS = {"root", "debug", "frida", "emulator", "hooking", "antidebug",
                      "isdebugg", "systemproperties", "buildtags", "emulat", "genymotion"}

    idx["crypto_findings"] = []
    idx["webview_findings"] = []
    idx["ssl_findings"] = []
    idx["anti_analysis"] = []

    for f_ in code_finding_dicts:
        title_lower = (f_.get("title", "") + " " + f_.get("description", "")).lower()
        rule_id_lower = f_.get("rule_id", "").lower()
        combined = title_lower + " " + rule_id_lower
        sev = f_.get("severity", "info")
        masvs = f_.get("masvs", "")
        cwe = f_.get("cwe", "")
        owasp = f_.get("owasp", "")
        line = (f"[{sev.upper()}] {_apk_str(f_.get('title', 'Unknown finding'))}"
                f"{' (MASVS: ' + _apk_str(masvs) + ')' if masvs else ''}"
                f"{' (CWE: ' + _apk_str(cwe) + ')' if cwe else ''}"
                f"{' (OWASP: ' + _apk_str(owasp) + ')' if owasp else ''}")
        if any(k in combined for k in _CRYPTO_KEYWORDS):
            idx["crypto_findings"].append(f"Crypto: {line}")
        if any(k in combined for k in _WEBVIEW_KEYWORDS):
            idx["webview_findings"].append(f"WebView: {line}")
        if any(k in combined for k in _SSL_KEYWORDS):
            idx["ssl_findings"].append(f"SSL/TLS: {line}")
        if any(k in combined for k in _ANTI_KEYWORDS):
            idx["anti_analysis"].append(f"Anti-Analysis: {line}")

    if not idx["crypto_findings"]:
        idx["crypto_findings"] = ["No specific cryptographic weaknesses were identified in static code findings."]
    if not idx["webview_findings"]:
        idx["webview_findings"] = ["No WebView security issues were identified in static code findings."]
    if not idx["ssl_findings"]:
        idx["ssl_findings"] = ["No SSL/TLS weaknesses were identified in static code findings."]
    if not idx["anti_analysis"]:
        idx["anti_analysis"] = ["No anti-analysis techniques were identified in static code findings."]

    # ── Secrets ───────────────────────────────────────────────────────────────
    secrets_list = report.get("hardcoded_secrets", [])
    idx["secrets"] = [f"Hardcoded Secret: {_apk_str(s)[:120]}" for s in secrets_list[:30]]
    if not idx["secrets"]:
        idx["secrets"] = ["No hardcoded secrets were detected."]
    idx["secrets"].append(f"Total hardcoded secrets found: {len(secrets_list)}")

    # ── Trackers / Third-party SDKs ───────────────────────────────────────────
    trackers = report.get("trackers", [])
    idx["trackers"] = []
    for t in trackers[:20]:
        if isinstance(t, dict):
            cats = ", ".join(t.get("categories", [])) if t.get("categories") else "Unknown category"
            idx["trackers"].append(
                f"Third-party SDK/Tracker: {_apk_str(t.get('name', 'Unknown'))} - {cats}"
            )
    if not idx["trackers"]:
        idx["trackers"] = ["No third-party tracker fingerprints detected (requires MobSF analysis mode)."]
    idx["trackers"].append(f"Total SDKs/trackers detected: {len(trackers)}")

    # ── Network Security Config ───────────────────────────────────────────────
    netsec = report.get("network_security", {}) or {}
    idx["network_security"] = []
    if netsec:
        # MobSF network_security can have cleartext_traffic, certificate_pinning, trust_anchors
        for key, val in netsec.items():
            if isinstance(val, (str, bool, int)):
                idx["network_security"].append(f"NSC {key.replace('_', ' ').title()}: {val}")
            elif isinstance(val, list) and val:
                idx["network_security"].append(f"NSC {key}: {', '.join(str(v) for v in val[:5])}")
            elif isinstance(val, dict):
                idx["network_security"].append(f"NSC {key}: {json.dumps(val)[:200]}")
    if not idx["network_security"]:
        idx["network_security"] = ["Network Security Config data not available for this APK."]

    for section_name, chunks in idx.items():
        idx[section_name] = [_sanitize_chunk_text(c) for c in chunks]



    # Store index (LRU-bounded)
    if sha256 in _investigation_index:
        _investigation_index.move_to_end(sha256)
    _investigation_index[sha256] = idx
    while len(_investigation_index) > _INDEX_MAX_ENTRIES:
        evicted, _ = _investigation_index.popitem(last=False)
        logger.debug(f"[RAG] Evicted investigation index for {evicted[:12]}…")
    logger.info(
        f"[RAG] Investigation index built for {sha256} - "
        f"{sum(len(v) for v in idx.values())} evidence chunks across {len(idx)} sections"
    )


def is_indexed(sha256: str) -> bool:
    return sha256 in _investigation_index


# ─── 2. Intent Detector ───────────────────────────────────────────────────────

def detect_intent(question: str) -> str:
    """Classify question intent to select relevant evidence sections."""
    q = question.lower()

    if any(w in q for w in ["screenshot", "scr-", "visual evidence", "what was visible", "what did the screen"]):
        return "visual"
    if any(w in q for w in ["otp", "sms", "message", "intercept", "read_sms"]):
        return "otp"
    if any(w in q for w in ["accessibility", "a11y", "screen control", "tap inject"]):
        return "accessibility"
    if any(w in q for w in ["overlay", "fake screen", "phishing", "system_alert"]):
        return "overlay"
    if any(w in q for w in ["safe", "why safe", "benign", "clean", "not malicious"]):
        return "safe"
    if any(w in q for w in ["score", "risk", "points", "rating", "why high", "why low", "what increased"]):
        return "score"
    if any(w in q for w in ["permission", "perm", "dangerous perm"]):
        return "permissions"
    if any(w in q for w in ["network", "url", "ip", "domain", "connect", "c2", "server"]):
        return "network"
    if any(w in q for w in ["mitre", "att&ck", "technique", "tactic"]):
        return "mitre"
    if any(w in q for w in ["malware", "family", "trojan", "banker", "teabot", "drinik", "cerberus", "anubis"]):
        return "malware"
    if any(w in q for w in ["manifest", "component", "activity", "service", "receiver", "exported"]):
        return "manifest"
    if any(w in q for w in ["certificate", "signing", "signer"]):
        return "certificate"
    if any(w in q for w in ["virustotal", "vt", "threat intel", "ioc", "hash"]):
        return "virustotal"
    if any(w in q for w in ["dynamic", "runtime", "frida", "sandbox", "behaviour", "behavior"]):
        return "dynamic"
    if any(w in q for w in ["timeline", "sequence", "attack chain", "stages"]):
        return "timeline"
    if any(w in q for w in ["block", "action", "recommend", "should i", "deploy", "allow"]):
        return "recommend"
    if any(w in q for w in ["report", "rbi", "cert-in", "soc report", "generate", "summary", "executive", "ciso"]):
        return "report"
    if any(w in q for w in ["compare", "similar", "like teabot", "against"]):
        return "compare"
    if any(w in q for w in ["executive", "non-technical", "customer", "bank employee", "manager"]):
        return "executive"
    # New intents for enriched MobSF data
    if any(w in q for w in ["crypto", "encryption", "weak algo", "des", "md5", "sha1", "ecb", "aes", "hardcoded key", "hardcoded secret"]):
        return "crypto"
    if any(w in q for w in ["webview", "javascript interface", "addjavascriptinterface", "loadurl", "evaluatejavascript"]):
        return "webview"
    if any(w in q for w in ["ssl", "tls", "trustmanager", "hostnamevalidator", "pinning", "certificate pinning", "cleartext"]):
        return "ssl"
    if any(w in q for w in ["secret", "token", "api key", "password", "credential", "firebase", "jwt"]):
        return "secrets"
    if any(w in q for w in ["sdk", "tracker", "analytics", "facebook", "appsflyer", "crashlytics", "onesignal", "third party"]):
        return "sdk"
    if any(w in q for w in ["native", "so file", "jni", "loadlibrary", "binary", "nx bit", "canary", "relro"]):
        return "native"
    if any(w in q for w in ["anti-debug", "anti-root", "anti-frida", "anti-vm", "anti-emulator", "anti analysis", "evasion", "detection"]):
        return "anti"
    if any(w in q for w in ["exported", "attack surface", "exposed component"]):
        return "exported"

    return "default"


# ─── 3. Hybrid Retriever ──────────────────────────────────────────────────────

def _score_chunk(chunk: str, keywords: List[str]) -> float:
    """BM25-style keyword scoring for a single chunk."""
    score = 0.0
    chunk_lower = chunk.lower()
    for kw in keywords:
        count = chunk_lower.count(kw.lower())
        if count > 0:
            score += 1.0 + (count - 1) * 0.25  # IDF-like diminishing returns
    return score


def retrieve_evidence(
    sha256: str,
    question: str,
    top_k: int = 10,
) -> Tuple[List[str], List[str]]:
    """
    Retrieve the most relevant evidence chunks for a question.

    Returns:
        (chunks, sections_used)
    """
    if sha256 not in _investigation_index:
        return ["No investigation data found for this SHA256. Please analyze the APK first."], []

    _investigation_index.move_to_end(sha256)
    idx = _investigation_index[sha256]
    intent = detect_intent(question)
    target_sections = INTENT_SECTION_MAP.get(intent, INTENT_SECTION_MAP["default"])

    # Extract keywords from the question
    stop_words = {"the", "a", "an", "is", "are", "was", "this", "that", "it", "in", "of",
                  "for", "to", "with", "and", "or", "did", "does", "do", "why", "how",
                  "what", "which", "show", "me", "explain", "tell", "about", "any"}
    keywords = [w for w in re.findall(r'\w+', question.lower()) if w not in stop_words and len(w) > 2]

    # Score all chunks in target sections
    scored_chunks: List[Tuple[float, str, str]] = []  # (score, section, chunk)

    for section in target_sections:
        chunks = idx.get(section, [])
        for chunk in chunks:
            kw_score = _score_chunk(chunk, keywords)
            # Boost score for being in a priority section
            section_boost = 1.5 if section in target_sections[:3] else 1.0
            scored_chunks.append((kw_score * section_boost + 0.1, section, chunk))

    # Sort by score descending
    scored_chunks.sort(key=lambda x: x[0], reverse=True)

    # Deduplicate and pick top_k
    seen: set = set()
    result_chunks: List[str] = []
    sections_used: List[str] = []

    for score, section, chunk in scored_chunks:
        if chunk not in seen and len(result_chunks) < top_k:
            seen.add(chunk)
            result_chunks.append(chunk)
            if section not in sections_used:
                sections_used.append(section)

    # Always include verdict and score as anchor context
    anchor_chunks = idx.get("verdict", [])[:3]
    for c in anchor_chunks:
        if c not in seen:
            result_chunks.insert(0, c)
            seen.add(c)

    return result_chunks[:top_k + 3], sections_used


# ─── 4. Context Builder ───────────────────────────────────────────────────────

def build_investigation_context(
    sha256: str,
    question: str,
    retrieved_chunks: List[str],
    sections_used: List[str],
    conversation_history: List[Dict[str, str]],
) -> str:
    """
    Build a structured investigation context string for the Gemini prompt.
    Never sends entire reports - only retrieved chunks.
    """
    idx = _investigation_index.get(sha256, {})

    # Build context sections
    lines = ["=== INVESTIGATION CONTEXT ==="]
    lines.append(f"Question: {sanitize(question)}")
    lines.append(f"Sections Retrieved: {', '.join(sections_used)}")
    lines.append("")

    # Add retrieved evidence
    lines.append("=== RETRIEVED EVIDENCE ===")
    for chunk in retrieved_chunks:
        lines.append(f"• {chunk}")
    lines.append("")

    # Add conversation context summary (last 2 turns)
    if conversation_history:
        lines.append("=== CONVERSATION HISTORY (last 2 turns) ===")
        for turn in conversation_history[-2:]:
            role = turn.get("role", "user")
            raw_content = turn.get("content", "").strip()
            # Clean up UI cards and section markers from turn history
            clean_content = re.sub(r'__PACKAGE_CARD__:[^_]+__', '', raw_content)
            clean_content = re.sub(r'__RISK_CARD__:[^_]+__', '', clean_content)
            clean_content = re.sub(r'---[A-Z\s]+---', '', clean_content)
            clean_content = re.sub(r'###\s+[^\n]+', '', clean_content).strip()
            if clean_content:
                lines.append(f"[{role.upper()}]: {clean_content[:250]}")
        lines.append("")

    return "\n".join(lines)


# ─── 5. Prompt Builder ────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """You are SUDARSHAN - the Sudarshan Banking Threat Intelligence Assistant.

YOUR ROLE:
• Explain mobile malware and fraud investigation evidence collected by the Sudarshan platform
• Translate low-level static decompilation, dynamic Frida traces, and network logs into clear human language
• Answer questions based ONLY on the evidence provided to you
• NEVER invent, guess, or estimate any information not present in the evidence

YOU ARE NOT:
• The risk scoring engine (the deterministic engine has already computed all scores)
• The malware classifier (family classification is already established)
• A generic AI chat bot

CRITICAL FORMATTING & SPACING RULES:
1. Use clear Markdown headings (###), bullet points (*), and paragraph spacing (\n\n) between all sections.
2. EVERY section must be separated by double line breaks (\n\n) so the output is easy for users to read.
3. Use bullet points (*) with bold labels (**Label**) for all evidence items and lists.
4. NEVER dump raw unformatted text blocks or single run-on paragraphs without line breaks.
5. If evidence is absent, state: "I couldn't find evidence supporting that conclusion in this investigation."

REQUIRED RESPONSE FORMAT:

### Direct Answer
[Provide a clear, 1-2 sentence direct answer immediately.]

### Executive Summary
[Explain in plain, clear English for bank staff. Use proper paragraph spacing.]

### Key Decision Evidence
* **Evidence Factor 1**: Description
* **Evidence Factor 2**: Description

### Detailed Investigation Findings
* **Static Analysis**: Decompiled APK findings
* **Dynamic Analysis**: Frida runtime telemetry & behavioral hooks
* **Network & C2**: Intercepted HTTP/HTTPS traffic & IPs
* **Threat Intelligence**: VirusTotal / OTX / AbuseIPDB correlation

### Confidence Score
**Confidence**: 95% - High confidence based on verified static & dynamic findings.

### Recommended Action
**Action**: [Allow / Monitor / Manual Review / Block APK / Escalate to SOC / Escalate to CERT-In]

### Suggested Follow-up Questions
* What are the specific permissions requested by this APK?
* Did dynamic analysis detect any SMS or OTP interception?
* What C2 infrastructure or IPs were identified?
* What steps should the fraud operations team take next?
"""


def build_gemini_prompt(
    question: str,
    context: str,
) -> str:
    safe_question = sanitize(question)
    return f"""{context}

=== ANALYST QUESTION ===
{safe_question}

Answer following the exact 7-section format specified in your instructions.
Base your answer ONLY on the evidence provided in the INVESTIGATION CONTEXT above.
If the evidence is insufficient to answer a specific part, say so explicitly.
"""


# ─── 6. Gemini Streaming Client ───────────────────────────────────────────────

async def stream_investigation_response(
    sha256: str,
    question: str,
    conversation_history: Optional[List[Dict[str, str]]] = None,
) -> AsyncGenerator[str, None]:
    """
    Main entry point. Retrieves evidence and streams a Gemini response.
    Yields SSE-formatted data chunks.
    """
    if conversation_history is None:
        conversation_history = []

    api_key = _get_gemini_api_key()
    if not api_key:
        yield _sse("error", "Gemini API key not configured. Set GEMINI_API_KEY in .env")
        return

    # Ensure investigation is indexed
    if not is_indexed(sha256):
        yield _sse("error", f"No investigation data found for SHA256: {sha256}. Please analyze the APK first.")
        return

    # Retrieve evidence
    chunks, sections_used = retrieve_evidence(sha256, question, top_k=12)

    # Build context
    context = build_investigation_context(
        sha256=sha256,
        question=question,
        retrieved_chunks=chunks,
        sections_used=sections_used,
        conversation_history=conversation_history,
    )

    # Build prompt
    prompt = build_gemini_prompt(question, context)

    # Stream from Gemini
    try:
        import google.genai as genai

        client = genai.Client(api_key=api_key)

        response = client.models.generate_content_stream(
            model=MODEL_NAME,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=0.2,
                max_output_tokens=3000,
            ),
        )

        # Emit sections_used metadata first
        yield _sse("sections", sections_used)

        # Stream tokens
        for chunk in response:
            if chunk.text:
                yield _sse("token", chunk.text)
            await asyncio.sleep(0)

        yield _sse("done", "")

    except ImportError:
        yield _sse("error", "google-genai package not installed. Run: pip install google-genai")
    except Exception as e:
        logger.error(f"[RAG] Gemini stream error: {e}")
        yield _sse("error", f"AI service error: {str(e)[:200]}")


def _sse(event: str, data: Any) -> str:
    """Format a Server-Sent Event with clean JSON data payload."""
    payload = json.dumps(data)
    return f"event: {event}\ndata: {payload}\n\n"


# ─── Synchronous (non-streaming) fallback ────────────────────────────────────

async def get_investigation_answer(
    sha256: str,
    question: str,
    conversation_history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Non-streaming version. Returns complete answer as a dict.
    Used by the legacy /chat endpoint.
    """
    if conversation_history is None:
        conversation_history = []

    api_key = _get_gemini_api_key()
    if not api_key:
        return {
            "answer": "Gemini API key not configured. Set GEMINI_API_KEY in .env",
            "sections_used": [],
            "source": "error",
        }

    if not is_indexed(sha256):
        return {
            "answer": "No investigation data found for this APK. Please analyze it first.",
            "sections_used": [],
            "source": "not_indexed",
        }

    chunks, sections_used = retrieve_evidence(sha256, question, top_k=12)
    context = build_investigation_context(
        sha256=sha256,
        question=question,
        retrieved_chunks=chunks,
        sections_used=sections_used,
        conversation_history=conversation_history,
    )
    prompt = build_gemini_prompt(question, context)

    try:
        import google.genai as genai

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=0.2,
                max_output_tokens=3000,
            ),
        )
        answer = response.text or "No response generated."
        return {
            "answer": answer,
            "sections_used": sections_used,
            "source": "gemini_rag",
        }
    except Exception as e:
        logger.error(f"[RAG] Gemini error: {e}")
        return {
            "answer": f"AI service temporarily unavailable. Error: {str(e)[:100]}",
            "sections_used": sections_used,
            "source": "error",
        }
