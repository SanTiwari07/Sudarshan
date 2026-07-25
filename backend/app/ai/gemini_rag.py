# backend/app/ai/gemini_rag.py
"""
Sudarshan Investigation Assistant — Gemini RAG Engine
======================================================
Implements the Evidence-Aware Investigation Assistant for Sudarshan.

Architecture:
  1. Investigation Graph Builder   — indexes all evidence sections per SHA256
  2. Intent Detector               — classifies the question type
  3. Hybrid Retriever              — keyword + section-aware + intent retrieval
  4. Context Builder               — compresses evidence into a focused prompt
  5. Gemini Streamer                — streams structured 7-section response

Design Rules:
  - Gemini NEVER receives raw APK data or full reports
  - Gemini NEVER decides risk — it only explains deterministic engine output
  - Every statement in the response traces back to indexed evidence
  - If evidence is absent, the assistant says so explicitly
"""

from __future__ import annotations

import json
import logging
import os
import re
import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# ─── Investigation Graph (in-memory per SHA256) ───────────────────────────────
# Structure: { sha256: { section_name: [chunk_str, ...] } }
_investigation_index: Dict[str, Dict[str, List[str]]] = {}


# ─── Section Definitions ──────────────────────────────────────────────────────

SECTION_NAMES = [
    "metadata", "manifest", "permissions", "activities", "services",
    "receivers", "components", "static_findings", "dynamic_findings",
    "runtime_events", "timeline", "network", "files", "apis",
    "mitre", "malware_family", "threat_intelligence", "risk_engine",
    "recommendations", "verdict", "fraud_workflow",
]

# Intent → relevant sections mapping
INTENT_SECTION_MAP: Dict[str, List[str]] = {
    "safe":              ["verdict", "risk_engine", "static_findings", "dynamic_findings", "threat_intelligence"],
    "score":             ["risk_engine", "verdict", "static_findings"],
    "otp":               ["dynamic_findings", "runtime_events", "permissions", "static_findings", "threat_intelligence"],
    "sms":               ["dynamic_findings", "runtime_events", "permissions", "static_findings"],
    "accessibility":     ["dynamic_findings", "runtime_events", "static_findings", "permissions"],
    "overlay":           ["dynamic_findings", "runtime_events", "permissions", "static_findings"],
    "permissions":       ["permissions", "static_findings", "manifest"],
    "network":           ["network", "threat_intelligence", "dynamic_findings", "static_findings"],
    "mitre":             ["mitre", "static_findings", "dynamic_findings"],
    "malware":           ["malware_family", "threat_intelligence", "static_findings"],
    "manifest":          ["manifest", "components", "activities", "services", "receivers"],
    "certificate":       ["metadata", "static_findings"],
    "virustotal":        ["threat_intelligence"],
    "dynamic":           ["dynamic_findings", "runtime_events", "timeline", "network", "files"],
    "timeline":          ["timeline", "dynamic_findings", "runtime_events"],
    "recommend":         ["recommendations", "verdict", "risk_engine"],
    "report":            ["verdict", "risk_engine", "static_findings", "dynamic_findings", "threat_intelligence", "mitre", "recommendations"],
    "compare":           ["malware_family", "threat_intelligence", "mitre", "static_findings"],
    "executive":         ["verdict", "risk_engine", "recommendations", "threat_intelligence"],
    "workflow":          ["fraud_workflow", "dynamic_findings", "runtime_events", "timeline"],
    "chain":             ["fraud_workflow", "dynamic_findings", "runtime_events"],
    "sequence":          ["fraud_workflow", "dynamic_findings", "runtime_events"],
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
        f"Package: {report.get('package_name', 'Unknown')}",
        f"App Name: {report.get('app_name', 'Unknown')}",
        f"Analysis Mode: {report.get('analysis_mode', 'Unknown')}",
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
        f"Family Classification: {report.get('family_classification', 'Unknown')}",
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
            f"STEI Axes — CT (Credential Theft): {stei_axes.get('ct', 0):.1f}, "
            f"BT (Banking Targeting): {stei_axes.get('bt', 0):.1f}, "
            f"PR (Permission Risk): {stei_axes.get('pr', 0):.1f}, "
            f"OB (Obfuscation): {stei_axes.get('ob', 0):.1f}, "
            f"IR (Infrastructure Risk): {stei_axes.get('ir', 0):.1f}"
        )

    # Include evidence chain from risk engine
    evidence_chain = report.get("evidence", [])
    for ev in evidence_chain[:10]:
        idx["risk_engine"].append(f"Risk Evidence: {ev}")

    # ── Permissions ───────────────────────────────────────────────────────────
    all_perms = report.get("all_permissions", [])
    idx["permissions"] = [f"Total Permissions: {len(all_perms)}"]

    dangerous_perms = report.get("dangerous_perms", [])
    for perm in dangerous_perms:
        if isinstance(perm, dict):
            idx["permissions"].append(
                f"DANGEROUS: {perm.get('permission', '')} — {perm.get('info', '')} — {perm.get('description', '')}"
            )
        elif isinstance(perm, str):
            idx["permissions"].append(f"DANGEROUS: {perm}")

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
                f"[{finding.get('severity', 'INFO')}] {finding.get('title', '')}: "
                f"{finding.get('description', '')} — Component: {finding.get('component', '')}"
            )

    # ── Activities / Services / Receivers ─────────────────────────────────────
    activities = report.get("activities", [])
    idx["activities"] = [f"Activity: {a}" for a in activities[:20]]
    idx["activities"].append(f"Total Activities: {len(activities)}")

    services = report.get("services_list", [])
    idx["services"] = [f"Service: {s}" for s in services[:20]]
    idx["services"].append(f"Total Services: {len(services)}")

    receivers = report.get("receivers", [])
    idx["receivers"] = [f"Receiver: {r}" for r in receivers[:20]]
    idx["receivers"].append(f"Total Receivers: {len(receivers)}")

    idx["components"] = [
        f"Exported Components — check manifest section for exported=true details",
        f"Activities: {len(activities)}, Services: {len(services)}, Receivers: {len(receivers)}",
    ]

    # ── Static Findings ───────────────────────────────────────────────────────
    idx["static_findings"] = []

    for finding in report.get("code_findings", [])[:15]:
        if isinstance(finding, dict):
            idx["static_findings"].append(
                f"[{finding.get('severity', 'INFO')}] {finding.get('title', '')}: "
                f"{finding.get('description', '')}"
            )

    urls = report.get("hardcoded_urls_ips", [])
    if urls:
        idx["static_findings"].append(f"Hardcoded URLs/IPs ({len(urls)}): {', '.join(urls[:10])}")

    secrets = report.get("hardcoded_secrets", [])
    if secrets:
        idx["static_findings"].append(f"Hardcoded Secrets ({len(secrets)}): {', '.join(secrets[:5])}")

    obf_score = report.get("obfuscation_score", 0)
    idx["static_findings"].append(f"Obfuscation Score: {obf_score:.1f}")
    idx["static_findings"].append(f"Has Reflection: {report.get('has_reflection', False)}")
    idx["static_findings"].append(f"Suspicious Strings count: {len(report.get('suspicious_strings', []))}")
    idx["static_findings"].append(f"AppSec Score (MobSF): {report.get('appsec_score', 'N/A')}")

    # ── APIs ──────────────────────────────────────────────────────────────────
    dangerous_apis = report.get("dangerous_apis_found_raw", [])
    idx["apis"] = [f"Dangerous API: {api}" for api in dangerous_apis[:20]]
    idx["apis"].append(f"Total Dangerous APIs: {len(dangerous_apis)}")

    # ── Dynamic Findings ──────────────────────────────────────────────────────
    dyn = report.get("dynamic_result", {}) or {}
    dyn_available = dyn.get("available", False)

    idx["dynamic_findings"] = [f"Dynamic Analysis Available: {dyn_available}"]

    if dyn_available:
        api_calls = dyn.get("api_calls", [])
        idx["dynamic_findings"].extend([f"Runtime API Call: {c}" for c in api_calls[:15]])
        idx["dynamic_findings"].append(f"Total Runtime API Calls: {len(api_calls)}")

        network_logs = dyn.get("network_logs", [])
        idx["dynamic_findings"].append(f"Network Connections Observed: {len(network_logs)}")
        for net in network_logs[:10]:
            idx["dynamic_findings"].append(f"Network: {net}")

        files = dyn.get("files_accessed", [])
        idx["dynamic_findings"].extend([f"File Accessed: {f}" for f in files[:10]])

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
                    f"  Stage {i}: {stg.get('label', '')} [{stg.get('technique_id', '')}] "
                    f"— {stg.get('description', '')} (confidence={conf:.0%})"
                )
    else:
        idx["fraud_workflow"] = ["No fraud workflow was reconstructed from dynamic evidence."]

    # ── Network ───────────────────────────────────────────────────────────────
    idx["network"] = []
    if urls:
        idx["network"].extend([f"Hardcoded URL/IP: {u}" for u in urls[:15]])
    corr = report.get("threat_correlation", {}) or {}
    suspicious_domains = corr.get("suspicious_domains", [])
    malicious_ips = corr.get("malicious_ips", [])
    if suspicious_domains:
        idx["network"].extend([f"Suspicious Domain (VT): {d}" for d in suspicious_domains[:10]])
    if malicious_ips:
        idx["network"].extend([f"Malicious IP (VT): {ip}" for ip in malicious_ips[:10]])
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
                f"Flagged by: {', '.join(vendors[:5])}"
            )

        known_family = corr.get("known_family")
        if known_family:
            idx["threat_intelligence"].append(f"Known Malware Family (VT): {known_family}")

        campaign = corr.get("campaign")
        if campaign:
            idx["threat_intelligence"].append(f"Campaign Attribution: {campaign}")

        threat_score = corr.get("threat_score", 0)
        idx["threat_intelligence"].append(f"Threat Intelligence Score: {threat_score:.1f}/100")

        ioc_reps = corr.get("ioc_reputation", [])
        for ioc in ioc_reps[:8]:
            if isinstance(ioc, dict):
                idx["threat_intelligence"].append(
                    f"IOC [{ioc.get('type', '')}] {ioc.get('indicator', '')} — "
                    f"Reputation: {ioc.get('reputation', '')} (Source: {ioc.get('source', '')})"
                )
    else:
        idx["threat_intelligence"].append(
            "Threat intelligence correlation was not available or could not be retrieved."
        )

    # ── Malware Family ────────────────────────────────────────────────────────
    family = report.get("family_classification", "Unknown")
    idx["malware_family"] = [
        f"Classified Family: {family}",
        f"Matched Rule: {report.get('matched_rule', 'No rule matched')}",
    ]
    if corr.get("known_family"):
        idx["malware_family"].append(f"VirusTotal Family: {corr.get('known_family')}")
    if family == "Unknown":
        idx["malware_family"].append(
            "No known malware family was matched. The APK does not match any known banking trojan signature."
        )

    # ── MITRE Mapping ─────────────────────────────────────────────────────────
    intel = report.get("intelligence_report", {}) or {}
    mitre_techs = intel.get("mitre_techniques_used", [])
    idx["mitre"] = [f"MITRE Technique: {t}" for t in mitre_techs[:15]]
    if not mitre_techs:
        idx["mitre"] = ["No MITRE ATT&CK for Mobile techniques were mapped for this APK."]

    # ── Recommendations ───────────────────────────────────────────────────────
    recs = intel.get("recommended_actions", [])
    cert_recs = intel.get("cert_in_recommendations", [])
    idx["recommendations"] = [f"Action: {r}" for r in recs[:8]]
    idx["recommendations"].extend([f"CERT-In: {r}" for r in cert_recs[:5]])
    if action:
        idx["recommendations"].append(f"Deterministic Recommendation: {action}")

    # Store index
    _investigation_index[sha256] = idx
    logger.info(
        f"[RAG] Investigation index built for {sha256} — "
        f"{sum(len(v) for v in idx.values())} evidence chunks across {len(idx)} sections"
    )


def is_indexed(sha256: str) -> bool:
    return sha256 in _investigation_index


# ─── 2. Intent Detector ───────────────────────────────────────────────────────

def detect_intent(question: str) -> str:
    """Classify question intent to select relevant evidence sections."""
    q = question.lower()

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
    Never sends entire reports — only retrieved chunks.
    """
    idx = _investigation_index.get(sha256, {})

    # Build context sections
    lines = ["=== INVESTIGATION CONTEXT ==="]
    lines.append(f"Question: {question}")
    lines.append(f"Sections Retrieved: {', '.join(sections_used)}")
    lines.append("")

    # Add retrieved evidence
    lines.append("=== RETRIEVED EVIDENCE ===")
    for chunk in retrieved_chunks:
        lines.append(f"• {chunk}")
    lines.append("")

    # Add conversation context summary (last 3 turns)
    if conversation_history:
        lines.append("=== CONVERSATION HISTORY (last 3 turns) ===")
        for turn in conversation_history[-3:]:
            role = turn.get("role", "user")
            content = turn.get("content", "")[:300]
            lines.append(f"[{role.upper()}]: {content}")
        lines.append("")

    return "\n".join(lines)


# ─── 5. Prompt Builder ────────────────────────────────────────────────────────

SYSTEM_INSTRUCTION = """You are SUDARSHAN — the Sudarshan Banking Investigation Assistant.

You are NOT an AI assistant. You are an evidence-aware banking malware investigator.

YOUR ROLE:
• Explain investigation evidence collected by the Sudarshan platform
• Translate technical findings into clear human language
• Answer questions based ONLY on the evidence provided to you
• NEVER invent, guess, or estimate any information not present in the evidence

YOU ARE NOT:
• The risk scoring engine (deterministic engine already calculated the score)
• The malware classifier (classification was already done)
• A generic AI assistant

CRITICAL RULES:
1. If evidence does not exist, say: "I couldn't find evidence supporting that conclusion in this investigation."
2. NEVER start with "The report indicates...", "Based on the analysis...", "According to..."
3. ALWAYS answer in plain English first, then gradually add technical depth
4. ALWAYS cite which evidence led to each statement
5. NEVER fabricate findings, scores, or detection results

RESPONSE FORMAT (always follow this exact order):

---DIRECT ANSWER---
One or two sentences. Answer immediately and naturally.
Examples: "Yes, this APK appears safe." / "No, this APK shows banking malware behaviour."

---SIMPLE ENGLISH---
Explain in language a bank employee can understand. No jargon. 2-4 sentences.

---WHY---
Short bullet checklist of the key evidence.
Use ✔ for safe/absent findings, ✗ for detected threats.

---DETAILED FINDINGS---
Group evidence by: Static Analysis | Dynamic Analysis | Network Behaviour | Threat Intelligence | MITRE Mapping
For each finding include: what was found, what it means, and the security impact.
Convert all technical data to readable English. Never dump raw JSON.

---CONFIDENCE---
Percentage (e.g., 94%) and one sentence explaining why.

---RECOMMENDATION---
Single clear action: Allow | Monitor | Manual Review | Block APK | Escalate to SOC | Escalate to CERT-In

---SOURCES USED---
List the evidence types that were used to answer this question.

---FOLLOW-UP QUESTIONS---
Generate exactly 4 context-aware follow-up questions. Make them relevant to what was just explained.
Format as a JSON array: ["Q1", "Q2", "Q3", "Q4"]"""


def build_gemini_prompt(
    question: str,
    context: str,
) -> str:
    return f"""{context}

=== ANALYST QUESTION ===
{question}

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

    if not GEMINI_API_KEY:
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

        client = genai.Client(api_key=GEMINI_API_KEY)

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
        yield _sse("sections", json.dumps(sections_used))

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


def _sse(event: str, data: str) -> str:
    """Format a Server-Sent Event."""
    return f"event: {event}\ndata: {data}\n\n"


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

    if not GEMINI_API_KEY:
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

        client = genai.Client(api_key=GEMINI_API_KEY)
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
