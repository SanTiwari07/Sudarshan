# backend/app/rag/knowledge_base.py
"""
Sudarshan Banking Intelligence RAG Engine
==========================================
Retrieval-Augmented Generation layer for evidence-grounded AI responses.

Provides relevant context from:
 - MITRE ATT&CK for Mobile
 - RBI Master Directions
 - CERT-In Advisories
 - NPCI Security Guidelines
 - Known Indian Banking Malware Families

Works in two modes:
  1. ChromaDB mode - full semantic similarity search (requires pip install chromadb)
  2. Static mode - keyword-based lookup (zero-dependency fallback)
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Data Paths ────────────────────────────────────────────────────────────────

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_MITRE_PATH = os.path.join(_DATA_DIR, "mitre_mobile.json")
_BANKING_PATH = os.path.join(_DATA_DIR, "banking_context.json")
_FAMILIES_PATH = os.path.join(_DATA_DIR, "malware_families.json")

# ─── Load Corpus ───────────────────────────────────────────────────────────────

def _load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {path}: {e}")
        return None

_MITRE_DATA: Optional[List[Dict]] = _load_json(_MITRE_PATH)
_BANKING_DATA: Optional[Dict] = _load_json(_BANKING_PATH)
_FAMILIES_DATA: Optional[Dict] = _load_json(_FAMILIES_PATH)

# ─── Static Retrieval Functions ─────────────────────────────────────────────────

def get_mitre_techniques_for_flags(flags: Dict[str, Any]) -> List[Dict]:
    """Map behavioral flags to MITRE ATT&CK techniques."""
    if not _MITRE_DATA:
        return []

    matched_ids = []
    if flags.get("has_accessibility_abuse"):
        matched_ids.extend(["T1411"])
    if flags.get("has_sms_read_write"):
        matched_ids.extend(["T1412"])
    if flags.get("has_system_alert_window"):
        matched_ids.extend(["T1444"])
    if flags.get("targets_indian_banks"):
        matched_ids.extend(["T1418"])

    dangerous_apis = flags.get("dangerous_apis_found", [])
    if any(a in dangerous_apis for a in ["DexClassLoader", "PathClassLoader"]):
        matched_ids.extend(["T1407", "T1406"])
    if "addJavascriptInterface" in dangerous_apis:
        matched_ids.extend(["T1516"])
    if any(a in dangerous_apis for a in ["Runtime.exec", "ProcessBuilder.start"]):
        matched_ids.extend(["T1603"])
    if any(a in dangerous_apis for a in ["System.loadLibrary"]):
        matched_ids.extend(["T1406"])
    if flags.get("hardcoded_urls_ips"):
        matched_ids.extend(["T1437"])

    seen = set()
    results = []
    for tech in _MITRE_DATA:
        if tech["id"] in matched_ids and tech["id"] not in seen:
            seen.add(tech["id"])
            results.append(tech)

    return results


def get_malware_family_context(family_name: str) -> Optional[Dict]:
    """Get rich context for a matched malware family."""
    if not _FAMILIES_DATA:
        return None

    for family in _FAMILIES_DATA.get("families", []):
        if family["name"].lower() == family_name.lower():
            return family
        if family_name.lower() in [a.lower() for a in family.get("aliases", [])]:
            return family
    return None


def get_regulatory_context(flags: Dict[str, Any]) -> List[Dict]:
    """Return relevant RBI/CERT-In/NPCI regulations for current threat flags."""
    if not _BANKING_DATA:
        return []

    results = []

    if flags.get("has_sms_read_write") or flags.get("has_accessibility_abuse"):
        rbi = next(
            (r for r in _BANKING_DATA.get("rbi_directives", []) if r["id"] == "RBI-MDS-2021"),
            None
        )
        if rbi:
            results.append({
                "source": "RBI Master Direction",
                "id": rbi["id"],
                "title": rbi["title"],
                "relevance": "This APK targets SMS OTP interception which violates RBI MDS-2021 security controls",
                "key_points": rbi.get("key_controls", [])[:3],
                "customer_action": rbi.get("advisory_template", "")
            })

    if flags.get("targets_indian_banks"):
        cert_advisory = next(
            (c for c in _BANKING_DATA.get("cert_in_advisories", []) if c["id"] == "CIAD-2023-0067"),
            None
        )
        if cert_advisory:
            results.append({
                "source": "CERT-In Advisory",
                "id": cert_advisory["id"],
                "title": cert_advisory["title"],
                "relevance": "Active campaign targeting Indian banking apps matches this APK's behavior",
                "recommended_actions": cert_advisory.get("recommended_actions", [])
            })

    return results


def get_banking_package_names() -> Dict[str, str]:
    """Return the full Indian banking package name dictionary."""
    if _BANKING_DATA:
        return _BANKING_DATA.get("indian_banking_packages", {})
    return {}


def build_rag_context(
    family: str,
    flags: Dict[str, Any],
    correlation_result: Optional[Dict] = None,
) -> str:
    """
    Build a verified, evidence-grounded context string for Gemini 2.5 Flash prompt injection.
    Returns a formatted string with MITRE techniques, regulatory context, and family profile.
    """
    sections: List[str] = []

    # ── 1. MITRE ATT&CK Techniques ─────────────────────────────────────────────
    techniques = get_mitre_techniques_for_flags(flags)
    if techniques:
        tech_lines = []
        for t in techniques[:5]:  # Cap at 5 for token efficiency
            tech_lines.append(
                f"  • {t['id']} {t['name']} (Tactic: {t['tactic']}) - "
                f"Banking relevance: {t['banking_relevance']}"
            )
        sections.append("MITRE ATT&CK FOR MOBILE TECHNIQUES:\n" + "\n".join(tech_lines))

    # ── 2. Malware Family Profile ───────────────────────────────────────────────
    if family and family != "Unknown":
        family_ctx = get_malware_family_context(family)
        if family_ctx:
            sections.append(
                f"CONFIRMED MALWARE FAMILY - {family_ctx['name']}:\n"
                f"  Type: {family_ctx['type']}\n"
                f"  Last Active: {family_ctx['last_active']}\n"
                f"  Targeted Banks: {', '.join(family_ctx['targeted_banks'][:5])}\n"
                f"  Capabilities: {', '.join(family_ctx['capabilities'][:4])}\n"
                f"  Banking Impact: {family_ctx['banker_impact']}\n"
                f"  Threat Level: {family_ctx['threat_level']}"
            )

    # ── 3. Regulatory Context ───────────────────────────────────────────────────
    regulatory = get_regulatory_context(flags)
    if regulatory:
        reg_lines = []
        for reg in regulatory[:2]:
            reg_lines.append(
                f"  • {reg['source']} {reg['id']} - {reg['title']}\n"
                f"    Relevance: {reg['relevance']}"
            )
        sections.append("REGULATORY CONTEXT:\n" + "\n".join(reg_lines))

    # ── 4. Threat Intelligence (from correlator) ────────────────────────────────
    if correlation_result:
        vt_score = correlation_result.get("vt_detection_ratio", 0)
        known_family = correlation_result.get("known_family")
        campaign = correlation_result.get("campaign")

        if vt_score > 0 or known_family:
            ti_lines = []
            if vt_score > 0:
                ti_lines.append(f"  • VirusTotal: {vt_score:.0%} detection rate")
            if known_family:
                ti_lines.append(f"  • Known malware family: {known_family}")
            if campaign:
                ti_lines.append(f"  • Campaign: {campaign}")
            sections.append("THREAT INTELLIGENCE CORRELATION:\n" + "\n".join(ti_lines))

    if not sections:
        return "No additional context retrieved from knowledge base."

    return "\n\n".join(sections)


def get_cert_in_recommendations(family: str, flags: Dict[str, Any]) -> List[str]:
    """Return CERT-In aligned recommendations for detected threat."""
    recs = []

    if flags.get("has_accessibility_abuse") or flags.get("has_sms_read_write"):
        recs.append(
            "Per RBI MDS-2021: Immediately isolate device and revoke all banking session tokens"
        )
        recs.append(
            "Per CERT-In CIAD-2023-0042: Submit APK hash to CERT-In within 6 hours of detection"
        )

    if flags.get("targets_indian_banks"):
        recs.append(
            "Per RBI CPG-2022: Issue proactive customer advisory within 24 hours if customers may be affected"
        )

    if family != "Unknown":
        family_ctx = get_malware_family_context(family)
        if family_ctx and family_ctx.get("cert_in_references"):
            for ref in family_ctx["cert_in_references"]:
                if _BANKING_DATA:
                    advisory = next(
                        (a for a in _BANKING_DATA.get("cert_in_advisories", []) if a["id"] == ref),
                        None
                    )
                    if advisory:
                        recs.extend(advisory.get("recommended_actions", [])[:2])

    if not recs:
        recs = [
            "Verify APK source before deployment in enterprise environment",
            "Monitor device network traffic for connections to flagged URLs",
            "Run APK in controlled sandbox for dynamic behavioral analysis"
        ]

    return list(dict.fromkeys(recs))[:6]  # Deduplicate, cap at 6
