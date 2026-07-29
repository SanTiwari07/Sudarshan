"""
Sudarshan Standardized Gemini 2.5 Flash Intelligence Engine
============================================================
Exclusively leverages Google Gemini 2.5 Flash API for evidence-grounded
malware threat synthesis, RAG context injection, and CERT-In advisory generation.

Flow:
  Static / Dynamic / Threat Intel / Risk Engine → RAG → Gemini 2.5 Flash API
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from app.rag.knowledge_base import build_rag_context, get_cert_in_recommendations

logger = logging.getLogger(__name__)

# ─── RAG-Grounded Prompt Template ─────────────────────────────────────────────

RAG_PROMPT_TEMPLATE = """You are SUDARSHAN — a senior banking malware intelligence analyst at the Bank of India Cyber Security Operations Centre.

Your analysis is STRICTLY grounded in the verified evidence provided below.
You MUST NOT invent or guess any information not present in the evidence.
You MUST NOT name malware families unless the Family field explicitly states one.

=== VERIFIED EVIDENCE BEGIN ===
{evidence_json}
=== VERIFIED EVIDENCE END ===

=== RETRIEVED KNOWLEDGE BASE CONTEXT BEGIN ===
{rag_context}
=== RETRIEVED KNOWLEDGE BASE CONTEXT END ===

=== CERT-In RECOMMENDATIONS BEGIN ===
{cert_in_recs}
=== CERT-In RECOMMENDATIONS END ===

=== TASK ===
Using ONLY the above verified evidence and retrieved knowledge context, produce a structured intelligence report.

IMPORTANT RULES:
1. Plain English Narrative: 2–4 sentences explaining what this app does and why it is dangerous, in terms a non-technical banking executive can understand.
2. Fraud Objective: One sentence — what specific fraud this app enables (e.g., "OTP theft enabling unauthorized UPI transfers").
3. Affected Banking Apps: List only apps mentioned in the evidence.
4. MITRE Mapping: Use only techniques present in the retrieved context.
5. Banking Impact: Reference RBI/NPCI rules only from the provided regulatory context.
6. CERT-In Recommendation: Use the exact recommendations provided above.
7. Recommended Actions: 3 specific, actionable steps for the SOC analyst.
8. Customer Advisory: 1–2 sentences for non-technical customers.
9. Confidence: "High" only if multiple evidence sources confirm; "Medium" if single static source; "Low" if insufficient evidence.

You MUST respond with strictly valid JSON. No markdown. No code blocks. No extra text.

{{
    "plain_english_narrative": "...",
    "fraud_objective": "...",
    "affected_banking_apps": ["..."],
    "mitre_techniques_used": ["T1411 — ...", "..."],
    "banking_impact_assessment": "...",
    "cert_in_recommendations": ["...", "...", "..."],
    "recommended_actions": ["...", "...", "..."],
    "customer_advisory_draft": "...",
    "confidence": "High|Medium|Low",
    "analysis_note": "Based on static analysis only|Based on static + threat correlation|Based on static + dynamic + correlation"
}}"""


def _build_evidence_dict(
    flags: Dict[str, Any],
    family: str,
    matched_rule: str,
    package_name: str,
    risk_result: Dict[str, Any],
    correlation: Optional[Dict] = None,
    dynamic: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Build structured evidence dict for Gemini — strictly grounded data."""
    evidence: Dict[str, Any] = {
        "Package": package_name,
        "Family": family,
        "ClassificationRule": matched_rule,
        "FinalRiskScore": risk_result.get("final_risk_score", 0),
        "RiskBand": risk_result.get("risk_band", "Unknown"),
        "Confidence": f"{risk_result.get('confidence', 50):.0f}%",
        "FRSBreakdown": risk_result.get("frs_breakdown", {}),
        "StaticFlags": {
            "AccessibilityAbuse": flags.get("has_accessibility_abuse", False),
            "SMSInterception": flags.get("has_sms_read_write", False),
            "OverlayCapability": flags.get("has_system_alert_window", False),
            "DangerousAPIs": flags.get("dangerous_apis_found", [])[:5],
            "HardcodedURLs": flags.get("hardcoded_urls_ips", [])[:5],
            "TargetsIndianBanks": flags.get("targets_indian_banks", False),
            "BankPackagesFound": flags.get("indian_bank_packages_found", [])[:5],
        },
        "Evidence": risk_result.get("evidence", [])[:8],
    }

    if correlation and correlation.get("available"):
        evidence["ThreatIntelligence"] = {
            "VTDetectionRatio": f"{correlation.get('vt_detection_ratio', 0):.0%}",
            "VTMaliciousVendors": correlation.get("vt_malicious_vendors", [])[:3],
            "KnownFamily": correlation.get("known_family"),
            "Campaign": correlation.get("campaign"),
            "MaliciousIPs": correlation.get("malicious_ips", [])[:3],
            "SourcesQueried": correlation.get("sources_queried", []),
        }

    if dynamic and dynamic.get("available"):
        evidence["DynamicBehavior"] = {
            "RuntimeAPICalls": dynamic.get("api_calls", [])[:5],
            "NetworkConnections": len(dynamic.get("network_logs", [])),
            "FilesAccessed": dynamic.get("files_accessed", [])[:5],
        }

    return evidence


def _to_str_list(val: Any) -> List[str]:
    if isinstance(val, list):
        return [str(x) for x in val if x is not None]
    if isinstance(val, str) and val.strip():
        return [val.strip()]
    return []


def _validate_report_json(parsed: Dict[str, Any], cert_recs: List[str]) -> Dict[str, Any]:
    """Validate and sanitize JSON output from Gemini."""
    if not isinstance(parsed, dict) or not parsed.get("plain_english_narrative"):
        raise ValueError("Invalid report structure — missing plain_english_narrative")

    for field in ("affected_banking_apps", "mitre_techniques_used", "cert_in_recommendations", "recommended_actions"):
        parsed[field] = _to_str_list(parsed.get(field))

    if not parsed["cert_in_recommendations"]:
        parsed["cert_in_recommendations"] = cert_recs

    if not parsed["recommended_actions"]:
        parsed["recommended_actions"] = [
            "Isolate the device from the network immediately",
            "Review all flagged permissions and API calls",
            "Submit sample hash for SOC correlation"
        ]

    return parsed


def _get_fallback_template(cert_recs: List[str], error_reason: str) -> Dict[str, Any]:
    """Deterministic fallback if Gemini API is unreachable or unconfigured."""
    return {
        "plain_english_narrative": (
            f"Deterministic Threat Assessment: This application exhibits suspicious behavioral indicators. "
            f"Note: Gemini AI narrative generation was bypassed ({error_reason}). "
            f"Deterministic risk score and static/dynamic evidence below remain fully accurate."
        ),
        "fraud_objective": "Requires investigation based on static and dynamic flags.",
        "affected_banking_apps": [],
        "mitre_techniques_used": [],
        "banking_impact_assessment": "Manual review recommended for flagged permissions and network IOCs.",
        "cert_in_recommendations": cert_recs or [
            "Isolate device from network immediately",
            "Review all flagged permissions manually",
            "Submit to CERT-In within 6 hours if Critical"
        ],
        "recommended_actions": [
            "Isolate the device from the network",
            "Review all flagged permissions and API calls manually",
            "Monitor network traffic for connections to flagged URLs/IPs"
        ],
        "customer_advisory_draft": (
            "We have detected potentially suspicious indicators in this application. "
            "Please contact your security team for a full assessment before installing or using it."
        ),
        "confidence": "Medium",
        "analysis_note": f"Deterministic engine verdict ({error_reason})"
    }


async def analyze_with_llm(
    flags: Dict[str, Any],
    family: str = "Unknown",
    matched_rule: str = "No rule matched",
    package_name: str = "Unknown",
    risk_result: Optional[Dict[str, Any]] = None,
    correlation: Optional[Dict] = None,
    dynamic: Optional[Dict] = None,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    RAG-grounded Gemini 2.5 Flash intelligence analysis with exponential retry.
    """
    if risk_result is None:
        risk_result = {}

    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        try:
            from pathlib import Path
            from dotenv import load_dotenv
            curr = Path(__file__).resolve().parent
            for _ in range(5):
                env_file = curr / ".env"
                if env_file.exists():
                    load_dotenv(dotenv_path=env_file, override=True)
                    gemini_key = os.getenv("GEMINI_API_KEY")
                    break
                curr = curr.parent
        except Exception:
            pass

    cert_recs = get_cert_in_recommendations(family, flags)

    if not gemini_key:
        logger.warning("[Gemini] GEMINI_API_KEY is not set. Returning deterministic template.")
        return _get_fallback_template(cert_recs, "GEMINI_API_KEY not configured")

    # ── Build verified evidence & RAG context ─────────────────────────────────
    evidence = _build_evidence_dict(
        flags, family, matched_rule, package_name, risk_result, correlation, dynamic
    )
    rag_context = build_rag_context(family=family, flags=flags, correlation_result=correlation)
    evidence_json = json.dumps(evidence, indent=2)
    cert_recs_str = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(cert_recs))

    prompt = RAG_PROMPT_TEMPLATE.format(
        evidence_json=evidence_json,
        rag_context=rag_context,
        cert_in_recs=cert_recs_str,
    )

    # ── Execute Gemini API call with exponential retries ──────────────────────
    model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    for attempt in range(max_retries):
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=gemini_key)
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                )
            )

            if response and response.text:
                parsed = json.loads(response.text)
                validated = _validate_report_json(parsed, cert_recs)
                logger.info(f"[Gemini] RAG threat report generated successfully via {model_name} (Attempt {attempt+1})")
                return validated
        except Exception as e:
            backoff = (2 ** attempt) * 0.5
            logger.warning(f"[Gemini] Attempt {attempt+1}/{max_retries} failed ({e}). Retrying in {backoff:.1f}s...")
            time.sleep(backoff)

    logger.error("[Gemini] All Gemini Flash API retries exhausted. Returning fallback template.")
    return _get_fallback_template(cert_recs, "Gemini Flash API retries exhausted")
