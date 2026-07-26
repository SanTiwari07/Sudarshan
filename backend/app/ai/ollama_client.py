# backend/app/ai/ollama_client.py
"""
Sudarshan RAG-Grounded Intelligence Engine
==========================================
Ollama is NEVER fed raw APK data.
It is ONLY given pre-verified, structured evidence.

Flow:
  Androguard/MobSF → Threat Correlation → Risk Engine → RAG → Ollama

The RAG context provides verified MITRE techniques, regulatory guidance,
and malware family profiles. Ollama synthesizes these into analyst-grade output.

No hallucinations — Ollama is explicitly instructed to use only provided evidence.
"""

import httpx
import json
import logging
import os
from typing import Any, Dict, List, Optional

from app.rag.knowledge_base import build_rag_context, get_cert_in_recommendations

logger = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_URL = f"{OLLAMA_HOST}/api/generate"
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3")

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
    """Build structured evidence dict for Ollama — no raw bytecode."""
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


async def _check_ollama_available() -> bool:
    """Quick health check."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OLLAMA_HOST}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


_FALLBACK_RESPONSE = {
    "plain_english_narrative": (
        "AI narrative unavailable — Ollama service is not running. "
        "Start Ollama with: ollama pull llama3.1 && ollama serve. "
        "Deterministic risk score and evidence below remain accurate."
    ),
    "fraud_objective": "Cannot determine without AI engine — see static flags.",
    "affected_banking_apps": [],
    "mitre_techniques_used": [],
    "banking_impact_assessment": "Manual review required — see MITRE and permissions panels.",
    "cert_in_recommendations": [
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
    "confidence": "Low",
    "analysis_note": "AI engine unavailable — based on static analysis only"
}


def _analyze_with_gemini(prompt: str, cert_recs: List[str]) -> Optional[Dict[str, Any]]:
    gemini_key = os.getenv("GEMINI_API_KEY")
    if not gemini_key:
        return None
    try:
        from google import genai
        from google.genai import types
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        client = genai.Client(api_key=gemini_key)
        res = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            )
        )
        if res and res.text:
            parsed = json.loads(res.text)
            if "plain_english_narrative" in parsed:
                if not parsed.get("cert_in_recommendations"):
                    parsed["cert_in_recommendations"] = cert_recs
                logger.info("[Gemini] RAG threat intelligence report generated successfully via Gemini Flash.")
                return parsed
    except Exception as e:
        logger.warning(f"[Gemini] Gemini intelligence fallback error: {e}")
    return None


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
    RAG-grounded Ollama analysis.

    Args:
        flags: StaticAnalysisFlags dict
        family: Matched malware family
        matched_rule: Classification rule text
        package_name: APK package name
        risk_result: Full FRS result dict
        correlation: Threat correlator result
        dynamic: MobSF dynamic analysis result
        max_retries: Retry count

    Returns:
        Structured intelligence report dict
    """
    if risk_result is None:
        risk_result = {}

    # ── Build verified evidence ──────────────────────────────────────────────
    evidence = _build_evidence_dict(
        flags, family, matched_rule, package_name, risk_result, correlation, dynamic
    )

    # ── Build RAG context ────────────────────────────────────────────────────
    rag_context = build_rag_context(
        family=family,
        flags=flags,
        correlation_result=correlation,
    )

    # ── CERT-In recommendations ──────────────────────────────────────────────
    cert_recs = get_cert_in_recommendations(family, flags)

    # ── Build final prompt ───────────────────────────────────────────────────
    evidence_json = json.dumps(evidence, indent=2)
    cert_recs_str = "\n".join(f"  {i+1}. {r}" for i, r in enumerate(cert_recs))

    prompt = RAG_PROMPT_TEMPLATE.format(
        evidence_json=evidence_json,
        rag_context=rag_context,
        cert_in_recs=cert_recs_str,
    )

    # Fallback to Gemini 2.5 Flash if Ollama is not available
    if not await _check_ollama_available():
        logger.info(f"Ollama not reachable at {OLLAMA_HOST}. Attempting Gemini Flash AI fallback...")
        gemini_res = _analyze_with_gemini(prompt, cert_recs)
        if gemini_res:
            return gemini_res
        return _FALLBACK_RESPONSE

    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                response = await client.post(
                    OLLAMA_URL,
                    json={
                        "model": MODEL_NAME,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                response.raise_for_status()
                data = response.json()
                llm_output = data.get("response", "{}")

                try:
                    parsed = json.loads(llm_output)
                    # Validate required fields
                    if "plain_english_narrative" in parsed and "recommended_actions" in parsed:
                        # Merge cert_in_recommendations if Ollama didn't produce them
                        if not parsed.get("cert_in_recommendations"):
                            parsed["cert_in_recommendations"] = cert_recs
                        logger.info(f"RAG-grounded LLM analysis succeeded on attempt {attempt+1}")
                        return parsed
                    else:
                        logger.warning(f"Attempt {attempt+1}: Missing required keys: {list(parsed.keys())}")
                except json.JSONDecodeError as e:
                    logger.warning(f"Attempt {attempt+1}: Malformed JSON from Ollama: {e}")
                    continue
        except httpx.TimeoutException:
            logger.error(f"Attempt {attempt+1}: Ollama timed out")
            continue
        except httpx.ConnectError as e:
            logger.error(f"Attempt {attempt+1}: Cannot connect: {e}")
            break
        except Exception as e:
            logger.error(f"Attempt {attempt+1}: {type(e).__name__}: {e}")
            continue

    return _FALLBACK_RESPONSE
