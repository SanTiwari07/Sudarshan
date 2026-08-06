#!/usr/bin/env python3
"""One-shot live device certification run (Frida + correlate + risk)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

APK = ROOT / "tests" / "apks" / "categories" / "insecurebankv2.apk"
OUT = ROOT / "sudarshan_artifacts" / "e2e_cert_latest.json"


async def main() -> int:
    if not APK.is_file():
        print("MISSING_APK", APK)
        return 2

    from sudarshan_core.engines.frida_sandbox import run_frida_analysis
    from sudarshan_core.services.threat_correlator import correlate, extract_dynamic_urls
    from sudarshan_core.engines.risk_engine import calculate_risk_score

    dyn = await run_frida_analysis(
        str(APK.resolve()),
        package_name="com.android.insecurebankv2",
    )

    payload = {
        "apk": str(APK),
        "dynamic": {
            "available": dyn.get("available"),
            "dynamic_status": dyn.get("dynamic_status"),
            "canary_received": dyn.get("canary_received"),
            "java_hooks_installed": dyn.get("java_hooks_installed"),
            "native_hooks_installed": dyn.get("native_hooks_installed"),
            "hooks_installed": dyn.get("hooks_installed"),
            "raw_event_counts": dyn.get("raw_event_counts"),
            "hook_fire_counts": dyn.get("hook_fire_counts"),
            "hook_error_counts": dyn.get("hook_error_counts"),
            "bfci": dyn.get("bfci"),
            "bfci_components": dyn.get("bfci_components"),
            "evidence_record_count": dyn.get("evidence_record_count"),
            "network_logs": dyn.get("network_logs"),
            "network_flows_count": len(dyn.get("network_flows") or []),
            "screenshots_count": len(dyn.get("screenshots") or []),
            "error": dyn.get("error"),
            "launch_method_used": dyn.get("launch_method_used"),
            "explorer_used": dyn.get("explorer_used"),
            "artifact_dir": dyn.get("artifact_dir"),
        },
    }

    tc = await correlate(
        sha256="0" * 64,
        urls=[],
        package_name="com.android.insecurebankv2",
        dynamic_urls=extract_dynamic_urls(dyn),
    )
    payload["threat_correlation"] = {
        "available": tc.get("available"),
        "ioc_reputation_count": len(tc.get("ioc_reputation") or []),
        "sources_queried": tc.get("sources_queried"),
        "threat_score": tc.get("threat_score"),
    }

    if dyn.get("available"):
        risk = calculate_risk_score(
            flags={
                "dangerous_apis_found": [],
                "hardcoded_urls_ips": [],
                "targets_indian_banks": True,
                "has_accessibility_abuse": True,
            },
            dynamic_result=dyn,
            correlation_result=tc,
        )
        payload["risk"] = {
            "final_risk_score": risk.get("final_risk_score"),
            "risk_band": risk.get("risk_band"),
            "frs_breakdown": risk.get("frs_breakdown"),
        }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if dyn.get("available") and dyn.get("dynamic_status") == "EVENTS_CAPTURED" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
