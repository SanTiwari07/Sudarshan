"""Dynamic WebView HTML → VIDE profile (deterministic, no emulator)."""

from sudarshan_core.engines.vide.pipeline import (
    collect_webview_html_from_frida_events,
    run_vide_analysis,
)
from sudarshan_core.engines.vide.baseline_store import InstitutionBaseline
from sudarshan_core.engines.vide.html_profile import profile_from_html
from sudarshan_core.engines.vide.ui_profile import UIProfile


def _sbi_baseline() -> InstitutionBaseline:
    from sudarshan_core.engines.vide.baseline_store import load_baselines

    return next(b for b in load_baselines() if b.institution_id == "demo_sbi_yono")


def test_collect_webview_html_from_load_data_event():
    dynamic = {
        "frida_events": {
            "overlay": [
                {
                    "data": {
                        "hook": "WebView.loadData",
                        "html_preview": "<html><body><h1>YONO</h1><p>Enter UPI PIN</p><p>Login</p></body></html>",
                    }
                }
            ]
        }
    }
    snippets = collect_webview_html_from_frida_events(dynamic)
    assert len(snippets) == 1
    prof = profile_from_html(snippets[0], "webview_dump")
    assert "yono" in " ".join(prof.strings).lower() or any("YONO" in s for s in prof.strings)


def test_frida_html_feeds_vide_compare():
    dynamic = {
        "frida_events": {
            "banking": [
                {
                    "data": {
                        "hook": "WebView.loadDataWithBaseURL",
                        "html_preview": (
                            "<html><body>\nEnter UPI PIN\nMPIN\nUser ID\nForgot Password\nLogin\n"
                            "YONO\nState Bank of India\nNet Banking\nOTP\nAccount Balance\n"
                            "</body></html>"
                        ),
                    }
                }
            ]
        }
    }
    baseline = _sbi_baseline()
    empty = run_vide_analysis(
        suspect_profile=UIProfile(source="dynamic_only"),
        dynamic_result={},
        package_name="com.fake.bank.trojan",
        baselines=[baseline],
    )
    result = run_vide_analysis(
        suspect_profile=UIProfile(source="dynamic_only"),
        dynamic_result=dynamic,
        package_name="com.fake.bank.trojan",
        certificate={"certificate_sha256": "c" * 64},
        baselines=[baseline],
    )
    assert result["suspect_profile_summary"]["string_count"] > empty["suspect_profile_summary"]["string_count"]
    scores = result["vide_compare"]["scores"]
    assert scores["string_jaccard"] > 0.3
    matched = result["vide_compare"].get("matched_strings") or []
    assert "enter upi pin" in [s.lower() for s in matched]
