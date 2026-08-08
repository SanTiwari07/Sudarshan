"""
Live VIDE WebView verification — Genymotion + InsecureBankv2 + vide_live_probe.

Uses the same WebView.loadData hook/event shape as banking_trojan.js (network category).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shared"))

ADB_SERIAL = os.getenv("SUDARSHAN_ADB_SERIAL", "192.168.56.101:5555")
FRIDA_PORT = int(os.getenv("SUDARSHAN_FRIDA_PORT", "27042"))
TARGET_PKG = os.getenv("VIDE_LIVE_TARGET_PKG", "com.android.insecurebankv2")
PROBE_BUNDLE = REPO / "scripts" / "vide_live_probe.bundle.js"
APK = REPO / "backend" / "test_sample.apk"


def _adb(*args: str) -> None:
    subprocess.run(["adb", "-s", ADB_SERIAL, *args], check=False, capture_output=True)


def main() -> int:
    import frida

    from sudarshan_core.engines.risk_engine import calculate_risk_score
    from sudarshan_core.engines.vide.pipeline import (
        collect_webview_html_from_frida_events,
        run_vide_analysis,
    )

    if not PROBE_BUNDLE.is_file():
        print("ERROR: build vide_live_probe.bundle.js first (see verify_vide_webview_device.md)")
        return 1

    if APK.is_file():
        _adb("install", "-r", str(APK))

    _adb("forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}")
    device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{FRIDA_PORT}")
    print("frida_device", device, flush=True)
    print("frida_process_count", len(device.enumerate_processes()), flush=True)

    events_by_cat: dict[str, list] = {}
    live_msgs: list[dict] = []

    def on_message(message, _data):
        if message.get("type") == "error":
            print("FRIDA_SCRIPT_ERROR:", message, flush=True)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload") or {}
        if payload.get("type") == "event":
            ev = payload.get("payload") or payload
            if not ev.get("category"):
                ev = payload
            cat = ev.get("category") or "network"
            events_by_cat.setdefault(cat, []).append(ev)
            data = ev.get("data") or {}
            if "loadData" in str(data.get("hook", "")):
                print(
                    "HOOK",
                    data.get("hook"),
                    "html_len",
                    len(data.get("html_preview") or ""),
                    flush=True,
                )
        if payload.get("type") == "vide_live":
            live_msgs.append(payload)
            print("LIVE", payload, flush=True)

    _adb("shell", "am", "force-stop", TARGET_PKG)
    pid = device.spawn([TARGET_PKG])
    session = device.attach(pid)
    script = session.create_script(PROBE_BUNDLE.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    _adb(
        "shell",
        "monkey",
        "-p",
        TARGET_PKG,
        "-c",
        "android.intent.category.LAUNCHER",
        "1",
    )
    time.sleep(20)

    dynamic_result = {"frida_events": {k: list(v) for k, v in events_by_cat.items()}}
    html_snips = collect_webview_html_from_frida_events(dynamic_result)
    vide = run_vide_analysis(
        dynamic_result=dynamic_result,
        package_name=TARGET_PKG,
        certificate={"certificate_sha256": "f" * 64},
    )
    risk = calculate_risk_score({}, vide_result=vide)

    out = {
        "adb_serial": ADB_SERIAL,
        "frida_port": FRIDA_PORT,
        "target_pkg": TARGET_PKG,
        "live_msgs": live_msgs,
        "event_categories": {k: len(v) for k, v in events_by_cat.items()},
        "html_snippet_count": len(html_snips),
        "html_preview_len": len(html_snips[0]) if html_snips else 0,
        "vide_detected": vide.get("visual_impersonation_detected"),
        "vide_compare": vide.get("vide_compare"),
        "risk_band": risk.get("risk_band"),
        "final_risk_score": risk.get("final_risk_score"),
    }
    print(json.dumps(out, indent=2), flush=True)

    try:
        session.detach()
    except Exception:
        pass
    try:
        device.kill(pid)
    except Exception:
        pass

    return 0 if html_snips else 2


if __name__ == "__main__":
    raise SystemExit(main())
