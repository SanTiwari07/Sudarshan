import os
import sys
import time
import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shared"))

import frida
from sudarshan_core.engines.vide.pipeline import (
    collect_webview_html_from_frida_events,
    run_vide_analysis,
)

DEVICE_SERIAL = "emulator-5554"
TARGET_PKG = "com.baseline.sbi"
MAIN_ACT = "com.baseline.sbi.MainActivity"
APK = REPO / "test apk" / "BASE-01-SBI.apk"

def adb(*args):
    return subprocess.run(["adb", "-s", DEVICE_SERIAL, *args], capture_output=True, text=True)

def ensure_frida_server():
    res = adb("shell", "ps -A")
    if "frida-server" not in res.stdout:
        print("[Setup] Starting frida-server on device...")
        adb("shell", "su 0 sh -c 'nohup /data/local/tmp/frida-server </dev/null >/dev/null 2>&1 &'")
        time.sleep(2)
    adb("forward", "tcp:27042", "tcp:27042")

def get_device():
    ensure_frida_server()
    try:
        dev = frida.get_device_manager().add_remote_device("127.0.0.1:27042")
        dev.enumerate_processes()
        return dev
    except Exception:
        all_devs = frida.enumerate_devices()
        d = next((x for x in all_devs if x.id == DEVICE_SERIAL), None)
        if not d:
            d = frida.get_usb_device()
        return d

def main():
    print("=== STEP 1: Launch target app via am start ===")
    adb("shell", "am", "force-stop", TARGET_PKG)
    adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
    time.sleep(3)
    
    pid_str = adb("shell", "pidof", TARGET_PKG).stdout.strip()
    if not pid_str:
        print("ERROR: Target app not running")
        return 1
    pid = int(pid_str.split()[0])
    print(f"Target app running as PID: {pid}")
    
    print("=== STEP 2: Attach Frida to PID ===")
    dev = get_device()
    session = dev.attach(pid)
    print("Frida attached successfully")
    
    events_by_category = {}
    collected_events = []
    
    def on_message(message, data):
        if message.get("type") == "log":
            print("[JS LOG]", message.get("payload") or message.get("text") or message)
        elif message.get("type") == "send":
            payload = message.get("payload") or {}
            if payload.get("type") == "event":
                ev = payload.get("payload") or payload
                cat = ev.get("category") or "network"
                events_by_category.setdefault(cat, []).append(ev)
                collected_events.append(ev)
                print(f"[Frida Event] category={cat}, hook={ev.get('data', {}).get('hook') or ev.get('hook')}")
            elif payload.get("type") == "diag":
                print(f"[Frida Diag] {payload.get('msg')} {payload}")
    
    # We use the banking_trojan.bundle.js directly
    bundle_path = REPO / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.bundle.js"
    script_source = bundle_path.read_text(encoding="utf-8")
    
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    print("=== STEP 3: Script loaded. Waiting 6 seconds for telemetry... ===")
    
    time.sleep(8)
    
    session.detach()
    adb("shell", "am", "force-stop", TARGET_PKG)
    
    print("\n=== STEP 4: Inspect Collected Events ===")
    print(f"Total events collected: {len(collected_events)}")
    
    loadurl_events = []
    for ev in collected_events:
        hook_name = str(ev.get("data", {}).get("hook") or ev.get("hook") or "")
        if "loadUrl" in hook_name:
            loadurl_events.append(ev)
            print("FOUND loadUrl EVENT:", json.dumps(ev, indent=2))
            
    if not loadurl_events:
        print("RESULT: RUNTIME_NOT_VERIFIED (0 loadUrl events captured)")
        return 2
        
    print(f"RESULT: RUNTIME_VERIFIED ({len(loadurl_events)} loadUrl event(s) captured!)")
    
    print("\n=== STEP 5: Feed to VIDE Pipeline ===")
    dynamic_result = {"frida_events": events_by_category}
    extracted_htmls = collect_webview_html_from_frida_events(dynamic_result)
    print(f"VIDE pipeline extracted {len(extracted_htmls)} HTML artifacts from Frida events.")
    
    # Run VIDE analysis with dynamic profile
    vide_result = run_vide_analysis(
        dynamic_result=dynamic_result,
        package_name=TARGET_PKG,
    )
    
    print("\n=== STEP 6: VIDE Result with Dynamic Signals ===")
    print("Detected:", vide_result.get("visual_impersonation_detected"))
    print("Institution:", vide_result.get("visual_impersonation_institution"))
    print("Confidence:", vide_result.get("visual_impersonation_confidence"))
    print("Matched Baseline:", vide_result.get("matched_baseline"))
    print("Extracted Profile Source:", vide_result.get("extracted_profile", {}).get("source"))
    print("Profile Summary:", vide_result.get("suspect_profile_summary"))
    print("\nALL STEPS COMPLETED WITH RUNTIME VERIFICATION.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
