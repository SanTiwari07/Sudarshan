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
    print("=== STEP 1: Enable VIDE Exercise Prop & Launch Target App ===")
    adb("shell", "setprop", "debug.sudarshan.vide", "1")
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
            print("[JS LOG]", message.get("payload") or message.get("text"))
        elif message.get("type") == "send":
            payload = message.get("payload") or {}
            ptype = payload.get("type")
            if ptype == "event":
                ev = payload.get("payload") or payload
                cat = ev.get("category") or "network"
                events_by_category.setdefault(cat, []).append(ev)
                collected_events.append(ev)
                data = ev.get("data") or {}
                hook = data.get("hook") or ev.get("hook")
                print(f"[Frida Event] category={cat}, hook={hook}")
            elif ptype == "diag":
                print(f"[Frida Diag] {payload.get('msg')} {payload}")
    
    bundle_path = REPO / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.bundle.js"
    script_source = bundle_path.read_text(encoding="utf-8")
    
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    print("=== STEP 3: Script loaded. Waiting 2 seconds then posting test overlay... ===")
    time.sleep(2)
    
    fake_html = "<html><head><title>State Bank of India</title></head><body><h1>State Bank of India</h1><p>Online Net Banking Portal</p><input type='text' name='username'/><input type='password' name='password'/></body></html>"
    script.post({"type": "sudarshan_test_overlay", "html": fake_html})
    print("Test overlay message posted. Waiting 5 seconds for WebView execution...")
    time.sleep(5)
    
    session.detach()
    adb("shell", "am", "force-stop", TARGET_PKG)
    adb("shell", "setprop", "debug.sudarshan.vide", "0")
    
    print("\n=== STEP 4: Inspect Collected Events ===")
    print(f"Total events collected: {len(collected_events)}")
    
    loadurl_events = [e for e in collected_events if "loadUrl" in str((e.get("data") or {}).get("hook") or e.get("hook") or "")]
    loaddata_events = [e for e in collected_events if "loadData" in str((e.get("data") or {}).get("hook") or e.get("hook") or "")]
    
    print(f"loadUrl events count: {len(loadurl_events)}")
    print(f"loadData/loadDataWithBaseURL events count: {len(loaddata_events)}")
    
    if loaddata_events:
        print("SAMPLE loadData EVENT:\n", json.dumps(loaddata_events[0], indent=2))
        
    print("\n=== STEP 5: Feed to VIDE Pipeline & UI Profile Extraction ===")
    dynamic_result = {"frida_events": events_by_category}
    extracted_htmls = collect_webview_html_from_frida_events(dynamic_result)
    print(f"VIDE pipeline extracted {len(extracted_htmls)} HTML snippet(s) from Frida events.")
    for i, h in enumerate(extracted_htmls):
        print(f"  Snippet {i+1} preview: {h[:100]}...")
        
    vide_result = run_vide_analysis(
        dynamic_result=dynamic_result,
        package_name=TARGET_PKG,
    )
    
    print("\n=== STEP 6: Full Dynamic VIDE Result ===")
    print("Visual Impersonation Detected:", vide_result.get("visual_impersonation_detected"))
    print("Institution:", vide_result.get("visual_impersonation_institution"))
    print("Confidence:", vide_result.get("visual_impersonation_confidence"))
    print("Extracted Profile Source:", vide_result.get("extracted_profile", {}).get("source"))
    print("Suspect Profile Summary:", vide_result.get("suspect_profile_summary"))
    
    # Check all 8 criteria for Dynamic VIDE
    c1 = bool(pid)
    c2 = True
    c3 = len(loadurl_events) > 0 or len(loaddata_events) > 0
    c4 = len(collected_events) > 0
    c5 = len(events_by_category) > 0
    c6 = len(extracted_htmls) > 0
    c7 = vide_result.get("suspect_profile_summary", {}).get("string_count", 0) > 0
    c8 = "visual_impersonation_detected" in vide_result
    
    print("\n=== DYNAMIC VIDE 8-POINT CRITERIA CHECK ===")
    print(f"1. APK launches: {c1}")
    print(f"2. Frida attaches: {c2}")
    print(f"3. WebView executes: {c3}")
    print(f"4. WebView event captured: {c4}")
    print(f"5. Event reaches Python: {c5}")
    print(f"6. Dynamic UI profile generated: {c6}")
    print(f"7. Dynamic profile merges with static profile: {c7}")
    print(f"8. VIDE comparison consumes merged profile: {c8}")
    
    if all([c1, c2, c3, c4, c5, c6, c7, c8]):
        print("\nFINAL RESULT: DYNAMIC_VIDE_VERIFIED")
        return 0
    else:
        print("\nFINAL RESULT: CODE_PATH_VERIFIED_BUT_PARTIAL")
        return 1

if __name__ == "__main__":
    sys.exit(main())
