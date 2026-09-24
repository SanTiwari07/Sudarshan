import os
import sys
import time
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shared"))

import frida

DEVICE_SERIAL = "emulator-5554"
TARGET_PKG = "com.baseline.sbi"
MAIN_ACT = "com.baseline.sbi.MainActivity"

def adb(*args):
    return subprocess.run(["adb", "-s", DEVICE_SERIAL, *args], capture_output=True, text=True)

def ensure_installed():
    apk = REPO / "test apk" / "BASE-01-SBI.apk"
    adb("install", "-r", str(apk))

def force_stop():
    adb("shell", "am", "force-stop", TARGET_PKG)
    time.sleep(1)

def get_pid():
    res = adb("shell", "pidof", TARGET_PKG)
    out = res.stdout.strip()
    if out:
        try:
            return int(out.split()[0])
        except Exception:
            return None
    return None

def get_device():
    # Enumerate devices
    all_devs = frida.enumerate_devices()
    d = next((x for x in all_devs if x.id == DEVICE_SERIAL), None)
    if not d:
        d = frida.get_usb_device()
    return d

def test_stage(name, script_code, spawn=False):
    print(f"\n==================== TEST: {name} (spawn={spawn}) ====================")
    force_stop()
    adb("logcat", "-c")
    dev = get_device()
    
    pid = None
    session = None
    script = None
    messages = []
    
    def on_message(message, data):
        messages.append(message)
        if message.get("type") == "error":
            print(f"[{name}] ERROR:", message)
        else:
            print(f"[{name}] MSG:", message.get("payload"))

    try:
        if spawn:
            print(f"[{name}] Spawning {TARGET_PKG}...")
            pid = dev.spawn([TARGET_PKG])
            session = dev.attach(pid)
            if script_code:
                script = session.create_script(script_code)
                script.on("message", on_message)
                script.load()
            dev.resume(pid)
            adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
        else:
            print(f"[{name}] Starting {TARGET_PKG} via am start...")
            adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
            time.sleep(2)
            pid = get_pid()
            if not pid:
                print(f"[{name}] FAILED: Process did not start!")
                return "FAIL_NO_PROCESS"
            print(f"[{name}] Attaching to PID {pid}...")
            session = dev.attach(pid)
            if script_code:
                script = session.create_script(script_code)
                script.on("message", on_message)
                script.load()

        print(f"[{name}] Monitoring for 10 seconds...")
        for i in range(10):
            time.sleep(1)
            current_pid = get_pid()
            if not current_pid:
                print(f"[{name}] PROCESS CRASHED / DIED at second {i+1}!")
                # Get crash from logcat
                log = adb("logcat", "-d")
                for line in log.stdout.splitlines():
                    if "FATAL" in line or "SIGABRT" in line or "JNI ERROR" in line:
                        print("  CRASH LOG:", line)
                return "CRASH"
        
        print(f"[{name}] Process is still alive (PID: {get_pid()}). SUCCESS!")
        return "PASS"
    except Exception as e:
        print(f"[{name}] EXCEPTION: {e}")
        return f"EXCEPTION: {e}"
    finally:
        if script:
            try: script.unload()
            except: pass
        if session:
            try: session.detach()
            except: pass
        force_stop()

def main():
    ensure_installed()
    
    results = {}
    
    # Stage A: No Frida (Control)
    print("\n==================== TEST A: No Frida ====================")
    force_stop()
    adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
    time.sleep(5)
    pid = get_pid()
    results["A: No Frida"] = "PASS" if pid else "FAIL"
    print("Result A:", results["A: No Frida"])
    force_stop()
    
    # Stage B1: Frida attach, no hooks
    results["B1: Frida Attach (no hooks)"] = test_stage("B1: Attach (no hooks)", script_code=None, spawn=False)
    
    # Stage B2: Frida spawn, no hooks
    results["B2: Frida Spawn (no hooks)"] = test_stage("B2: Spawn (no hooks)", script_code=None, spawn=True)
    
    # Stage C: Minimal Java hook (e.g. Activity.onResume)
    min_java_hook = """
    Java.perform(function() {
        console.log("Java.perform executed");
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function() {
            console.log("Activity.onResume hooked!");
            return this.onResume();
        };
    });
    """
    results["C1: Attach + Minimal Java Hook"] = test_stage("C1: Attach + Min Java Hook", script_code=min_java_hook, spawn=False)
    results["C2: Spawn + Minimal Java Hook"] = test_stage("C2: Spawn + Min Java Hook", script_code=min_java_hook, spawn=True)
    
    # Stage D: WebView / Capacitor hook
    cap_hook = """
    Java.perform(function() {
        console.log("Hooking WebView...");
        try {
            var WebView = Java.use("android.webkit.WebView");
            WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
                console.log("WebView.loadUrl hooked: " + url);
                send({type: "event", hook: "loadUrl", url: url});
                return this.loadUrl(url);
            };
        } catch(e) {
            console.log("WebView hook error: " + e);
        }
    });
    """
    results["D1: Attach + WebView Hook"] = test_stage("D1: Attach + WebView Hook", script_code=cap_hook, spawn=False)
    results["D2: Spawn + WebView Hook"] = test_stage("D2: Spawn + WebView Hook", script_code=cap_hook, spawn=True)
    
    # Stage E: Full SUDARSHAN hooks
    bundle_path = REPO / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.bundle.js"
    if bundle_path.exists():
        full_code = bundle_path.read_text(encoding="utf-8")
        results["E1: Attach + Full SUDARSHAN Bundle"] = test_stage("E1: Attach + Full Bundle", script_code=full_code, spawn=False)
        results["E2: Spawn + Full SUDARSHAN Bundle"] = test_stage("E2: Spawn + Full Bundle", script_code=full_code, spawn=True)
        
    print("\n\n==================== FINAL RESULTS MATRIX ====================")
    for k, v in results.items():
        print(f"{k:40}: {v}")

if __name__ == "__main__":
    main()
