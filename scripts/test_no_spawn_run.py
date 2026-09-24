import os
import sys
import time
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "shared"))

# Set SPAWN_FIRST to 0
os.environ["SUDARSHAN_SPAWN_FIRST"] = "0"
os.environ["SUDARSHAN_ENABLE_EXPLORER"] = "0"

from sudarshan_core.engines.frida_sandbox import FridaSession

DEVICE_SERIAL = "emulator-5554"
TARGET_PKG = "com.baseline.sbi"
MAIN_ACT = "com.baseline.sbi.MainActivity"
APK = REPO / "test apk" / "BASE-01-SBI.apk"

def adb(*args):
    return subprocess.run(["adb", "-s", DEVICE_SERIAL, *args], capture_output=True, text=True)

def main():
    print("Installing BASE-01-SBI.apk...")
    adb("install", "-r", str(APK))
    adb("shell", "am", "force-stop", TARGET_PKG)
    
    art_dir = REPO / "test apk" / "sudarshan_artifacts" / "test_no_spawn"
    art_dir.mkdir(parents=True, exist_ok=True)
    
    print("Creating FridaSession with SPAWN_FIRST=0...")
    session = FridaSession(
        device_serial=DEVICE_SERIAL,
        package_name=TARGET_PKG,
        main_activity=MAIN_ACT,
        artifact_dir=art_dir,
    )
    
    print("Running FridaSession.run() for 15 seconds...")
    ok = session.run(duration_seconds=15)
    print("FridaSession.run() returned:", ok)
    print("Launch method used:", getattr(session, "launch_method_used", None))
    print("Dynamic status:", getattr(session, "dynamic_status", None))
    print("Events collected:", len(session.events))
    
    # Check if process is still alive
    pid = adb("shell", "pidof", TARGET_PKG).stdout.strip()
    print("Target PID alive at end of run:", pid)
    
    # Print sample events
    for ev in session.events[:10]:
        print("  Event:", ev.get("category"), ev.get("hook") or ev.get("method"))

if __name__ == "__main__":
    main()
