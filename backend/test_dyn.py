
import asyncio
import sys
import json
import os
import traceback
from pathlib import Path

# ── Silence androguard's very verbose DEBUG/INFO loguru output ────────────────
import loguru
import logging
loguru.logger.add(sys.stderr, level="INFO") # show INFO and above
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ── Windows-native path setup ─────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BACKEND_DIR))
from dotenv import load_dotenv
load_dotenv(BACKEND_DIR.parent / ".env")

from sudarshan_core.engines.frida_sandbox import run_frida_analysis

# ── Paths (Windows-native) ────────────────────────────────────────────────────
# Drop any .apk file here to test it
APK_PATH = BACKEND_DIR / "test_sample.apk"
OUTPUT_JSON = BACKEND_DIR / "dynamic_result.json"

async def run():
    try:
        print("=" * 60)
        print("SUDARSHAN - Frida Dynamic Analysis (Windows Native Mode)")
        print("=" * 60)

        import frida
        print(f"\n[*] Frida version : {frida.__version__}")
        print("[*] Available Frida devices:")
        devices = frida.enumerate_devices()
        for d in devices:
            print(f"     - {d.id} : {d.name} : {d.type}")

        # Check emulator is visible
        emulators = [d for d in devices if d.type == "usb" or "emulator" in d.id]
        if not emulators:
            print("\n[!] No Android emulator detected by Frida.")
            print("    Make sure the emulator is running and frida-server is started:")
            print("    adb shell '/data/local/tmp/frida-server &'")
            return

        print(f"\n[*] Using device : {emulators[0].id}")

        # Check APK exists
        if not APK_PATH.exists():
            print(f"\n[!] No APK found at: {APK_PATH}")
            print(f"    Copy a test APK to: {APK_PATH}")
            print("    Skipping dynamic analysis - testing device connectivity only.")
            return

        print(f"[*] APK path      : {APK_PATH}")
        print(f"[*] Output JSON   : {OUTPUT_JSON}")
        print()

        res = await run_frida_analysis(str(APK_PATH))

        with open(OUTPUT_JSON, "w") as f:
            json.dump(res, f, indent=2)

        print(f"\n[*] Result saved to: {OUTPUT_JSON}")

        if res.get("available"):
            bfci = res.get("bfci", 0.0)
            components = res.get("bfci_components", {})
            print(f"✅ SUCCESS: Dynamic Analysis Complete")
            print(f"   Package  : {res.get('package_name')}")
            print(f"   Device   : {res.get('device')}")
            print(f"   Duration : {res.get('duration_seconds')}s")
            print(f"   BFCI Score : {bfci:.2f} / 100")
            print(f"   ┌─ Accessibility : {components.get('accessibility', 0):.1f}  (w=0.35)")
            print(f"   ├─ SMS/OTP       : {components.get('sms', 0):.1f}  (w=0.25)")
            print(f"   ├─ Overlay       : {components.get('overlay', 0):.1f}  (w=0.20)")
            print(f"   ├─ Banking       : {components.get('banking', 0):.1f}  (w=0.10)")
            print(f"   ├─ Network C2    : {components.get('network', 0):.1f}  (w=0.05)")
            print(f"   └─ Persistence   : {components.get('persistence', 0):.1f}  (w=0.05)")
            if res.get("bfci_evidence"):
                print(f"   Evidence:")
                for e in res["bfci_evidence"]:
                    print(f"     • {e}")
        else:
            print("❌ FAILED: " + str(res.get("error", "Unknown error")))

    except Exception as e:
        print("\n[EXCEPTION] " + str(e))
        traceback.print_exc()

asyncio.run(run())
