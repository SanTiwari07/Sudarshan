import time
import subprocess
from pathlib import Path
import frida

DEVICE_SERIAL = "emulator-5554"
TARGET_PKG = "com.baseline.sbi"
MAIN_ACT = "com.baseline.sbi.MainActivity"
REPO = Path(__file__).resolve().parents[1]

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

def force_stop():
    adb("shell", "am", "force-stop", TARGET_PKG)
    time.sleep(1)

def get_pid():
    res = adb("shell", "pidof", TARGET_PKG)
    out = res.stdout.strip()
    if out:
        try: return int(out.split()[0])
        except Exception: return None
    return None

def run_test(name, js_code, spawn=False, wait_sec=10):
    print(f"\n==================== TEST: {name} (spawn={spawn}) ====================")
    force_stop()
    adb("logcat", "-c")
    dev = get_device()
    script = None
    session = None
    try:
        if spawn:
            print(f"Spawning {TARGET_PKG}...")
            pid = dev.spawn([TARGET_PKG])
            session = dev.attach(pid)
            script = session.create_script(js_code)
            script.load()
            dev.resume(pid)
            adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
        else:
            print(f"Starting {TARGET_PKG} via am start...")
            adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
            time.sleep(2)
            pid = get_pid()
            if not pid:
                print("Could not get pid for attach")
                return False
            print(f"Attaching to PID {pid}...")
            session = dev.attach(pid)
            script = session.create_script(js_code)
            script.load()

        print(f"Monitoring for {wait_sec} seconds...")
        for i in range(wait_sec):
            time.sleep(1)
            cpid = get_pid()
            if not cpid:
                print(f"FAILED: Process crashed at second {i+1}!")
                log = adb("logcat", "-d")
                for line in log.stdout.splitlines():
                    if "JNI DETECTED ERROR" in line or "SIGABRT" in line or "Abort message" in line:
                        print("  CRASH LOG:", line)
                return False
        print(f"SUCCESS: Process alive after {wait_sec} seconds (PID: {get_pid()})")
        return True
    except Exception as e:
        print(f"EXCEPTION: {e}")
        return False
    finally:
        if script:
            try: script.unload()
            except: pass
        if session:
            try: session.detach()
            except: pass
        force_stop()

if __name__ == "__main__":
    ensure_frida_server()

    bundle_path = REPO / "shared" / "sudarshan_core" / "engines" / "frida_hooks" / "banking_trojan.bundle.js"
    full_code = bundle_path.read_text(encoding="utf-8")

    # Test A: Recompiled Bundle on Attach
    res_attach = run_test("Recompiled Bundle (Attach mode)", full_code, spawn=False, wait_sec=12)

    # Test B: Recompiled Bundle on Spawn
    res_spawn = run_test("Recompiled Bundle (Spawn mode)", full_code, spawn=True, wait_sec=10)

    print("\n\n==================== RESULTS SUMMARY ====================")
    print("Recompiled Bundle (Attach mode):", "PASS" if res_attach else "CRASH")
    print("Recompiled Bundle (Spawn mode):", "PASS" if res_spawn else "CRASH")
