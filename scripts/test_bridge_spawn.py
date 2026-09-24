import time
import subprocess
from pathlib import Path
import frida

DEVICE_SERIAL = "emulator-5554"
TARGET_PKG = "com.baseline.sbi"
MAIN_ACT = "com.baseline.sbi.MainActivity"

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

def test_spawn(name, js_code):
    print(f"\n---> Testing Spawn with: {name}")
    force_stop()
    adb("logcat", "-c")
    dev = get_device()
    script = None
    session = None
    try:
        pid = dev.spawn([TARGET_PKG])
        session = dev.attach(pid)
        script = session.create_script(js_code)
        script.load()
        dev.resume(pid)
        adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
        for i in range(5):
            time.sleep(1)
            cpid = get_pid()
            if not cpid:
                print(f"FAILED on {name} at second {i+1}!")
                log = adb("logcat", "-d")
                for line in log.stdout.splitlines():
                    if "Abort message" in line or "JNI ERROR" in line:
                        print("  CRASH:", line)
                return False
        print(f"PASSED {name}! (PID {get_pid()})")
        return True
    except Exception as e:
        print(f"EXCEPTION on {name}: {e}")
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

    bundle = Path("shared/sudarshan_core/engines/frida_hooks/banking_trojan.bundle.js").read_text(encoding="utf-8")
    lines = bundle.splitlines()

    # Create empty initHooks
    # line 13749 is initHooks();
    # Let's replace function initHooks() { ... } with empty one
    empty_init = """
    function initHooks() {
        if (!Java || !Java.available) return;
        Java.perform(function() {
            console.log("Java perform empty works!");
        });
    }
    """
    prefix = "\n".join(lines[:13749]) + "\n" + empty_init
    test_spawn("frida-java-bridge bundled + empty Java.perform()", prefix)
