import time
import subprocess
from pathlib import Path
import frida
import json

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

def main():
    adb("shell", "am", "force-stop", TARGET_PKG)
    time.sleep(1)

    dev = get_device()
    print("Spawning target...")
    pid = dev.spawn([TARGET_PKG])
    session = dev.attach(pid)

    cap_hook = """
    Java.perform(function() {
        send({type: 'diag', msg: 'Java.perform started in spawn'});
        try {
            var WebView = Java.use("android.webkit.WebView");
            WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
                send({
                    type: 'event',
                    category: 'network',
                    hook: 'WebView.loadUrl',
                    url: url ? url.toString() : null,
                    description: 'WebView loaded URL: ' + url
                });
                return this.loadUrl(url);
            };
            send({type: 'diag', msg: 'WebView.loadUrl hooked'});
        } catch(e) {
            send({type: 'error', error: e.toString()});
        }
    });
    """

    events = []
    def on_message(message, data):
        print("[MESSAGE]", message)
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            if payload.get("type") == "event":
                events.append(payload)

    script = session.create_script(cap_hook)
    script.on("message", on_message)
    script.load()

    dev.resume(pid)
    adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")

    print("Monitoring for 10 seconds...")
    for _ in range(10):
        time.sleep(1)

    session.detach()
    adb("shell", "am", "force-stop", TARGET_PKG)

    print(f"\n==================== TOTAL CAPTURED LOADURL EVENTS: {len(events)} ====================")
    for ev in events:
        print(json.dumps(ev, indent=2))

if __name__ == "__main__":
    main()
