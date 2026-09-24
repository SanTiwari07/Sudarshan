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

def main():
    adb("shell", "am", "force-stop", TARGET_PKG)
    adb("shell", "am", "start", "-n", f"{TARGET_PKG}/{MAIN_ACT}")
    time.sleep(2)
    pid = int(adb("shell", "pidof", TARGET_PKG).stdout.strip().split()[0])
    print(f"Target PID: {pid}")

    dev = get_device()
    session = dev.attach(pid)

    js_code = """
    Java.perform(function() {
        console.log("Java perform started");
        
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log(">>> [HOOK TRIGGERED] WebView.loadUrl called with URL: " + url);
            send({
                type: 'event',
                category: 'network',
                hook: 'WebView.loadUrl',
                url: url
            });
            return this.loadUrl(url);
        };
        console.log("WebView.loadUrl hook installed.");

        // Try Java.choose on com.getcapacitor.CapacitorWebView
        Java.choose('com.getcapacitor.CapacitorWebView', {
            onMatch: function(wv) {
                console.log("Found CapacitorWebView: " + wv);
                Java.scheduleOnMainThread(function() {
                    console.log("Calling loadUrl on CapacitorWebView...");
                    wv.loadUrl("https://localhost/test_verification.html");
                });
            },
            onComplete: function() {
                console.log("CapacitorWebView choose complete.");
            }
        });

        // Also try through MainActivity
        Java.choose('com.baseline.sbi.MainActivity', {
            onMatch: function(act) {
                console.log("Found MainActivity: " + act);
                Java.scheduleOnMainThread(function() {
                    try {
                        var wv = act.findViewById(0x7f0800c2);
                        console.log("Found View by id 0x7f0800c2: " + wv);
                        if (wv) {
                            var casted = Java.cast(wv, Java.use('android.webkit.WebView'));
                            casted.loadUrl("https://localhost/activity_verification.html");
                        }
                    } catch(e) {
                        console.log("Error finding/calling on activity: " + e);
                    }
                });
            },
            onComplete: function() {
                console.log("MainActivity choose complete.");
            }
        });
    });
    """

    events = []
    def on_message(message, data):
        if message.get("type") == "log":
            print("[JS LOG]", message.get("payload"))
        elif message.get("type") == "send":
            print("[JS SEND]", message.get("payload"))
            events.append(message.get("payload"))

    script = session.create_script(js_code)
    script.on("message", on_message)
    script.load()

    time.sleep(5)
    session.detach()
    print(f"Total events captured: {len(events)}")

if __name__ == "__main__":
    main()
