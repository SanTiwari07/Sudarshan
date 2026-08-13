import frida
import os
import subprocess

ADB_HOST = os.environ.get("SUDARSHAN_ADB_HOST", "host.docker.internal")
device_serial = "emulator-5554"

def _adb(*args):
    cmd = ["adb"] + list(args)
    subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run():
    print("Testing TCP first...")
    candidate_ports = [27042, 27055]
    device = None
    
    for f_port in candidate_ports:
        _adb("-s", device_serial, "forward", f"tcp:{f_port}", f"tcp:{f_port}")
        hosts_to_try = ("127.0.0.1", ADB_HOST)
        for frida_host in hosts_to_try:
            try:
                print(f"Trying TCP: {frida_host}:{f_port}")
                dev_remote = frida.get_device_manager().add_remote_device(f"{frida_host}:{f_port}")
                dev_remote.enumerate_processes()
                device = dev_remote
                print(f"TCP remote device connected: {frida_host}:{f_port}")
                break
            except Exception as e:
                print(f"TCP failed for {frida_host}:{f_port}: {type(e).__name__} {e}")
        if device:
            break
            
    if device:
        print("Successfully got TCP device.")
        # Try spawning to see if it works reliably
        try:
            pid = device.spawn(['com.android.settings'])
            print("Spawned settings pid:", pid)
            session = device.attach(pid)
            print("Attached!")
            device.resume(pid)
            print("Resumed!")
            session.detach()
            device.kill(pid)
        except Exception as e:
            print("Action failed:", e)
    else:
        print("Failed to get TCP device.")

run()
