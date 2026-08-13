import frida

def run():
    print("Testing spawn...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        pid = d1.spawn(['com.android.insecurebankv2'])
        print('spawned pid:', pid)
        session = d1.attach(pid)
        print('attached to spawned pid')
        d1.resume(pid)
        print('resumed pid')
    except Exception as e:
        print('Spawn error:', type(e).__name__, e)

run()
