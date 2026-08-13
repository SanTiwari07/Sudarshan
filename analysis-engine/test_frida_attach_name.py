import frida

def run():
    print("Testing attach by name to system_server...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        print('d1:', d1)
        proc = d1.get_process('system_server')
        print('system_server process:', proc)
        session = d1.attach('system_server')
        print("Attached successfully to system_server via local usb!")
    except Exception as e:
        print('Attach error:', type(e).__name__, e)

run()
