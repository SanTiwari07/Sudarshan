import frida

def run():
    print("Enumerating local USB devices...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        print('d1:', d1)
        print('d1 procs:', len(d1.enumerate_processes()))
    except Exception as e:
        print('d1 err:', e)

    print("\nEnumerating TCP remote device...")
    try:
        d2 = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
        print('d2:', d2)
        print('d2 procs:', len(d2.enumerate_processes()))
    except Exception as e:
        print('d2 err:', e)

    print("\nTesting attach...")
    try:
        if 'd1' in locals() and d1:
            session = d1.attach(14259) # Or some other PID, maybe just system_server
            print("d1 attach success!")
    except Exception as e:
        print('d1 attach err:', e)

    try:
        if 'd2' in locals() and d2:
            session = d2.attach(14259)
            print("d2 attach success!")
    except Exception as e:
        print('d2 attach err:', e)

run()
