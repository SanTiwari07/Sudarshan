import frida

def run():
    print("Testing frida attach after manual start...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        
        print('attaching...')
        session = d1.attach('com.android.insecurebankv2')
        print('attached!')
        
    except Exception as e:
        print('Error:', type(e).__name__, e)

run()
