import frida

def run():
    print("Testing frida attach by pid to insecurebankv2...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        
        print('attaching to pid 15300...')
        session = d1.attach(15300)
        print('attached!')
        
    except Exception as e:
        print('Error:', type(e).__name__, e)

run()
