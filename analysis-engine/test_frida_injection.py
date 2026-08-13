import frida
import time

def on_message(message, data):
    print('[Message]', message)

def run():
    print("Testing frida script injection...")
    try:
        d1 = frida.get_device_manager().get_device('emulator-5554')
        
        # Make sure app is running
        try:
            pid = d1.spawn(['com.android.insecurebankv2'])
            print('spawned pid:', pid)
            d1.resume(pid)
            time.sleep(2)
        except Exception as e:
            print("Spawn failed, trying to just attach:", e)

        print('attaching...')
        session = d1.attach('com.android.insecurebankv2')
        print('attached!')
        
        script = session.create_script('''
            Java.perform(function () {
                console.log('Java bridge loaded!');
                send({type: 'diag', msg: 'hello from java bridge'});
            });
        ''')
        script.on('message', on_message)
        print("loading script...")
        script.load()
        print("script loaded!")
        
        time.sleep(5)
        print('done')
    except Exception as e:
        print('Error:', type(e).__name__, e)

run()
