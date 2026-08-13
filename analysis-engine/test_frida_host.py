import frida

try:
    d2 = frida.get_device_manager().add_remote_device('host.docker.internal:27042')
    print('d2:', d2)
    print('d2 procs:', len(d2.enumerate_processes()))
except Exception as e:
    print('d2 err:', e)
