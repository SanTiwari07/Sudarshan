import os
import time
print("Killing frida-server")
os.system("adb shell killall frida-server")
time.sleep(1)
print("Starting frida-server with NO arguments")
os.system("adb shell 'su 0 sh -c \"nohup /data/local/tmp/frida-server </dev/null >/dev/null 2>&1 &\"'")
time.sleep(2)
print("Checking if it runs:")
os.system("adb shell 'ps -A | grep frida'")
