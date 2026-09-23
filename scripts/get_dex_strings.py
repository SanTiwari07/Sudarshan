import re
with open('test apk/Malware/Anubis_extracted/classes.dex', 'rb') as f:
    data = f.read()
strings = re.findall(b'[a-zA-Z0-9_\.\-]{6,}', data)
ascii_strs = set([s.decode('ascii', errors='ignore') for s in strings])
print('--- Endpoints ---')
for s in ascii_strs:
    if 'http' in s.lower() or '.com' in s.lower() or '.net' in s.lower() or '.org' in s.lower():
        if 'android' not in s and 'google' not in s and 'androidx' not in s:
            print(s)
print('--- Intent Actions ---')
for s in ascii_strs:
    if 'android.intent.action' in s:
        print(s)
