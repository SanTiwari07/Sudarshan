import re
with open('test apk/Malware/Anubis_extracted/AndroidManifest.xml', 'rb') as f:
    data = f.read()
# AXML UTF-16LE strings (every other byte 0)
utf16_matches = re.findall(b'(?:[a-zA-Z0-9_\.]\x00){5,}', data)
utf16_strings = set([m.decode('utf-16le', errors='ignore') for m in utf16_matches])
print('--- PACKAGES/PERMISSIONS ---')
for s in utf16_strings:
    if 'permission' in s.lower() or 'com.' in s.lower():
        print(s)
