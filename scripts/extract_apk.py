import re, zipfile, sys

try:
    with zipfile.ZipFile('test apk/Malware/Anubis.apk', 'r') as z:
        manifest = z.read('AndroidManifest.xml') if 'AndroidManifest.xml' in z.namelist() else b''
        dex = z.read('classes.dex') if 'classes.dex' in z.namelist() else b''
except Exception as e:
    print('Zip err:', e)
    sys.exit(1)

def get_strings(data):
    # AXML often has UTF-16 strings, so we search for both ASCII and UTF-16LE, but let's try a simple approach
    # Let's just find anything resembling a package/permission in UTF-8/ASCII
    chars = b'[A-Za-z0-9_/\-\.]{8,}'
    res = re.findall(chars, data)
    return set([m.decode('ascii', errors='ignore') for m in res])

m_strings = get_strings(manifest)
d_strings = get_strings(dex)

all_strings = m_strings.union(d_strings)

permissions = [s for s in all_strings if 'permission' in s.lower()]
comps = [s for s in all_strings if 'service' in s.lower() or 'receiver' in s.lower()]
packages = [s for s in all_strings if s.startswith('com.')]

print('--- PERMISSIONS ---')
for p in sorted(permissions): print(p)

print('\n--- COM. PACKAGES ---')
for p in sorted(packages)[:30]: print(p)
