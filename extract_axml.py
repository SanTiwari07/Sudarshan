import re

def extract(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Extract ASCII strings
    ascii_strings = [m.decode('ascii', errors='ignore') for m in re.findall(b'[a-zA-Z0-9_\.]{5,}', data)]
    
    # Extract UTF-16LE strings (simple heuristic: every other byte is 00)
    utf16_matches = re.findall(b'(?:[a-zA-Z0-9_\.]\x00){5,}', data)
    utf16_strings = [m.decode('utf-16le', errors='ignore') for m in utf16_matches]

    all_strings = set(ascii_strings + utf16_strings)
    
    permissions = sorted(list(set([s for s in all_strings if 'permission' in s.lower()])))
    comps = sorted(list(set([s for s in all_strings if ('service' in s.lower() or 'receiver' in s.lower()) and 'com.' in s])))
    packages = sorted(list(set([s for s in all_strings if s.startswith('com.')])))

    print('--- PERMISSIONS ---')
    for p in permissions: print(p)

    print('\n--- COMPONENTS ---')
    for c in comps[:20]: print(c)
    
    print('\n--- PACKAGES ---')
    for p in packages[:20]: print(p)

extract('test apk/Malware/Anubis_extracted/AndroidManifest.xml')
