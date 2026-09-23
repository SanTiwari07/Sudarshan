import os, re, json
patterns = {'AWS Access Key': r'AKIA[0-9A-Z]{16}', 'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----', 'JWT': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'}
compiled = {k: re.compile(v) for k, v in patterns.items()}
results = []
ignore = ['.git', '__pycache__', '.pytest_cache', 'venv', 'env', '.venv', 'node_modules', 'sudarshan_artifacts']
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ignore]
    for f in files:
        if not f.endswith(('.py', '.json', '.md', '.env', '.txt', '.yml')):
            continue
        path = os.path.join(root, f)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for i, line in enumerate(fh):
                    for name, pat in compiled.items():
                        if pat.search(line):
                            results.append({'file': path, 'line': i+1, 'type': name})
        except Exception:
            pass
print(json.dumps(results, indent=2))
