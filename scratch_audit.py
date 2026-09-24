import os
import re

directories = ['backend', 'analysis-engine', 'shared']
patterns = [
    r'/tmp', r'/app/uploads', r'uploads', r'upload', r'open\(', r'Path\(', r'shutil',
    r'copy', r'move', r'write_bytes', r'write_text', r'FileResponse', r'StaticFiles',
    r'os\.path', r'tempfile', r'NamedTemporaryFile', r'artifact', r'screenshot',
    r'report', r'har', r'jadx', r'apktool', r'mobsf', r'frida'
]

results = {}

for d in directories:
    for root, _, files in os.walk(d):
        for file in files:
            if not file.endswith('.py'):
                continue
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        for p in patterns:
                            if re.search(p, line, re.IGNORECASE):
                                if path not in results:
                                    results[path] = []
                                results[path].append({'line': i+1, 'content': line.strip(), 'pattern': p})
            except Exception as e:
                pass

with open('audit_results.txt', 'w', encoding='utf-8') as f:
    for path, matches in results.items():
        f.write(f"\n--- {path} ---\n")
        for m in matches:
            f.write(f"L{m['line']} [{m['pattern']}]: {m['content']}\n")
