import re
from pathlib import Path

for ext in ['*.py', '*.json', '*.yml', '*.yaml']:
    for p in Path('.').rglob(ext):
        if not p.is_file() or 'venv' in p.parts or 'pycache' in p.parts:
            continue
        try:
            c = p.read_text(encoding='utf-8')
            if re.search(r'C:[/\\]Users[\\/]', c, flags=re.IGNORECASE):
                print(f"Found in {p}")
        except Exception:
            pass
