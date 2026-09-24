import glob
import re
from pathlib import Path

paths = list(Path('backend/tests').glob('*.py')) + list(Path('tests/unit').glob('*.py')) + list(Path('scripts').glob('*.py')) + list(Path('backend').glob('test_*.py'))

for p in paths:
    if not p.is_file():
        continue
    content = p.read_text(encoding='utf-8')
    
    # Replace monkeypatch setenv JWT_SECRET_KEY
    new_content = re.sub(r'monkeypatch\.setenv\("JWT_SECRET_KEY",\s*["\'].*?["\']\)', 'monkeypatch.setenv("JWT_SECRET_KEY", "test_secret_key")', content)
    
    if new_content != content:
        p.write_text(new_content, encoding='utf-8')
        print(f"Updated monkeypatch secrets in {p}")
