import glob
import re
from pathlib import Path

# Paths to process
paths = list(Path('backend/tests').glob('*.py')) + list(Path('tests/unit').glob('*.py')) + list(Path('scripts').glob('*.py')) + list(Path('backend').glob('test_*.py'))

for p in paths:
    if not p.is_file():
        continue
    content = p.read_text(encoding='utf-8')
    
    # Replace JWT_SECRET_KEY
    new_content = re.sub(r'os\.environ\["JWT_SECRET_KEY"\]\s*=\s*".*?"', 'os.environ["JWT_SECRET_KEY"] = "test_secret_key"', content)
    
    # Replace DATABASE_URL with a local sqlite db instead of hardcoded postgres or paths
    # Unless it's an explicitly postgres test
    new_content = re.sub(r'os\.environ\["DATABASE_URL"\]\s*=\s*"(?:postgres|sqlite)[^"]+"', 'os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"', new_content)
    
    if new_content != content:
        p.write_text(new_content, encoding='utf-8')
        print(f"Updated secrets in {p}")
