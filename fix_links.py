import re
from pathlib import Path

docs = list(Path('docs').rglob('*.md')) + list(Path('.').glob('*.md'))

for doc in docs:
    if not doc.is_file():
        continue
    try:
        content = doc.read_text(encoding='utf-8')
        new_content = re.sub(r'file:///C:[\\/]Projects[\\/]Sudarshan[\\/]', '../', content, flags=re.IGNORECASE)
        
        if new_content != content:
            doc.write_text(new_content, encoding='utf-8')
            print(f"Updated links in {doc}")
    except Exception:
        pass
