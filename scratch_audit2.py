import os
import re

directories = ['backend', 'analysis-engine', 'shared', 'frontend']
# We are looking for usage of os.path, tempfile, shutil, file writing, open(), Path() specifically related to storage.

lines_of_interest = []

for d in directories:
    if not os.path.exists(d): continue
    for root, _, files in os.walk(d):
        for file in files:
            if not file.endswith('.py') and not file.endswith('.ts') and not file.endswith('.tsx'):
                continue
            path = os.path.join(root, file)
            if 'tests' in path or 'test_' in path:
                continue
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        line_strip = line.strip()
                        if ('open(' in line_strip and 'w' in line_strip) or \
                           ('open(' in line_strip and 'wb' in line_strip) or \
                           ('write_bytes' in line_strip) or \
                           ('write_text' in line_strip) or \
                           ('FileResponse' in line_strip) or \
                           ('tempfile' in line_strip) or \
                           ('/tmp' in line_strip) or \
                           ('NamedTemporaryFile' in line_strip) or \
                           ('shutil.move' in line_strip) or \
                           ('shutil.copy' in line_strip) or \
                           ('os.remove' in line_strip) or \
                           ('UploadFile' in line_strip):
                            lines_of_interest.append(f"{path}:{i+1}: {line_strip}")
            except Exception:
                pass

with open('audit_summary.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines_of_interest))
