import os
import glob
import re

src_dir = r"c:\Projects\Sudarshan\frontend\src"

def replace_in_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = content
    
    # Replace various slate-50 opacities with surface-secondary
    new_content = re.sub(r'bg-slate-50/(50|40|60|80|30)', r'bg-surface-secondary', new_content)
    # Replace plain bg-slate-50 with bg-surface-secondary
    new_content = re.sub(r'\bbg-slate-50\b', r'bg-surface-secondary', new_content)
    
    # Replace bg-slate-100 with surface-secondary
    new_content = re.sub(r'\bbg-slate-100\b', r'bg-surface-secondary', new_content)

    # For bg-white, let's change it to bg-surface-card.
    new_content = re.sub(r'\bbg-white\b', r'bg-surface-card', new_content)
    
    # Let's replace bg-gray-50 too
    new_content = re.sub(r'\bbg-gray-50\b', r'bg-surface-secondary', new_content)
    new_content = re.sub(r'\bbg-gray-100\b', r'bg-surface-secondary', new_content)

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated {filepath}")

for filepath in glob.glob(src_dir + "/**/*.tsx", recursive=True):
    replace_in_file(filepath)

for filepath in glob.glob(src_dir + "/**/*.ts", recursive=True):
    replace_in_file(filepath)
