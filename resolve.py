import os
import re

def resolve_file(filepath, preference):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Conflict markers format:
    # <<<<<<< HEAD
    # (ours)
    # =======
    # (theirs)
    # >>>>>>> commit_hash
    pattern = re.compile(r'<<<<<<< HEAD\n(.*?)\n=======\n(.*?)\n>>>>>>> [a-f0-9]+', re.DOTALL)
    
    def repl(match):
        ours = match.group(1)
        theirs = match.group(2)
        if preference == 'ours':
            return ours
        elif preference == 'theirs':
            return theirs
        else:
            return ours # Default to ours

    new_content = pattern.sub(repl, content)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)

resolve_file('docs/api/ENDPOINTS.md', 'ours')
resolve_file('tests/unit/test_explorer_scope_guard.py', 'theirs')
resolve_file('backend/tests/test_pdf_generator.py', 'theirs')
resolve_file('backend/dynamic_result.json', 'theirs')

print("Resolved files successfully.")
