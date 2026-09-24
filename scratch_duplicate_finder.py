import os
import ast
import hashlib
import json
from collections import defaultdict
import difflib

def get_ast_hash(node):
    try:
        # Remove docstrings for comparison
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if ast.get_docstring(node):
                node.body = node.body[1:]
        
        # Unparse to get normalized source
        source = ast.unparse(node)
        # Hash it
        return hashlib.md5(source.encode('utf-8')).hexdigest(), source
    except Exception:
        return None, None

def find_duplicates(root_dir):
    py_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if 'venv' in dirpath or '__pycache__' in dirpath or '.git' in dirpath or '.venv' in dirpath:
            continue
        for f in filenames:
            if f.endswith('.py'):
                py_files.append(os.path.join(dirpath, f))

    functions = defaultdict(list)
    classes = defaultdict(list)
    file_hashes = defaultdict(list)
    
    file_contents = {}

    for filepath in py_files:
        try:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(filepath, 'r', encoding='utf-16') as f:
                    content = f.read()
            file_contents[filepath] = content
            file_hash = hashlib.md5(content.encode('utf-8', 'ignore')).hexdigest()
            file_hashes[file_hash].append(filepath)
                
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    h, src = get_ast_hash(node)
                    if h:
                        functions[h].append({
                            'file': filepath,
                            'name': node.name,
                            'line': node.lineno,
                            'source': src
                        })
                elif isinstance(node, ast.ClassDef):
                    h, src = get_ast_hash(node)
                    if h:
                        classes[h].append({
                            'file': filepath,
                            'name': node.name,
                            'line': node.lineno,
                            'source': src
                        })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

    # Filter out non-duplicates and trivial ones (like empty functions, pass, or just raise NotImplementedError)
    dup_funcs = {k: v for k, v in functions.items() if len(v) > 1 and len(v[0]['source']) > 50}
    dup_classes = {k: v for k, v in classes.items() if len(v) > 1 and len(v[0]['source']) > 50}
    dup_files = {k: v for k, v in file_hashes.items() if len(v) > 1}

    # Find file pairs with high similarity
    similar_files = []
    # (O(N^2) might be slow if there are many files, let's limit to files with same names or sizes)
    # Group by filename
    by_filename = defaultdict(list)
    for f in py_files:
        by_filename[os.path.basename(f)].append(f)
    
    for name, files in by_filename.items():
        if len(files) > 1:
            for i in range(len(files)):
                for j in range(i+1, len(files)):
                    f1 = files[i]
                    f2 = files[j]
                    if f1 not in file_contents or f2 not in file_contents:
                        continue
                    if f1 in dup_files.get(hashlib.md5(file_contents[f1].encode('utf-8', 'ignore')).hexdigest(), []):
                         continue # exact match already caught
                    # Check similarity
                    seq = difflib.SequenceMatcher(None, file_contents[f1], file_contents[f2])
                    if seq.ratio() > 0.8:
                        similar_files.append((f1, f2, seq.ratio()))

    # Also look for names that look like v1/v2 or old/new
    versioned_files = []
    for f1 in py_files:
        base1 = os.path.basename(f1)
        name1, ext1 = os.path.splitext(base1)
        for f2 in py_files:
            if f1 >= f2: continue
            base2 = os.path.basename(f2)
            name2, ext2 = os.path.splitext(base2)
            if (name1 in name2 or name2 in name1) and name1 != name2:
                if len(name1) > 4 and len(name2) > 4:
                    versioned_files.append((f1, f2))

    report = {
        'duplicate_files': dup_files,
        'duplicate_functions': dup_funcs,
        'duplicate_classes': dup_classes,
        'similar_files': similar_files,
        'versioned_files': versioned_files
    }

    with open('duplicate_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    find_duplicates(r"C:\Projects\Sudarshan")
