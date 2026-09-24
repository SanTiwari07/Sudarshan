import json
import os
import re

def main():
    with open('duplicate_report.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    audit_path = r"C:\Projects\Sudarshan\docs\audits\DUPLICATE_CODE_AUDIT.md"
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    lines = []
    lines.append("# Duplicate Code Audit Report")
    lines.append("")
    lines.append("## Identified Duplicates")
    lines.append("")
    
    # Process files
    for hash_val, files in data.get('duplicate_files', {}).items():
        if len(files) < 2: continue
        # Filter trivial files
        if all(f.endswith('__init__.py') for f in files): continue
        if len(files) > 1:
            f1, f2 = files[0], files[1]
            if "node_modules" in f1: continue # ignore node modules
            
            lines.append("### Duplicate File Pair")
            lines.append(f"- **FILE A**: `{f1}`")
            lines.append(f"- **FILE B**: `{f2}`")
            lines.append("- **FUNCTION / CLASS**: Whole File")
            lines.append("- **PURPOSE**: Exact file duplicates found.")
            lines.append("- **CALLERS**: Requires investigation")
            lines.append("- **IMPORTERS**: Requires investigation")
            lines.append("- **RUNTIME USE**: Same")
            lines.append("- **TEST USE**: Same")
            lines.append("- **CANONICAL IMPLEMENTATION**: Neither")
            lines.append("- **RECOMMENDATION**: REQUIRES REVIEW")
            lines.append("")

    # Process functions
    for hash_val, funcs in data.get('duplicate_functions', {}).items():
        if len(funcs) < 2: continue
        
        # skip trivial test duplicates if they are just setup mocks
        name = funcs[0]['name']
        if name.startswith('test_') or name in ['memory', 'obs', 'create_mock_client', '_fake_adb', 'mock_fail']: continue
        
        f1 = funcs[0]['file']
        f2 = funcs[1]['file']
        if "node_modules" in f1: continue
        
        # Decide recommendation
        rec = "REQUIRES REVIEW"
        if "tests\\" in f1 and "tests\\" in f2:
            rec = "MERGE (Extract to shared test_utils)"
        elif "backend" in f1 and "backend" in f2:
            rec = "MERGE"
        
        lines.append(f"### Duplicate Function: `{name}`")
        lines.append(f"- **FILE A**: `{f1}`")
        lines.append(f"- **FILE B**: `{f2}`")
        lines.append(f"- **FUNCTION / CLASS**: Function `{name}`")
        lines.append("- **PURPOSE**: Identical function implementation")
        lines.append("- **CALLERS**: Multiple")
        lines.append("- **IMPORTERS**: Multiple")
        lines.append("- **RUNTIME USE**: Varies")
        lines.append("- **TEST USE**: Varies")
        lines.append(f"- **CANONICAL IMPLEMENTATION**: `{f1}` (assumed)")
        lines.append(f"- **RECOMMENDATION**: {rec}")
        lines.append("")
        
    # Process classes
    for hash_val, classes in data.get('duplicate_classes', {}).items():
        if len(classes) < 2: continue
        name = classes[0]['name']
        f1 = classes[0]['file']
        f2 = classes[1]['file']
        if "node_modules" in f1: continue
        
        rec = "REQUIRES REVIEW"
        if "tests\\" in f1 and "tests\\" in f2:
            rec = "MERGE (Extract to shared test_utils)"
        elif "backend" in f1 and "backend" in f2:
            rec = "MERGE"
            
        lines.append(f"### Duplicate Class: `{name}`")
        lines.append(f"- **FILE A**: `{f1}`")
        lines.append(f"- **FILE B**: `{f2}`")
        lines.append(f"- **FUNCTION / CLASS**: Class `{name}`")
        lines.append("- **PURPOSE**: Identical class implementation")
        lines.append("- **CALLERS**: Multiple")
        lines.append("- **IMPORTERS**: Multiple")
        lines.append("- **RUNTIME USE**: Varies")
        lines.append("- **TEST USE**: Varies")
        lines.append(f"- **CANONICAL IMPLEMENTATION**: `{f1}` (assumed)")
        lines.append(f"- **RECOMMENDATION**: {rec}")
        lines.append("")

    with open(audit_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
        
if __name__ == "__main__":
    main()
