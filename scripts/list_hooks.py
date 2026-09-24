import sys
from pathlib import Path
import re

content = Path("shared/sudarshan_core/engines/frida_hooks/banking_trojan.js").read_text(encoding="utf-8")
matches = re.findall(r"registerHook\((['\"])(.*?)\1\)", content)
print(f"Total registerHook calls: {len(matches)}")
for m in matches:
    print(f"  {m[1]}")
