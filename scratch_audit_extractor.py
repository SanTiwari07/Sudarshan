import os
import re
import json
from pathlib import Path

FRONTEND_DIR = r"c:\Projects\Sudarshan\frontend\src"
BACKEND_DIR = r"c:\Projects\Sudarshan\backend\app"
SHARED_DIR = r"c:\Projects\Sudarshan\shared\sudarshan_core"

def scan_frontend():
    routes = []
    components = []
    api_calls = []
    hardcoded = []
    
    for root, _, files in os.walk(FRONTEND_DIR):
        for f in files:
            if not f.endswith('.tsx') and not f.endswith('.ts'): continue
            path = os.path.join(root, f)
            try:
                content = open(path, 'r', encoding='utf-8').read()
            except: continue
            
            # Find routes
            if 'Route path=' in content or 'path:' in content:
                routes.append(path)
            
            # Find API calls
            calls = re.findall(r'(axios|fetch|api\.)\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]', content)
            for c in calls:
                api_calls.append((path, c[2]))
                
            # Find hardcoded strings / placeholder data (heuristic)
            if 'TODO' in content or 'FIXME' in content or 'mock' in content.lower() or 'dummy' in content.lower():
                hardcoded.append(path)
                
    return {'routes': routes, 'api_calls': api_calls, 'hardcoded_indicators': hardcoded}

def scan_backend():
    endpoints = []
    models = []
    for root, _, files in os.walk(BACKEND_DIR):
        for f in files:
            if not f.endswith('.py'): continue
            path = os.path.join(root, f)
            try:
                content = open(path, 'r', encoding='utf-8').read()
            except: continue
            
            # Endpoints
            eps = re.findall(r'@(router|app)\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]', content)
            for ep in eps:
                endpoints.append((path, ep[1], ep[2]))
                
            # DB Models
            if 'BaseModel' in content or 'declarative_base' in content:
                models.append(path)
                
    return {'endpoints': endpoints, 'models': models}

if __name__ == '__main__':
    data = {
        'frontend': scan_frontend(),
        'backend': scan_backend()
    }
    with open('audit_dump.json', 'w') as f:
        json.dump(data, f, indent=2)
    print("Done")
