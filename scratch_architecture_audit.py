import os
import ast
import json

def analyze_frontend_components():
    frontend_dir = 'frontend/src'
    components = {}
    for root, _, files in os.walk(frontend_dir):
        if 'test' in root: continue
        for file in files:
            if file.endswith(('.tsx', '.ts')):
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        components[path] = len(content.split('\n'))
                except:
                    pass
    return components

def analyze_backend_routes():
    backend_dir = 'backend/app/routes'
    routes = []
    if os.path.exists(backend_dir):
        for root, _, files in os.walk(backend_dir):
            for file in files:
                if file.endswith('.py'):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            tree = ast.parse(f.read())
                            for node in ast.walk(tree):
                                if isinstance(node, ast.FunctionDef):
                                    for d in node.decorator_list:
                                        if isinstance(d, ast.Call) and hasattr(d.func, 'attr') and d.func.attr in ('get', 'post', 'put', 'delete', 'patch'):
                                            routes.append(f"{file} -> {d.func.attr} {node.name}")
                    except Exception as e:
                        pass
    return routes

print(json.dumps({
    'frontend_files_count': len(analyze_frontend_components()),
    'routes': analyze_backend_routes()
}, indent=2))
