import os
import sys
import subprocess

base_dir = os.path.dirname(os.path.abspath(__file__))
env = os.environ.copy()
env["PYTHONPATH"] = f"{os.path.join(base_dir, 'backend')}{os.pathsep}{os.path.join(base_dir, 'shared')}"
env["JWT_SECRET_KEY"] = "test"
print("PYTHONPATH is", env["PYTHONPATH"])

cmd = [os.path.join(base_dir, "backend", ".venv", "Scripts", "python.exe"), "-m", "pytest", "backend/tests/", "tests/"]
subprocess.run(cmd, env=env)
