import os
from pathlib import Path

# Common Paths
ARTIFACTS_DIR = os.getenv("SUDARSHAN_ARTIFACTS_DIR", "sudarshan_artifacts")
UPLOADS_DIR = os.getenv("SUDARSHAN_UPLOAD_DIR", "/app/uploads")
DB_PATH = os.getenv("SUDARSHAN_DB_PATH", "sqlite:///sudarshan.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH}" if not str(DB_PATH).startswith("postgre") and not str(DB_PATH).startswith("sqlite") else DB_PATH)

# Endpoints / Hosts
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
ENGINE_URL = os.getenv("ENGINE_URL", "http://localhost:8001")
MOBSF_URL = os.getenv("MOBSF_URL", "http://localhost:8008")

# ADB
ADB_HOST = os.getenv("ADB_HOST", "")
ADB_PORT = int(os.getenv("ADB_PORT", 5555))
ADB_PATH = os.getenv("ADB_PATH", "adb")

# Frida
FRIDA_HOST = os.getenv("FRIDA_LISTEN_HOST", "127.0.0.1")
FRIDA_PORT = int(os.getenv("FRIDA_PORT", 27055))

# CORS
CORS_ALLOW_ORIGINS = [o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()]

