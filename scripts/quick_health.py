#!/usr/bin/env python3
import requests, json

results = {}

# Backend health
try:
    r = requests.get("http://localhost:8000/health", timeout=5)
    results["backend_health"] = r.status_code
    results["backend_ok"] = r.json()
except Exception as e:
    results["backend_health"] = f"FAIL: {e}"

# Backend root
try:
    r = requests.get("http://localhost:8000/", timeout=5)
    d = r.json()
    results["backend_version"] = d.get("version")
    results["backend_engines"] = d.get("engines", [])
except Exception as e:
    results["backend_root"] = f"FAIL: {e}"

# MobSF
try:
    r = requests.get("http://localhost:8008/", timeout=5)
    results["mobsf_health"] = r.status_code
except Exception as e:
    results["mobsf_health"] = f"FAIL: {e}"

# Frontend
try:
    r = requests.get("http://localhost:5173/", timeout=5)
    results["frontend"] = r.status_code
except Exception as e:
    results["frontend"] = f"FAIL: {e}"

print(json.dumps(results, indent=2))
