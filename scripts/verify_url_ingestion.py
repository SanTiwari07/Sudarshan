import asyncio
import hashlib
import tempfile
import os
import shutil
import zipfile
import threading
import uvicorn
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.responses import Response, StreamingResponse, RedirectResponse

# Mock SSRF protection to allow localhost testing
from app.services.discovery.security import is_safe_ip
import app.services.discovery.security
import app.services.discovery.downloader

app.services.discovery.security.is_safe_ip = lambda ip: True

from app.services.discovery.downloader import secure_download_apk
from app.services.discovery.validator import validate_apk

# Constants
TEST_PORT = 19999
TEST_APK_BYTES = b"PK\x03\x04" + os.urandom(1024) # Minimum fake ZIP
VALID_APK_PATH = Path("test_artifact.apk")

def create_valid_apk():
    with zipfile.ZipFile(VALID_APK_PATH, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        z.writestr("classes.dex", b"DEX")

create_valid_apk()
VALID_APK_BYTES = VALID_APK_PATH.read_bytes()
VALID_APK_SHA256 = hashlib.sha256(VALID_APK_BYTES).hexdigest()

# HTTP Server routes using FastAPI
mock_app = FastAPI()

@mock_app.get('/valid.apk')
async def handle_valid_apk():
    return Response(content=VALID_APK_BYTES, media_type="application/vnd.android.package-archive")

@mock_app.get('/redirect.apk')
async def handle_redirect():
    return RedirectResponse(url='/valid.apk')

@mock_app.get('/redirect-loop')
async def handle_redirect_loop():
    return RedirectResponse(url='/redirect-loop')

@mock_app.get('/html')
async def handle_html():
    return Response(content="<html><body>Not an APK</body></html>", media_type="text/html")

@mock_app.get('/large.apk')
async def handle_large():
    async def large_stream():
        chunk = b"0" * (10 * 1024 * 1024)
        for _ in range(25): # 250MB
             yield chunk
             await asyncio.sleep(0.01)
    return StreamingResponse(large_stream(), headers={'Content-Length': str(250 * 1024 * 1024)})

@mock_app.get('/slow.apk')
async def handle_slow():
    async def slow_stream():
        await asyncio.sleep(65)
        yield b"PK\x03\x04" + b"0"*1024
    return StreamingResponse(slow_stream(), headers={'Content-Length': str(10 * 1024 * 1024)})

def start_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=TEST_PORT, log_level="critical")

# Start background server
server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

import time
time.sleep(2)

import sys

async def run_tests():
    print("--- STARTING URL INGESTION VERIFICATION ---")
    session_id = "test_session_123"
    
    # 1. Valid APK
    print("Testing Valid APK Download...")
    try:
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/valid.apk", session_id)
        is_valid, sha256, err = validate_apk(temp_path)
        assert is_valid == True, f"Failed validation: {err}"
        assert sha256 == VALID_APK_SHA256, f"SHA256 mismatch! Expected {VALID_APK_SHA256}, got {sha256}"
        print("✅ Valid APK passed")
        os.remove(temp_path)
    except Exception as e:
        print(f"❌ Valid APK failed: {e}")

    # 2. Redirect
    print("Testing Redirect...")
    try:
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/redirect.apk", session_id)
        is_valid, sha256, err = validate_apk(temp_path)
        assert is_valid == True
        assert sha256 == VALID_APK_SHA256
        print("✅ Redirect passed")
        os.remove(temp_path)
    except Exception as e:
        print(f"❌ Redirect failed: {e}")
        
    # 3. HTML Response
    print("Testing HTML Response...")
    try:
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/html", session_id)
        print("❌ HTML Response failed: Should have raised Exception but didn't")
    except Exception as e:
        if "magic byte mismatch" in str(e).lower() or "not a valid zip/apk" in str(e).lower():
             print("✅ HTML Response properly rejected")
        else:
             print(f"❌ HTML Response failed with unexpected error: {e}")

    # 4. Redirect Loop
    print("Testing Redirect Loop...")
    try:
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/redirect-loop", session_id)
        print("❌ Redirect Loop failed: Should have raised Exception but didn't")
    except Exception as e:
        if "too many redirects" in str(e).lower():
            print("✅ Redirect Loop properly rejected")
        else:
            print(f"❌ Redirect Loop failed with unexpected error: {e}")

    # 5. Oversized APK
    print("Testing Large APK...")
    try:
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/large.apk", session_id)
        print("❌ Large APK failed: Should have raised Exception but didn't")
    except Exception as e:
        if "limit" in str(e).lower() or "exceeds" in str(e).lower():
             print("✅ Large APK properly rejected")
        else:
             print(f"❌ Large APK failed with unexpected error: {e}")
             
    # 6. SSRF Protection (Restore is_safe_ip and test)
    print("Testing SSRF Protection...")
    # Unmock
    def original_safe_ip(ip_str):
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified: return False
            return True
        except ValueError:
            return False
    app.services.discovery.security.is_safe_ip = original_safe_ip
    
    try:
        # We need a fresh httpx client without the mocked is_safe_ip
        temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/valid.apk", session_id)
        print("❌ SSRF Protection failed: allowed 127.0.0.1")
    except Exception as e:
        if "forbidden" in str(e).lower() or "private" in str(e).lower() or "internal" in str(e).lower():
            print("✅ SSRF Protection properly rejected localhost")
        else:
            print(f"❌ SSRF Protection failed with unexpected error: {e}")
            
    print("--- VERIFICATION COMPLETE ---")
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(run_tests())
