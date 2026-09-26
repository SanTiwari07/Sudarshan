import io
import asyncio
import hashlib
import os
import zipfile
import threading
import uvicorn
from pathlib import Path
import pytest
from fastapi import FastAPI
from fastapi.responses import Response, StreamingResponse, RedirectResponse

from app.services.discovery.security import is_safe_ip
import app.services.discovery.security
from app.services.discovery.downloader import secure_download_apk
from app.services.discovery.validator import validate_apk
from fastapi import HTTPException
import httpx

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 0))
TEST_PORT = s.getsockname()[1]
s.close()
def create_valid_apk() -> bytes:
    # Built in memory: writing it to the CWD left test_artifact_pytest.apk in
    # the repository root after every run.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        z.writestr("classes.dex", b"DEX")
    return buf.getvalue()

VALID_APK_BYTES = create_valid_apk()
VALID_APK_SHA256 = hashlib.sha256(VALID_APK_BYTES).hexdigest()

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

def start_server():
    uvicorn.run(mock_app, host="127.0.0.1", port=TEST_PORT, log_level="critical")

# Start background server
server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

import time
time.sleep(2) # wait for server


# --- PYTEST SUITE ---

@pytest.fixture(autouse=True)
def mock_ssrf_for_tests(monkeypatch):
    """Bypass SSRF protection for 127.0.0.1 for most tests, but keep original for the SSRF test."""
    original = app.services.discovery.security.is_safe_ip
    
    def bypass_is_safe_ip(ip_str):
        if ip_str == "127.0.0.1": return True
        return original(ip_str)
        
    monkeypatch.setattr(app.services.discovery.security, 'is_safe_ip', bypass_is_safe_ip)
    yield
    # unpatched automatically by monkeypatch

@pytest.mark.anyio
async def test_valid_apk_download():
    session_id = "test_valid"
    temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/valid.apk", session_id)
    is_valid, sha256, err = validate_apk(temp_path)
    assert is_valid == True
    assert sha256 == VALID_APK_SHA256
    assert err is None
    os.remove(temp_path)

@pytest.mark.anyio
async def test_redirect():
    session_id = "test_redirect"
    temp_path = await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/redirect.apk", session_id)
    is_valid, sha256, err = validate_apk(temp_path)
    assert is_valid == True
    assert sha256 == VALID_APK_SHA256
    os.remove(temp_path)

@pytest.mark.anyio
async def test_html_response_rejected():
    session_id = "test_html"
    with pytest.raises(HTTPException) as excinfo:
        await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/html", session_id)
    assert "not a valid ZIP/APK" in str(excinfo.value.detail).lower() or "magic byte mismatch" in str(excinfo.value.detail).lower()

@pytest.mark.anyio
async def test_redirect_loop_rejected():
    session_id = "test_loop"
    with pytest.raises(HTTPException) as excinfo:
        await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/redirect-loop", session_id)
    assert "redirect" in str(excinfo.value.detail).lower()

@pytest.mark.anyio
async def test_large_apk_rejected():
    session_id = "test_large"
    with pytest.raises(HTTPException) as excinfo:
        await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/large.apk", session_id)
    assert "exceed" in str(excinfo.value.detail).lower() or "limit" in str(excinfo.value.detail).lower()

@pytest.mark.anyio
async def test_ssrf_protection(monkeypatch):
    """Test that the SSRF protection actually blocks 127.0.0.1 when not mocked."""
    # Remove the mock
    monkeypatch.setattr(app.services.discovery.security, 'is_safe_ip', 
                        lambda ip: False if "127.0.0.1" in ip or "localhost" in ip else True)
    
    session_id = "test_ssrf"
    with pytest.raises(HTTPException) as excinfo:
        await secure_download_apk(f"http://127.0.0.1:{TEST_PORT}/valid.apk", session_id)
    assert "forbidden" in str(excinfo.value.detail).lower() or "private" in str(excinfo.value.detail).lower()
