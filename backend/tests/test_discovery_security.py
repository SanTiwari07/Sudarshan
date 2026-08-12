import pytest
import httpx
from fastapi import HTTPException
from app.services.discovery.security import is_safe_ip, resolve_and_check_url

def test_is_safe_ip():
    assert is_safe_ip("8.8.8.8") == True
    assert is_safe_ip("142.250.67.202") == True
    
    assert is_safe_ip("127.0.0.1") == False
    assert is_safe_ip("10.0.0.1") == False
    assert is_safe_ip("192.168.1.100") == False
    assert is_safe_ip("172.16.0.5") == False
    assert is_safe_ip("169.254.169.254") == False
    assert is_safe_ip("0.0.0.0") == False
    assert is_safe_ip("::1") == False
    assert is_safe_ip("fc00::1") == False
    assert is_safe_ip("fe80::1") == False

def test_resolve_and_check_url_valid():
    # Should not raise exception
    resolve_and_check_url("https://github.com/ImranR98/Obtainium")
    resolve_and_check_url("http://example.com")

def test_resolve_and_check_url_invalid_schema():
    with pytest.raises(HTTPException) as exc:
        resolve_and_check_url("file:///etc/passwd")
    assert exc.value.status_code == 400

def test_resolve_and_check_url_localhost():
    with pytest.raises(HTTPException) as exc:
        resolve_and_check_url("http://localhost:8080")
    assert exc.value.status_code == 403

def test_resolve_and_check_url_metadata():
    with pytest.raises(HTTPException) as exc:
        resolve_and_check_url("http://169.254.169.254/latest/meta-data/")
    assert exc.value.status_code == 403
