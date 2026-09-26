import ipaddress
import socket
import logging
from urllib.parse import urlparse
import httpx
from fastapi import HTTPException

logger = logging.getLogger(__name__)

def is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_loopback or
            ip.is_private or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_unspecified
        ):
            return False
        return True
    except ValueError:
        return False

def resolve_and_check_url(url: str) -> None:
    # Legacy wrapper for compatibility with tests that expect None
    resolve_and_get_ip(url)

def resolve_and_get_ip(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Invalid URL schema. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL format.")

    try:
        # Resolve all IPs for the hostname
        addrs = socket.getaddrinfo(hostname, None)
        ips = [addr[4][0] for addr in addrs]
    except socket.gaierror as e:
        logger.warning(f"[Discovery] DNS resolution failed for {hostname}: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to resolve hostname: {hostname}")

    safe_ip = None
    for ip in ips:
        if not is_safe_ip(ip):
            logger.warning(f"[Discovery] Blocked access to unsafe IP {ip} for {url}")
            raise HTTPException(status_code=403, detail="Access to internal or private IPs is forbidden.")
        if safe_ip is None:
            safe_ip = ip
            
    if not safe_ip:
        raise HTTPException(status_code=403, detail="No safe IPs found")
        
    return safe_ip

class _SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """
    Validates and IP-pins EVERY request the client sends, including each hop
    of a followed redirect.

    This used to live in AsyncClient.send(), which httpx calls once per
    top-level request - redirects are followed further down the stack without
    re-entering send(). A public URL answering 302 -> http://127.0.0.1/ (or the
    cloud metadata address) was therefore fetched unchecked. The transport is
    the one layer every hop passes through.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        safe_ip = resolve_and_get_ip(str(request.url))
        parsed = urlparse(str(request.url))
        extensions = dict(request.extensions)
        if parsed.scheme == "https" and parsed.hostname:
            # Connect to the pinned IP but present/verify the real hostname in
            # TLS; without it every HTTPS handshake failed.
            extensions["sni_hostname"] = parsed.hostname
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=safe_ip),
            headers=request.headers,  # keeps the original Host header
            stream=request.stream,
            extensions=extensions,
        )
        return await super().handle_async_request(pinned)


class SSRFSafeAsyncClient(httpx.AsyncClient):
    """An httpx.AsyncClient whose every request - redirects included - is SSRF-checked."""

    def __init__(self, *args, **kwargs):
        kwargs.pop("transport", None)
        super().__init__(*args, transport=_SSRFSafeTransport(), **kwargs)
