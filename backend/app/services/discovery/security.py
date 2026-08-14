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
    """
    Parses the URL, resolves the hostname to an IP, and checks against the denylist.
    Raises HTTPException if the IP is blocked.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Invalid URL schema. Only http and https are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL format.")

    try:
        # Resolve all IPs for the hostname
        addrs = socket.getaddrinfo(hostname, None)
        ips = {addr[4][0] for addr in addrs}
    except socket.gaierror as e:
        logger.warning(f"[Discovery] DNS resolution failed for {hostname}: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to resolve hostname: {hostname}")

    for ip in ips:
        if not is_safe_ip(ip):
            logger.warning(f"[Discovery] Blocked access to unsafe IP {ip} for {url}")
            raise HTTPException(status_code=403, detail="Access to internal or private IPs is forbidden.")

class SSRFSafeAsyncClient(httpx.AsyncClient):
    """
    An httpx.AsyncClient that checks the URL against an IP denylist before fetching.
    By overriding `send`, we ensure that all requests, including streams and 
    automatically followed redirects, are intercepted and validated.
    """
    async def send(self, request: httpx.Request, *args, **kwargs):
        resolve_and_check_url(str(request.url))
        return await super().send(request, *args, **kwargs)
