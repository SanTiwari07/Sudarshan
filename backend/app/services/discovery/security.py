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
    It also intercepts redirects and re-validates the Location header.
    """
    async def request(self, method: str, url: str, *args, **kwargs):
        resolve_and_check_url(str(url))
        
        # Disable automatic redirect following to manually check each hop
        allow_redirects = kwargs.pop("follow_redirects", False)
        
        response = await super().request(method, url, follow_redirects=False, *args, **kwargs)
        
        if allow_redirects:
            redirect_count = 0
            max_redirects = 5
            while response.is_redirect and redirect_count < max_redirects:
                redirect_count += 1
                next_url = response.headers.get("location")
                if not next_url:
                    break
                # Handle relative redirects
                next_url = str(response.url.join(next_url))
                resolve_and_check_url(next_url)
                response = await super().request("GET", next_url, follow_redirects=False, *args, **kwargs)
                
            if response.is_redirect:
                raise HTTPException(status_code=400, detail="Too many redirects.")
                
        return response
