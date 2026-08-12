import re
import logging
from urllib.parse import urlparse
from app.services.discovery.crawler import crawl_for_apks
from app.services.discovery.github import resolve_github_release

logger = logging.getLogger(__name__)

def detect_store_link(url: str, session) -> str | None:
    """
    Detects if the URL is an official store link and returns the package ID if possible.
    """
    parsed = urlparse(url)
    if "play.google.com" in parsed.netloc and "/store/apps/details" in parsed.path:
        # Extract id parameter
        from urllib.parse import parse_qs
        qs = parse_qs(parsed.query)
        if "id" in qs:
            pkg_id = qs["id"][0]
            session.add_log(f"Detected Google Play Store link for package: {pkg_id}")
            return pkg_id
            
    if "f-droid.org" in parsed.netloc and "/packages/" in parsed.path:
         match = re.search(r"/packages/([^/]+)", parsed.path)
         if match:
             pkg_id = match.group(1)
             session.add_log(f"Detected F-Droid link for package: {pkg_id}")
             return pkg_id
             
    return None

async def resolve_url(url: str, session) -> tuple[list[str], str]:
    """
    Master resolver function. Determines the strategy based on the URL.
    Returns: (list_of_apk_urls, source_type)
    """
    store_pkg = detect_store_link(url, session)
    if store_pkg:
        # For store links, we don't return an APK download URL (yet)
        # We just report it as a store link candidate.
        return [], f"store:{store_pkg}"
        
    if "github.com" in urlparse(url).netloc:
        apks = await resolve_github_release(url, session)
        if apks:
            return apks, "github"
            
    # Fallback to HTML crawling
    session.add_log(f"Initiating HTML fallback crawl for {url}")
    apks = await crawl_for_apks(url, session)
    return apks, "html"
