import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from app.services.discovery.security import SSRFSafeAsyncClient

logger = logging.getLogger(__name__)

async def crawl_for_apks(url: str, session, max_depth: int = 2) -> list[str]:
    """
    Crawls a given URL looking for .apk links.
    Returns a list of discovered APK URLs.
    """
    found_apks = set()
    visited = set()
    visited_github_repos = set()
    to_visit = [(url, 0)]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }

    async with SSRFSafeAsyncClient(timeout=15.0, headers=headers) as client:
        while to_visit:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited:
                continue
            visited.add(current_url)
            
            session.add_log(f"Crawling (depth {depth}): {current_url}")
            
            try:
                response = await client.get(current_url, follow_redirects=True)
                if response.status_code != 200:
                    continue
                    
                # Basic check if the URL itself is an APK
                content_type = response.headers.get("Content-Type", "").lower()
                if "application/vnd.android.package-archive" in content_type or current_url.lower().endswith(".apk"):
                     found_apks.add(current_url)
                     session.add_log(f"Found direct APK URL: {current_url}")
                     continue

                if "text/html" not in content_type:
                    continue
                    
                soup = BeautifulSoup(response.text, "html.parser")
                session.pages_scanned += 1
                
                # Look for anchor tags
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    full_url = urljoin(current_url, href)
                    
                    if full_url.lower().endswith(".apk"):
                        found_apks.add(full_url)
                        session.add_log(f"Found APK link in HTML: {full_url}")
                    elif "github.com" in urlparse(full_url).netloc and "/releases" in full_url:
                        # Extract the owner and repo to prevent duplicate API calls
                        import re
                        match = re.search(r"github\.com/([^/]+)/([^/]+)", full_url)
                        if match:
                            repo_key = f"{match.group(1)}/{match.group(2)}"
                            if repo_key not in visited_github_repos:
                                visited_github_repos.add(repo_key)
                                # Found a github release link, delegate to github resolver
                                from app.services.discovery.github import resolve_github_release
                                gh_apks = await resolve_github_release(full_url, session)
                                for apk in gh_apks:
                                    found_apks.add(apk)
                    elif depth < max_depth and urlparse(full_url).netloc == urlparse(url).netloc:
                        # Only follow links on the same domain
                        if full_url not in visited:
                             # Basic filter to avoid static assets
                             if not any(full_url.lower().endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".pdf", ".zip"]):
                                to_visit.append((full_url, depth + 1))
                                
            except Exception as e:
                logger.warning(f"[Crawler] Failed to fetch {current_url}: {e}")
                
    return list(found_apks)
