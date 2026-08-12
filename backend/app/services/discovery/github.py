import re
import logging
from app.services.discovery.security import SSRFSafeAsyncClient

logger = logging.getLogger(__name__)

async def resolve_github_release(url: str, session) -> list[str]:
    """
    Parses a GitHub URL and attempts to find APK assets in the latest release.
    """
    match = re.search(r"github\.com/([^/]+)/([^/]+)", url)
    if not match:
        return []
        
    owner, repo = match.groups()
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    session.add_log(f"Attempting GitHub API resolution: {api_url}")
    
    headers = {"Accept": "application/vnd.github.v3+json"}
    found_apks = []
    
    try:
        async with SSRFSafeAsyncClient(timeout=10.0, headers=headers) as client:
            response = await client.get(api_url, follow_redirects=True)
            if response.status_code == 200:
                data = response.json()
                for asset in data.get("assets", []):
                    name = asset.get("name", "")
                    if name.lower().endswith(".apk"):
                        download_url = asset.get("browser_download_url")
                        if download_url:
                            found_apks.append(download_url)
                            session.add_log(f"Found GitHub Release APK: {name}")
            else:
                 session.add_log(f"GitHub API returned {response.status_code}")
    except Exception as e:
        logger.warning(f"GitHub resolution failed for {url}: {e}")
        session.add_log(f"GitHub resolution error: {e}")
        
    return found_apks
