import os
import tempfile
import logging
from pathlib import Path
from fastapi import HTTPException
from app.services.discovery.security import SSRFSafeAsyncClient

logger = logging.getLogger(__name__)

# Re-use MAX_UPLOAD_BYTES limit
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(200 * 1024 * 1024)))
_UPLOAD_CHUNK_BYTES = 8 * 1024 * 1024
_UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", "/app/uploads"))
_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

async def secure_download_apk(url: str, session_id: str) -> str:
    """
    Securely streams an APK to a temporary file in the shared uploads directory.
    Enforces size limits and checks magic bytes early.
    Returns the path to the downloaded file.
    """
    total = 0
    temp_path = None
    
    try:
        async with SSRFSafeAsyncClient(timeout=60.0) as client:
            async with client.stream("GET", url, follow_redirects=True) as response:
                if response.status_code != 200:
                    raise HTTPException(status_code=400, detail=f"Download failed with status {response.status_code}")
                
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)}MB limit.")

                with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=_UPLOADS_DIR, prefix=f"disc_{session_id}_") as tmp:
                    temp_path = tmp.name
                    first = True
                    
                    async for chunk in response.aiter_bytes(chunk_size=_UPLOAD_CHUNK_BYTES):
                        if not chunk:
                            continue
                            
                        if first:
                            if not chunk.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
                                raise HTTPException(status_code=400, detail="Downloaded file is not a valid ZIP/APK (magic byte mismatch).")
                            first = False
                            
                        total += len(chunk)
                        if total > MAX_UPLOAD_BYTES:
                            raise HTTPException(status_code=413, detail=f"Stream exceeded {MAX_UPLOAD_BYTES // (1024*1024)}MB limit.")
                            
                        tmp.write(chunk)
                        
                    if first:
                        raise HTTPException(status_code=400, detail="Empty download.")
                        
        return temp_path
        
    except Exception as e:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass
        if isinstance(e, HTTPException):
            raise e
        logger.error(f"[Discovery] Download error for {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")
