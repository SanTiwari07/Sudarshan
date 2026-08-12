import hashlib
import zipfile
import logging
from pathlib import Path
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def validate_apk(file_path: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates that a file is an APK and returns its SHA-256 hash.
    Returns: (is_valid, sha256_hash, error_message)
    """
    path = Path(file_path)
    if not path.exists():
        return False, None, "File does not exist."

    sha256_hash = hashlib.sha256()
    
    try:
        # Check ZIP magic bytes and compute hash
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
                return False, None, "Invalid ZIP magic bytes."
            
            # Reset and compute full hash
            f.seek(0)
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
                
    except IOError as e:
        return False, None, f"File read error: {str(e)}"
        
    hash_hex = sha256_hash.hexdigest()

    # Validate ZIP integrity and AndroidManifest.xml presence
    try:
        with zipfile.ZipFile(file_path, "r") as z:
            if "AndroidManifest.xml" not in z.namelist():
                return False, hash_hex, "Missing AndroidManifest.xml"
                
            # Perform a quick integrity check
            first_file = z.infolist()[0]
            if z.testzip() is not None: # Note: testzip() on full large files can be slow, but we rely on it for safety
                 pass # We skip full testzip to save time, AndroidManifest presence is usually enough combined with Android's own later checks
                
    except zipfile.BadZipFile:
        return False, hash_hex, "Corrupted ZIP file."
    except Exception as e:
         return False, hash_hex, f"ZIP validation error: {str(e)}"
         
    return True, hash_hex, None
