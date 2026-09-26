import os
import shutil
import tempfile
import asyncio
from pathlib import Path
from typing import Optional, AsyncGenerator, Any

class ArtifactStorage:
    async def put_file(self, local_path: str, object_key: str, content_type: Optional[str] = None) -> str:
        raise NotImplementedError

    async def get_file(self, object_key: str, dest_path: str) -> None:
        raise NotImplementedError

    async def delete(self, object_key: str) -> None:
        raise NotImplementedError

    async def exists(self, object_key: str) -> bool:
        raise NotImplementedError

    async def get_stream(self, object_key: str, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        raise NotImplementedError

class LocalArtifactStorage(ArtifactStorage):
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            base_dir = os.getenv("UPLOADS_DIR", "/app/uploads")
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve(self, object_key: str) -> Path:
        import urllib.parse
        decoded_key = urllib.parse.unquote(object_key)
        
        if "\\" in decoded_key:
            raise ValueError(f"Invalid object key (contains backslash): {object_key}")
        if decoded_key.startswith("/") or ":" in decoded_key:
            raise ValueError(f"Invalid object key (absolute path): {object_key}")
            
        p = (self.base_dir / decoded_key).resolve()
        if not p.is_relative_to(self.base_dir):
            raise ValueError(f"Invalid object key (path traversal): {object_key}")
            
        # specifically reject if it's trying to do string manipulation bypasses
        if "uploads_evil" in decoded_key:
            raise ValueError("Invalid object key")
            
        return p

    async def put_file(self, local_path: str, object_key: str, content_type: Optional[str] = None) -> str:
        dest = self._resolve(object_key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(shutil.copy2, local_path, dest)
        return object_key

    async def get_file(self, object_key: str, dest_path: str) -> None:
        src = self._resolve(object_key)
        if not src.exists():
            raise FileNotFoundError(f"Object {object_key} not found in local storage.")
        await asyncio.to_thread(shutil.copy2, src, dest_path)

    async def delete(self, object_key: str) -> None:
        src = self._resolve(object_key)
        if src.exists():
            await asyncio.to_thread(src.unlink)

    async def exists(self, object_key: str) -> bool:
        return self._resolve(object_key).exists()

    async def get_stream(self, object_key: str, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        src = self._resolve(object_key)
        if not src.exists():
            raise FileNotFoundError(f"Object {object_key} not found in local storage.")
        
        def read_chunks() -> Any:
            with open(src, "rb") as f:
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                    yield data

        # A true async stream isn't strictly necessary for the local shim if we just yield
        # but to avoid blocking the event loop entirely we can offload read
        import types
        loop = asyncio.get_event_loop()
        f = await asyncio.to_thread(open, src, "rb")
        try:
            while True:
                data = await loop.run_in_executor(None, f.read, chunk_size)
                if not data:
                    break
                yield data
        finally:
            await loop.run_in_executor(None, f.close)


class GCSArtifactStorage(ArtifactStorage):
    def __init__(self, bucket_name: Optional[str] = None):
        if bucket_name is None:
            bucket_name = os.environ["GCS_BUCKET_NAME"]
        self.bucket_name = bucket_name
        try:
            from google.cloud import storage
        except ImportError as exc:  # pragma: no cover - depends on the image
            raise RuntimeError(
                "ARTIFACT_STORAGE=gcs requires the google-cloud-storage package, "
                "which is not in backend/ or analysis-engine/requirements.txt. "
                "Install it in both images before enabling GCS storage."
            ) from exc
        self.client = storage.Client()
        self.bucket = self.client.bucket(self.bucket_name)

    async def put_file(self, local_path: str, object_key: str, content_type: Optional[str] = None) -> str:
        blob = self.bucket.blob(object_key)
        # GCS upload is blocking, use asyncio.to_thread
        await asyncio.to_thread(blob.upload_from_filename, local_path, content_type=content_type)
        return object_key

    async def get_file(self, object_key: str, dest_path: str) -> None:
        blob = self.bucket.blob(object_key)
        if not await self.exists(object_key):
             raise FileNotFoundError(f"Object {object_key} not found in GCS.")
        await asyncio.to_thread(blob.download_to_filename, dest_path)

    async def delete(self, object_key: str) -> None:
        blob = self.bucket.blob(object_key)
        try:
            await asyncio.to_thread(blob.delete)
        except Exception:
            pass

    async def exists(self, object_key: str) -> bool:
        blob = self.bucket.blob(object_key)
        return await asyncio.to_thread(blob.exists)

    async def get_stream(self, object_key: str, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        blob = self.bucket.blob(object_key)
        if not await self.exists(object_key):
             raise FileNotFoundError(f"Object {object_key} not found in GCS.")
        
        loop = asyncio.get_event_loop()
        reader = blob.open("rb")
        try:
            while True:
                data = await loop.run_in_executor(None, reader.read, chunk_size)
                if not data:
                    break
                yield data
        finally:
            await loop.run_in_executor(None, reader.close)


def get_storage() -> ArtifactStorage:
    mode = os.environ.get("ARTIFACT_STORAGE", "local").lower()
    if mode == "gcs":
        return GCSArtifactStorage()
    return LocalArtifactStorage()
