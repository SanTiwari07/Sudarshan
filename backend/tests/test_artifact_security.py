import pytest
import asyncio
from pathlib import Path
import os
from sudarshan_core.storage.artifact_storage import LocalArtifactStorage

def test_local_artifact_storage_traversal(tmp_path):
    base_dir = tmp_path / "uploads"
    base_dir.mkdir()
    storage = LocalArtifactStorage(base_dir=str(base_dir))

    # Test valid
    assert storage._resolve("safe/file.txt") == (base_dir / "safe" / "file.txt").resolve()

@pytest.mark.parametrize("evil", [
    "../secret",
    "../../secret",
    "foo/../../secret",
    "uploads_evil/file",
    "/etc/passwd",
    "C:\\Windows\\System32\\cmd.exe",
    "d:/secret.txt",
    "....//secret",
    "%2e%2e%2fsecret"
])
def test_local_artifact_storage_traversal_evil(tmp_path, evil):
    base_dir = tmp_path / "uploads"
    base_dir.mkdir()
    storage = LocalArtifactStorage(base_dir=str(base_dir))
    with pytest.raises(ValueError):
        storage._resolve(evil)
