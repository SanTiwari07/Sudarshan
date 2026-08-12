import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class CandidateStatus(str, Enum):
    PENDING = "pending"
    DOWNLOADING = "downloading"
    DOWNLOAD_FAILED = "download_failed"
    VALIDATING = "validating"
    VALID_APK = "valid_apk"
    INVALID_APK = "invalid_apk"

class SessionStatus(str, Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"

class DiscoveryCandidate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    source_url: str
    discovery_url: str
    filename: Optional[str] = None
    source_type: str  # e.g., "html", "github", "store"
    package_id: Optional[str] = None
    download_status: str = CandidateStatus.PENDING
    validation_status: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    storage_path: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class DiscoverySession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    domain: str
    status: str = SessionStatus.IN_PROGRESS
    pages_scanned: int = 0
    candidates: List[DiscoveryCandidate] = []
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    progress_logs: List[str] = []

    def add_log(self, message: str):
        self.progress_logs.append(message)
        self.updated_at = datetime.now(timezone.utc)
