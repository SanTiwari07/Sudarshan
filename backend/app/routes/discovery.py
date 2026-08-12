import logging
import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.auth.auth import require_analyst
from app.db.database import (
    save_discovery_session, get_discovery_session,
    save_discovery_candidate, get_discovery_candidates
)
from app.services.discovery.models import DiscoverySession, DiscoveryCandidate, SessionStatus, CandidateStatus
from app.services.discovery.resolver import resolve_url
from app.services.discovery.downloader import secure_download_apk
from app.services.discovery.validator import validate_apk

# Needed for analysis handoff
from app.workers.analysis_queue import create_job, persist_job, enqueue

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/discovery", tags=["APK Discovery"])

class StartDiscoveryRequest(BaseModel):
    url: str

class AnalyzeCandidateRequest(BaseModel):
    candidate_id: str

async def _run_discovery_background(session: DiscoverySession):
    """Background task that crawls, downloads, and validates APKs."""
    try:
        session.add_log("Starting discovery engine...")
        await save_discovery_session(session.model_dump())
        
        apk_urls, source_type = await resolve_url(session.target_url, session)
        
        if not apk_urls and not source_type.startswith("store:"):
            session.add_log("No APK links found during discovery.")
            session.status = SessionStatus.COMPLETED
            await save_discovery_session(session.model_dump())
            return
            
        for apk_url in apk_urls:
            candidate = DiscoveryCandidate(
                session_id=session.id,
                source_url=session.target_url,
                discovery_url=apk_url,
                source_type=source_type,
            )
            await save_discovery_candidate(candidate.model_dump())
            
            # Download
            candidate.download_status = CandidateStatus.DOWNLOADING
            session.add_log(f"Downloading candidate from {apk_url}")
            await save_discovery_candidate(candidate.model_dump())
            
            try:
                # This enforces size limits and streaming
                temp_path = await secure_download_apk(apk_url, session.id)
                candidate.storage_path = temp_path
                
                import os
                candidate.size = os.path.getsize(temp_path)
                candidate.filename = os.path.basename(temp_path) # we will rename during validation if needed
                
                session.add_log(f"Download complete: {candidate.size / (1024*1024):.2f} MB")
                
                # Validation
                candidate.download_status = CandidateStatus.VALIDATING
                await save_discovery_candidate(candidate.model_dump())
                session.add_log("Validating downloaded APK...")
                
                # Yield to not block the event loop heavily during validation (especially hashing large files)
                is_valid, sha256_hash, error_msg = await asyncio.to_thread(validate_apk, temp_path)
                
                if is_valid:
                    candidate.validation_status = CandidateStatus.VALID_APK
                    candidate.sha256 = sha256_hash
                    session.add_log(f"Candidate validated successfully (SHA-256: {sha256_hash[:8]}...)")
                else:
                    candidate.validation_status = CandidateStatus.INVALID_APK
                    candidate.error = error_msg
                    session.add_log(f"Candidate validation failed: {error_msg}")
                    # Cleanup invalid file
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                    
            except Exception as e:
                candidate.download_status = CandidateStatus.DOWNLOAD_FAILED
                candidate.error = str(e)
                session.add_log(f"Download failed: {e}")
                
            await save_discovery_candidate(candidate.model_dump())
            
        session.status = SessionStatus.COMPLETED
        session.add_log("Discovery session completed.")
        await save_discovery_session(session.model_dump())
        
    except Exception as e:
        logger.exception(f"Discovery engine error for {session.id}: {e}")
        session.status = SessionStatus.FAILED
        session.error = str(e)
        session.add_log(f"Critical error: {e}")
        await save_discovery_session(session.model_dump())

@router.post("/start")
async def start_discovery(req: StartDiscoveryRequest, background_tasks: BackgroundTasks, user: dict = Depends(require_analyst)):
    """Starts a new asynchronous discovery session for a given URL."""
    from urllib.parse import urlparse
    parsed = urlparse(req.url)
    domain = parsed.netloc if parsed.netloc else "unknown"
    
    session = DiscoverySession(target_url=req.url, domain=domain)
    
    # Save initial state
    await save_discovery_session(session.model_dump())
    
    # Kick off background process
    background_tasks.add_task(_run_discovery_background, session)
    
    return {"session_id": session.id, "status": session.status}

@router.get("/{session_id}/status")
async def get_status(session_id: str, user: dict = Depends(require_analyst)):
    """Polling endpoint for discovery session status and logs."""
    session_data = await get_discovery_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Discovery session not found.")
    
    # Exclude heavy objects like full candidate lists, just return progress
    return {
        "session_id": session_data["id"],
        "status": session_data["status"],
        "pages_scanned": session_data.get("pages_scanned", 0),
        "error": session_data.get("error"),
        "progress_logs": session_data.get("progress_logs", [])
    }

@router.get("/{session_id}/results")
async def get_results(session_id: str, user: dict = Depends(require_analyst)):
    """Returns the list of candidates discovered and validated in the session."""
    session_data = await get_discovery_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Discovery session not found.")
        
    candidates = await get_discovery_candidates(session_id)
    return {"candidates": candidates}

@router.post("/{session_id}/analyze")
async def analyze_candidate(session_id: str, req: AnalyzeCandidateRequest, user: dict = Depends(require_analyst)):
    """Takes a successfully validated candidate and hands it off to the existing analysis pipeline."""
    candidates = await get_discovery_candidates(session_id)
    target_candidate = next((c for c in candidates if c["id"] == req.candidate_id), None)
    
    if not target_candidate:
        raise HTTPException(status_code=404, detail="Candidate not found.")
        
    if target_candidate.get("validation_status") != CandidateStatus.VALID_APK.value:
        raise HTTPException(status_code=400, detail="Cannot analyze an invalid or unvalidated candidate.")
        
    storage_path = target_candidate.get("storage_path")
    sha256_hash = target_candidate.get("sha256")
    filename = target_candidate.get("filename") or "discovered.apk"
    
    if not storage_path or not sha256_hash:
         raise HTTPException(status_code=500, detail="Candidate is missing storage path or hash.")
         
    import os
    if not os.path.exists(storage_path):
         raise HTTPException(status_code=404, detail="Candidate file was deleted or lost.")

    # Reuse the exact same async analysis entrypoint contract as upload.py
    job_id = create_job(sha256_hash=sha256_hash, analyst_id=user.get("id"))
    await persist_job(job_id)
    await enqueue(job_id, storage_path, filename, sha256_hash, analyst_id=user.get("id"))

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Analysis job queued from discovery candidate. Poll /api/v1/status/{job_id} for result.",
        "sha256": sha256_hash
    }
