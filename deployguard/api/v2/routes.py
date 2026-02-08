"""
DeployGuard API v2 - FastAPI Routes
RESTful API for repository scanning and cleaning

This module provides the REST API endpoints for the DeployGuard service.
The API requires RabbitMQ and MinIO to be available for background job processing.
The CLI operates independently without these dependencies.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks, Header
from fastapi.responses import StreamingResponse, RedirectResponse
from sqlalchemy.orm import Session

from .models import (
    Job, SecretFound, AuditLog, JobStatus,
    JobCreateRequest, JobResponse, JobDetailResponse,
    SecretFoundResponse, SecretSelectionRequest, PushRequest,
    get_db_session
)
from .tasks import (
    scan_repository_task, clean_repository_task, push_repository_task,
    StorageClient, check_broker_connection
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2", tags=["DeployGuard API v2"])


# Dependency to get database session
def get_db():
    db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
    try:
        yield db
    finally:
        db.close()


def get_current_user(x_user_id: str = Header(..., description="User ID from auth service")):
    """Extract user ID from header (set by API gateway/auth service)"""
    return x_user_id


def require_broker():
    """Dependency to verify broker is available before accepting jobs."""
    if not check_broker_connection():
        logger.error("RabbitMQ broker not available")
        raise HTTPException(
            status_code=503,
            detail="Service temporarily unavailable. Background job processing is not ready. Please try again later."
        )


def log_audit(db: Session, job_id: str, user_id: str, action: str, 
              details: dict = None, request_info: dict = None):
    """Create audit log entry"""
    log = AuditLog(
        job_id=job_id,
        user_id=user_id,
        action=action,
        details=details,
        ip_address=request_info.get('ip') if request_info else None,
        user_agent=request_info.get('user_agent') if request_info else None
    )
    db.add(log)
    db.commit()


# ============== Health Checks ==============

@router.get("/health")
async def health_check():
    """
    Basic health check - returns OK if API is running.
    Does not check backend services (use /health/ready for that).
    """
    return {"status": "healthy", "service": "deployguard-api"}


@router.get("/health/ready")
async def readiness_check():
    """
    Readiness check - verifies all backend services are available.
    
    Returns:
        - 200 if all services ready
        - 503 if any service unavailable
    """
    status = {
        "rabbitmq": False,
        "storage": False,
        "database": False
    }
    
    # Check RabbitMQ
    try:
        status["rabbitmq"] = check_broker_connection()
    except Exception as e:
        logger.warning(f"RabbitMQ check failed: {e}")
    
    # Check MinIO/S3
    try:
        storage = StorageClient()
        storage.client.list_buckets()
        status["storage"] = True
    except Exception as e:
        logger.warning(f"Storage check failed: {e}")
    
    # Check Database
    try:
        db = get_db_session(os.getenv('DATABASE_URL', 'sqlite:///deployguard.db'))
        db.execute("SELECT 1")
        db.close()
        status["database"] = True
    except Exception as e:
        logger.warning(f"Database check failed: {e}")
    
    all_ready = all(status.values())
    
    if not all_ready:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "services": status,
                "message": "One or more backend services are unavailable"
            }
        )
    
    return {"status": "ready", "services": status}


# ============== Job Management ==============

@router.post("/jobs", response_model=JobResponse, status_code=201)
async def create_scan_job(
    request: JobCreateRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    _broker: None = Depends(require_broker)
):
    """
    Create a new repository scan job.
    
    The scan will run in the background. Use GET /jobs/{id} to check status.
    
    Supported platforms: github, bitbucket, gitlab, azure_devops
    
    **Requires**: RabbitMQ broker must be available (returns 503 if not)
    """
    # Validate platform
    valid_platforms = ['github', 'bitbucket', 'gitlab', 'azure_devops']
    if request.source_platform.lower() not in valid_platforms:
        raise HTTPException(400, f"Invalid platform. Must be one of: {valid_platforms}")
    
    # Create job
    job = Job(
        user_id=user_id,
        source_platform=request.source_platform.lower(),
        source_url=request.source_url,
        source_branch=request.source_branch or "main",
        source_credentials_id=request.source_credentials_id,
        status=JobStatus.PENDING,
        status_message="Job created, waiting to start...",
        expires_at=datetime.utcnow() + timedelta(days=7)
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Log audit
    log_audit(db, job.id, user_id, "job_created", {
        "source_url": request.source_url,
        "source_platform": request.source_platform
    })
    
    # Start background task
    try:
        scan_repository_task.delay(job.id, user_id)
    except Exception as e:
        logger.error(f"Failed to queue scan task: {e}")
        job.status = JobStatus.FAILED
        job.status_message = "Failed to start scan job. Please try again."
        db.commit()
        raise HTTPException(503, "Failed to queue job. Service temporarily unavailable.")
    
    return JobResponse.model_validate(job)


@router.get("/jobs", response_model=List[JobResponse])
async def list_jobs(
    status: Optional[JobStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """List all jobs for the current user"""
    query = db.query(Job).filter(Job.user_id == user_id)
    
    if status:
        query = query.filter(Job.status == status)
    
    jobs = query.order_by(Job.created_at.desc()).offset(offset).limit(limit).all()
    
    return [JobResponse.model_validate(job) for job in jobs]


@router.get("/jobs/{job_id}", response_model=JobDetailResponse)
async def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Get job details including found secrets"""
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    secrets = db.query(SecretFound).filter(SecretFound.job_id == job_id).all()
    
    # Generate download URL if cleaned repo is available
    download_url = None
    if job.storage_cleaned_path:
        storage = StorageClient()
        download_url = storage.generate_presigned_url(job.storage_cleaned_path, expiration=3600)
    
    # Generate report URL
    report_url = None
    if job.storage_report_path:
        storage = StorageClient()
        report_url = storage.generate_presigned_url(job.storage_report_path, expiration=3600)
    
    return JobDetailResponse(
        job=JobResponse.model_validate(job),
        secrets=[SecretFoundResponse.model_validate(s) for s in secrets],
        download_url=download_url,
        report_url=report_url
    )


@router.delete("/jobs/{job_id}", status_code=204)
async def cancel_job(
    job_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Cancel a job and clean up its resources"""
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    # Clean up storage
    storage = StorageClient()
    if job.storage_repo_path:
        storage.delete_prefix(job.storage_repo_path)
    if job.storage_cleaned_path:
        storage.delete_prefix(job.storage_cleaned_path)
    if job.storage_report_path:
        storage.delete_prefix(os.path.dirname(job.storage_report_path))
    
    # Update job status
    job.status = JobStatus.CANCELLED
    job.status_message = "Job cancelled by user"
    db.commit()
    
    log_audit(db, job_id, user_id, "job_cancelled")


# ============== Secret Selection ==============

@router.get("/jobs/{job_id}/secrets", response_model=List[SecretFoundResponse])
async def list_secrets(
    job_id: str,
    include_false_positives: bool = Query(False),
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """List all secrets found in a job"""
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    query = db.query(SecretFound).filter(SecretFound.job_id == job_id)
    
    if not include_false_positives:
        query = query.filter(SecretFound.is_false_positive == False)
    
    secrets = query.all()
    
    return [SecretFoundResponse.model_validate(s) for s in secrets]


@router.post("/jobs/{job_id}/secrets/select")
async def select_secrets_for_cleaning(
    job_id: str,
    request: SecretSelectionRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """
    Select which secrets to clean from the repository history.
    
    Only selected secrets will be removed during the clean phase.
    """
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    if job.status != JobStatus.AWAITING_SELECTION:
        raise HTTPException(400, f"Job is not awaiting selection. Current status: {job.status}")
    
    # Reset all selections
    db.query(SecretFound).filter(SecretFound.job_id == job_id).update({
        SecretFound.selected_for_cleaning: False
    })
    
    # Mark selected secrets
    db.query(SecretFound).filter(
        SecretFound.id.in_(request.secret_ids),
        SecretFound.job_id == job_id
    ).update({SecretFound.selected_for_cleaning: True}, synchronize_session='fetch')
    
    # Mark false positives
    if request.mark_false_positives:
        db.query(SecretFound).filter(
            SecretFound.id.in_(request.mark_false_positives),
            SecretFound.job_id == job_id
        ).update({
            SecretFound.is_false_positive: True,
            SecretFound.selected_for_cleaning: False
        }, synchronize_session='fetch')
    
    db.commit()
    
    # Update job
    selected_count = db.query(SecretFound).filter(
        SecretFound.job_id == job_id,
        SecretFound.selected_for_cleaning == True
    ).count()
    
    job.secrets_selected_for_cleaning = selected_count
    db.commit()
    
    log_audit(db, job_id, user_id, "secrets_selected", {
        "selected_count": selected_count,
        "false_positives_count": len(request.mark_false_positives or [])
    })
    
    return {
        "message": f"Selected {selected_count} secrets for cleaning",
        "selected_count": selected_count
    }


@router.patch("/jobs/{job_id}/secrets/{secret_id}")
async def update_secret(
    job_id: str,
    secret_id: str,
    selected_for_cleaning: Optional[bool] = None,
    is_false_positive: Optional[bool] = None,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Update a single secret's selection status"""
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    secret = db.query(SecretFound).filter(
        SecretFound.id == secret_id,
        SecretFound.job_id == job_id
    ).first()
    
    if not secret:
        raise HTTPException(404, "Secret not found")
    
    if selected_for_cleaning is not None:
        secret.selected_for_cleaning = selected_for_cleaning
    
    if is_false_positive is not None:
        secret.is_false_positive = is_false_positive
        if is_false_positive:
            secret.selected_for_cleaning = False
    
    db.commit()
    
    return SecretFoundResponse.model_validate(secret)


# ============== Clean & Push ==============

@router.post("/jobs/{job_id}/clean")
async def start_cleaning(
    job_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    _broker: None = Depends(require_broker)
):
    """
    Start the cleaning process for selected secrets.
    
    Prerequisites:
    - Job must be in AWAITING_SELECTION status
    - At least one secret must be selected for cleaning
    
    **Requires**: RabbitMQ broker must be available (returns 503 if not)
    """
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    if job.status != JobStatus.AWAITING_SELECTION:
        raise HTTPException(400, f"Job is not ready for cleaning. Current status: {job.status}")
    
    # Get selected secret IDs
    selected_secrets = db.query(SecretFound).filter(
        SecretFound.job_id == job_id,
        SecretFound.selected_for_cleaning == True
    ).all()
    
    if not selected_secrets:
        raise HTTPException(400, "No secrets selected for cleaning")
    
    secret_ids = [s.id for s in selected_secrets]
    
    # Update job status
    job.status = JobStatus.CLEANING
    job.status_message = f"Starting cleanup of {len(secret_ids)} secrets..."
    db.commit()
    
    log_audit(db, job_id, user_id, "clean_started", {
        "secrets_count": len(secret_ids)
    })
    
    # Start background task
    try:
        clean_repository_task.delay(job_id, user_id, secret_ids)
    except Exception as e:
        logger.error(f"Failed to queue clean task: {e}")
        job.status = JobStatus.AWAITING_SELECTION
        job.status_message = "Failed to start clean job. Please try again."
        db.commit()
        raise HTTPException(503, "Failed to queue job. Service temporarily unavailable.")
    
    return {
        "message": f"Cleaning started for {len(secret_ids)} secrets",
        "job_id": job_id
    }


@router.get("/jobs/{job_id}/download")
async def download_cleaned_repo(
    job_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """
    Get a download URL for the cleaned repository.
    
    Returns a pre-signed URL valid for 1 hour.
    """
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    if not job.storage_cleaned_path:
        raise HTTPException(400, "No cleaned repository available. Run clean first.")
    
    storage = StorageClient()
    download_url = storage.generate_presigned_url(job.storage_cleaned_path, expiration=3600)
    
    log_audit(db, job_id, user_id, "download_requested")
    
    return RedirectResponse(url=download_url)


@router.post("/jobs/{job_id}/push")
async def push_to_target(
    job_id: str,
    request: PushRequest,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user),
    _broker: None = Depends(require_broker)
):
    """
    Push the cleaned repository to a target repository.
    
    Note: force_push is typically required since we've rewritten history.
    
    **Requires**: RabbitMQ broker must be available (returns 503 if not)
    """
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    if job.status != JobStatus.CLEAN_COMPLETE:
        raise HTTPException(400, f"Job is not ready for push. Current status: {job.status}")
    
    if not job.storage_cleaned_path:
        raise HTTPException(400, "No cleaned repository available")
    
    # Validate platform
    valid_platforms = ['github', 'bitbucket', 'gitlab', 'azure_devops']
    if request.target_platform.lower() not in valid_platforms:
        raise HTTPException(400, f"Invalid platform. Must be one of: {valid_platforms}")
    
    # Update job
    job.status = JobStatus.PUSHING
    job.status_message = "Starting push to target repository..."
    job.target_platform = request.target_platform.lower()
    job.target_url = request.target_url
    job.target_branch = request.target_branch
    job.target_credentials_id = request.target_credentials_id
    db.commit()
    
    log_audit(db, job_id, user_id, "push_started", {
        "target_url": request.target_url,
        "target_platform": request.target_platform
    })
    
    # Start background task
    try:
        push_repository_task.delay(
            job_id, user_id, request.target_url,
            request.target_credentials_id, request.force_push,
            request.push_all_branches
        )
    except Exception as e:
        logger.error(f"Failed to queue push task: {e}")
        job.status = JobStatus.CLEAN_COMPLETE
        job.status_message = "Failed to start push job. Please try again."
        db.commit()
        raise HTTPException(503, "Failed to queue job. Service temporarily unavailable.")
    
    return {
        "message": "Push started",
        "job_id": job_id,
        "target_url": request.target_url
    }


# ============== Reports & Statistics ==============

@router.get("/jobs/{job_id}/report")
async def get_scan_report(
    job_id: str,
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Get the detailed scan report"""
    job = db.query(Job).filter(Job.id == job_id, Job.user_id == user_id).first()
    
    if not job:
        raise HTTPException(404, "Job not found")
    
    if not job.storage_report_path:
        raise HTTPException(400, "No report available yet")
    
    storage = StorageClient()
    report_url = storage.generate_presigned_url(job.storage_report_path, expiration=3600)
    
    return RedirectResponse(url=report_url)


@router.get("/stats")
async def get_user_stats(
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """Get statistics for the current user"""
    total_jobs = db.query(Job).filter(Job.user_id == user_id).count()
    completed_jobs = db.query(Job).filter(
        Job.user_id == user_id,
        Job.status == JobStatus.COMPLETED
    ).count()
    total_secrets_found = db.query(Job).filter(Job.user_id == user_id).with_entities(
        db.func.sum(Job.total_secrets_found)
    ).scalar() or 0
    total_secrets_cleaned = db.query(Job).filter(Job.user_id == user_id).with_entities(
        db.func.sum(Job.secrets_selected_for_cleaning)
    ).scalar() or 0
    
    return {
        "total_jobs": total_jobs,
        "completed_jobs": completed_jobs,
        "total_secrets_found": total_secrets_found,
        "total_secrets_cleaned": total_secrets_cleaned
    }


# ============== Health Check ==============

@router.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes"""
    return {"status": "healthy", "version": "2.0.0"}
