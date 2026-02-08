"""
API Routes - Clean Architecture Version

Thin controllers that delegate to use cases.
Routes handle HTTP concerns (request/response mapping, status codes)
while use cases handle business logic.
"""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from pydantic import BaseModel, Field
import logging

from .container import get_container, Container
from .application.dtos import (
    CreateJobRequest, SelectSecretsRequest, StartCleaningRequest,
    PushRepositoryRequest, CancelJobRequest, GetJobRequest, ListJobsRequest,
    Result, ResultStatus, JobDTO, SecretDTO, JobListDTO,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2", tags=["Jobs"])


# ==================== Pydantic Request/Response Models ====================

class CreateJobRequestModel(BaseModel):
    """API request model for creating a job."""
    source_platform: str = Field(..., description="Source platform (github, bitbucket)")
    source_url: str = Field(..., description="Repository URL")
    source_branch: str = Field("main", description="Branch to scan")
    source_token: Optional[str] = Field(None, description="Access token for source")
    target_platform: Optional[str] = Field(None, description="Target platform")
    target_url: Optional[str] = Field(None, description="Target repository URL")
    target_token: Optional[str] = Field(None, description="Access token for target")


class SelectSecretsRequestModel(BaseModel):
    """API request model for selecting secrets."""
    selected_ids: List[str] = Field(default_factory=list, description="IDs of secrets to clean")
    false_positive_ids: List[str] = Field(default_factory=list, description="IDs of false positives")


class PushRequestModel(BaseModel):
    """API request model for pushing repository."""
    target_platform: Optional[str] = Field(None, description="Target platform")
    target_url: Optional[str] = Field(None, description="Target repository URL")
    target_token: Optional[str] = Field(None, description="Access token for target")
    force_push: bool = Field(False, description="Force push to target")


class CancelRequestModel(BaseModel):
    """API request model for cancelling a job."""
    reason: str = Field("Cancelled by user", description="Cancellation reason")


class JobResponseModel(BaseModel):
    """API response model for a job."""
    id: str
    user_id: str
    status: str
    status_message: str
    progress_percent: int
    source_platform: str
    source_url: str
    source_branch: str
    target_platform: Optional[str]
    target_url: Optional[str]
    secrets_count: int
    selected_secrets_count: int
    total_commits_scanned: int
    total_branches_scanned: int
    commits_rewritten: int
    branches_pushed: int
    tags_pushed: int
    error_code: Optional[str]
    error_message: Optional[str]
    created_at: str
    updated_at: str
    expires_at: Optional[str]
    
    class Config:
        from_attributes = True


class SecretResponseModel(BaseModel):
    """API response model for a secret."""
    id: str
    file_path: str
    line_number: int
    commit_hash: str
    branch: str
    secret_type: str
    secret_preview: str
    pattern_name: str
    severity: str
    confidence: float
    selected_for_cleaning: bool
    marked_as_false_positive: bool
    code_context: Optional[str]
    author: Optional[str]
    commit_date: Optional[str]
    
    class Config:
        from_attributes = True


class JobListResponseModel(BaseModel):
    """API response model for job list."""
    items: List[JobResponseModel]
    total: int
    skip: int
    limit: int
    has_more: bool


class ErrorResponseModel(BaseModel):
    """API response model for errors."""
    detail: str
    errors: List[str] = []


# ==================== Dependencies ====================

async def get_current_user(request: Request) -> str:
    """
    Extract current user from request.
    
    In production, this would validate JWT tokens or API keys.
    For now, we use a header or default value.
    """
    return request.headers.get("X-User-ID", "default-user")


def get_container_dep() -> Container:
    """FastAPI dependency for container."""
    return get_container()


# ==================== Helper Functions ====================

def result_to_response(result: Result, success_status: int = 200):
    """Convert Result to HTTP response."""
    if result.status == ResultStatus.SUCCESS:
        return result.data
    
    status_map = {
        ResultStatus.NOT_FOUND: 404,
        ResultStatus.FORBIDDEN: 403,
        ResultStatus.CONFLICT: 409,
        ResultStatus.VALIDATION_ERROR: 422,
        ResultStatus.FAILURE: 500,
    }
    
    status_code = status_map.get(result.status, 500)
    raise HTTPException(
        status_code=status_code,
        detail=result.message,
    )


def job_dto_to_response(dto: JobDTO) -> JobResponseModel:
    """Convert JobDTO to response model."""
    return JobResponseModel(
        id=dto.id,
        user_id=dto.user_id,
        status=dto.status,
        status_message=dto.status_message,
        progress_percent=dto.progress_percent,
        source_platform=dto.source_platform,
        source_url=dto.source_url,
        source_branch=dto.source_branch,
        target_platform=dto.target_platform,
        target_url=dto.target_url,
        secrets_count=dto.secrets_count,
        selected_secrets_count=dto.selected_secrets_count,
        total_commits_scanned=dto.total_commits_scanned,
        total_branches_scanned=dto.total_branches_scanned,
        commits_rewritten=dto.commits_rewritten,
        branches_pushed=dto.branches_pushed,
        tags_pushed=dto.tags_pushed,
        error_code=dto.error_code,
        error_message=dto.error_message,
        created_at=dto.created_at,
        updated_at=dto.updated_at,
        expires_at=dto.expires_at,
    )


# ==================== Routes ====================

@router.post(
    "/jobs",
    response_model=JobResponseModel,
    status_code=201,
    summary="Create a new scan job",
    description="Create a new job to scan a repository for secrets.",
)
async def create_job(
    request_body: CreateJobRequestModel,
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Create a new scan job."""
    use_case = container.create_scan_job_use_case()
    
    result = await use_case.execute(CreateJobRequest(
        user_id=user_id,
        source_platform=request_body.source_platform,
        source_url=request_body.source_url,
        source_branch=request_body.source_branch,
        source_token=request_body.source_token,
        target_platform=request_body.target_platform,
        target_url=request_body.target_url,
        target_token=request_body.target_token,
    ))
    
    data = result_to_response(result)
    return job_dto_to_response(data.job)


@router.get(
    "/jobs",
    response_model=JobListResponseModel,
    summary="List jobs",
    description="List all jobs for the current user.",
)
async def list_jobs(
    skip: int = Query(0, ge=0, description="Number of jobs to skip"),
    limit: int = Query(20, ge=1, le=100, description="Maximum jobs to return"),
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """List jobs for the current user."""
    use_case = container.list_jobs_use_case()
    
    result = await use_case.execute(ListJobsRequest(
        user_id=user_id,
        skip=skip,
        limit=limit,
    ))
    
    data: JobListDTO = result_to_response(result)
    
    return JobListResponseModel(
        items=[job_dto_to_response(j) for j in data.items],
        total=data.total,
        skip=data.skip,
        limit=data.limit,
        has_more=data.has_more,
    )


@router.get(
    "/jobs/{job_id}",
    response_model=JobResponseModel,
    summary="Get job details",
    description="Get details of a specific job.",
)
async def get_job(
    job_id: str,
    include_secrets: bool = Query(False, description="Include secrets in response"),
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Get job details."""
    use_case = container.get_job_use_case()
    
    result = await use_case.execute(GetJobRequest(
        job_id=job_id,
        user_id=user_id,
        include_secrets=include_secrets,
    ))
    
    data: JobDTO = result_to_response(result)
    return job_dto_to_response(data)


@router.get(
    "/jobs/{job_id}/secrets",
    response_model=List[SecretResponseModel],
    summary="Get job secrets",
    description="Get all secrets found for a job.",
)
async def get_job_secrets(
    job_id: str,
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Get secrets for a job."""
    use_case = container.get_job_use_case()
    
    result = await use_case.execute(GetJobRequest(
        job_id=job_id,
        user_id=user_id,
        include_secrets=True,
    ))
    
    data: JobDTO = result_to_response(result)
    
    return [
        SecretResponseModel(
            id=s.id,
            file_path=s.file_path,
            line_number=s.line_number,
            commit_hash=s.commit_hash,
            branch=s.branch,
            secret_type=s.secret_type,
            secret_preview=s.secret_preview,
            pattern_name=s.pattern_name,
            severity=s.severity,
            confidence=s.confidence,
            selected_for_cleaning=s.selected_for_cleaning,
            marked_as_false_positive=s.marked_as_false_positive,
            code_context=s.code_context,
            author=s.author,
            commit_date=s.commit_date,
        )
        for s in data.secrets
    ]


@router.post(
    "/jobs/{job_id}/select",
    response_model=JobResponseModel,
    summary="Select secrets for cleaning",
    description="Select which secrets to clean and mark false positives.",
)
async def select_secrets(
    job_id: str,
    request_body: SelectSecretsRequestModel,
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Select secrets for cleaning."""
    use_case = container.select_secrets_use_case()
    
    result = await use_case.execute(SelectSecretsRequest(
        job_id=job_id,
        user_id=user_id,
        selected_secret_ids=request_body.selected_ids,
        false_positive_ids=request_body.false_positive_ids,
    ))
    
    data: JobDTO = result_to_response(result)
    return job_dto_to_response(data)


@router.post(
    "/jobs/{job_id}/clean",
    response_model=JobResponseModel,
    status_code=202,
    summary="Start cleaning",
    description="Start cleaning secrets from repository history.",
)
async def start_cleaning(
    job_id: str,
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Start the cleaning process."""
    use_case = container.start_cleaning_use_case()
    
    result = await use_case.execute(StartCleaningRequest(
        job_id=job_id,
        user_id=user_id,
    ))
    
    data: JobDTO = result_to_response(result)
    return job_dto_to_response(data)


@router.post(
    "/jobs/{job_id}/push",
    response_model=JobResponseModel,
    status_code=202,
    summary="Push to target",
    description="Push cleaned repository to target.",
)
async def push_repository(
    job_id: str,
    request_body: PushRequestModel,
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Push repository to target."""
    use_case = container.push_repository_use_case()
    
    result = await use_case.execute(PushRepositoryRequest(
        job_id=job_id,
        user_id=user_id,
        target_platform=request_body.target_platform,
        target_url=request_body.target_url,
        target_token=request_body.target_token,
        force_push=request_body.force_push,
    ))
    
    data: JobDTO = result_to_response(result)
    return job_dto_to_response(data)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=JobResponseModel,
    summary="Cancel job",
    description="Cancel a running job.",
)
async def cancel_job(
    job_id: str,
    request_body: CancelRequestModel = CancelRequestModel(),
    user_id: str = Depends(get_current_user),
    container: Container = Depends(get_container_dep),
):
    """Cancel a job."""
    use_case = container.cancel_job_use_case()
    
    result = await use_case.execute(CancelJobRequest(
        job_id=job_id,
        user_id=user_id,
        reason=request_body.reason,
    ))
    
    data: JobDTO = result_to_response(result)
    return job_dto_to_response(data)


# ==================== Health Check Routes ====================

@router.get(
    "/health",
    summary="Health check",
    description="Basic health check endpoint.",
)
async def health_check():
    """Basic health check."""
    return {"status": "healthy"}


@router.get(
    "/health/ready",
    summary="Readiness check",
    description="Check if service is ready to accept requests.",
)
async def readiness_check(container: Container = Depends(get_container_dep)):
    """Check if service is ready."""
    # Check database connection
    try:
        async with container.unit_of_work() as uow:
            await uow.jobs.count_by_user("health-check")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # Check message broker
    try:
        connected = await container.event_publisher.is_connected()
        broker_status = "connected" if connected else "disconnected"
    except Exception as e:
        broker_status = f"error: {str(e)}"
    
    status = "ready" if db_status == "connected" else "not_ready"
    
    return {
        "status": status,
        "components": {
            "database": db_status,
            "message_broker": broker_status,
        }
    }
