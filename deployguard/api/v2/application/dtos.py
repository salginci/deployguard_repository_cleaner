"""
Application Layer - DTOs (Data Transfer Objects)

DTOs are used to transfer data between layers.
They decouple the API layer from the domain layer.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum


# ==================== Request DTOs ====================

@dataclass
class CreateJobRequest:
    """Request to create a new scan job."""
    user_id: str
    source_platform: str
    source_url: str
    source_branch: str = "main"
    source_token: Optional[str] = None
    target_platform: Optional[str] = None
    target_url: Optional[str] = None
    target_token: Optional[str] = None


@dataclass
class SelectSecretsRequest:
    """Request to select secrets for cleaning."""
    job_id: str
    user_id: str
    selected_secret_ids: List[str] = field(default_factory=list)
    false_positive_ids: List[str] = field(default_factory=list)


@dataclass
class StartCleaningRequest:
    """Request to start the cleaning process."""
    job_id: str
    user_id: str


@dataclass
class PushRepositoryRequest:
    """Request to push cleaned repository to target."""
    job_id: str
    user_id: str
    target_platform: Optional[str] = None
    target_url: Optional[str] = None
    target_token: Optional[str] = None
    force_push: bool = False


@dataclass
class CancelJobRequest:
    """Request to cancel a job."""
    job_id: str
    user_id: str
    reason: str = "Cancelled by user"


@dataclass
class GetJobRequest:
    """Request to get a single job."""
    job_id: str
    user_id: str
    include_secrets: bool = False


@dataclass
class ListJobsRequest:
    """Request to list jobs for a user."""
    user_id: str
    skip: int = 0
    limit: int = 20
    status_filter: Optional[str] = None


# ==================== Response DTOs ====================

@dataclass
class SecretDTO:
    """DTO for a secret finding."""
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
    code_context: Optional[str] = None
    author: Optional[str] = None
    commit_date: Optional[str] = None
    
    @classmethod
    def from_entity(cls, entity) -> 'SecretDTO':
        """Create DTO from domain entity."""
        return cls(
            id=entity.id,
            file_path=entity.file_path,
            line_number=entity.line_number,
            commit_hash=entity.commit_hash,
            branch=entity.branch,
            secret_type=entity.secret_type.value,
            secret_preview=entity.secret_preview,
            pattern_name=entity.pattern_name,
            severity=entity.severity.value,
            confidence=entity.confidence,
            selected_for_cleaning=entity.selected_for_cleaning,
            marked_as_false_positive=entity.marked_as_false_positive,
            code_context=entity.code_context,
            author=entity.author,
            commit_date=entity.commit_date.isoformat() if entity.commit_date else None,
        )


@dataclass
class JobDTO:
    """DTO for a job."""
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
    secrets: List[SecretDTO] = field(default_factory=list)
    
    @classmethod
    def from_entity(cls, entity, include_secrets: bool = False) -> 'JobDTO':
        """Create DTO from domain entity."""
        secrets = []
        if include_secrets:
            secrets = [SecretDTO.from_entity(s) for s in entity.secrets]
        
        return cls(
            id=entity.id,
            user_id=entity.user_id,
            status=entity.status.value,
            status_message=entity.status_message,
            progress_percent=entity.progress_percent,
            source_platform=entity.source_platform,
            source_url=entity.source_url,
            source_branch=entity.source_branch,
            target_platform=entity.target_platform,
            target_url=entity.target_url,
            secrets_count=len(entity.secrets),
            selected_secrets_count=len(entity.selected_secrets),
            total_commits_scanned=entity.total_commits_scanned,
            total_branches_scanned=entity.total_branches_scanned,
            commits_rewritten=entity.commits_rewritten,
            branches_pushed=entity.branches_pushed,
            tags_pushed=entity.tags_pushed,
            error_code=entity.error_code,
            error_message=entity.error_message,
            created_at=entity.created_at.isoformat(),
            updated_at=entity.updated_at.isoformat(),
            expires_at=entity.expires_at.isoformat() if entity.expires_at else None,
            secrets=secrets,
        )


@dataclass
class JobListDTO:
    """DTO for paginated job list."""
    items: List[JobDTO]
    total: int
    skip: int
    limit: int
    has_more: bool


@dataclass
class AuditEntryDTO:
    """DTO for an audit entry."""
    id: str
    job_id: str
    user_id: str
    action: str
    details: Dict[str, Any]
    created_at: str
    
    @classmethod
    def from_entity(cls, entity) -> 'AuditEntryDTO':
        """Create DTO from domain entity."""
        return cls(
            id=entity.id,
            job_id=entity.job_id,
            user_id=entity.user_id,
            action=entity.action,
            details=entity.details,
            created_at=entity.created_at.isoformat(),
        )


# ==================== Result DTOs ====================

class ResultStatus(str, Enum):
    """Status of a use case result."""
    SUCCESS = "success"
    FAILURE = "failure"
    NOT_FOUND = "not_found"
    FORBIDDEN = "forbidden"
    CONFLICT = "conflict"
    VALIDATION_ERROR = "validation_error"


@dataclass
class Result:
    """
    Generic result wrapper for use case responses.
    
    Follows the Result pattern to handle success/failure
    without exceptions for expected failures.
    """
    status: ResultStatus
    message: str = ""
    data: Any = None
    errors: List[str] = field(default_factory=list)
    
    @property
    def is_success(self) -> bool:
        return self.status == ResultStatus.SUCCESS
    
    @property
    def is_failure(self) -> bool:
        return self.status != ResultStatus.SUCCESS
    
    @classmethod
    def success(cls, data: Any = None, message: str = "Success") -> 'Result':
        """Create a success result."""
        return cls(status=ResultStatus.SUCCESS, message=message, data=data)
    
    @classmethod
    def failure(cls, message: str, errors: List[str] = None) -> 'Result':
        """Create a failure result."""
        return cls(
            status=ResultStatus.FAILURE,
            message=message,
            errors=errors or [],
        )
    
    @classmethod
    def not_found(cls, message: str = "Resource not found") -> 'Result':
        """Create a not found result."""
        return cls(status=ResultStatus.NOT_FOUND, message=message)
    
    @classmethod
    def forbidden(cls, message: str = "Access denied") -> 'Result':
        """Create a forbidden result."""
        return cls(status=ResultStatus.FORBIDDEN, message=message)
    
    @classmethod
    def conflict(cls, message: str = "Conflict") -> 'Result':
        """Create a conflict result."""
        return cls(status=ResultStatus.CONFLICT, message=message)
    
    @classmethod
    def validation_error(cls, errors: List[str]) -> 'Result':
        """Create a validation error result."""
        return cls(
            status=ResultStatus.VALIDATION_ERROR,
            message="Validation failed",
            errors=errors,
        )


@dataclass
class CreateJobResult:
    """Result of creating a job."""
    job: JobDTO
    task_id: Optional[str] = None  # Celery task ID for polling


@dataclass
class ScanResult:
    """Result of scanning a repository."""
    job: JobDTO
    scan_duration_seconds: float = 0.0


@dataclass
class CleanResult:
    """Result of cleaning a repository."""
    job: JobDTO
    task_id: Optional[str] = None


@dataclass
class PushResult:
    """Result of pushing a repository."""
    job: JobDTO
    branches_pushed: int = 0
    tags_pushed: int = 0
