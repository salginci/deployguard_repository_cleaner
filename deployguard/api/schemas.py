"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity levels for findings."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingType(str, Enum):
    """Types of findings."""
    api_key = "api_key"
    password = "password"
    token = "token"
    secret = "secret"
    credential = "credential"
    private_key = "private_key"
    certificate = "certificate"
    other = "other"


class VerificationStatus(str, Enum):
    """Status of secret verification."""
    active = "active"
    inactive = "inactive"
    unknown = "unknown"
    error = "error"


# Request schemas
class ScanRequest(BaseModel):
    """Request schema for scanning a repository or path."""
    path: str = Field(..., description="Path to scan (local path or git URL)")
    patterns: Optional[list[str]] = Field(None, description="Specific pattern IDs to use")
    exclude_patterns: Optional[list[str]] = Field(None, description="Pattern IDs to exclude")
    include_extensions: Optional[list[str]] = Field(None, description="File extensions to include")
    exclude_extensions: Optional[list[str]] = Field(None, description="File extensions to exclude")
    max_file_size: Optional[int] = Field(None, description="Maximum file size in bytes")
    scan_git_history: bool = Field(False, description="Scan git history")
    verify_secrets: bool = Field(False, description="Verify if secrets are active")


class VerifyRequest(BaseModel):
    """Request schema for verifying secrets."""
    secrets: list[dict] = Field(..., description="List of secrets to verify")
    timeout: int = Field(10, description="Timeout in seconds for each verification")


# Response schemas
class FindingResponse(BaseModel):
    """Response schema for a single finding."""
    id: str = Field(..., description="Unique finding ID")
    file_path: str = Field(..., description="Path to file containing the finding")
    line_number: int = Field(..., description="Line number of the finding")
    pattern_id: str = Field(..., description="Pattern ID that matched")
    pattern_name: str = Field(..., description="Human-readable pattern name")
    severity: SeverityLevel = Field(..., description="Severity level")
    finding_type: FindingType = Field(..., description="Type of finding")
    matched_text: str = Field(..., description="Redacted matched text")
    context: Optional[str] = Field(None, description="Surrounding context")
    verification_status: Optional[VerificationStatus] = Field(None, description="Verification status if checked")
    commit_hash: Optional[str] = Field(None, description="Git commit hash if from history")
    author: Optional[str] = Field(None, description="Git author if from history")


class ScanResponse(BaseModel):
    """Response schema for a scan operation."""
    scan_id: str = Field(..., description="Unique scan ID")
    status: str = Field(..., description="Scan status")
    path: str = Field(..., description="Scanned path")
    started_at: datetime = Field(..., description="Scan start time")
    completed_at: Optional[datetime] = Field(None, description="Scan completion time")
    total_files: int = Field(0, description="Total files scanned")
    total_findings: int = Field(0, description="Total findings detected")
    findings: list[FindingResponse] = Field(default_factory=list, description="List of findings")
    summary: dict = Field(default_factory=dict, description="Summary statistics")


class ScanListItem(BaseModel):
    """Response schema for scan list item."""
    scan_id: str
    path: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    total_findings: int


class ScanListResponse(BaseModel):
    """Response schema for listing scans."""
    scans: list[ScanListItem]
    total: int


class VerifyResponse(BaseModel):
    """Response schema for secret verification."""
    verified: int = Field(..., description="Number of secrets verified")
    results: list[dict] = Field(..., description="Verification results")


class PatternResponse(BaseModel):
    """Response schema for a single pattern."""
    id: str
    name: str
    description: Optional[str]
    severity: SeverityLevel
    pattern_type: FindingType
    enabled: bool


class PatternListResponse(BaseModel):
    """Response schema for listing patterns."""
    patterns: list[PatternResponse]
    total: int


class StatsResponse(BaseModel):
    """Response schema for statistics."""
    total_scans: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_type: dict[str, int]
    top_patterns: list[dict]
    recent_scans: list[ScanListItem]


class HealthResponse(BaseModel):
    """Response schema for health check."""
    status: str
    version: str
    patterns_loaded: int
    uptime_seconds: float


class ErrorResponse(BaseModel):
    """Response schema for errors."""
    error: str
    detail: Optional[str] = None
    status_code: int
