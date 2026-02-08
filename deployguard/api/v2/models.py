"""
DeployGuard API v2 - Database Models
Handles job tracking, secrets found, and user selections
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, Boolean, 
    ForeignKey, JSON, Enum as SQLEnum, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from pydantic import BaseModel, Field
import uuid

Base = declarative_base()


class JobStatus(str, Enum):
    """Job status enumeration"""
    PENDING = "pending"
    CLONING = "cloning"
    SCANNING = "scanning"
    SCAN_COMPLETE = "scan_complete"
    AWAITING_SELECTION = "awaiting_selection"
    CLEANING = "cleaning"
    CLEAN_COMPLETE = "clean_complete"
    UPLOADING = "uploading"
    PUSHING = "pushing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecretType(str, Enum):
    """Types of secrets detected"""
    PASSWORD = "password"
    API_KEY = "api_key"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    CONNECTION_STRING = "connection_string"
    ENCRYPTION_KEY = "encryption_key"
    CREDENTIAL = "credential"
    OTHER = "other"


# SQLAlchemy Models

class Job(Base):
    """Main job tracking table"""
    __tablename__ = "jobs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(255), nullable=False, index=True)
    
    # Source repository info
    source_platform = Column(String(50), nullable=False)  # github, bitbucket, gitlab
    source_url = Column(String(500), nullable=False)
    source_branch = Column(String(255), default="main")
    source_credentials_id = Column(String(255))  # Reference to external auth service
    
    # Target repository info (optional, for push)
    target_platform = Column(String(50))
    target_url = Column(String(500))
    target_branch = Column(String(255))
    target_credentials_id = Column(String(255))
    
    # Job status
    status = Column(SQLEnum(JobStatus), default=JobStatus.PENDING, index=True)
    status_message = Column(Text)
    progress_percent = Column(Integer, default=0)
    
    # Storage references (MinIO/S3 paths)
    storage_repo_path = Column(String(500))  # Temp cloned repo in object storage
    storage_report_path = Column(String(500))  # Scan report JSON
    storage_cleaned_path = Column(String(500))  # Cleaned repo archive
    
    # Statistics
    total_commits = Column(Integer)
    total_branches = Column(Integer)
    total_secrets_found = Column(Integer, default=0)
    secrets_selected_for_cleaning = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    scan_completed_at = Column(DateTime)
    clean_completed_at = Column(DateTime)
    completed_at = Column(DateTime)
    expires_at = Column(DateTime)  # Auto-cleanup after this time
    
    # Relationships
    secrets = relationship("SecretFound", back_populates="job", cascade="all, delete-orphan")
    

class SecretFound(Base):
    """Secrets discovered during scan"""
    __tablename__ = "secrets_found"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("jobs.id"), nullable=False, index=True)
    
    # Secret details
    secret_type = Column(SQLEnum(SecretType), default=SecretType.OTHER)
    secret_name = Column(String(255))  # e.g., "DATABASE_PASSWORD"
    secret_value_preview = Column(String(50))  # First/last chars only: "abc...xyz"
    secret_value_hash = Column(String(64))  # SHA256 for dedup
    
    # Location info
    file_path = Column(String(500))
    line_number = Column(Integer)
    commit_hash = Column(String(40))
    commit_date = Column(DateTime)
    author = Column(String(255))
    
    # Detection info
    pattern_matched = Column(String(255))  # Which regex/rule matched
    confidence = Column(Integer, default=100)  # 0-100
    is_false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(String(255))
    
    # User selection
    selected_for_cleaning = Column(Boolean, default=True)  # Default: clean all
    
    # Occurrence count (same secret in multiple places)
    occurrence_count = Column(Integer, default=1)
    
    # Additional context
    context_before = Column(Text)  # Lines before for context
    context_after = Column(Text)  # Lines after for context
    
    # Relationships
    job = relationship("Job", back_populates="secrets")


class AuditLog(Base):
    """Audit trail for compliance"""
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("jobs.id"), index=True)
    user_id = Column(String(255), index=True)
    
    action = Column(String(100), nullable=False)  # scan_started, secret_selected, clean_completed
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    
    created_at = Column(DateTime, default=datetime.utcnow)


# Pydantic Models for API

class JobCreateRequest(BaseModel):
    """Request to create a new scan job"""
    source_platform: str = Field(..., description="github, bitbucket, gitlab, azure_devops")
    source_url: str = Field(..., description="Repository URL to scan")
    source_branch: Optional[str] = Field("main", description="Branch to scan")
    source_credentials_id: Optional[str] = Field(None, description="Credential ID from auth service")
    
    class Config:
        json_schema_extra = {
            "example": {
                "source_platform": "bitbucket",
                "source_url": "https://bitbucket.example.com/scm/proj/repo.git",
                "source_branch": "main",
                "source_credentials_id": "cred-123-456"
            }
        }


class JobResponse(BaseModel):
    """Job status response"""
    id: str
    status: JobStatus
    status_message: Optional[str]
    progress_percent: int
    total_secrets_found: int
    secrets_selected_for_cleaning: int
    created_at: datetime
    scan_completed_at: Optional[datetime]
    clean_completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class SecretFoundResponse(BaseModel):
    """Secret details for user review"""
    id: str
    secret_type: SecretType
    secret_name: Optional[str]
    secret_value_preview: Optional[str]
    file_path: str
    line_number: Optional[int]
    commit_hash: Optional[str]
    pattern_matched: Optional[str]
    confidence: int
    is_false_positive: bool
    selected_for_cleaning: bool
    occurrence_count: int
    
    class Config:
        from_attributes = True


class SecretSelectionRequest(BaseModel):
    """User selection of which secrets to clean"""
    secret_ids: List[str] = Field(..., description="List of secret IDs to clean")
    mark_false_positives: Optional[List[str]] = Field([], description="Secret IDs that are false positives")
    
    class Config:
        json_schema_extra = {
            "example": {
                "secret_ids": ["secret-1", "secret-2", "secret-3"],
                "mark_false_positives": ["secret-4"]
            }
        }


class PushRequest(BaseModel):
    """Request to push cleaned repo"""
    target_platform: str = Field(..., description="github, bitbucket, gitlab")
    target_url: str = Field(..., description="Target repository URL")
    target_branch: Optional[str] = Field("main", description="Target branch")
    target_credentials_id: Optional[str] = Field(None, description="Credential ID for target")
    force_push: bool = Field(False, description="Force push (required for history rewrite)")
    push_all_branches: bool = Field(True, description="Push all branches or just selected")
    
    class Config:
        json_schema_extra = {
            "example": {
                "target_platform": "github",
                "target_url": "https://github.example.com/org/repo.git",
                "target_branch": "main",
                "force_push": True,
                "push_all_branches": True
            }
        }


class JobDetailResponse(BaseModel):
    """Detailed job response with secrets"""
    job: JobResponse
    secrets: List[SecretFoundResponse]
    download_url: Optional[str] = None
    report_url: Optional[str] = None


# Database initialization
def init_db(database_url: str):
    """Initialize database connection and create tables"""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def get_db_session(database_url: str):
    """Get a database session"""
    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    return Session()
