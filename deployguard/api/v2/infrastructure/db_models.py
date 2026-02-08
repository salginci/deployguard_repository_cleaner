"""
Infrastructure Layer - SQLAlchemy Models

Database models for persistence. These are infrastructure concerns
and should not leak into the domain layer.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import UUID
import uuid

Base = declarative_base()


class JobModel(Base):
    """SQLAlchemy model for Job aggregate."""
    
    __tablename__ = "jobs"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Identity
    user_id = Column(String(255), nullable=False, index=True)
    
    # Source repository
    source_platform = Column(String(50), nullable=False)
    source_url = Column(String(500), nullable=False)
    source_branch = Column(String(255), default="main")
    
    # Target repository
    target_platform = Column(String(50), nullable=True)
    target_url = Column(String(500), nullable=True)
    
    # Status
    status = Column(String(50), nullable=False, default="pending", index=True)
    status_message = Column(Text, default="")
    progress_percent = Column(Integer, default=0)
    
    # Scan results
    total_commits_scanned = Column(Integer, default=0)
    total_branches_scanned = Column(Integer, default=0)
    
    # Cleaning results
    commits_rewritten = Column(Integer, default=0)
    branches_pushed = Column(Integer, default=0)
    tags_pushed = Column(Integer, default=0)
    
    # Storage
    storage_path = Column(String(500), nullable=True)
    
    # Error info
    error_code = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Optimistic locking
    version = Column(Integer, default=1)
    
    # Relationships
    secrets = relationship("SecretModel", back_populates="job", cascade="all, delete-orphan")
    audit_logs = relationship("AuditModel", back_populates="job", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("ix_jobs_user_status", "user_id", "status"),
        Index("ix_jobs_expires_status", "expires_at", "status"),
    )


class SecretModel(Base):
    """SQLAlchemy model for SecretFinding entity."""
    
    __tablename__ = "secrets"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Location info
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer, nullable=False)
    commit_hash = Column(String(40), nullable=False)
    branch = Column(String(255), default="main")
    
    # Secret info
    secret_type = Column(String(50), nullable=False)
    secret_hash = Column(String(64), nullable=False)  # SHA256
    secret_preview = Column(String(100), nullable=False)  # Masked
    pattern_name = Column(String(100), nullable=False)
    
    # Context
    code_context = Column(Text, default="")
    author = Column(String(255), default="")
    commit_date = Column(DateTime, nullable=True)
    
    # Classification
    severity = Column(String(20), default="medium")
    confidence = Column(Float, default=0.8)
    
    # Selection state
    selected_for_cleaning = Column(Boolean, default=True)
    marked_as_false_positive = Column(Boolean, default=False)
    
    # Timestamp
    found_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    job = relationship("JobModel", back_populates="secrets")
    
    # Indexes
    __table_args__ = (
        Index("ix_secrets_job_selected", "job_id", "selected_for_cleaning"),
        Index("ix_secrets_hash", "secret_hash"),
    )


class AuditModel(Base):
    """SQLAlchemy model for AuditEntry entity."""
    
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Foreign key
    job_id = Column(String(36), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Identity
    user_id = Column(String(255), nullable=False, index=True)
    
    # Action info
    action = Column(String(100), nullable=False, index=True)
    details = Column(JSON, default=dict)
    
    # Context
    ip_address = Column(String(45), default="")
    user_agent = Column(String(500), default="")
    
    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationship
    job = relationship("JobModel", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index("ix_audit_user_action", "user_id", "action"),
    )


class OutboxModel(Base):
    """
    SQLAlchemy model for Outbox Pattern.
    
    The outbox table stores domain events that need to be published
    to the message broker. A separate processor reads from this table
    and publishes events, ensuring at-least-once delivery.
    """
    
    __tablename__ = "outbox"
    
    # Primary key
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Event metadata
    event_id = Column(String(36), nullable=False, unique=True)
    event_type = Column(String(100), nullable=False, index=True)
    aggregate_type = Column(String(100), nullable=False)
    aggregate_id = Column(String(36), nullable=False, index=True)
    
    # Event payload (serialized JSON)
    payload = Column(JSON, nullable=False)
    
    # Publishing state
    published = Column(Boolean, default=False, index=True)
    published_at = Column(DateTime, nullable=True)
    
    # Retry tracking
    retry_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Indexes for efficient processing
    __table_args__ = (
        Index("ix_outbox_unpublished", "published", "created_at"),
        Index("ix_outbox_aggregate", "aggregate_type", "aggregate_id"),
    )
