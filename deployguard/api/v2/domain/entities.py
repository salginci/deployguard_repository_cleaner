"""
Domain Entities

Entities are objects with a unique identity that runs through time and different states.
They encapsulate business logic and enforce invariants.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import uuid

from .value_objects import (
    JobId, UserId, SecretHash, JobStatus, SecretType, Severity,
    Platform, RepositoryUrl, SecretPreview
)
from .events import (
    DomainEvent, JobCreatedEvent, JobStatusChangedEvent,
    ScanCompletedEvent, SecretsSelectedEvent, CleaningStartedEvent,
    CleaningCompletedEvent, PushStartedEvent, PushCompletedEvent,
    JobFailedEvent, JobCancelledEvent, JobExpiredEvent
)
from .exceptions import (
    InvalidJobStateError, SecretsNotSelectedError,
    JobExpiredError, ConcurrentModificationError
)


@dataclass
class SecretFinding:
    """
    Entity representing a secret found in repository.
    
    Immutable after creation - secrets don't change once found.
    Selection state is managed through Job aggregate.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str = ""
    
    # Location info
    file_path: str = ""
    line_number: int = 0
    commit_hash: str = ""
    branch: str = ""
    
    # Secret info
    secret_type: SecretType = SecretType.OTHER
    secret_hash: str = ""  # SHA256 of actual secret
    secret_preview: str = ""  # Masked preview
    pattern_name: str = ""
    
    # Context
    code_context: str = ""  # Surrounding lines
    author: str = ""
    commit_date: Optional[datetime] = None
    
    # Classification
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8
    
    # Selection state
    selected_for_cleaning: bool = True  # Default to clean
    marked_as_false_positive: bool = False
    
    # Metadata
    found_at: datetime = field(default_factory=datetime.utcnow)
    
    @classmethod
    def create(
        cls,
        job_id: str,
        file_path: str,
        line_number: int,
        commit_hash: str,
        secret_value: str,
        pattern_name: str,
        severity: str = "medium",
        confidence: float = 0.8,
        branch: str = "main",
        code_context: str = "",
        author: str = "",
        commit_date: Optional[datetime] = None,
    ) -> 'SecretFinding':
        """Factory method to create a SecretFinding with proper value objects."""
        secret_hash_obj = SecretHash.create(secret_value)
        preview = SecretPreview.create(secret_value)
        secret_type = SecretType.from_pattern_name(pattern_name)
        severity_obj = Severity.from_string(severity)
        
        return cls(
            job_id=job_id,
            file_path=file_path,
            line_number=line_number,
            commit_hash=commit_hash,
            branch=branch,
            secret_type=secret_type,
            secret_hash=secret_hash_obj.value,
            secret_preview=preview.value,
            pattern_name=pattern_name,
            code_context=code_context,
            author=author,
            commit_date=commit_date,
            severity=severity_obj,
            confidence=confidence,
        )
    
    def mark_as_false_positive(self) -> None:
        """Mark this finding as a false positive."""
        self.marked_as_false_positive = True
        self.selected_for_cleaning = False
    
    def select_for_cleaning(self) -> None:
        """Select this finding for cleaning."""
        if not self.marked_as_false_positive:
            self.selected_for_cleaning = True
    
    def deselect_for_cleaning(self) -> None:
        """Deselect this finding from cleaning."""
        self.selected_for_cleaning = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'id': self.id,
            'job_id': self.job_id,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'commit_hash': self.commit_hash,
            'branch': self.branch,
            'secret_type': self.secret_type.value,
            'secret_hash': self.secret_hash,
            'secret_preview': self.secret_preview,
            'pattern_name': self.pattern_name,
            'code_context': self.code_context,
            'author': self.author,
            'commit_date': self.commit_date.isoformat() if self.commit_date else None,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'selected_for_cleaning': self.selected_for_cleaning,
            'marked_as_false_positive': self.marked_as_false_positive,
            'found_at': self.found_at.isoformat(),
        }


@dataclass
class AuditEntry:
    """
    Entity representing an audit log entry.
    
    Immutable after creation - audit logs should never be modified.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str = ""
    user_id: str = ""
    
    # Action info
    action: str = ""  # e.g., "job_created", "scan_completed", "secret_selected"
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    ip_address: str = ""
    user_agent: str = ""
    
    # Timestamp
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @classmethod
    def create(
        cls,
        job_id: str,
        user_id: str,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: str = "",
        user_agent: str = "",
    ) -> 'AuditEntry':
        """Factory method to create an audit entry."""
        return cls(
            job_id=job_id,
            user_id=user_id,
            action=action,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'id': self.id,
            'job_id': self.job_id,
            'user_id': self.user_id,
            'action': self.action,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat(),
        }


@dataclass
class Job:
    """
    Aggregate Root for the scanning/cleaning job.
    
    The Job entity is the central aggregate that:
    - Manages lifecycle state transitions
    - Owns SecretFindings
    - Enforces business rules (invariants)
    - Emits domain events
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    
    # Source repository
    source_platform: str = ""
    source_url: str = ""
    source_branch: str = "main"
    
    # Target repository (optional)
    target_platform: Optional[str] = None
    target_url: Optional[str] = None
    
    # Status and progress
    status: JobStatus = JobStatus.PENDING
    status_message: str = ""
    progress_percent: int = 0
    
    # Scan results
    secrets: List[SecretFinding] = field(default_factory=list)
    total_commits_scanned: int = 0
    total_branches_scanned: int = 0
    
    # Cleaning results
    commits_rewritten: int = 0
    branches_pushed: int = 0
    tags_pushed: int = 0
    
    # Storage
    storage_path: Optional[str] = None
    
    # Error info
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    
    # Optimistic locking
    version: int = 1
    
    # Domain events (not persisted, cleared after save)
    _events: List[DomainEvent] = field(default_factory=list, repr=False)
    
    # Constants
    DEFAULT_EXPIRY_HOURS: int = 24
    
    @classmethod
    def create(
        cls,
        user_id: str,
        source_platform: str,
        source_url: str,
        source_branch: str = "main",
        target_platform: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> 'Job':
        """
        Factory method to create a new Job.
        
        Validates inputs and emits JobCreatedEvent.
        """
        # Validate platform
        Platform.validate(source_platform)
        if target_platform:
            Platform.validate(target_platform)
        
        job = cls(
            user_id=user_id,
            source_platform=source_platform,
            source_url=source_url,
            source_branch=source_branch,
            target_platform=target_platform,
            target_url=target_url,
            status=JobStatus.PENDING,
            expires_at=datetime.utcnow() + timedelta(hours=cls.DEFAULT_EXPIRY_HOURS),
        )
        
        # Emit creation event
        job._add_event(JobCreatedEvent(
            job_id=job.id,
            user_id=user_id,
            source_platform=source_platform,
            source_url=source_url,
            source_branch=source_branch,
        ))
        
        return job
    
    # ==================== State Transitions ====================
    
    def start_scanning(self) -> None:
        """Transition to scanning state."""
        self._transition_to(JobStatus.SCANNING, "Starting repository scan")
    
    def complete_scan(
        self,
        secrets: List[SecretFinding],
        total_commits: int,
        total_branches: int,
        scan_duration: float,
    ) -> None:
        """Complete scan with results."""
        self._check_not_expired()
        
        if self.status != JobStatus.SCANNING:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "complete_scan"
            )
        
        self.secrets = secrets
        self.total_commits_scanned = total_commits
        self.total_branches_scanned = total_branches
        
        new_status = JobStatus.SECRETS_FOUND if secrets else JobStatus.NO_SECRETS_FOUND
        self._transition_to(new_status, f"Found {len(secrets)} secrets")
        
        self._add_event(ScanCompletedEvent(
            job_id=self.id,
            user_id=self.user_id,
            secrets_found=len(secrets),
            total_commits=total_commits,
            total_branches=total_branches,
            scan_duration_seconds=scan_duration,
        ))
    
    def select_secrets(
        self,
        selected_ids: List[str],
        false_positive_ids: List[str],
    ) -> None:
        """User selects which secrets to clean and marks false positives."""
        self._check_not_expired()
        
        if self.status != JobStatus.SECRETS_FOUND:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "select_secrets"
            )
        
        # Update selection state
        for secret in self.secrets:
            if secret.id in false_positive_ids:
                secret.mark_as_false_positive()
            elif secret.id in selected_ids:
                secret.select_for_cleaning()
            else:
                secret.deselect_for_cleaning()
        
        selected_count = sum(1 for s in self.secrets if s.selected_for_cleaning)
        
        self._transition_to(
            JobStatus.SECRETS_SELECTED,
            f"Selected {selected_count} secrets for cleaning"
        )
        
        self._add_event(SecretsSelectedEvent(
            job_id=self.id,
            user_id=self.user_id,
            selected_count=selected_count,
            false_positives_count=len(false_positive_ids),
            secret_ids=selected_ids,
        ))
    
    def start_cleaning(self) -> None:
        """Start the cleaning process."""
        self._check_not_expired()
        
        if self.status != JobStatus.SECRETS_SELECTED:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "start_cleaning"
            )
        
        selected_count = sum(1 for s in self.secrets if s.selected_for_cleaning)
        if selected_count == 0:
            raise SecretsNotSelectedError(self.id)
        
        self._transition_to(JobStatus.CLEANING, "Starting history cleanup")
        
        self._add_event(CleaningStartedEvent(
            job_id=self.id,
            user_id=self.user_id,
            secrets_to_clean=selected_count,
        ))
    
    def complete_cleaning(
        self,
        secrets_cleaned: int,
        commits_rewritten: int,
        clean_duration: float,
    ) -> None:
        """Complete the cleaning process."""
        self._check_not_expired()
        
        if self.status != JobStatus.CLEANING:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "complete_cleaning"
            )
        
        self.commits_rewritten = commits_rewritten
        self._transition_to(JobStatus.CLEANED, f"Cleaned {secrets_cleaned} secrets")
        
        self._add_event(CleaningCompletedEvent(
            job_id=self.id,
            user_id=self.user_id,
            secrets_cleaned=secrets_cleaned,
            commits_rewritten=commits_rewritten,
            clean_duration_seconds=clean_duration,
        ))
    
    def start_pushing(self, force_push: bool = False) -> None:
        """Start pushing to target repository."""
        self._check_not_expired()
        
        if self.status != JobStatus.CLEANED:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "start_pushing"
            )
        
        if not self.target_url:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "start_pushing (no target configured)"
            )
        
        self._transition_to(JobStatus.PUSHING, "Pushing to target repository")
        
        self._add_event(PushStartedEvent(
            job_id=self.id,
            user_id=self.user_id,
            target_platform=self.target_platform or "",
            target_url=self.target_url,
            force_push=force_push,
        ))
    
    def complete_push(
        self,
        branches_pushed: int,
        tags_pushed: int,
    ) -> None:
        """Complete the push process."""
        self._check_not_expired()
        
        if self.status != JobStatus.PUSHING:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "complete_push"
            )
        
        self.branches_pushed = branches_pushed
        self.tags_pushed = tags_pushed
        self._transition_to(JobStatus.COMPLETED, "Migration completed successfully")
        
        self._add_event(PushCompletedEvent(
            job_id=self.id,
            user_id=self.user_id,
            target_platform=self.target_platform or "",
            target_url=self.target_url or "",
            branches_pushed=branches_pushed,
            tags_pushed=tags_pushed,
        ))
    
    def fail(self, error_code: str, error_message: str) -> None:
        """Mark job as failed."""
        old_status = self.status
        
        self.error_code = error_code
        self.error_message = error_message
        self._transition_to(JobStatus.FAILED, error_message)
        
        self._add_event(JobFailedEvent(
            job_id=self.id,
            user_id=self.user_id,
            failed_at_status=str(old_status.value),
            error_code=error_code,
            error_message=error_message,
        ))
    
    def cancel(self, reason: str = "Cancelled by user") -> None:
        """Cancel the job."""
        if self.status.is_terminal:
            raise InvalidJobStateError(
                self.id, str(self.status.value), "cancel"
            )
        
        old_status = self.status
        self._transition_to(JobStatus.CANCELLED, reason)
        
        self._add_event(JobCancelledEvent(
            job_id=self.id,
            user_id=self.user_id,
            cancelled_at_status=str(old_status.value),
            reason=reason,
        ))
    
    def expire(self) -> None:
        """Mark job as expired."""
        if self.status.is_terminal:
            return  # Already in terminal state
        
        old_status = self.status
        self._transition_to(JobStatus.EXPIRED, "Job expired due to inactivity")
        
        self._add_event(JobExpiredEvent(
            job_id=self.id,
            user_id=self.user_id,
            expired_at_status=str(old_status.value),
        ))
    
    # ==================== Progress Updates ====================
    
    def update_progress(self, percent: int, message: str = "") -> None:
        """Update progress without changing state."""
        self.progress_percent = max(0, min(100, percent))
        if message:
            self.status_message = message
        self._touch()
    
    def set_storage_path(self, path: str) -> None:
        """Set the storage path for the cloned repository."""
        self.storage_path = path
        self._touch()
    
    # ==================== Query Methods ====================
    
    @property
    def selected_secrets(self) -> List[SecretFinding]:
        """Get secrets selected for cleaning."""
        return [s for s in self.secrets if s.selected_for_cleaning]
    
    @property
    def false_positives(self) -> List[SecretFinding]:
        """Get secrets marked as false positives."""
        return [s for s in self.secrets if s.marked_as_false_positive]
    
    @property
    def is_expired(self) -> bool:
        """Check if job has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    @property
    def can_be_cancelled(self) -> bool:
        """Check if job can be cancelled."""
        return not self.status.is_terminal
    
    @property
    def domain_events(self) -> List[DomainEvent]:
        """Get pending domain events."""
        return list(self._events)
    
    def clear_events(self) -> List[DomainEvent]:
        """Clear and return pending events (called after persistence)."""
        events = self._events
        self._events = []
        return events
    
    # ==================== Optimistic Locking ====================
    
    def check_version(self, expected_version: int) -> None:
        """Check version for optimistic locking."""
        if self.version != expected_version:
            raise ConcurrentModificationError(
                self.id, expected_version, self.version
            )
    
    def increment_version(self) -> None:
        """Increment version after successful update."""
        self.version += 1
    
    # ==================== Private Methods ====================
    
    def _transition_to(self, new_status: JobStatus, message: str = "") -> None:
        """Internal method to transition status with validation."""
        if not self.status.can_transition_to(new_status):
            raise InvalidJobStateError(
                self.id,
                str(self.status.value),
                f"transition to {new_status.value}",
            )
        
        old_status = self.status
        self.status = new_status
        self.status_message = message
        self._touch()
        
        # Emit status change event
        self._add_event(JobStatusChangedEvent(
            job_id=self.id,
            user_id=self.user_id,
            old_status=str(old_status.value),
            new_status=str(new_status.value),
            message=message,
            progress_percent=self.progress_percent,
        ))
    
    def _touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.utcnow()
    
    def _check_not_expired(self) -> None:
        """Check that job hasn't expired."""
        if self.is_expired:
            raise JobExpiredError(self.id)
    
    def _add_event(self, event: DomainEvent) -> None:
        """Add a domain event."""
        self._events.append(event)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'source_platform': self.source_platform,
            'source_url': self.source_url,
            'source_branch': self.source_branch,
            'target_platform': self.target_platform,
            'target_url': self.target_url,
            'status': self.status.value,
            'status_message': self.status_message,
            'progress_percent': self.progress_percent,
            'secrets_count': len(self.secrets),
            'selected_secrets_count': len(self.selected_secrets),
            'total_commits_scanned': self.total_commits_scanned,
            'total_branches_scanned': self.total_branches_scanned,
            'commits_rewritten': self.commits_rewritten,
            'branches_pushed': self.branches_pushed,
            'tags_pushed': self.tags_pushed,
            'storage_path': self.storage_path,
            'error_code': self.error_code,
            'error_message': self.error_message,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'version': self.version,
        }
