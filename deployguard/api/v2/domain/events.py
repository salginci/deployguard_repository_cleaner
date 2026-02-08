"""
Domain Events

Events represent something that happened in the domain.
They are used for:
1. Event sourcing (rebuilding state from events)
2. Integration with external systems (via Outbox Pattern)
3. Triggering side effects in a decoupled way
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
import uuid
import json


@dataclass
class DomainEvent:
    """
    Base class for domain events.
    
    Events are immutable facts about something that happened.
    They are named in past tense (JobCreated, ScanCompleted).
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1
    
    @property
    def event_type(self) -> str:
        """Event type name for serialization."""
        return self.__class__.__name__
    
    @property
    def aggregate_type(self) -> str:
        """Type of aggregate this event belongs to."""
        return "Job"  # Default, override in subclasses
    
    @property
    def aggregate_id(self) -> str:
        """ID of the aggregate this event belongs to."""
        raise NotImplementedError("Subclasses must implement aggregate_id")
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize event to dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'aggregate_type': self.aggregate_type,
            'aggregate_id': self.aggregate_id,
            'occurred_at': self.occurred_at.isoformat(),
            'version': self.version,
            'payload': self._payload(),
        }
    
    def _payload(self) -> Dict[str, Any]:
        """Event-specific payload. Override in subclasses."""
        return {}
    
    def to_json(self) -> str:
        """Serialize event to JSON string."""
        return json.dumps(self.to_dict(), default=str)


@dataclass
class JobCreatedEvent(DomainEvent):
    """Emitted when a new scan job is created."""
    job_id: str = ""
    user_id: str = ""
    source_platform: str = ""
    source_url: str = ""
    source_branch: str = "main"
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'source_platform': self.source_platform,
            'source_url': self.source_url,
            'source_branch': self.source_branch,
        }


@dataclass
class JobStatusChangedEvent(DomainEvent):
    """Emitted when job status changes."""
    job_id: str = ""
    user_id: str = ""
    old_status: str = ""
    new_status: str = ""
    message: str = ""
    progress_percent: int = 0
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'old_status': self.old_status,
            'new_status': self.new_status,
            'message': self.message,
            'progress_percent': self.progress_percent,
        }


@dataclass
class ScanCompletedEvent(DomainEvent):
    """Emitted when repository scan completes."""
    job_id: str = ""
    user_id: str = ""
    secrets_found: int = 0
    total_commits: int = 0
    total_branches: int = 0
    scan_duration_seconds: float = 0.0
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'secrets_found': self.secrets_found,
            'total_commits': self.total_commits,
            'total_branches': self.total_branches,
            'scan_duration_seconds': self.scan_duration_seconds,
        }


@dataclass
class SecretsSelectedEvent(DomainEvent):
    """Emitted when user selects secrets to clean."""
    job_id: str = ""
    user_id: str = ""
    selected_count: int = 0
    false_positives_count: int = 0
    secret_ids: List[str] = field(default_factory=list)
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'selected_count': self.selected_count,
            'false_positives_count': self.false_positives_count,
            'secret_ids': self.secret_ids,
        }


@dataclass
class CleaningStartedEvent(DomainEvent):
    """Emitted when cleaning process starts."""
    job_id: str = ""
    user_id: str = ""
    secrets_to_clean: int = 0
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'secrets_to_clean': self.secrets_to_clean,
        }


@dataclass
class CleaningCompletedEvent(DomainEvent):
    """Emitted when history cleaning completes."""
    job_id: str = ""
    user_id: str = ""
    secrets_cleaned: int = 0
    commits_rewritten: int = 0
    clean_duration_seconds: float = 0.0
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'secrets_cleaned': self.secrets_cleaned,
            'commits_rewritten': self.commits_rewritten,
            'clean_duration_seconds': self.clean_duration_seconds,
        }


@dataclass
class PushStartedEvent(DomainEvent):
    """Emitted when push to target starts."""
    job_id: str = ""
    user_id: str = ""
    target_platform: str = ""
    target_url: str = ""
    force_push: bool = False
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'target_platform': self.target_platform,
            'target_url': self.target_url,
            'force_push': self.force_push,
        }


@dataclass
class PushCompletedEvent(DomainEvent):
    """Emitted when repository is pushed to target."""
    job_id: str = ""
    user_id: str = ""
    target_platform: str = ""
    target_url: str = ""
    branches_pushed: int = 0
    tags_pushed: int = 0
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'target_platform': self.target_platform,
            'target_url': self.target_url,
            'branches_pushed': self.branches_pushed,
            'tags_pushed': self.tags_pushed,
        }


@dataclass
class JobFailedEvent(DomainEvent):
    """Emitted when a job fails."""
    job_id: str = ""
    user_id: str = ""
    failed_at_status: str = ""
    error_code: str = ""
    error_message: str = ""
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'failed_at_status': self.failed_at_status,
            'error_code': self.error_code,
            'error_message': self.error_message,
        }


@dataclass
class JobCancelledEvent(DomainEvent):
    """Emitted when a job is cancelled by user."""
    job_id: str = ""
    user_id: str = ""
    cancelled_at_status: str = ""
    reason: str = ""
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'cancelled_at_status': self.cancelled_at_status,
            'reason': self.reason,
        }


@dataclass
class JobExpiredEvent(DomainEvent):
    """Emitted when a job expires automatically."""
    job_id: str = ""
    user_id: str = ""
    expired_at_status: str = ""
    
    @property
    def aggregate_id(self) -> str:
        return self.job_id
    
    def _payload(self) -> Dict[str, Any]:
        return {
            'job_id': self.job_id,
            'user_id': self.user_id,
            'expired_at_status': self.expired_at_status,
        }
