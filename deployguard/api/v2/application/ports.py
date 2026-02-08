"""
Application Layer - Ports (Interfaces)

Ports define the contracts between the application layer and infrastructure.
They follow the Dependency Inversion Principle - high-level modules don't
depend on low-level modules, both depend on abstractions.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime

from ..domain.entities import Job, SecretFinding, AuditEntry
from ..domain.events import DomainEvent


class JobRepository(ABC):
    """
    Repository interface for Job aggregate persistence.
    
    Repositories handle persistence concerns while keeping
    the domain layer clean of infrastructure details.
    """
    
    @abstractmethod
    async def save(self, job: Job) -> None:
        """Save a job (insert or update based on existence)."""
        pass
    
    @abstractmethod
    async def get_by_id(self, job_id: str) -> Optional[Job]:
        """Get a job by its ID."""
        pass
    
    @abstractmethod
    async def get_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 20,
    ) -> List[Job]:
        """Get jobs for a user with pagination."""
        pass
    
    @abstractmethod
    async def delete(self, job_id: str) -> bool:
        """Delete a job and its related data."""
        pass
    
    @abstractmethod
    async def get_expired_jobs(self, before: datetime) -> List[Job]:
        """Get jobs that have expired."""
        pass
    
    @abstractmethod
    async def count_by_user(self, user_id: str) -> int:
        """Count jobs for a user."""
        pass


class SecretRepository(ABC):
    """
    Repository interface for SecretFinding persistence.
    
    Secrets are part of the Job aggregate but may need
    separate persistence operations for performance.
    """
    
    @abstractmethod
    async def save_all(self, secrets: List[SecretFinding]) -> None:
        """Save multiple secrets in a single transaction."""
        pass
    
    @abstractmethod
    async def get_by_job(self, job_id: str) -> List[SecretFinding]:
        """Get all secrets for a job."""
        pass
    
    @abstractmethod
    async def update_selection(
        self,
        job_id: str,
        selected_ids: List[str],
        false_positive_ids: List[str],
    ) -> None:
        """Update selection state for secrets."""
        pass
    
    @abstractmethod
    async def delete_by_job(self, job_id: str) -> int:
        """Delete all secrets for a job. Returns count deleted."""
        pass


class AuditRepository(ABC):
    """
    Repository interface for AuditEntry persistence.
    
    Audit logs are append-only and immutable.
    """
    
    @abstractmethod
    async def save(self, entry: AuditEntry) -> None:
        """Save an audit entry."""
        pass
    
    @abstractmethod
    async def get_by_job(
        self,
        job_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit entries for a job."""
        pass
    
    @abstractmethod
    async def get_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit entries for a user."""
        pass


class OutboxRepository(ABC):
    """
    Repository interface for Outbox Pattern implementation.
    
    The Outbox Pattern ensures reliable event publishing by:
    1. Storing events in the same transaction as aggregate changes
    2. Having a separate process publish events to message broker
    3. Marking events as published after successful delivery
    """
    
    @abstractmethod
    async def save(self, event: DomainEvent) -> None:
        """Save an event to the outbox."""
        pass
    
    @abstractmethod
    async def save_all(self, events: List[DomainEvent]) -> None:
        """Save multiple events to the outbox in a single transaction."""
        pass
    
    @abstractmethod
    async def get_unpublished(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get unpublished events for processing.
        
        Returns list of dicts with:
        - id: outbox message id
        - event_type: type of event
        - aggregate_type: type of aggregate
        - aggregate_id: id of aggregate
        - payload: serialized event data
        - created_at: when event was created
        """
        pass
    
    @abstractmethod
    async def mark_as_published(self, message_ids: List[str]) -> None:
        """Mark events as published after successful delivery."""
        pass
    
    @abstractmethod
    async def delete_published(self, older_than: datetime) -> int:
        """Delete old published messages. Returns count deleted."""
        pass


class StorageService(ABC):
    """
    Service interface for repository storage (MinIO/S3).
    
    Handles temporary storage of cloned repositories.
    """
    
    @abstractmethod
    async def create_workspace(self, job_id: str) -> str:
        """Create a workspace directory for a job. Returns path."""
        pass
    
    @abstractmethod
    async def delete_workspace(self, job_id: str) -> None:
        """Delete the workspace for a job."""
        pass
    
    @abstractmethod
    async def get_workspace_path(self, job_id: str) -> Optional[str]:
        """Get the workspace path for a job."""
        pass
    
    @abstractmethod
    async def workspace_exists(self, job_id: str) -> bool:
        """Check if workspace exists."""
        pass


class GitService(ABC):
    """
    Service interface for Git operations.
    
    Wraps git operations with platform-specific authentication.
    """
    
    @abstractmethod
    async def clone(
        self,
        url: str,
        target_path: str,
        branch: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> None:
        """Clone a repository."""
        pass
    
    @abstractmethod
    async def push(
        self,
        repo_path: str,
        remote_url: str,
        force: bool = False,
        credentials: Optional[Dict[str, str]] = None,
    ) -> Dict[str, int]:
        """
        Push repository to remote.
        
        Returns dict with branches_pushed, tags_pushed counts.
        """
        pass


class ScannerService(ABC):
    """
    Service interface for secret scanning.
    """
    
    @abstractmethod
    async def scan(
        self,
        repo_path: str,
        branches: Optional[List[str]] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan repository for secrets.
        
        Returns list of findings with:
        - file_path, line_number, commit_hash, branch
        - secret_value, pattern_name, severity, confidence
        - code_context, author, commit_date
        """
        pass


class CleanerService(ABC):
    """
    Service interface for history cleaning.
    """
    
    @abstractmethod
    async def clean(
        self,
        repo_path: str,
        secrets_to_remove: List[str],
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Clean secrets from repository history.
        
        Returns dict with:
        - commits_rewritten: int
        - secrets_removed: int
        - duration_seconds: float
        """
        pass


class EventPublisher(ABC):
    """
    Service interface for publishing domain events.
    
    Used by the Outbox Processor to publish events to message broker.
    """
    
    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish a single event to the message broker."""
        pass
    
    @abstractmethod
    async def publish_batch(self, events: List[DomainEvent]) -> None:
        """Publish multiple events to the message broker."""
        pass
    
    @abstractmethod
    async def is_connected(self) -> bool:
        """Check if connection to message broker is available."""
        pass


class UnitOfWork(ABC):
    """
    Unit of Work pattern for managing transactions.
    
    Ensures that all operations within a use case are
    committed or rolled back together.
    """
    
    @property
    @abstractmethod
    def jobs(self) -> JobRepository:
        """Get the job repository."""
        pass
    
    @property
    @abstractmethod
    def secrets(self) -> SecretRepository:
        """Get the secret repository."""
        pass
    
    @property
    @abstractmethod
    def audits(self) -> AuditRepository:
        """Get the audit repository."""
        pass
    
    @property
    @abstractmethod
    def outbox(self) -> OutboxRepository:
        """Get the outbox repository."""
        pass
    
    @abstractmethod
    async def begin(self) -> None:
        """Begin a transaction."""
        pass
    
    @abstractmethod
    async def commit(self) -> None:
        """Commit the transaction."""
        pass
    
    @abstractmethod
    async def rollback(self) -> None:
        """Rollback the transaction."""
        pass
    
    @abstractmethod
    async def __aenter__(self) -> 'UnitOfWork':
        """Enter async context manager."""
        pass
    
    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager, commit or rollback."""
        pass
