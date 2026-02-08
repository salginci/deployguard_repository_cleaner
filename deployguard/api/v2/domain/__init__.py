"""
Domain Layer - DeployGuard API v2

This layer contains the core business logic and domain entities.
It has NO dependencies on external frameworks (FastAPI, SQLAlchemy, Celery).

Clean Architecture Principles:
- Entities are pure Python classes with business logic
- Value Objects are immutable and define by their attributes
- Domain Events represent something that happened in the domain
- Domain Services contain business logic that doesn't belong to entities
"""

from .entities import Job, SecretFinding, AuditEntry
from .value_objects import JobId, UserId, SecretHash, JobStatus, SecretType, Severity
from .events import (
    DomainEvent,
    JobCreatedEvent,
    ScanCompletedEvent,
    SecretsSelectedEvent,
    CleaningCompletedEvent,
    PushCompletedEvent,
    JobFailedEvent
)
from .exceptions import (
    DomainError,
    JobNotFoundError,
    InvalidJobStateError,
    SecretsNotSelectedError,
    RepositoryAccessError
)

__all__ = [
    # Entities
    'Job', 'SecretFinding', 'AuditEntry',
    # Value Objects
    'JobId', 'UserId', 'SecretHash', 'JobStatus', 'SecretType', 'Severity',
    # Events
    'DomainEvent', 'JobCreatedEvent', 'ScanCompletedEvent', 'SecretsSelectedEvent',
    'CleaningCompletedEvent', 'PushCompletedEvent', 'JobFailedEvent',
    # Exceptions
    'DomainError', 'JobNotFoundError', 'InvalidJobStateError',
    'SecretsNotSelectedError', 'RepositoryAccessError'
]
