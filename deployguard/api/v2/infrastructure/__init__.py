"""
Infrastructure Layer

This layer contains implementations of interfaces defined in the application layer.
It handles external concerns like databases, message brokers, and file systems.
"""

from .db_models import Base, JobModel, SecretModel, AuditModel, OutboxModel
from .repositories import (
    SQLAlchemyJobRepository,
    SQLAlchemySecretRepository,
    SQLAlchemyAuditRepository,
    SQLAlchemyOutboxRepository,
)
from .unit_of_work import SQLAlchemyUnitOfWork, create_unit_of_work_factory
from .outbox_processor import OutboxProcessor, RabbitMQEventPublisher
from .services import (
    LocalStorageService,
    GitCommandService,
    SecretScannerService,
    HistoryCleanerService,
)


__all__ = [
    # Database Models
    "Base",
    "JobModel",
    "SecretModel",
    "AuditModel",
    "OutboxModel",
    # Repositories
    "SQLAlchemyJobRepository",
    "SQLAlchemySecretRepository",
    "SQLAlchemyAuditRepository",
    "SQLAlchemyOutboxRepository",
    # Unit of Work
    "SQLAlchemyUnitOfWork",
    "create_unit_of_work_factory",
    # Outbox Pattern
    "OutboxProcessor",
    "RabbitMQEventPublisher",
    # Services
    "LocalStorageService",
    "GitCommandService",
    "SecretScannerService",
    "HistoryCleanerService",
]
