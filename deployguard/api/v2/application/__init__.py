"""
Application Layer

This layer contains the application business rules (use cases).
It orchestrates the flow of data between the domain and infrastructure layers.
"""

from .ports import (
    JobRepository,
    SecretRepository,
    AuditRepository,
    OutboxRepository,
    StorageService,
    GitService,
    ScannerService,
    CleanerService,
    EventPublisher,
    UnitOfWork,
)

from .dtos import (
    # Request DTOs
    CreateJobRequest,
    SelectSecretsRequest,
    StartCleaningRequest,
    PushRepositoryRequest,
    CancelJobRequest,
    GetJobRequest,
    ListJobsRequest,
    # Response DTOs
    SecretDTO,
    JobDTO,
    JobListDTO,
    AuditEntryDTO,
    # Result types
    Result,
    ResultStatus,
    CreateJobResult,
    ScanResult,
    CleanResult,
    PushResult,
)

from .use_cases import (
    CreateScanJobUseCase,
    ExecuteScanUseCase,
    SelectSecretsUseCase,
    StartCleaningUseCase,
    ExecuteCleaningUseCase,
    PushRepositoryUseCase,
    GetJobUseCase,
    ListJobsUseCase,
    CancelJobUseCase,
)


__all__ = [
    # Ports (Interfaces)
    "JobRepository",
    "SecretRepository",
    "AuditRepository",
    "OutboxRepository",
    "StorageService",
    "GitService",
    "ScannerService",
    "CleanerService",
    "EventPublisher",
    "UnitOfWork",
    # Request DTOs
    "CreateJobRequest",
    "SelectSecretsRequest",
    "StartCleaningRequest",
    "PushRepositoryRequest",
    "CancelJobRequest",
    "GetJobRequest",
    "ListJobsRequest",
    # Response DTOs
    "SecretDTO",
    "JobDTO",
    "JobListDTO",
    "AuditEntryDTO",
    # Result types
    "Result",
    "ResultStatus",
    "CreateJobResult",
    "ScanResult",
    "CleanResult",
    "PushResult",
    # Use Cases
    "CreateScanJobUseCase",
    "ExecuteScanUseCase",
    "SelectSecretsUseCase",
    "StartCleaningUseCase",
    "ExecuteCleaningUseCase",
    "PushRepositoryUseCase",
    "GetJobUseCase",
    "ListJobsUseCase",
    "CancelJobUseCase",
]
