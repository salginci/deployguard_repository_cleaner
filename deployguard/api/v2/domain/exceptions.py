"""
Domain Exceptions

Custom exceptions for the domain layer.
These represent business rule violations.
"""


class DomainError(Exception):
    """Base class for domain exceptions."""
    
    def __init__(self, message: str, code: str = None):
        self.message = message
        self.code = code or self.__class__.__name__
        super().__init__(message)


class JobNotFoundError(DomainError):
    """Raised when a job cannot be found."""
    
    def __init__(self, job_id: str):
        super().__init__(
            message=f"Job not found: {job_id}",
            code="JOB_NOT_FOUND"
        )
        self.job_id = job_id


class InvalidJobStateError(DomainError):
    """Raised when an operation is invalid for the current job state."""
    
    def __init__(self, current_state: str, expected_states: list, operation: str):
        states = ", ".join(expected_states)
        super().__init__(
            message=f"Cannot {operation} job in state '{current_state}'. Expected: {states}",
            code="INVALID_JOB_STATE"
        )
        self.current_state = current_state
        self.expected_states = expected_states
        self.operation = operation


class SecretsNotSelectedError(DomainError):
    """Raised when no secrets are selected for cleaning."""
    
    def __init__(self, job_id: str):
        super().__init__(
            message=f"No secrets selected for cleaning in job: {job_id}",
            code="NO_SECRETS_SELECTED"
        )
        self.job_id = job_id


class RepositoryAccessError(DomainError):
    """Raised when repository cannot be accessed."""
    
    def __init__(self, url: str, reason: str):
        super().__init__(
            message=f"Cannot access repository '{url}': {reason}",
            code="REPOSITORY_ACCESS_ERROR"
        )
        self.url = url
        self.reason = reason


class InvalidCredentialsError(DomainError):
    """Raised when credentials are invalid or expired."""
    
    def __init__(self, credential_id: str):
        super().__init__(
            message=f"Invalid or expired credentials: {credential_id}",
            code="INVALID_CREDENTIALS"
        )
        self.credential_id = credential_id


class StorageError(DomainError):
    """Raised when storage operations fail."""
    
    def __init__(self, operation: str, path: str, reason: str):
        super().__init__(
            message=f"Storage {operation} failed for '{path}': {reason}",
            code="STORAGE_ERROR"
        )
        self.operation = operation
        self.path = path
        self.reason = reason


class ScanError(DomainError):
    """Raised when secret scanning fails."""
    
    def __init__(self, job_id: str, reason: str):
        super().__init__(
            message=f"Scan failed for job '{job_id}': {reason}",
            code="SCAN_ERROR"
        )
        self.job_id = job_id
        self.reason = reason


class CleaningError(DomainError):
    """Raised when history cleaning fails."""
    
    def __init__(self, job_id: str, reason: str):
        super().__init__(
            message=f"Cleaning failed for job '{job_id}': {reason}",
            code="CLEANING_ERROR"
        )
        self.job_id = job_id
        self.reason = reason


class PushError(DomainError):
    """Raised when push to target repository fails."""
    
    def __init__(self, job_id: str, target_url: str, reason: str):
        super().__init__(
            message=f"Push failed for job '{job_id}' to '{target_url}': {reason}",
            code="PUSH_ERROR"
        )
        self.job_id = job_id
        self.target_url = target_url
        self.reason = reason


class JobExpiredError(DomainError):
    """Raised when job has expired."""
    
    def __init__(self, job_id: str):
        super().__init__(
            message=f"Job has expired: {job_id}",
            code="JOB_EXPIRED"
        )
        self.job_id = job_id


class ConcurrentModificationError(DomainError):
    """Raised when concurrent modification is detected."""
    
    def __init__(self, entity_type: str, entity_id: str):
        super().__init__(
            message=f"Concurrent modification detected for {entity_type}: {entity_id}",
            code="CONCURRENT_MODIFICATION"
        )
        self.entity_type = entity_type
        self.entity_id = entity_id
