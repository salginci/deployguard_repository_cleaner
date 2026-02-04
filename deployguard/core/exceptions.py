"""Core exceptions for DeployGuard."""


class DeployGuardError(Exception):
    """Base exception for all DeployGuard errors."""

    def __init__(self, message: str, details: dict = None):
        """Initialize the exception."""
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(DeployGuardError):
    """Raised when authentication fails."""

    pass


class PlatformError(DeployGuardError):
    """Raised when a platform-specific error occurs."""

    pass


class RepositoryError(DeployGuardError):
    """Raised when repository operations fail."""

    pass


class CloneError(RepositoryError):
    """Raised when repository cloning fails."""

    pass


class ScanError(DeployGuardError):
    """Raised when scanning fails."""

    pass


class CleanupError(DeployGuardError):
    """Raised when cleanup operations fail."""

    pass


class PublishError(DeployGuardError):
    """Raised when publishing fails."""

    pass


class ConfigurationError(DeployGuardError):
    """Raised when configuration is invalid."""

    pass


class ValidationError(DeployGuardError):
    """Raised when data validation fails."""

    pass


class NotFoundError(DeployGuardError):
    """Raised when a resource is not found."""

    pass


class RateLimitError(DeployGuardError):
    """Raised when rate limit is exceeded."""

    pass
