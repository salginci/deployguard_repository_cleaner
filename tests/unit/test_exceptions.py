"""Unit tests for exceptions."""

import pytest

from deployguard.core.exceptions import (
    AuthenticationError,
    CleanupError,
    CloneError,
    ConfigurationError,
    DeployGuardError,
    NotFoundError,
    PlatformError,
    PublishError,
    RateLimitError,
    RepositoryError,
    ScanError,
    ValidationError,
)


@pytest.mark.unit
class TestExceptions:
    """Test custom exceptions."""

    def test_base_exception(self):
        """Test base DeployGuardError."""
        error = DeployGuardError("Test error", details={"key": "value"})

        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.details == {"key": "value"}

    def test_authentication_error(self):
        """Test AuthenticationError."""
        error = AuthenticationError("Invalid token")

        assert isinstance(error, DeployGuardError)
        assert str(error) == "Invalid token"

    def test_platform_error(self):
        """Test PlatformError."""
        error = PlatformError("API error", details={"status": 500})

        assert isinstance(error, DeployGuardError)
        assert error.details["status"] == 500

    def test_repository_error(self):
        """Test RepositoryError."""
        error = RepositoryError("Repo not found")

        assert isinstance(error, DeployGuardError)

    def test_clone_error(self):
        """Test CloneError inherits from RepositoryError."""
        error = CloneError("Clone failed")

        assert isinstance(error, RepositoryError)
        assert isinstance(error, DeployGuardError)

    def test_scan_error(self):
        """Test ScanError."""
        error = ScanError("Scan failed")

        assert isinstance(error, DeployGuardError)

    def test_cleanup_error(self):
        """Test CleanupError."""
        error = CleanupError("Cleanup failed")

        assert isinstance(error, DeployGuardError)

    def test_publish_error(self):
        """Test PublishError."""
        error = PublishError("Publish failed")

        assert isinstance(error, DeployGuardError)

    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError("Invalid config")

        assert isinstance(error, DeployGuardError)

    def test_validation_error(self):
        """Test ValidationError."""
        error = ValidationError("Invalid input")

        assert isinstance(error, DeployGuardError)

    def test_not_found_error(self):
        """Test NotFoundError."""
        error = NotFoundError("Resource not found")

        assert isinstance(error, DeployGuardError)

    def test_rate_limit_error(self):
        """Test RateLimitError."""
        error = RateLimitError("Rate limit exceeded")

        assert isinstance(error, DeployGuardError)

    def test_exception_with_empty_details(self):
        """Test exception without details."""
        error = DeployGuardError("Test error")

        assert error.details == {}
