"""Base interfaces for platform adapters."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from deployguard.core.models import Platform, Repository


class IPlatformAdapter(ABC):
    """Interface for Git platform adapters."""

    @abstractmethod
    def authenticate(self, credentials: Dict[str, str]) -> bool:
        """
        Authenticate with the platform.

        Args:
            credentials: Platform-specific credentials (token, OAuth, etc.)

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        pass

    @abstractmethod
    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        pass

    @abstractmethod
    def get_repositories(
        self,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
        **filters: any,
    ) -> List[Repository]:
        """
        List repositories accessible to the authenticated user.

        Args:
            search: Search query string
            page: Page number for pagination
            per_page: Items per page
            **filters: Platform-specific filters

        Returns:
            List of Repository objects
        """
        pass

    @abstractmethod
    def get_repository(self, owner: str, name: str) -> Repository:
        """
        Get a specific repository.

        Args:
            owner: Repository owner/organization
            name: Repository name

        Returns:
            Repository object

        Raises:
            NotFoundError: If repository not found
        """
        pass

    @abstractmethod
    def create_repository(
        self,
        name: str,
        description: str = "",
        private: bool = True,
        **options: any,
    ) -> Repository:
        """
        Create a new repository.

        Args:
            name: Repository name
            description: Repository description
            private: Whether the repository should be private
            **options: Platform-specific options

        Returns:
            Created Repository object
        """
        pass

    @abstractmethod
    def upload_secrets(
        self,
        repository: Repository,
        secrets: Dict[str, str],
        environment: Optional[str] = None,
    ) -> bool:
        """
        Upload environment variables/secrets to the repository.

        Args:
            repository: Target repository
            secrets: Dictionary of secret names to values
            environment: Environment scope (e.g., 'production')

        Returns:
            True if successful
        """
        pass

    @property
    @abstractmethod
    def platform_type(self) -> Platform:
        """Get the platform type."""
        pass
