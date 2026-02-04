"""GitHub platform adapter implementation."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from github import Github, GithubException
from github.Repository import Repository as GHRepo

from deployguard.core.exceptions import (
    AuthenticationError,
    NotFoundError,
    PlatformError,
    RateLimitError,
)
from deployguard.core.models import Platform, Repository
from deployguard.platforms.base import IPlatformAdapter


class GitHubAdapter(IPlatformAdapter):
    """
    GitHub platform adapter using PyGithub.

    Handles authentication, repository operations, and secret management
    for GitHub repositories.
    """

    def __init__(self):
        """Initialize GitHub adapter."""
        self._client: Optional[Github] = None
        self._token: Optional[str] = None

    def authenticate(self, credentials: Dict[str, str]) -> bool:
        """
        Authenticate with GitHub using Personal Access Token.

        Args:
            credentials: Dict containing 'token' key with PAT

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        token = credentials.get("token")
        if not token:
            raise AuthenticationError("GitHub token is required")

        try:
            self._client = Github(token)
            self._token = token

            # Test authentication by getting user info
            user = self._client.get_user()
            user.login  # Force API call

            return True

        except GithubException as e:
            if e.status == 401:
                raise AuthenticationError(f"Invalid GitHub token: {e.data.get('message', '')}")
            elif e.status == 403:
                raise RateLimitError(f"GitHub rate limit exceeded: {e.data.get('message', '')}")
            else:
                raise PlatformError(f"GitHub authentication error: {e.data.get('message', '')}")

    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        if not self._client:
            return False

        try:
            user = self._client.get_user()
            user.login
            return True
        except Exception:
            return False

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
            per_page: Items per page (max 100)
            **filters: Additional filters (visibility, affiliation, etc.)

        Returns:
            List of Repository objects
        """
        if not self._client:
            raise AuthenticationError("Not authenticated with GitHub")

        try:
            repos: List[Repository] = []
            user = self._client.get_user()

            # Get repositories with filters
            visibility = filters.get("visibility", "all")
            affiliation = filters.get("affiliation", "owner,collaborator,organization_member")

            gh_repos = user.get_repos(
                visibility=visibility,
                affiliation=affiliation,
                sort="updated",
                direction="desc",
            )

            # Apply search filter if provided
            filtered_repos = gh_repos
            if search:
                search_lower = search.lower()
                filtered_repos = [
                    r
                    for r in gh_repos
                    if search_lower in r.name.lower() or search_lower in r.full_name.lower()
                ]

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page

            for gh_repo in list(filtered_repos)[start:end]:
                repos.append(self._convert_to_repository(gh_repo))

            return repos

        except GithubException as e:
            raise PlatformError(f"Failed to list repositories: {e.data.get('message', '')}")

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
        if not self._client:
            raise AuthenticationError("Not authenticated with GitHub")

        try:
            gh_repo = self._client.get_repo(f"{owner}/{name}")
            return self._convert_to_repository(gh_repo)

        except GithubException as e:
            if e.status == 404:
                raise NotFoundError(f"Repository {owner}/{name} not found")
            raise PlatformError(f"Failed to get repository: {e.data.get('message', '')}")

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
            **options: Additional options (auto_init, gitignore_template, etc.)

        Returns:
            Created Repository object
        """
        if not self._client:
            raise AuthenticationError("Not authenticated with GitHub")

        try:
            user = self._client.get_user()

            # Check if creating in organization
            org_name = options.get("organization")
            if org_name:
                org = self._client.get_organization(org_name)
                gh_repo = org.create_repo(
                    name=name,
                    description=description,
                    private=private,
                    auto_init=options.get("auto_init", True),
                    gitignore_template=options.get("gitignore_template"),
                )
            else:
                gh_repo = user.create_repo(
                    name=name,
                    description=description,
                    private=private,
                    auto_init=options.get("auto_init", True),
                    gitignore_template=options.get("gitignore_template"),
                )

            return self._convert_to_repository(gh_repo)

        except GithubException as e:
            raise PlatformError(f"Failed to create repository: {e.data.get('message', '')}")

    def upload_secrets(
        self,
        repository: Repository,
        secrets: Dict[str, str],
        environment: Optional[str] = None,
    ) -> bool:
        """
        Upload environment variables/secrets to GitHub Actions.

        Args:
            repository: Target repository
            secrets: Dictionary of secret names to values
            environment: Environment scope (optional)

        Returns:
            True if successful
        """
        if not self._client:
            raise AuthenticationError("Not authenticated with GitHub")

        try:
            gh_repo = self._client.get_repo(repository.full_name)

            # Upload each secret
            for secret_name, secret_value in secrets.items():
                # GitHub Actions secrets
                gh_repo.create_secret(secret_name, secret_value)

            return True

        except GithubException as e:
            raise PlatformError(f"Failed to upload secrets: {e.data.get('message', '')}")

    def _convert_to_repository(self, gh_repo: GHRepo) -> Repository:
        """Convert GitHub Repository to our Repository model."""
        return Repository(
            id=uuid4(),
            platform=Platform.GITHUB,
            owner=gh_repo.owner.login,
            name=gh_repo.name,
            full_name=gh_repo.full_name,
            url=gh_repo.clone_url,
            default_branch=gh_repo.default_branch or "main",
            is_private=gh_repo.private,
            created_at=gh_repo.created_at or datetime.utcnow(),
            updated_at=gh_repo.updated_at or datetime.utcnow(),
            metadata={
                "description": gh_repo.description,
                "stars": gh_repo.stargazers_count,
                "forks": gh_repo.forks_count,
                "language": gh_repo.language,
                "size_kb": gh_repo.size,
            },
        )

    @property
    def platform_type(self) -> Platform:
        """Get the platform type."""
        return Platform.GITHUB
