"""BitBucket platform adapter implementation."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

import requests
from atlassian.bitbucket import Cloud as BitBucketCloud

from deployguard.core.exceptions import (
    AuthenticationError,
    NotFoundError,
    PlatformError,
)
from deployguard.core.models import Platform, Repository
from deployguard.platforms.base import IPlatformAdapter


class BitBucketAdapter(IPlatformAdapter):
    """
    BitBucket platform adapter using atlassian-python-api.

    Handles authentication, repository operations, and secret management
    for BitBucket repositories.
    """

    def __init__(self):
        """Initialize BitBucket adapter."""
        self._client: Optional[BitBucketCloud] = None
        self._workspace: Optional[str] = None
        self._username: Optional[str] = None
        self._token: Optional[str] = None

    def authenticate(self, credentials: Dict[str, str]) -> bool:
        """
        Authenticate with BitBucket using App Password.

        Args:
            credentials: Dict containing 'username', 'token', and 'workspace'

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        username = credentials.get("username")
        token = credentials.get("token")
        workspace = credentials.get("workspace")

        if not all([username, token, workspace]):
            raise AuthenticationError(
                "BitBucket requires username, token (app password), and workspace"
            )

        try:
            self._client = BitBucketCloud(
                url="https://api.bitbucket.org/",
                username=username,
                password=token,
                cloud=True,
            )

            self._username = username
            self._token = token
            self._workspace = workspace

            # Test authentication by getting workspace info
            self._client.workspaces.get(workspace)

            return True

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise AuthenticationError("Invalid BitBucket credentials")
            elif e.response.status_code == 404:
                raise AuthenticationError(f"Workspace '{workspace}' not found")
            else:
                raise PlatformError(f"BitBucket authentication error: {str(e)}")

    def is_authenticated(self) -> bool:
        """Check if currently authenticated."""
        if not self._client or not self._workspace:
            return False

        try:
            self._client.workspaces.get(self._workspace)
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
        List repositories in the workspace.

        Args:
            search: Search query string
            page: Page number for pagination
            per_page: Items per page
            **filters: Additional filters (role, etc.)

        Returns:
            List of Repository objects
        """
        if not self._client or not self._workspace:
            raise AuthenticationError("Not authenticated with BitBucket")

        try:
            repos: List[Repository] = []

            # Get repositories from workspace
            bb_repos = self._client.workspaces.get_repositories(self._workspace)

            # Apply search filter if provided
            if search:
                search_lower = search.lower()
                bb_repos = [
                    r
                    for r in bb_repos
                    if search_lower in r.get("name", "").lower()
                    or search_lower in r.get("full_name", "").lower()
                ]

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page

            for bb_repo in bb_repos[start:end]:
                repos.append(self._convert_to_repository(bb_repo))

            return repos

        except requests.exceptions.HTTPError as e:
            raise PlatformError(f"Failed to list repositories: {str(e)}")

    def get_repository(self, owner: str, name: str) -> Repository:
        """
        Get a specific repository.

        Args:
            owner: Repository owner/workspace
            name: Repository name (slug)

        Returns:
            Repository object

        Raises:
            NotFoundError: If repository not found
        """
        if not self._client:
            raise AuthenticationError("Not authenticated with BitBucket")

        try:
            bb_repo = self._client.repositories.get(owner, name)
            return self._convert_to_repository(bb_repo)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise NotFoundError(f"Repository {owner}/{name} not found")
            raise PlatformError(f"Failed to get repository: {str(e)}")

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
            name: Repository name (slug)
            description: Repository description
            private: Whether the repository should be private
            **options: Additional options (project, language, etc.)

        Returns:
            Created Repository object
        """
        if not self._client or not self._workspace:
            raise AuthenticationError("Not authenticated with BitBucket")

        try:
            # Prepare repository data
            repo_data = {
                "scm": "git",
                "is_private": private,
                "description": description,
                "fork_policy": "no_forks",
            }

            # Add optional project
            if "project" in options:
                repo_data["project"] = {"key": options["project"]}

            # Add optional language
            if "language" in options:
                repo_data["language"] = options["language"]

            bb_repo = self._client.repositories.create(
                self._workspace, name, **repo_data
            )

            return self._convert_to_repository(bb_repo)

        except requests.exceptions.HTTPError as e:
            raise PlatformError(f"Failed to create repository: {str(e)}")

    def upload_secrets(
        self,
        repository: Repository,
        secrets: Dict[str, str],
        environment: Optional[str] = None,
    ) -> bool:
        """
        Upload environment variables to BitBucket Pipelines.

        Args:
            repository: Target repository
            secrets: Dictionary of secret names to values
            environment: Environment scope (optional)

        Returns:
            True if successful
        """
        if not self._client:
            raise AuthenticationError("Not authenticated with BitBucket")

        try:
            # BitBucket API for repository variables
            owner, repo_slug = repository.full_name.split("/")

            for secret_name, secret_value in secrets.items():
                # Create pipeline variable
                variable_data = {
                    "key": secret_name,
                    "value": secret_value,
                    "secured": True,  # Mark as secured/secret
                }

                # Use requests to create variable (atlassian-python-api might not support this)
                url = f"https://api.bitbucket.org/2.0/repositories/{owner}/{repo_slug}/pipelines_config/variables/"
                response = requests.post(
                    url,
                    json=variable_data,
                    auth=(self._username, self._token),
                )
                response.raise_for_status()

            return True

        except requests.exceptions.HTTPError as e:
            raise PlatformError(f"Failed to upload secrets: {str(e)}")

    def _convert_to_repository(self, bb_repo: Dict) -> Repository:
        """Convert BitBucket repository dict to our Repository model."""
        full_name = bb_repo.get("full_name", "")
        owner = full_name.split("/")[0] if "/" in full_name else ""

        # Get clone URL (prefer HTTPS)
        clone_url = ""
        for clone in bb_repo.get("links", {}).get("clone", []):
            if clone.get("name") == "https":
                clone_url = clone.get("href", "")
                break

        return Repository(
            id=uuid4(),
            platform=Platform.BITBUCKET,
            owner=owner,
            name=bb_repo.get("name", ""),
            full_name=full_name,
            url=clone_url,
            default_branch=bb_repo.get("mainbranch", {}).get("name", "main"),
            is_private=bb_repo.get("is_private", True),
            created_at=datetime.fromisoformat(
                bb_repo.get("created_on", datetime.utcnow().isoformat()).replace(
                    "Z", "+00:00"
                )
            ),
            updated_at=datetime.fromisoformat(
                bb_repo.get("updated_on", datetime.utcnow().isoformat()).replace(
                    "Z", "+00:00"
                )
            ),
            metadata={
                "description": bb_repo.get("description", ""),
                "language": bb_repo.get("language", ""),
                "size_bytes": bb_repo.get("size", 0),
                "uuid": bb_repo.get("uuid", ""),
            },
        )

    @property
    def platform_type(self) -> Platform:
        """Get the platform type."""
        return Platform.BITBUCKET
