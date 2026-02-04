"""
Repository connection endpoints using Personal Access Tokens (PAT).

Flow:
1. User creates a PAT on GitHub/Bitbucket (with repo access)
2. User pastes the token in the control panel
3. We validate and store the token
4. User can list and scan their repositories
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()

# In-memory stores (use database in production)
_user_tokens: dict[str, dict] = {}
_connected_repos: dict[str, dict] = {}


# =============================================================================
# Request/Response Models
# =============================================================================

class ConnectTokenRequest(BaseModel):
    """Request to connect with a personal access token."""
    provider: str  # "github", "bitbucket", or "bitbucket_server"
    token: str
    # For Bitbucket Cloud, username is needed with app password
    username: Optional[str] = None
    # For Bitbucket Server, the server URL is needed
    server_url: Optional[str] = None


class ConnectRepositoryRequest(BaseModel):
    """Request to connect a repository for scanning."""
    provider: str
    repo_full_name: str  # e.g., "owner/repo-name"


class ScanOptionsRequest(BaseModel):
    """Options for scanning a repository."""
    scan_history: bool = False
    verify_secrets: bool = False
    branch: Optional[str] = None


# =============================================================================
# Provider Configuration
# =============================================================================

@router.get("/providers")
async def list_providers():
    """List available source control providers with setup instructions."""
    return {
        "providers": [
            {
                "id": "github",
                "name": "GitHub",
                "icon": "github",
                "token_url": "https://github.com/settings/tokens/new",
                "instructions": [
                    "Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)",
                    "Click 'Generate new token (classic)'",
                    "Give it a name like 'DeployGuard'",
                    "Select scopes: 'repo' (full control of private repos)",
                    "Click 'Generate token' and copy it",
                ],
                "required_scopes": ["repo"],
            },
            {
                "id": "bitbucket",
                "name": "Bitbucket Cloud",
                "icon": "bitbucket",
                "token_url": "https://bitbucket.org/account/settings/app-passwords/new",
                "instructions": [
                    "Go to Bitbucket → Personal settings → App passwords",
                    "Click 'Create app password'",
                    "Give it a label like 'DeployGuard'",
                    "Select permissions: Repositories (Read, Write)",
                    "Click 'Create' and copy the password",
                    "You'll also need your Bitbucket username",
                ],
                "required_scopes": ["repository:read", "repository:write"],
                "requires_username": True,
            },
            {
                "id": "bitbucket_server",
                "name": "Bitbucket Server / Data Center",
                "icon": "bitbucket",
                "token_url": "",  # Dynamic based on server URL
                "instructions": [
                    "Go to your Bitbucket Server → Account settings → HTTP access tokens",
                    "Click 'Create token'",
                    "Give it a name like 'DeployGuard'",
                    "Select permissions: Project Admin and Repository Admin",
                    "Click 'Create' and copy the token",
                    "You'll also need to provide your Bitbucket Server URL",
                ],
                "required_scopes": ["PROJECT_ADMIN", "REPOSITORY_ADMIN"],
                "requires_server_url": True,
            },
        ]
    }


# =============================================================================
# Token Management
# =============================================================================

@router.post("/connect")
async def connect_provider(
    request: ConnectTokenRequest,
    user_id: str = Query(..., description="User ID from your system"),
):
    """
    Connect a source control provider with a personal access token.
    
    Validates the token and stores it for the user.
    """
    import aiohttp
    
    provider = request.provider.lower()
    token = request.token
    
    if provider not in ["github", "bitbucket", "bitbucket_server"]:
        raise HTTPException(status_code=400, detail="Provider must be 'github', 'bitbucket', or 'bitbucket_server'")
    
    # Validate token by fetching user info
    async with aiohttp.ClientSession() as session:
        if provider == "github":
            user_info = await _validate_github_token(session, token)
        elif provider == "bitbucket":
            if not request.username:
                raise HTTPException(status_code=400, detail="Bitbucket Cloud requires username with app password")
            user_info = await _validate_bitbucket_token(session, request.username, token)
        elif provider == "bitbucket_server":
            if not request.server_url:
                raise HTTPException(status_code=400, detail="Bitbucket Server requires server_url")
            user_info = await _validate_bitbucket_server_token(session, request.server_url, token)
        else:
            user_info = None
    
    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token or insufficient permissions")
    
    # Store token
    key = f"{user_id}:{provider}"
    _user_tokens[key] = {
        "provider": provider,
        "token": token,
        "username": user_info.get("username") or request.username,
        "server_url": request.server_url,  # Store server URL for Bitbucket Server
        "user_info": user_info,
        "connected_at": datetime.utcnow(),
    }
    
    return {
        "connected": True,
        "provider": provider,
        "username": user_info.get("username"),
        "name": user_info.get("name"),
        "avatar_url": user_info.get("avatar_url"),
    }


async def _validate_github_token(session, token: str) -> Optional[dict]:
    """Validate GitHub token and return user info."""
    async with session.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
    ) as resp:
        if resp.status != 200:
            return None
        data = await resp.json()
        return {
            "username": data.get("login"),
            "name": data.get("name"),
            "email": data.get("email"),
            "avatar_url": data.get("avatar_url"),
        }


async def _validate_bitbucket_token(session, username: str, token: str) -> Optional[dict]:
    """Validate Bitbucket Cloud app password and return user info."""
    import base64
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    
    async with session.get(
        "https://api.bitbucket.org/2.0/user",
        headers={
            "Authorization": f"Basic {auth}",
            "Accept": "application/json",
        },
    ) as resp:
        if resp.status != 200:
            return None
        data = await resp.json()
        return {
            "username": data.get("username"),
            "name": data.get("display_name"),
            "avatar_url": data.get("links", {}).get("avatar", {}).get("href"),
        }


async def _validate_bitbucket_server_token(session, server_url: str, token: str) -> Optional[dict]:
    """Validate Bitbucket Server/Data Center HTTP access token and return user info."""
    # Ensure server URL doesn't have trailing slash
    server_url = server_url.rstrip("/")
    
    # Bitbucket Server REST API endpoint for current user
    # API is at /rest/api/1.0/ for Bitbucket Server
    async with session.get(
        f"{server_url}/rest/api/1.0/users",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        params={"limit": 1},
        ssl=False,  # Allow self-signed certs for internal servers
    ) as resp:
        if resp.status == 401:
            return None
        # If we can list users, the token is valid. Now get current user info
        # Bitbucket Server doesn't have a direct /user endpoint, 
        # so we use the application-properties to verify, then get user from token
    
    # Try to get current user via a different approach
    async with session.get(
        f"{server_url}/rest/api/1.0/application-properties",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        ssl=False,
    ) as resp:
        if resp.status != 200:
            return None
        app_props = await resp.json()
    
    # Get projects to verify access (and potentially extract username from token permissions)
    async with session.get(
        f"{server_url}/rest/api/1.0/projects",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        params={"limit": 1},
        ssl=False,
    ) as resp:
        if resp.status != 200:
            return None
    
    # Token is valid - extract display name from app properties
    return {
        "username": "bitbucket_server_user",  # Token doesn't expose username directly
        "name": app_props.get("displayName", "Bitbucket Server"),
        "avatar_url": None,
        "server_url": server_url,
        "version": app_props.get("version"),
    }


@router.get("/accounts")
async def list_connected_accounts(user_id: str = Query(...)):
    """List all connected source control accounts for a user."""
    accounts = []
    
    for key, data in _user_tokens.items():
        if key.startswith(f"{user_id}:"):
            accounts.append({
                "provider": data["provider"],
                "username": data["username"],
                "name": data["user_info"].get("name"),
                "avatar_url": data["user_info"].get("avatar_url"),
                "connected_at": data["connected_at"],
            })
    
    return {"accounts": accounts}


@router.delete("/disconnect/{provider}")
async def disconnect_provider(provider: str, user_id: str = Query(...)):
    """Disconnect a source control provider."""
    key = f"{user_id}:{provider}"
    
    if key not in _user_tokens:
        raise HTTPException(status_code=404, detail="Provider not connected")
    
    del _user_tokens[key]
    
    # Also remove connected repos for this provider
    to_remove = [k for k, v in _connected_repos.items() if k.startswith(f"{user_id}:") and v.get("provider") == provider]
    for k in to_remove:
        del _connected_repos[k]
    
    return {"disconnected": True}


# =============================================================================
# Repository Listing
# =============================================================================

@router.get("/repositories")
async def list_repositories(
    provider: str = Query(...),
    user_id: str = Query(...),
    page: int = Query(1, ge=1),
    per_page: int = Query(30, ge=1, le=100),
    search: Optional[str] = Query(None),
):
    """
    List repositories from a connected provider.
    
    Returns the user's repositories they have access to.
    """
    import aiohttp
    
    key = f"{user_id}:{provider}"
    if key not in _user_tokens:
        raise HTTPException(status_code=401, detail=f"Not connected to {provider}. Please connect first.")
    
    token_data = _user_tokens[key]
    
    async with aiohttp.ClientSession() as session:
        if provider == "github":
            repos = await _list_github_repos(session, token_data["token"], page, per_page, search)
        elif provider == "bitbucket":
            repos = await _list_bitbucket_repos(session, token_data["username"], token_data["token"], page, per_page, search)
        elif provider == "bitbucket_server":
            repos = await _list_bitbucket_server_repos(session, token_data["server_url"], token_data["token"], page, per_page, search)
        else:
            raise HTTPException(status_code=400, detail="Unknown provider")
    
    return {
        "repositories": repos,
        "page": page,
        "per_page": per_page,
        "provider": provider,
    }


async def _list_github_repos(session, token: str, page: int, per_page: int, search: Optional[str]) -> list:
    """List GitHub repositories."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    
    async with session.get(
        "https://api.github.com/user/repos",
        params={
            "page": page,
            "per_page": per_page,
            "sort": "updated",
            "direction": "desc",
        },
        headers=headers,
    ) as resp:
        if resp.status != 200:
            return []
        repos = await resp.json()
    
    # Filter by search if provided
    if search:
        search_lower = search.lower()
        repos = [r for r in repos if search_lower in r["name"].lower() or search_lower in (r.get("description") or "").lower()]
    
    return [
        {
            "full_name": repo["full_name"],
            "name": repo["name"],
            "owner": repo["owner"]["login"],
            "description": repo.get("description"),
            "private": repo["private"],
            "default_branch": repo.get("default_branch", "main"),
            "clone_url": repo["clone_url"],
            "updated_at": repo.get("updated_at"),
            "language": repo.get("language"),
        }
        for repo in repos
    ]


async def _list_bitbucket_repos(session, username: str, token: str, page: int, per_page: int, search: Optional[str]) -> list:
    """List Bitbucket repositories."""
    import base64
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    
    params = {"page": page, "pagelen": per_page, "sort": "-updated_on"}
    if search:
        params["q"] = f'name ~ "{search}"'
    
    async with session.get(
        f"https://api.bitbucket.org/2.0/repositories/{username}",
        params=params,
        headers=headers,
    ) as resp:
        if resp.status != 200:
            # Try workspaces the user has access to
            async with session.get(
                "https://api.bitbucket.org/2.0/repositories",
                params={**params, "role": "member"},
                headers=headers,
            ) as resp2:
                if resp2.status != 200:
                    return []
                data = await resp2.json()
        else:
            data = await resp.json()
    
    repos = data.get("values", [])
    
    return [
        {
            "full_name": repo["full_name"],
            "name": repo["name"],
            "owner": repo.get("workspace", {}).get("slug", repo["full_name"].split("/")[0]),
            "description": repo.get("description"),
            "private": repo.get("is_private", True),
            "default_branch": repo.get("mainbranch", {}).get("name", "master"),
            "clone_url": next(
                (link["href"] for link in repo.get("links", {}).get("clone", []) if link["name"] == "https"),
                f"https://bitbucket.org/{repo['full_name']}.git"
            ),
            "updated_at": repo.get("updated_on"),
            "language": repo.get("language"),
        }
        for repo in repos
    ]


async def _list_bitbucket_server_repos(session, server_url: str, token: str, page: int, per_page: int, search: Optional[str]) -> list:
    """List Bitbucket Server/Data Center repositories."""
    server_url = server_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    
    # Bitbucket Server uses 'start' for pagination (0-indexed)
    start = (page - 1) * per_page
    params = {"start": start, "limit": per_page}
    
    all_repos = []
    
    # First, get all projects the user has access to
    async with session.get(
        f"{server_url}/rest/api/1.0/projects",
        params={"limit": 100},
        headers=headers,
        ssl=False,
    ) as resp:
        if resp.status != 200:
            return []
        projects_data = await resp.json()
    
    projects = projects_data.get("values", [])
    
    # Then get repositories from each project
    for project in projects:
        project_key = project.get("key")
        async with session.get(
            f"{server_url}/rest/api/1.0/projects/{project_key}/repos",
            params=params,
            headers=headers,
            ssl=False,
        ) as resp:
            if resp.status != 200:
                continue
            repos_data = await resp.json()
            
        for repo in repos_data.get("values", []):
            repo_name = repo.get("slug")
            full_name = f"{project_key}/{repo_name}"
            
            # Apply search filter
            if search:
                search_lower = search.lower()
                if search_lower not in repo_name.lower() and search_lower not in (repo.get("description") or "").lower():
                    continue
            
            # Get clone URL (prefer HTTPS)
            clone_url = None
            for clone_link in repo.get("links", {}).get("clone", []):
                if clone_link.get("name") == "http":
                    clone_url = clone_link.get("href")
                    break
            if not clone_url:
                clone_url = f"{server_url}/scm/{project_key.lower()}/{repo_name}.git"
            
            all_repos.append({
                "full_name": full_name,
                "name": repo_name,
                "owner": project_key,
                "description": repo.get("description"),
                "private": not repo.get("public", False),
                "default_branch": repo.get("defaultBranch", "master"),
                "clone_url": clone_url,
                "updated_at": None,  # Bitbucket Server doesn't provide this in list
                "language": None,
                "project_name": project.get("name"),
            })
    
    return all_repos


# =============================================================================
# Working Repository Management
# =============================================================================

@router.post("/repositories/select")
async def select_repository(
    request: ConnectRepositoryRequest,
    user_id: str = Query(...),
):
    """
    Select a repository as the working repository.
    
    After selecting, you can scan and remediate this repository.
    """
    provider = request.provider.lower()
    key = f"{user_id}:{provider}"
    
    if key not in _user_tokens:
        raise HTTPException(status_code=401, detail=f"Not connected to {provider}")
    
    token_data = _user_tokens[key]
    
    # Store as connected repo
    repo_key = f"{user_id}:{request.repo_full_name}"
    _connected_repos[repo_key] = {
        "full_name": request.repo_full_name,
        "provider": provider,
        "token": token_data["token"],
        "username": token_data["username"],
        "selected_at": datetime.utcnow(),
    }
    
    return {
        "selected": True,
        "repository": request.repo_full_name,
        "provider": provider,
    }


@router.get("/repositories/selected")
async def list_selected_repositories(user_id: str = Query(...)):
    """List all selected (working) repositories for a user."""
    repos = []
    
    for key, data in _connected_repos.items():
        if key.startswith(f"{user_id}:"):
            repos.append({
                "full_name": data["full_name"],
                "provider": data["provider"],
                "selected_at": data["selected_at"],
            })
    
    return {"repositories": repos}


@router.delete("/repositories/selected/{repo_full_name:path}")
async def deselect_repository(repo_full_name: str, user_id: str = Query(...)):
    """Remove a repository from selected repositories."""
    key = f"{user_id}:{repo_full_name}"
    
    if key not in _connected_repos:
        raise HTTPException(status_code=404, detail="Repository not selected")
    
    del _connected_repos[key]
    return {"deselected": True}


# =============================================================================
# Repository Scanning
# =============================================================================

@router.post("/repositories/{repo_full_name:path}/scan")
async def scan_repository(
    repo_full_name: str,
    user_id: str = Query(...),
    options: Optional[ScanOptionsRequest] = None,
):
    """
    Scan a selected repository for secrets.
    
    Clones the repository temporarily and runs the secret scanner.
    """
    import tempfile
    import shutil
    import subprocess
    
    key = f"{user_id}:{repo_full_name}"
    
    if key not in _connected_repos:
        raise HTTPException(status_code=404, detail="Repository not selected. Please select it first.")
    
    repo_data = _connected_repos[key]
    provider = repo_data["provider"]
    token = repo_data["token"]
    username = repo_data["username"]
    
    options = options or ScanOptionsRequest()
    
    # Build authenticated clone URL
    if provider == "github":
        clone_url = f"https://oauth2:{token}@github.com/{repo_full_name}.git"
    else:  # bitbucket
        clone_url = f"https://{username}:{token}@bitbucket.org/{repo_full_name}.git"
    
    # Clone to temp directory
    temp_dir = tempfile.mkdtemp(prefix="deployguard_scan_")
    
    try:
        # Clone
        clone_args = ["git", "clone"]
        if not options.scan_history:
            clone_args.extend(["--depth", "1"])
        if options.branch:
            clone_args.extend(["--branch", options.branch])
        clone_args.extend([clone_url, temp_dir])
        
        result = subprocess.run(clone_args, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Clone failed: {result.stderr}")
        
        # Run scanner
        from deployguard.core.scanner import SecretScanner
        
        scanner = SecretScanner()
        findings = scanner.scan_directory(temp_dir)
        
        # Verify secrets if requested
        if options.verify_secrets and findings:
            from deployguard.core.verifier import SecretVerifier
            verifier = SecretVerifier()
            results = await verifier.verify_findings(findings)
            for r in results:
                r.finding.verification_status = r.status.value
            findings = [r.finding for r in results]
        
        # Format response
        findings_list = []
        for f in findings:
            # Remove temp path prefix
            file_path = f.file_path.replace(temp_dir, "").lstrip("/")
            
            findings_list.append({
                "file": file_path,
                "line": f.line_number,
                "type": f.secret_type.value if hasattr(f.secret_type, 'value') else str(f.secret_type),
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "pattern": f.pattern_name,
                "preview": f.matched_text[:4] + "****" if f.matched_text and len(f.matched_text) > 4 else "****",
                "context": f.context,
                "verified": getattr(f, 'verification_status', None),
            })
        
        # Summary by severity
        severity_counts = {}
        for f in findings_list:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "repository": repo_full_name,
            "provider": provider,
            "branch": options.branch or "default",
            "scanned_at": datetime.utcnow().isoformat(),
            "total_findings": len(findings_list),
            "by_severity": severity_counts,
            "findings": findings_list,
        }
        
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
