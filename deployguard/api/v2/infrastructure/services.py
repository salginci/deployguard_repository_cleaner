"""
Infrastructure Layer - Service Implementations

Concrete implementations of service interfaces.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, List, Any
import asyncio
import logging

from ..application.ports import StorageService, GitService, ScannerService, CleanerService


logger = logging.getLogger(__name__)


class LocalStorageService(StorageService):
    """
    Local filesystem implementation of StorageService.
    
    For production, consider using MinIO/S3 with async operations.
    """
    
    def __init__(self, base_path: str = "/tmp/deployguard"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    async def create_workspace(self, job_id: str) -> str:
        """Create a workspace directory for a job."""
        workspace = self.base_path / job_id
        workspace.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created workspace: {workspace}")
        return str(workspace)
    
    async def delete_workspace(self, job_id: str) -> None:
        """Delete the workspace for a job."""
        workspace = self.base_path / job_id
        if workspace.exists():
            shutil.rmtree(workspace)
            logger.info(f"Deleted workspace: {workspace}")
    
    async def get_workspace_path(self, job_id: str) -> Optional[str]:
        """Get the workspace path for a job."""
        workspace = self.base_path / job_id
        if workspace.exists():
            return str(workspace)
        return None
    
    async def workspace_exists(self, job_id: str) -> bool:
        """Check if workspace exists."""
        workspace = self.base_path / job_id
        return workspace.exists()


class GitCommandService(GitService):
    """
    Git command-line implementation of GitService.
    
    Uses subprocess to run git commands.
    """
    
    async def clone(
        self,
        url: str,
        target_path: str,
        branch: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> None:
        """Clone a repository."""
        # Build URL with credentials if provided
        clone_url = url
        if credentials and credentials.get('token'):
            clone_url = self._inject_token(url, credentials['token'])
        
        # Build clone command
        cmd = ['git', 'clone', '--mirror', clone_url, target_path]
        
        if branch:
            cmd = ['git', 'clone', '-b', branch, clone_url, target_path]
        
        # Run clone
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Git clone failed: {stderr.decode()}")
        
        logger.info(f"Cloned repository to {target_path}")
    
    async def push(
        self,
        repo_path: str,
        remote_url: str,
        force: bool = False,
        credentials: Optional[Dict[str, str]] = None,
    ) -> Dict[str, int]:
        """Push repository to remote."""
        # Build URL with credentials
        push_url = remote_url
        if credentials and credentials.get('token'):
            push_url = self._inject_token(remote_url, credentials['token'])
        
        # Add or update remote
        await self._run_git(repo_path, ['remote', 'add', 'target', push_url])
        
        # Push branches
        push_cmd = ['push', 'target', '--all']
        if force:
            push_cmd.append('--force')
        
        await self._run_git(repo_path, push_cmd)
        
        # Push tags
        await self._run_git(repo_path, ['push', 'target', '--tags'])
        
        # Count branches and tags
        branches = await self._count_refs(repo_path, 'refs/heads')
        tags = await self._count_refs(repo_path, 'refs/tags')
        
        logger.info(f"Pushed {branches} branches and {tags} tags")
        
        return {
            'branches_pushed': branches,
            'tags_pushed': tags,
        }
    
    def _inject_token(self, url: str, token: str) -> str:
        """Inject token into URL for authentication."""
        if url.startswith('https://'):
            # https://github.com/... -> https://token@github.com/...
            return url.replace('https://', f'https://{token}@')
        return url
    
    async def _run_git(self, cwd: str, args: List[str]) -> str:
        """Run a git command."""
        cmd = ['git'] + args
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
        )
        
        stdout, stderr = await process.communicate()
        
        # Some commands (like remote add) may fail if remote exists
        if process.returncode != 0 and 'already exists' not in stderr.decode():
            logger.warning(f"Git command returned {process.returncode}: {stderr.decode()}")
        
        return stdout.decode()
    
    async def _count_refs(self, repo_path: str, ref_prefix: str) -> int:
        """Count refs matching a prefix."""
        output = await self._run_git(repo_path, ['for-each-ref', '--format=%(refname)', ref_prefix])
        refs = [r for r in output.strip().split('\n') if r]
        return len(refs)


class SecretScannerService(ScannerService):
    """
    Secret scanner implementation using the core scanner.
    
    Wraps the existing SecretScanner for use in the clean architecture.
    """
    
    def __init__(self, patterns_path: Optional[str] = None):
        self.patterns_path = patterns_path
    
    async def scan(
        self,
        repo_path: str,
        branches: Optional[List[str]] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[Dict[str, Any]]:
        """Scan repository for secrets."""
        # Import here to avoid circular imports
        from deployguard.core.scanner import SecretScanner
        
        # Create scanner instance
        scanner = SecretScanner(
            patterns_path=self.patterns_path,
        )
        
        # Run scan in thread pool to not block event loop
        loop = asyncio.get_event_loop()
        
        def do_scan():
            return scanner.scan_repository(
                repo_path=repo_path,
                branches=branches,
            )
        
        findings = await loop.run_in_executor(None, do_scan)
        
        # Convert to dicts
        return [
            {
                'file_path': f.file_path,
                'line_number': f.line_number,
                'commit_hash': f.commit_hash,
                'branch': f.branch,
                'secret_value': f.secret_value,
                'pattern_name': f.pattern_name,
                'severity': f.severity,
                'confidence': f.confidence,
                'code_context': f.context,
                'author': f.author,
                'commit_date': f.commit_date,
            }
            for f in findings
        ]


class HistoryCleanerService(CleanerService):
    """
    History cleaner implementation using the core cleaner.
    
    Wraps the existing GitHistoryCleaner for use in the clean architecture.
    """
    
    async def clean(
        self,
        repo_path: str,
        secrets_to_remove: List[str],
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """Clean secrets from repository history."""
        # Import here to avoid circular imports
        from deployguard.core.history_cleaner import GitHistoryCleaner
        
        cleaner = GitHistoryCleaner()
        
        # Run cleaner in thread pool
        loop = asyncio.get_event_loop()
        
        def do_clean():
            return cleaner.clean_history(
                repo_path=repo_path,
                secrets=secrets_to_remove,
            )
        
        result = await loop.run_in_executor(None, do_clean)
        
        return {
            'commits_rewritten': result.commits_rewritten,
            'secrets_removed': result.secrets_removed,
            'duration_seconds': result.duration_seconds,
        }
