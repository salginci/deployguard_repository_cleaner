"""Git history cleaner for purging secrets from repository history.

This module replaces BFG Repo-Cleaner functionality by providing:
- Full git history scanning
- Secret detection across all commits
- History rewriting to remove/replace secrets
- Garbage collection and cleanup
"""

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from deployguard.core.exceptions import ScanError
from deployguard.core.models import Finding, SecretType, Severity
from deployguard.core.scanner import SecretScanner


@dataclass
class SecretMatch:
    """Represents a secret found in git history."""
    
    value: str
    value_hash: str
    secret_type: str
    severity: str
    commits: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    suggested_env_var: str = ""
    replacement: str = "***REMOVED***"
    
    def __hash__(self):
        return hash(self.value_hash)
    
    def __eq__(self, other):
        return self.value_hash == other.value_hash


@dataclass
class CleanupResult:
    """Result of a git history cleanup operation."""
    
    secrets_found: int = 0
    secrets_removed: int = 0
    commits_rewritten: int = 0
    files_modified: int = 0
    errors: List[str] = field(default_factory=list)
    secrets_list: List[SecretMatch] = field(default_factory=list)
    purge_file_path: Optional[str] = None


class GitHistoryCleaner:
    """
    Cleans secrets from git repository history.
    
    This replaces BFG Repo-Cleaner with native Python implementation using:
    - git filter-repo (preferred) or git filter-branch
    - Full history scanning across all branches
    - Automatic env var name suggestions
    """
    
    PLACEHOLDER = "***REMOVED***"
    ENV_VAR_PLACEHOLDER = "${{{env_var}}}"
    
    def __init__(
        self,
        scanner: Optional[SecretScanner] = None,
        patterns_file: Optional[str] = None,
    ):
        """
        Initialize the git history cleaner.
        
        Args:
            scanner: SecretScanner instance to use for detection
            patterns_file: Path to patterns YAML file
        """
        self.scanner = scanner or SecretScanner(patterns_file)
        self._git_filter_repo_available = self._check_git_filter_repo()
        
    def _check_git_filter_repo(self) -> bool:
        """Check if git-filter-repo is available."""
        try:
            result = subprocess.run(
                ["git", "filter-repo", "--version"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _run_git(self, args: List[str], cwd: str) -> subprocess.CompletedProcess:
        """Run a git command."""
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    
    def scan_git_history(
        self,
        repo_path: str,
        branch: Optional[str] = None,
        include_all_branches: bool = True,
    ) -> List[SecretMatch]:
        """
        Scan entire git history for secrets.
        
        Args:
            repo_path: Path to git repository
            branch: Specific branch to scan (None for all)
            include_all_branches: Whether to scan all branches
            
        Returns:
            List of unique SecretMatch objects found
        """
        secrets: Dict[str, SecretMatch] = {}
        
        # Get list of commits to scan
        if include_all_branches:
            git_args = ["rev-list", "--all"]
        elif branch:
            git_args = ["rev-list", branch]
        else:
            git_args = ["rev-list", "HEAD"]
            
        result = self._run_git(git_args, repo_path)
        if result.returncode != 0:
            raise ScanError(f"Failed to get commit list: {result.stderr}")
        
        commits = result.stdout.strip().split("\n")
        
        for commit in commits:
            if not commit:
                continue
                
            # Get files changed in this commit
            diff_result = self._run_git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                repo_path,
            )
            
            if diff_result.returncode != 0:
                continue
                
            files = diff_result.stdout.strip().split("\n")
            
            for file_path in files:
                if not file_path:
                    continue
                    
                # Get file content at this commit
                show_result = self._run_git(
                    ["show", f"{commit}:{file_path}"],
                    repo_path,
                )
                
                if show_result.returncode != 0:
                    continue
                    
                content = show_result.stdout
                
                # Scan the content
                findings = self.scanner.scan_file(file_path, content)
                
                for finding in findings:
                    value_hash = finding.exposed_value_hash
                    
                    if value_hash not in secrets:
                        secrets[value_hash] = SecretMatch(
                            value=finding.exposed_value,
                            value_hash=value_hash,
                            secret_type=finding.type.value,
                            severity=finding.severity.value,
                            commits=[commit],
                            files=[file_path],
                            suggested_env_var=self._suggest_env_var_name(
                                finding.exposed_value, 
                                finding.type,
                                file_path,
                            ),
                        )
                    else:
                        if commit not in secrets[value_hash].commits:
                            secrets[value_hash].commits.append(commit)
                        if file_path not in secrets[value_hash].files:
                            secrets[value_hash].files.append(file_path)
        
        return list(secrets.values())
    
    def _suggest_env_var_name(
        self, 
        secret_value: str, 
        secret_type: SecretType,
        file_path: str,
    ) -> str:
        """
        Suggest an environment variable name for a secret.
        
        Args:
            secret_value: The secret value
            secret_type: Type of secret
            file_path: Path where secret was found
            
        Returns:
            Suggested environment variable name
        """
        # Extract context from the secret pattern
        type_prefixes = {
            SecretType.AWS_KEY: "AWS_ACCESS_KEY_ID",
            SecretType.AWS_SECRET: "AWS_SECRET_ACCESS_KEY",
            SecretType.GITHUB_TOKEN: "GITHUB_TOKEN",
            SecretType.API_KEY: "API_KEY",
            SecretType.DATABASE_URL: "DATABASE_URL",
            SecretType.PASSWORD: "DB_PASSWORD",
            SecretType.PRIVATE_KEY: "PRIVATE_KEY",
            SecretType.JWT_TOKEN: "JWT_SECRET",
            SecretType.OAUTH_SECRET: "OAUTH_CLIENT_SECRET",
            SecretType.ENCRYPTION_KEY: "ENCRYPTION_KEY",
        }
        
        base_name = type_prefixes.get(secret_type, "SECRET")
        
        # Try to extract service name from file path
        file_name = Path(file_path).stem.upper()
        if file_name and file_name not in ["CONFIG", "SETTINGS", "ENV", "SECRETS"]:
            return f"{file_name}_{base_name}"
        
        return base_name
    
    def generate_purge_file(
        self,
        secrets: List[SecretMatch],
        output_path: str,
        use_env_vars: bool = False,
    ) -> str:
        """
        Generate a secrets_to_purge.txt file (BFG-compatible format).
        
        Args:
            secrets: List of secrets to include
            output_path: Path to write the file
            use_env_vars: If True, use env var placeholders; otherwise use ***REMOVED***
            
        Returns:
            Path to the generated file
        """
        with open(output_path, "w") as f:
            for secret in secrets:
                # BFG format: literal_string==>replacement
                # or just: literal_string (will be replaced with ***REMOVED***)
                if use_env_vars and secret.suggested_env_var:
                    replacement = self.ENV_VAR_PLACEHOLDER.format(
                        env_var=secret.suggested_env_var
                    )
                    f.write(f"{secret.value}==>{replacement}\n")
                else:
                    f.write(f"{secret.value}\n")
        
        return output_path
    
    def generate_env_template(
        self,
        secrets: List[SecretMatch],
        output_path: str,
    ) -> str:
        """
        Generate a .env.template file with suggested variable names.
        
        Args:
            secrets: List of secrets
            output_path: Path to write the template
            
        Returns:
            Path to the generated file
        """
        env_vars: Dict[str, str] = {}
        
        for secret in secrets:
            var_name = secret.suggested_env_var
            # Avoid duplicates by adding suffix
            base_name = var_name
            counter = 1
            while var_name in env_vars:
                var_name = f"{base_name}_{counter}"
                counter += 1
            
            env_vars[var_name] = f"# {secret.secret_type} - Found in: {', '.join(secret.files[:3])}"
        
        with open(output_path, "w") as f:
            f.write("# Environment Variables Template\n")
            f.write("# Generated by DeployGuard Repository Cleaner\n")
            f.write("# Replace placeholder values with actual secrets\n\n")
            
            for var_name, comment in sorted(env_vars.items()):
                f.write(f"{comment}\n")
                f.write(f"{var_name}=your_secret_here\n\n")
        
        return output_path
    
    def clean_history(
        self,
        repo_path: str,
        secrets: List[SecretMatch],
        use_env_vars: bool = False,
        dry_run: bool = True,
    ) -> CleanupResult:
        """
        Rewrite git history to remove/replace secrets.
        
        Args:
            repo_path: Path to git repository (should be bare/mirror clone)
            secrets: List of secrets to remove
            use_env_vars: Use env var placeholders instead of ***REMOVED***
            dry_run: If True, only simulate (no actual changes)
            
        Returns:
            CleanupResult with operation details
        """
        result = CleanupResult(
            secrets_found=len(secrets),
            secrets_list=secrets,
        )
        
        if dry_run:
            # Just return what would be done
            result.secrets_removed = len(secrets)
            return result
        
        # Create temporary purge file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            purge_file = f.name
            self.generate_purge_file(secrets, purge_file, use_env_vars)
            result.purge_file_path = purge_file
        
        try:
            if self._git_filter_repo_available:
                # Use git-filter-repo (preferred, faster)
                cleanup_result = self._clean_with_filter_repo(
                    repo_path, secrets, use_env_vars
                )
            else:
                # Fallback to git filter-branch
                cleanup_result = self._clean_with_filter_branch(
                    repo_path, purge_file
                )
            
            result.secrets_removed = cleanup_result.get("removed", 0)
            result.commits_rewritten = cleanup_result.get("commits", 0)
            result.files_modified = cleanup_result.get("files", 0)
            
            # Run garbage collection
            self._run_garbage_collection(repo_path)
            
        except Exception as e:
            result.errors.append(str(e))
        finally:
            # Clean up temp file
            if os.path.exists(purge_file):
                os.unlink(purge_file)
        
        return result
    
    def _clean_with_filter_repo(
        self,
        repo_path: str,
        secrets: List[SecretMatch],
        use_env_vars: bool,
    ) -> Dict[str, int]:
        """Clean using git-filter-repo."""
        # Create replacement expressions file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            expr_file = f.name
            for secret in secrets:
                # Escape special regex characters
                escaped = re.escape(secret.value)
                if use_env_vars and secret.suggested_env_var:
                    replacement = self.ENV_VAR_PLACEHOLDER.format(
                        env_var=secret.suggested_env_var
                    )
                else:
                    replacement = self.PLACEHOLDER
                f.write(f"regex:{escaped}==>{replacement}\n")
        
        try:
            result = subprocess.run(
                [
                    "git", "filter-repo",
                    "--replace-text", expr_file,
                    "--force",
                ],
                cwd=repo_path,
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                raise ScanError(f"git-filter-repo failed: {result.stderr}")
            
            return {
                "removed": len(secrets),
                "commits": 0,  # Would need to parse output
                "files": 0,
            }
        finally:
            os.unlink(expr_file)
    
    def _clean_with_filter_branch(
        self,
        repo_path: str,
        purge_file: str,
    ) -> Dict[str, int]:
        """Clean using git filter-branch (fallback)."""
        # Read secrets from purge file
        with open(purge_file, "r") as f:
            lines = f.readlines()
        
        # Build sed-like replacement script
        replacements = []
        for line in lines:
            line = line.strip()
            if "==>" in line:
                old, new = line.split("==>", 1)
                replacements.append((old, new))
            else:
                replacements.append((line, self.PLACEHOLDER))
        
        # Create tree-filter script
        script = "#!/bin/bash\n"
        for old, new in replacements:
            escaped_old = old.replace("'", "'\\''")
            escaped_new = new.replace("'", "'\\''")
            script += f"find . -type f -exec sed -i '' 's/{escaped_old}/{escaped_new}/g' {{}} \\;\n"
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            script_file = f.name
            f.write(script)
            os.chmod(script_file, 0o755)
        
        try:
            result = subprocess.run(
                [
                    "git", "filter-branch",
                    "--tree-filter", script_file,
                    "--prune-empty",
                    "--",
                    "--all",
                ],
                cwd=repo_path,
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                raise ScanError(f"git filter-branch failed: {result.stderr}")
            
            return {
                "removed": len(replacements),
                "commits": 0,
                "files": 0,
            }
        finally:
            os.unlink(script_file)
    
    def _run_garbage_collection(self, repo_path: str) -> None:
        """Run git garbage collection to physically remove old data."""
        # Expire reflog
        self._run_git(["reflog", "expire", "--expire=now", "--all"], repo_path)
        
        # Aggressive garbage collection
        self._run_git(["gc", "--prune=now", "--aggressive"], repo_path)
    
    def create_mirror_clone(
        self,
        source_url: str,
        destination_path: str,
    ) -> str:
        """
        Create a mirror clone for safe history rewriting.
        
        Args:
            source_url: URL or path to source repository
            destination_path: Where to create the clone
            
        Returns:
            Path to the created bare repository
        """
        result = subprocess.run(
            ["git", "clone", "--mirror", source_url, destination_path],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            raise ScanError(f"Failed to create mirror clone: {result.stderr}")
        
        return destination_path
    
    def push_cleaned_repo(
        self,
        repo_path: str,
        remote_url: str,
        force: bool = False,
    ) -> bool:
        """
        Push cleaned repository to remote.
        
        Args:
            repo_path: Path to the cleaned repository
            remote_url: URL of the target remote
            force: Whether to use force push
            
        Returns:
            True if successful
        """
        # Add or update remote
        self._run_git(["remote", "set-url", "origin", remote_url], repo_path)
        
        # Use --force-with-lease for safety
        push_args = ["push", "--mirror"]
        if force:
            push_args.append("--force-with-lease")
        
        result = self._run_git(push_args, repo_path)
        
        if result.returncode != 0:
            raise ScanError(f"Failed to push: {result.stderr}")
        
        return True
