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
    large_files_found: int = 0
    large_files_removed: int = 0
    errors: List[str] = field(default_factory=list)
    secrets_list: List[SecretMatch] = field(default_factory=list)
    large_files_list: List[Tuple[str, int]] = field(default_factory=list)  # (path, size_bytes)
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
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    # Binary file extensions to skip
    BINARY_EXTENSIONS = {
        '.tgz', '.tar', '.gz', '.zip', '.rar', '.7z',
        '.exe', '.dll', '.so', '.dylib', '.bin',
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.wmv', '.webm',
        '.ttf', '.otf', '.woff', '.woff2', '.eot',
        '.pyc', '.pyo', '.class', '.o', '.obj',
        '.sqlite', '.db', '.sqlite3',
        '.pack', '.idx',  # Git pack files
        '.min.js', '.min.css',
        '.jar', '.war', '.ear',
        '.node', '.map',
        # Additional extensions to skip for performance
        '.webp', '.aab', '.apk', '.dex', '.aar',  # Android
        '.xcassets', '.storyboard', '.xib',  # iOS
        '.lock', '.sum',  # Lock files
        '.svg', '.ico', '.icns',  # Icons
    }
    
    # Files to skip by name pattern
    SKIP_FILES = {
        'gradlew', 'gradlew.bat', 'gradle-wrapper.jar',
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
        '.gitignore', '.gitattributes', 'LICENSE', 'CHANGELOG.md',
    }
    
    # Directories to skip
    SKIP_DIRS = {
        'node_modules', '.gradle', 'build', '.idea', '.vscode',
        '__pycache__', '.git', 'vendor', 'Pods',
    }
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped for scanning."""
        # Check extension
        ext = Path(file_path).suffix.lower()
        if ext in self.BINARY_EXTENSIONS:
            return True
        
        # Check filename
        name = Path(file_path).name
        if name in self.SKIP_FILES:
            return True
        
        # Check directory
        parts = Path(file_path).parts
        for part in parts:
            if part in self.SKIP_DIRS:
                return True
        
        return False
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary based on extension."""
        ext = Path(file_path).suffix.lower()
        return ext in self.BINARY_EXTENSIONS
    
    def _run_git(self, args: List[str], cwd: str) -> subprocess.CompletedProcess:
        """Run a git command."""
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,  # Add timeout
        )
    
    def _run_git_binary(self, args: List[str], cwd: str) -> subprocess.CompletedProcess:
        """Run a git command that may return binary content."""
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=False,  # Return bytes
            timeout=30,  # Add timeout
        )
    
    def scan_git_history(
        self,
        repo_path: str,
        branch: Optional[str] = None,
        include_all_branches: bool = True,
        show_progress: bool = True,
    ) -> List[SecretMatch]:
        """
        Scan entire git history for secrets.
        
        Args:
            repo_path: Path to git repository
            branch: Specific branch to scan (None for all)
            include_all_branches: Whether to scan all branches
            show_progress: Whether to show progress output
            
        Returns:
            List of unique SecretMatch objects found
        """
        import sys
        
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
        total_commits = len(commits)
        
        if show_progress:
            print(f"   Found {total_commits} commits to scan...")
        
        files_scanned = 0
        files_skipped = 0
        
        for idx, commit in enumerate(commits):
            if not commit:
                continue
            
            # Show progress every 50 commits (more frequent feedback)
            if show_progress and idx > 0 and idx % 50 == 0:
                print(f"   Progress: {idx}/{total_commits} commits ({len(secrets)} secrets found)")
                sys.stdout.flush()
                
            # Get files changed in this commit
            try:
                diff_result = self._run_git(
                    ["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                    repo_path,
                )
            except subprocess.TimeoutExpired:
                continue
            
            if diff_result.returncode != 0:
                continue
                
            files = diff_result.stdout.strip().split("\n")
            
            for file_path in files:
                if not file_path:
                    continue
                
                # Skip files that don't need scanning
                if self._should_skip_file(file_path):
                    files_skipped += 1
                    continue
                
                files_scanned += 1
                    
                # Get file content at this commit (as bytes to handle encoding)
                try:
                    show_result = self._run_git_binary(
                        ["show", f"{commit}:{file_path}"],
                        repo_path,
                    )
                except subprocess.TimeoutExpired:
                    continue
                
                if show_result.returncode != 0:
                    continue
                
                # Try to decode as text, skip if binary
                try:
                    content = show_result.stdout.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        content = show_result.stdout.decode('latin-1')
                    except:
                        continue  # Skip binary files
                
                # Scan the content
                findings = self.scanner.scan_file(file_path, content)
                
                for finding in findings:
                    value_hash = finding.exposed_value_hash
                    
                    # Handle both enum and string types
                    secret_type = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
                    severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                    
                    if value_hash not in secrets:
                        secrets[value_hash] = SecretMatch(
                            value=finding.exposed_value,
                            value_hash=value_hash,
                            secret_type=secret_type,
                            severity=severity,
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
        
        if show_progress:
            print(f"   Completed: {total_commits} commits scanned, {len(secrets)} unique secrets found")
        
        return list(secrets.values())
    
    def scan_large_files(
        self,
        repo_path: str,
        max_size_mb: float = 100.0,
        show_progress: bool = True,
    ) -> List[Tuple[str, int]]:
        """
        Scan git history for files exceeding GitHub's 100MB limit.
        
        Args:
            repo_path: Path to git repository
            max_size_mb: Maximum file size in MB (default 100MB for GitHub)
            show_progress: Whether to show progress output
            
        Returns:
            List of (file_path, size_in_bytes) tuples for files exceeding limit
        """
        import sys
        
        large_files: Dict[str, int] = {}
        max_size_bytes = int(max_size_mb * 1024 * 1024)
        
        if show_progress:
            print(f"   Scanning for files > {max_size_mb}MB...")
        
        # Use git rev-list with --objects to find all objects
        # Then use git cat-file to check sizes
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-list", "--objects", "--all"],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            if show_progress:
                print(f"   Warning: Could not scan for large files: {result.stderr}")
            return []
        
        # Parse object list
        objects = []
        for line in result.stdout.strip().split('\n'):
            if line and ' ' in line:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    objects.append((parts[0], parts[1]))  # (sha, path)
        
        if show_progress:
            print(f"   Found {len(objects)} objects to check...")
        
        # Check sizes using git cat-file --batch-check
        # This is much faster than checking individually
        shas = [obj[0] for obj in objects]
        sha_to_path = {obj[0]: obj[1] for obj in objects}
        
        # Process in batches
        batch_size = 1000
        for i in range(0, len(shas), batch_size):
            batch = shas[i:i+batch_size]
            
            proc = subprocess.Popen(
                ["git", "-C", repo_path, "cat-file", "--batch-check"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            input_data = '\n'.join(batch)
            stdout, _ = proc.communicate(input_data)
            
            for line in stdout.strip().split('\n'):
                if not line or ' missing' in line:
                    continue
                # Format: sha type size
                parts = line.split()
                if len(parts) >= 3:
                    sha = parts[0]
                    obj_type = parts[1]
                    try:
                        size = int(parts[2])
                    except ValueError:
                        continue
                    
                    if obj_type == 'blob' and size > max_size_bytes:
                        path = sha_to_path.get(sha, sha)
                        if path not in large_files or large_files[path] < size:
                            large_files[path] = size
        
        # Sort by size descending
        sorted_files = sorted(large_files.items(), key=lambda x: -x[1])
        
        if show_progress:
            if sorted_files:
                print(f"   Found {len(sorted_files)} files > {max_size_mb}MB:")
                for path, size in sorted_files[:10]:
                    print(f"      • {path}: {size / 1024 / 1024:.1f}MB")
                if len(sorted_files) > 10:
                    print(f"      ... and {len(sorted_files) - 10} more")
            else:
                print(f"   No files found > {max_size_mb}MB ✓")
        
        return sorted_files
    
    def _suggest_env_var_name(
        self, 
        secret_value: str, 
        secret_type,  # Can be SecretType enum or string
        file_path: str,
    ) -> str:
        """
        Suggest an environment variable name for a secret.
        
        Args:
            secret_value: The secret value
            secret_type: Type of secret (enum or string)
            file_path: Path where secret was found
            
        Returns:
            Suggested environment variable name with DG_ prefix
        """
        import hashlib
        
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
        
        # Handle both enum and string types
        if isinstance(secret_type, SecretType):
            type_name = type_prefixes.get(secret_type, "SECRET")
        else:
            # It's a string - try to create a sensible name
            type_name = str(secret_type).upper().replace("-", "_").replace(" ", "_")
        
        # Extract meaningful context from file path
        file_name = Path(file_path).stem.upper()
        parent_dir = Path(file_path).parent.name.upper() if Path(file_path).parent.name else ""
        
        # Skip generic file/folder names
        generic_names = {"CONFIG", "SETTINGS", "ENV", "SECRETS", "APPSETTINGS", "SRC", "MAIN", "APP", "RES", "VALUES"}
        
        context_parts = []
        if parent_dir and parent_dir not in generic_names:
            context_parts.append(parent_dir)
        if file_name and file_name not in generic_names:
            context_parts.append(file_name)
        
        # Try to extract context from the secret value itself
        value_context = self._extract_value_context(secret_value)
        if value_context:
            context_parts.append(value_context)
        
        # Build the env var name
        if context_parts:
            context = "_".join(context_parts[:2])  # Max 2 context parts
            base_name = f"DG_{context}_{type_name}"
        else:
            base_name = f"DG_{type_name}"
        
        # Add a short hash suffix to ensure uniqueness
        value_hash = hashlib.sha256(secret_value.encode()).hexdigest()[:4].upper()
        env_var_name = f"{base_name}_{value_hash}"
        
        # Clean up the name
        env_var_name = env_var_name.replace("__", "_").replace("-", "_")
        
        return env_var_name
    
    def _extract_value_context(self, secret_value: str) -> str:
        """
        Try to extract meaningful context from the secret value.
        
        Args:
            secret_value: The secret value
            
        Returns:
            Context string or empty string
        """
        value_lower = secret_value.lower()
        
        # Common patterns in secrets that indicate purpose
        contexts = {
            'firebase': 'FIREBASE',
            'google': 'GOOGLE',
            'maps': 'MAPS',
            'api': 'API',
            'auth': 'AUTH',
            'oauth': 'OAUTH',
            'jwt': 'JWT',
            'database': 'DB',
            'postgres': 'POSTGRES',
            'mysql': 'MYSQL',
            'mongo': 'MONGO',
            'redis': 'REDIS',
            'aws': 'AWS',
            'azure': 'AZURE',
            'stripe': 'STRIPE',
            'twilio': 'TWILIO',
            'sendgrid': 'SENDGRID',
            'slack': 'SLACK',
            'github': 'GITHUB',
            'gitlab': 'GITLAB',
            'bitbucket': 'BITBUCKET',
        }
        
        for pattern, context in contexts.items():
            if pattern in value_lower:
                return context
        
        return ""
    
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
        # Use literal matching (not regex) for safety
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            expr_file = f.name
            for secret in secrets:
                # Skip empty or very short secrets
                if not secret.value or len(secret.value) < 4:
                    continue
                
                # Determine replacement
                if use_env_vars and secret.suggested_env_var:
                    replacement = self.ENV_VAR_PLACEHOLDER.format(
                        env_var=secret.suggested_env_var
                    )
                else:
                    replacement = self.PLACEHOLDER
                
                # Use literal matching (no regex:) for most secrets
                # This avoids regex escaping issues
                value = secret.value
                
                # Skip secrets with problematic characters for git-filter-repo
                if '\x00' in value or '\n' in value or '\r' in value:
                    continue
                
                # For secrets containing ==>, use regex with proper escaping
                if '==>' in value:
                    # Escape for regex - be very careful
                    escaped = value.replace('\\', '\\\\')
                    escaped = escaped.replace('.', r'\.')
                    escaped = escaped.replace('*', r'\*')
                    escaped = escaped.replace('+', r'\+')
                    escaped = escaped.replace('?', r'\?')
                    escaped = escaped.replace('[', r'\[')
                    escaped = escaped.replace(']', r'\]')
                    escaped = escaped.replace('(', r'\(')
                    escaped = escaped.replace(')', r'\)')
                    escaped = escaped.replace('{', r'\{')
                    escaped = escaped.replace('}', r'\}')
                    escaped = escaped.replace('^', r'\^')
                    escaped = escaped.replace('$', r'\$')
                    escaped = escaped.replace('|', r'\|')
                    f.write(f"regex:{escaped}==>{replacement}\n")
                else:
                    # Use literal matching - much safer
                    f.write(f"{value}==>{replacement}\n")
        
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
    
    def remove_large_files(
        self,
        repo_path: str,
        large_files: List[Tuple[str, int]],
        dry_run: bool = True,
    ) -> Dict[str, any]:
        """
        Remove large files from git history.
        
        Uses git-filter-repo to completely remove files exceeding size limit.
        This is required for pushing to GitHub which has 100MB file limit.
        
        Args:
            repo_path: Path to git repository (should be bare/mirror clone)
            large_files: List of (file_path, size) tuples to remove
            dry_run: If True, only simulate (no actual changes)
            
        Returns:
            Dict with operation results
        """
        result = {
            "files_found": len(large_files),
            "files_removed": 0,
            "errors": [],
        }
        
        if not large_files:
            return result
        
        if dry_run:
            result["files_removed"] = len(large_files)
            return result
        
        if not self._git_filter_repo_available:
            result["errors"].append("git-filter-repo is required to remove large files. Install with: pip install git-filter-repo")
            return result
        
        # Remove each large file using git-filter-repo
        for file_path, size in large_files:
            try:
                cmd_result = subprocess.run(
                    [
                        "git", "filter-repo",
                        "--invert-paths",
                        "--path", file_path,
                        "--force",
                    ],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                )
                
                if cmd_result.returncode == 0:
                    result["files_removed"] += 1
                else:
                    result["errors"].append(f"Failed to remove {file_path}: {cmd_result.stderr}")
                    
            except Exception as e:
                result["errors"].append(f"Error removing {file_path}: {str(e)}")
        
        # Run garbage collection after removals
        self._run_garbage_collection(repo_path)
        
        return result
    
    def full_cleanup(
        self,
        repo_path: str,
        secrets: Optional[List[SecretMatch]] = None,
        large_files: Optional[List[Tuple[str, int]]] = None,
        use_env_vars: bool = False,
        dry_run: bool = True,
        show_progress: bool = True,
    ) -> CleanupResult:
        """
        Perform full repository cleanup: secrets AND large files.
        
        Args:
            repo_path: Path to git repository (should be bare/mirror clone)
            secrets: List of secrets to remove (None to skip)
            large_files: List of large files to remove (None to skip)
            use_env_vars: Use env var placeholders instead of ***REMOVED***
            dry_run: If True, only simulate (no actual changes)
            show_progress: Show progress output
            
        Returns:
            CleanupResult with all operation details
        """
        import sys
        
        result = CleanupResult()
        
        # Handle secrets
        if secrets:
            result.secrets_found = len(secrets)
            result.secrets_list = secrets
            
            if show_progress:
                print(f"   Found {len(secrets)} secrets to remove")
            
            if not dry_run:
                if show_progress:
                    print(f"   Removing secrets from git history...")
                
                cleanup = self.clean_history(repo_path, secrets, use_env_vars, dry_run=False)
                result.secrets_removed = cleanup.secrets_removed
                result.commits_rewritten = cleanup.commits_rewritten
                result.files_modified = cleanup.files_modified
                result.errors.extend(cleanup.errors)
            else:
                result.secrets_removed = len(secrets)
        
        # Handle large files
        if large_files:
            result.large_files_found = len(large_files)
            result.large_files_list = large_files
            
            if show_progress:
                print(f"   Found {len(large_files)} large files to remove")
            
            if not dry_run:
                if show_progress:
                    print(f"   Removing large files from git history...")
                
                large_result = self.remove_large_files(repo_path, large_files, dry_run=False)
                result.large_files_removed = large_result["files_removed"]
                result.errors.extend(large_result.get("errors", []))
            else:
                result.large_files_removed = len(large_files)
        
        # Final garbage collection
        if not dry_run and (secrets or large_files):
            if show_progress:
                print(f"   Running garbage collection...")
            self._run_garbage_collection(repo_path)
        
        return result
    
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
