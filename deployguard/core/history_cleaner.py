"""Git history cleaner for purging secrets from repository history.

This module replaces BFG Repo-Cleaner functionality by providing:
- Full git history scanning
- Secret detection across all commits
- History rewriting to remove/replace secrets
- Garbage collection and cleanup

UPDATED: Now supports .NET-compatible environment variable naming with __ separator
"""

import os
import re
import subprocess
import tempfile
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from deployguard.core.exceptions import ScanError
from deployguard.core.models import Finding, SecretType, Severity
from deployguard.core.scanner_fast import FastSecretScanner as SecretScanner


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
    replacement: str = ""  # Will be empty string for clean JSON
    json_key: str = ""  # The JSON key name (e.g., "Password", "client_secret")
    json_section: str = ""  # The JSON section (e.g., "AzureB2C", "ConnectionStrings")
    
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
    large_files_list: List[Tuple[str, int]] = field(default_factory=list)
    purge_file_path: Optional[str] = None
    env_var_mapping: Dict[str, str] = field(default_factory=dict)  # env_var -> value


class GitHistoryCleaner:
    """
    Cleans secrets from git repository history.
    
    This replaces BFG Repo-Cleaner with native Python implementation using:
    - git filter-repo (preferred) or git filter-branch
    - Full history scanning across all branches
    - .NET-compatible environment variable naming (Section__Key format)
    """
    
    ENV_VAR_PREFIX = "DG_"
    
    def __init__(
        self,
        scanner: Optional[SecretScanner] = None,
        patterns_file: Optional[str] = None,
    ):
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
        '.pack', '.idx',
        '.min.js', '.min.css',
        '.jar', '.war', '.ear',
        '.node', '.map',
    }
    
    def _is_binary_file(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self.BINARY_EXTENSIONS
    
    def _run_git(self, args: List[str], cwd: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    
    def _run_git_binary(self, args: List[str], cwd: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=False,
        )
    
    def _extract_json_context(self, content: str, secret_value: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract JSON section and key name for a secret value.
        
        For nested JSON:
        {
            "AzureB2C": {
                "client_secret": "the_secret_value"
            }
        }
        Returns: ("AzureB2C", "client_secret")
        
        For flat key-value:
        {
            "ApiKey": "the_secret_value"
        }
        Returns: (None, "ApiKey")
        """
        try:
            lines = content.split('\n')
            secret_line_idx = None
            
            # Find the line containing this secret
            for i, line in enumerate(lines):
                if secret_value in line:
                    secret_line_idx = i
                    break
            
            if secret_line_idx is None:
                return None, None
            
            # Extract key name from the line
            line = lines[secret_line_idx]
            
            # Match: "key_name": "value" or "key_name" : value
            key_match = re.search(r'"([^"]+)"\s*:\s*', line)
            if not key_match:
                return None, None
            
            key_name = key_match.group(1)
            
            # Look for parent section by scanning backwards
            section_name = None
            brace_count = 0
            
            for i in range(secret_line_idx - 1, -1, -1):
                check_line = lines[i].strip()
                
                # Track brace nesting
                brace_count += check_line.count('}') - check_line.count('{')
                
                # Look for section header: "SectionName": {
                if '{' in check_line:
                    section_match = re.search(r'"([^"]+)"\s*:\s*\{', check_line)
                    if section_match:
                        section_name = section_match.group(1)
                        break
                    # Check if section name is on previous line
                    if i > 0:
                        prev_line = lines[i-1].strip()
                        section_match = re.search(r'"([^"]+)"\s*:\s*$', prev_line)
                        if section_match:
                            section_name = section_match.group(1)
                            break
            
            return section_name, key_name
            
        except Exception:
            return None, None
    
    def _generate_dotnet_env_var(
        self, 
        section: Optional[str], 
        key: Optional[str],
        secret_type: str,
        file_path: str,
    ) -> str:
        """
        Generate .NET-compatible environment variable name.
        
        .NET uses __ (double underscore) as hierarchy separator.
        
        Examples:
            - Section: "AzureB2C", Key: "client_secret" -> DG_AzureB2C__client_secret
            - Section: None, Key: "ApiKey" -> DG_ApiKey
            - Section: "ConnectionStrings", Key: "HubDbContext" -> DG_ConnectionStrings__HubDbContext
        """
        prefix = self.ENV_VAR_PREFIX
        
        if section and key:
            # Nested: Section__Key
            env_var = f"{prefix}{section}__{key}"
        elif key:
            # Flat: just Key
            env_var = f"{prefix}{key}"
        else:
            # Fallback: use file and type
            file_stem = Path(file_path).stem if file_path else "UNKNOWN"
            type_name = secret_type.upper().replace("-", "_").replace(" ", "_")
            env_var = f"{prefix}{file_stem}__{type_name}"
        
        # Clean up: replace invalid characters (keep __ for .NET)
        # Only replace characters that are not alphanumeric or underscore
        env_var = re.sub(r'[^A-Za-z0-9_]', '_', env_var)
        
        return env_var
    
    def scan_git_history(
        self,
        repo_path: str,
        branch: Optional[str] = None,
        include_all_branches: bool = True,
        show_progress: bool = True,
    ) -> List[SecretMatch]:
        """Scan entire git history for secrets."""
        import sys
        
        secrets: Dict[str, SecretMatch] = {}
        
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
        
        for idx, commit in enumerate(commits):
            if not commit:
                continue
            
            if show_progress and idx > 0 and idx % 100 == 0:
                print(f"   Progress: {idx}/{total_commits} commits ({len(secrets)} secrets found)")
                sys.stdout.flush()
                
            diff_result = self._run_git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", commit],
                repo_path,
            )
            
            if diff_result.returncode != 0:
                continue
                
            files = diff_result.stdout.strip().split("\n")
            
            for file_path in files:
                if not file_path or self._is_binary_file(file_path):
                    continue
                    
                show_result = self._run_git_binary(
                    ["show", f"{commit}:{file_path}"],
                    repo_path,
                )
                
                if show_result.returncode != 0:
                    continue
                
                try:
                    content = show_result.stdout.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        content = show_result.stdout.decode('latin-1')
                    except:
                        continue
                
                findings = self.scanner.scan_file(file_path, content)
                
                for finding in findings:
                    value_hash = finding.exposed_value_hash
                    
                    secret_type = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
                    severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                    
                    # Extract JSON context for .NET env var naming
                    section, key = self._extract_json_context(content, finding.exposed_value)
                    
                    # Generate .NET-compatible env var name
                    env_var = self._generate_dotnet_env_var(section, key, secret_type, file_path)
                    
                    if value_hash not in secrets:
                        secrets[value_hash] = SecretMatch(
                            value=finding.exposed_value,
                            value_hash=value_hash,
                            secret_type=secret_type,
                            severity=severity,
                            commits=[commit],
                            files=[file_path],
                            suggested_env_var=env_var,
                            json_section=section or "",
                            json_key=key or "",
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
        """Scan git history for files exceeding GitHub's 100MB limit."""
        large_files: Dict[str, int] = {}
        max_size_bytes = int(max_size_mb * 1024 * 1024)
        
        if show_progress:
            print(f"   Scanning for files > {max_size_mb}MB...")
        
        result = subprocess.run(
            ["git", "-C", repo_path, "rev-list", "--objects", "--all"],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            if show_progress:
                print(f"   Warning: Could not scan for large files: {result.stderr}")
            return []
        
        objects = []
        for line in result.stdout.strip().split('\n'):
            if line and ' ' in line:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    objects.append((parts[0], parts[1]))
        
        if show_progress:
            print(f"   Found {len(objects)} objects to check...")
        
        shas = [obj[0] for obj in objects]
        sha_to_path = {obj[0]: obj[1] for obj in objects}
        
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
        
        sorted_files = sorted(large_files.items(), key=lambda x: -x[1])
        
        if show_progress:
            if sorted_files:
                print(f"   Found {len(sorted_files)} files > {max_size_mb}MB:")
                for path, size in sorted_files[:10]:
                    print(f"      • {path}: {size / 1024 / 1024:.1f}MB")
            else:
                print(f"   No files found > {max_size_mb}MB ✓")
        
        return sorted_files
    
    def clean_history(
        self,
        repo_path: str,
        secrets: List[SecretMatch],
        dry_run: bool = True,
    ) -> CleanupResult:
        """
        Rewrite git history to remove secrets by replacing with empty strings.
        
        This keeps JSON structure intact:
        "client_secret": "actual_secret" -> "client_secret": ""
        """
        result = CleanupResult(
            secrets_found=len(secrets),
            secrets_list=secrets,
        )
        
        for secret in secrets:
            result.env_var_mapping[secret.suggested_env_var] = secret.value
        
        if dry_run:
            result.secrets_removed = len(secrets)
            return result
        
        try:
            if self._git_filter_repo_available:
                cleanup_result = self._clean_with_filter_repo(repo_path, secrets)
            else:
                raise ScanError("git-filter-repo is required but not available")
            
            result.secrets_removed = cleanup_result.get("removed", 0)
            result.commits_rewritten = cleanup_result.get("commits", 0)
            result.errors.extend(cleanup_result.get("errors", []))
            
            self._run_garbage_collection(repo_path)
            
        except Exception as e:
            result.errors.append(str(e))
        
        return result
    
    def _clean_with_filter_repo(
        self,
        repo_path: str,
        secrets: List[SecretMatch],
    ) -> Dict[str, any]:
        """
        Clean using git-filter-repo.
        
        IMPORTANT: Replaces secret values with empty strings "" to keep JSON valid.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            expr_file = f.name
            valid_secrets = 0
            
            for secret in secrets:
                if not secret.value or len(secret.value) < 4:
                    continue
                
                value = secret.value
                
                # Skip problematic characters
                if '\x00' in value or '\n' in value or '\r' in value:
                    continue
                
                # CRITICAL: Replace with empty string to keep JSON structure
                replacement = ""
                
                if '==>' in value:
                    escaped = re.escape(value)
                    f.write(f"regex:{escaped}==>{replacement}\n")
                else:
                    # Use literal matching
                    f.write(f"{value}==>{replacement}\n")
                
                valid_secrets += 1
            
            print(f"   Found {valid_secrets} secrets to remove")
        
        try:
            print("   Removing secrets from git history...")
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
                return {
                    "removed": 0,
                    "commits": 0,
                    "errors": [f"git-filter-repo failed: {result.stderr}"],
                }
            
            return {
                "removed": valid_secrets,
                "commits": 0,
                "errors": [],
            }
        finally:
            os.unlink(expr_file)
    
    def _run_garbage_collection(self, repo_path: str) -> None:
        print("   Running garbage collection...")
        self._run_git(["reflog", "expire", "--expire=now", "--all"], repo_path)
        self._run_git(["gc", "--prune=now", "--aggressive"], repo_path)
    
    def remove_large_files(
        self,
        repo_path: str,
        large_files: List[Tuple[str, int]],
        dry_run: bool = True,
    ) -> Dict[str, any]:
        """Remove large files from git history."""
        result = {
            "found": len(large_files),
            "removed": 0,
            "errors": [],
        }
        
        if dry_run or not large_files:
            result["removed"] = len(large_files) if not dry_run else 0
            return result
        
        if not self._git_filter_repo_available:
            result["errors"].append("git-filter-repo not available")
            return result
        
        print(f"   Found {len(large_files)} large files to remove")
        
        for file_path, size in large_files:
            print(f"   Removing large files from git history...")
            
            proc = subprocess.run(
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
            
            if proc.returncode == 0:
                result["removed"] += 1
            else:
                result["errors"].append(f"Failed to remove {file_path}: {proc.stderr}")
        
        return result
    
    def full_cleanup(
        self,
        repo_path: str,
        secrets: Optional[List[SecretMatch]] = None,
        large_files: Optional[List[Tuple[str, int]]] = None,
        dry_run: bool = True,
        show_progress: bool = True,
    ) -> CleanupResult:
        """Perform full cleanup of repository."""
        result = CleanupResult()
        
        if secrets is None:
            if show_progress:
                print("   Scanning for secrets...")
            secrets = self.scan_git_history(repo_path, show_progress=show_progress)
        
        result.secrets_found = len(secrets)
        result.secrets_list = secrets
        
        if large_files is None:
            if show_progress:
                print("   Scanning for large files...")
            large_files = self.scan_large_files(repo_path, show_progress=show_progress)
        
        result.large_files_found = len(large_files)
        result.large_files_list = large_files
        
        for secret in secrets:
            result.env_var_mapping[secret.suggested_env_var] = secret.value
        
        if dry_run:
            result.secrets_removed = len(secrets)
            result.large_files_removed = len(large_files)
            return result
        
        if secrets:
            clean_result = self.clean_history(repo_path, secrets, dry_run=False)
            result.secrets_removed = clean_result.secrets_removed
            result.commits_rewritten = clean_result.commits_rewritten
            result.errors.extend(clean_result.errors)
        
        if large_files:
            lf_result = self.remove_large_files(repo_path, large_files, dry_run=False)
            result.large_files_removed = lf_result["removed"]
            result.errors.extend(lf_result.get("errors", []))
        
        return result
    
    def export_env_var_mapping(
        self,
        secrets: List[SecretMatch],
        output_path: str,
        format: str = "json",
    ) -> str:
        """
        Export environment variable to secret value mapping.
        
        Args:
            secrets: List of secrets
            output_path: Path to write the mapping
            format: Output format ("json", "env", "github_actions")
        """
        mapping = {}
        for secret in secrets:
            mapping[secret.suggested_env_var] = {
                "value": secret.value,
                "type": secret.secret_type,
                "severity": secret.severity,
                "section": secret.json_section,
                "key": secret.json_key,
                "files": secret.files[:3],
            }
        
        if format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(mapping, f, indent=2, ensure_ascii=False)
        
        elif format == "env":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# DeployGuard Environment Variables\n")
                f.write("# For .NET: Use __ (double underscore) for hierarchy\n\n")
                for env_var, data in mapping.items():
                    value = data["value"].replace('"', '\\"')
                    f.write(f"# Type: {data['type']}, Section: {data['section']}, Key: {data['key']}\n")
                    f.write(f'{env_var}="{value}"\n\n')
        
        elif format == "github_actions":
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# GitHub Actions Environment Variables\n")
                f.write("# Add this to your workflow file\n\n")
                f.write("env:\n")
                for env_var, data in mapping.items():
                    # For .NET: Remove DG_ prefix so env var matches config path
                    dotnet_var = env_var[3:] if env_var.startswith("DG_") else env_var
                    f.write(f"  {dotnet_var}: ${{{{ secrets.{env_var} }}}}\n")
        
        return output_path
