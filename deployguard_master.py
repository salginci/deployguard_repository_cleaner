#!/usr/bin/env python3
"""
DeployGuard Master Script for Complete Repository Cleanup

This script handles:
1. Scan repository for secrets and large files
2. Export secrets to multiple formats (JSON, .env, GitHub Secrets)
3. Clean git history (remove secrets + large files)
4. Push to GitHub (new or existing repo)
5. Generate comprehensive reports

Usage:
    python deployguard_master.py --repo /path/to/repo --github-repo owner/repo-name

For multiple repositories, just run multiple times with different paths.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.history_cleaner import GitHistoryCleaner, SecretMatch
from deployguard.core.scanner import SecretScanner


class DeployGuardMaster:
    """Master controller for complete repository cleanup workflow."""
    
    def __init__(
        self,
        repo_path: str,
        output_dir: Optional[str] = None,
        github_repo: Optional[str] = None,
        github_token: Optional[str] = None,
    ):
        self.repo_path = os.path.abspath(repo_path)
        self.repo_name = Path(repo_path).name
        self.output_dir = output_dir or f"{self.repo_path}_cleanup_output"
        self.mirror_path = f"{self.repo_path}_mirror.git"
        self.github_repo = github_repo
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        
        # Initialize tools
        self.scanner = SecretScanner()
        self.cleaner = GitHistoryCleaner(self.scanner)
        
        # Data
        self.secrets: List[SecretMatch] = []
        self.large_files: List[Tuple[str, int]] = []
        self.cleanup_result = None
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_full_workflow(
        self,
        dry_run: bool = False,
        skip_scan: bool = False,
        skip_cleanup: bool = False,
        skip_push: bool = False,
    ) -> Dict:
        """
        Run the complete workflow.
        
        Args:
            dry_run: If True, don't actually modify anything
            skip_scan: Skip scanning (use existing data)
            skip_cleanup: Skip cleanup (only scan and export)
            skip_push: Skip pushing to GitHub
            
        Returns:
            Dict with results
        """
        results = {
            "repo_name": self.repo_name,
            "repo_path": self.repo_path,
            "timestamp": datetime.now().isoformat(),
            "secrets_found": 0,
            "large_files_found": 0,
            "secrets_removed": 0,
            "large_files_removed": 0,
            "exports": {},
            "errors": [],
        }
        
        print("=" * 70)
        print("🔐 DeployGuard Master Workflow")
        print("=" * 70)
        print(f"📁 Repository: {self.repo_path}")
        print(f"📁 Output: {self.output_dir}")
        if self.github_repo:
            print(f"🐙 GitHub: {self.github_repo}")
        print()
        
        # Step 1: Create mirror clone
        print("📍 STEP 1: Creating mirror clone...")
        self._create_mirror()
        
        # Step 2: Scan for secrets
        if not skip_scan:
            print()
            print("📍 STEP 2: Scanning for secrets...")
            self.secrets = self.cleaner.scan_git_history(
                self.mirror_path, 
                include_all_branches=True
            )
            results["secrets_found"] = len(self.secrets)
            print(f"   Found {len(self.secrets)} secrets")
        
        # Step 3: Scan for large files
        if not skip_scan:
            print()
            print("📍 STEP 3: Scanning for large files (>100MB)...")
            self.large_files = self.cleaner.scan_large_files(
                self.mirror_path, 
                max_size_mb=100.0
            )
            results["large_files_found"] = len(self.large_files)
        
        # Step 4: Export secrets
        print()
        print("📍 STEP 4: Exporting secrets...")
        exports = self._export_secrets()
        results["exports"] = exports
        
        # Step 5: Cleanup
        if not skip_cleanup and not dry_run:
            print()
            print("📍 STEP 5: Cleaning git history...")
            self.cleanup_result = self.cleaner.full_cleanup(
                repo_path=self.mirror_path,
                secrets=self.secrets,
                large_files=self.large_files,
                use_env_vars=True,
                dry_run=False,
                show_progress=True,
            )
            results["secrets_removed"] = self.cleanup_result.secrets_removed
            results["large_files_removed"] = self.cleanup_result.large_files_removed
            results["errors"].extend(self.cleanup_result.errors)
        
        # Step 6: Push to GitHub
        if not skip_push and not dry_run and self.github_repo:
            print()
            print("📍 STEP 6: Pushing to GitHub...")
            push_result = self._push_to_github()
            results["push_success"] = push_result
        
        # Summary
        print()
        print("=" * 70)
        print("✅ WORKFLOW COMPLETE")
        print("=" * 70)
        print()
        print(f"   Secrets found: {results['secrets_found']}")
        print(f"   Secrets removed: {results.get('secrets_removed', 'N/A')}")
        print(f"   Large files found: {results['large_files_found']}")
        print(f"   Large files removed: {results.get('large_files_removed', 'N/A')}")
        print()
        print("📁 Exported files:")
        for name, path in results["exports"].items():
            print(f"   • {name}: {path}")
        
        return results
    
    def _create_mirror(self):
        """Create a mirror clone for safe history rewriting."""
        if os.path.exists(self.mirror_path):
            shutil.rmtree(self.mirror_path)
        self.cleaner.create_mirror_clone(self.repo_path, self.mirror_path)
        print(f"   ✅ Mirror clone created at: {self.mirror_path}")
    
    def _export_secrets(self) -> Dict[str, str]:
        """Export secrets to multiple formats."""
        exports = {}
        
        # 1. Export to JSON (complete data)
        json_path = os.path.join(self.output_dir, f"{self.repo_name}_secrets.json")
        self._export_json(json_path)
        exports["json"] = json_path
        print(f"   ✅ JSON: {json_path}")
        
        # 2. Export to .env format
        env_path = os.path.join(self.output_dir, f"{self.repo_name}_secrets.env")
        self._export_env(env_path)
        exports["env"] = env_path
        print(f"   ✅ ENV: {env_path}")
        
        # 3. Export GitHub Secrets format
        gh_path = os.path.join(self.output_dir, f"{self.repo_name}_github_secrets.json")
        self._export_github_format(gh_path)
        exports["github"] = gh_path
        print(f"   ✅ GitHub Secrets: {gh_path}")
        
        # 4. Export shell script for GitHub CLI
        gh_script_path = os.path.join(self.output_dir, f"{self.repo_name}_set_github_secrets.sh")
        self._export_github_cli_script(gh_script_path)
        exports["github_cli_script"] = gh_script_path
        print(f"   ✅ GitHub CLI Script: {gh_script_path}")
        
        return exports
    
    def _export_json(self, path: str):
        """Export secrets to JSON format."""
        data = {
            "repository": self.repo_name,
            "exported_at": datetime.now().isoformat(),
            "total_secrets": len(self.secrets),
            "secrets": []
        }
        
        for secret in self.secrets:
            data["secrets"].append({
                "env_var": secret.suggested_env_var,
                "value": secret.value,
                "type": secret.secret_type,
                "severity": secret.severity,
                "files": secret.files[:5],
                "commit_count": len(secret.commits),
            })
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _export_env(self, path: str):
        """Export secrets to .env format."""
        seen_vars = set()
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# DeployGuard Secrets Export\n")
            f.write(f"# Repository: {self.repo_name}\n")
            f.write(f"# Exported: {datetime.now().isoformat()}\n")
            f.write(f"# Total secrets: {len(self.secrets)}\n")
            f.write(f"#\n")
            f.write(f"# ⚠️  WARNING: This file contains sensitive data!\n")
            f.write(f"# ⚠️  Do NOT commit this file to git!\n")
            f.write(f"# ⚠️  Add to .gitignore immediately!\n")
            f.write(f"\n")
            
            for secret in self.secrets:
                var_name = secret.suggested_env_var
                
                # Handle duplicates
                if var_name in seen_vars:
                    counter = 1
                    while f"{var_name}_{counter}" in seen_vars:
                        counter += 1
                    var_name = f"{var_name}_{counter}"
                
                seen_vars.add(var_name)
                
                # Escape value for shell
                value = secret.value.replace("'", "'\\''")
                
                f.write(f"# Type: {secret.secret_type} | Severity: {secret.severity}\n")
                f.write(f"{var_name}='{value}'\n\n")
    
    def _export_github_format(self, path: str):
        """Export secrets in format ready for GitHub Secrets API."""
        data = {
            "repository": self.repo_name,
            "github_repo": self.github_repo,
            "exported_at": datetime.now().isoformat(),
            "secrets": {}
        }
        
        seen_vars = set()
        for secret in self.secrets:
            var_name = secret.suggested_env_var
            
            # GitHub secrets names: only alphanumeric and underscores
            var_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in var_name)
            var_name = var_name.upper()
            
            # Handle duplicates
            if var_name in seen_vars:
                counter = 1
                while f"{var_name}_{counter}" in seen_vars:
                    counter += 1
                var_name = f"{var_name}_{counter}"
            
            seen_vars.add(var_name)
            data["secrets"][var_name] = secret.value
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _export_github_cli_script(self, path: str):
        """Export shell script to set GitHub secrets using gh CLI."""
        seen_vars = set()
        
        with open(path, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            f.write(f"# DeployGuard - Set GitHub Secrets\n")
            f.write(f"# Repository: {self.repo_name}\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"#\n")
            f.write(f"# Prerequisites:\n")
            f.write(f"#   1. Install GitHub CLI: brew install gh\n")
            f.write(f"#   2. Authenticate: gh auth login\n")
            f.write(f"#   3. Run this script: bash {os.path.basename(path)}\n")
            f.write(f"#\n")
            f.write(f"# For GitHub Environments, add --env ENVIRONMENT_NAME\n")
            f.write(f"\n")
            f.write(f"set -e\n\n")
            
            if self.github_repo:
                f.write(f"REPO=\"{self.github_repo}\"\n")
            else:
                f.write(f"REPO=\"OWNER/REPO\"  # TODO: Set your repo\n")
            
            f.write(f"\n")
            f.write(f"echo \"Setting secrets for $REPO...\"\n")
            f.write(f"\n")
            
            for secret in self.secrets:
                var_name = secret.suggested_env_var
                var_name = ''.join(c if c.isalnum() or c == '_' else '_' for c in var_name)
                var_name = var_name.upper()
                
                if var_name in seen_vars:
                    counter = 1
                    while f"{var_name}_{counter}" in seen_vars:
                        counter += 1
                    var_name = f"{var_name}_{counter}"
                
                seen_vars.add(var_name)
                
                # Escape for shell
                value = secret.value.replace("'", "'\\''")
                
                f.write(f"# {secret.secret_type} ({secret.severity})\n")
                f.write(f"echo '{value}' | gh secret set {var_name} --repo \"$REPO\"\n\n")
            
            f.write(f"\necho \"✅ All {len(self.secrets)} secrets have been set!\"\n")
        
        # Make executable
        os.chmod(path, 0o755)
    
    def _push_to_github(self) -> bool:
        """Push cleaned repository to GitHub."""
        if not self.github_repo:
            print("   ⚠️  No GitHub repo specified, skipping push")
            return False
        
        github_url = f"https://github.com/{self.github_repo}.git"
        
        # If we have a token, use it
        if self.github_token:
            github_url = f"https://{self.github_token}@github.com/{self.github_repo}.git"
        
        print(f"   Pushing to: github.com/{self.github_repo}")
        
        # Set remote
        subprocess.run(
            ["git", "remote", "set-url", "origin", github_url],
            cwd=self.mirror_path,
            capture_output=True,
        )
        
        # Force push
        result = subprocess.run(
            ["git", "push", "--mirror", "--force"],
            cwd=self.mirror_path,
            capture_output=True,
            text=True,
        )
        
        if result.returncode == 0:
            print(f"   ✅ Successfully pushed to {self.github_repo}")
            return True
        else:
            print(f"   ❌ Push failed: {result.stderr}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="DeployGuard Master - Complete repository cleanup workflow"
    )
    parser.add_argument(
        "--repo", "-r",
        required=True,
        help="Path to the repository to clean"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for exports (default: {repo}_cleanup_output)"
    )
    parser.add_argument(
        "--github-repo", "-g",
        help="GitHub repository (owner/repo) to push to"
    )
    parser.add_argument(
        "--github-token", "-t",
        help="GitHub token (or set GITHUB_TOKEN env var)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually modify anything, just scan and export"
    )
    parser.add_argument(
        "--skip-push",
        action="store_true",
        help="Skip pushing to GitHub"
    )
    
    args = parser.parse_args()
    
    master = DeployGuardMaster(
        repo_path=args.repo,
        output_dir=args.output,
        github_repo=args.github_repo,
        github_token=args.github_token,
    )
    
    results = master.run_full_workflow(
        dry_run=args.dry_run,
        skip_push=args.skip_push,
    )
    
    # Save results
    results_path = os.path.join(master.output_dir, f"{master.repo_name}_results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    
    print()
    print(f"📋 Results saved to: {results_path}")


if __name__ == "__main__":
    main()
