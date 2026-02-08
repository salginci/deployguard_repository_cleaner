#!/usr/bin/env python3
"""
DeployGuard - Dynamic Repository Cleaner
=========================================

A complete workflow for:
1. Scanning repositories for secrets
2. Cleaning git history
3. Pushing secrets to GitHub
4. Pushing cleaned repository to GitHub

Usage:
    # Clean a single repository
    python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo
    
    # Clean multiple repositories from config
    python deployguard_workflow.py --config repos.yaml
    
    # Scan only (no cleanup)
    python deployguard_workflow.py --repo /path/to/repo --scan-only
    
    # Push secrets only (after manual build verification)
    python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo --push-secrets-only
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import Counter

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard.core.scanner_fast import FastSecretScanner as SecretScanner
from deployguard.core.history_cleaner import GitHistoryCleaner


@dataclass
class RepoConfig:
    """Configuration for a repository to clean."""
    local_path: str
    github_repo: str  # format: owner/repo
    github_environment: Optional[str] = None  # e.g., 'production'
    build_command: Optional[str] = None  # e.g., 'dotnet build'
    skip_build: bool = False
    push_to_github: bool = True
    create_backup: bool = True


@dataclass
class WorkflowState:
    """Track workflow progress for a repository."""
    repo_name: str
    local_path: str
    output_dir: str
    mirror_path: str
    cleaned_path: str
    secrets_file: str
    
    # Progress tracking
    scan_complete: bool = False
    cleanup_complete: bool = False
    build_verified: bool = False
    secrets_pushed: bool = False
    repo_pushed: bool = False
    
    # Results
    secrets_before: int = 0
    secrets_after: int = 0
    large_files_before: int = 0
    large_files_after: int = 0
    
    # Error tracking
    error: Optional[str] = None


class DeployGuardWorkflow:
    """Main workflow orchestrator."""
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.scanner = SecretScanner()
        self.cleaner = GitHistoryCleaner(self.scanner)
        
    def _print_header(self, title: str, char: str = "="):
        """Print a formatted header."""
        print()
        print(char * 70)
        print(f"🔐 {title}")
        print(char * 70)
        print()
    
    def _print_section(self, title: str):
        """Print a section header."""
        print()
        print(f"{'─' * 50}")
        print(f"📌 {title}")
        print(f"{'─' * 50}")
    
    def _run_command(self, cmd: list, cwd: str = None, env: dict = None) -> tuple:
        """Run a shell command and return (success, output)."""
        try:
            run_env = os.environ.copy()
            if env:
                run_env.update(env)
            result = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, env=run_env
            )
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def create_state(self, local_path: str, output_base: str = None) -> WorkflowState:
        """Create workflow state for a repository."""
        repo_name = os.path.basename(local_path.rstrip('/'))
        
        if output_base is None:
            output_base = os.path.dirname(local_path)
        
        return WorkflowState(
            repo_name=repo_name,
            local_path=local_path,
            output_dir=os.path.join(output_base, f"{repo_name}_security_audit"),
            mirror_path=os.path.join(output_base, f"{repo_name}_mirror.git"),
            cleaned_path=os.path.join(output_base, f"{repo_name}_CLEANED"),
            secrets_file=os.path.join(output_base, f"{repo_name}_security_audit", f"{repo_name}_secrets_BEFORE.json"),
        )
    
    def scan_repository(self, state: WorkflowState) -> WorkflowState:
        """Phase 1: Scan repository for secrets and large files."""
        self._print_header("PHASE 1: Scanning Repository for Secrets")
        
        print(f"Repository: {state.local_path}")
        print(f"Output: {state.output_dir}")
        print()
        
        # Create output directory
        os.makedirs(state.output_dir, exist_ok=True)
        
        # Scan for secrets
        print("⏳ Scanning git history for secrets...")
        secrets = self.cleaner.scan_git_history(
            state.local_path,
            include_all_branches=True,
            show_progress=True
        )
        
        state.secrets_before = len(secrets)
        
        # Count by severity
        severity_counts = Counter(s.severity for s in secrets)
        type_counts = Counter(s.secret_type for s in secrets)
        
        print()
        print(f"✅ Found {len(secrets)} unique secrets")
        print()
        print("By Severity:")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in severity_counts:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[sev]
                print(f"   {emoji} {sev.upper()}: {severity_counts[sev]}")
        
        # Scan for large files
        self._print_section("Scanning for Large Files (>100MB)")
        large_files = self.cleaner.scan_large_files(state.local_path, max_size_mb=100.0, show_progress=True)
        state.large_files_before = len(large_files)
        
        if large_files:
            print(f"✅ Found {len(large_files)} large files")
        else:
            print("✅ No large files found")
        
        # Export secrets to JSON
        self._print_section("Exporting Secrets")
        
        export_data = {
            "repository": state.repo_name,
            "scan_date": datetime.now().isoformat(),
            "total_secrets": len(secrets),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "secrets": []
        }
        
        for secret in secrets:
            export_data["secrets"].append({
                "env_var": secret.suggested_env_var,
                "value": secret.value,
                "type": secret.secret_type,
                "severity": secret.severity,
                "files": secret.files[:5],
                "commit_count": len(secret.commits),
            })
        
        with open(state.secrets_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"✅ Secrets exported: {state.secrets_file}")
        
        # Store secrets and large files for later use
        state._secrets = secrets
        state._large_files = large_files
        state.scan_complete = True
        
        return state
    
    def cleanup_repository(self, state: WorkflowState) -> WorkflowState:
        """Phase 2: Create mirror and clean git history."""
        if not state.scan_complete:
            print("❌ Must run scan first!")
            return state
        
        self._print_header("PHASE 2: Cleaning Git History")
        
        secrets = getattr(state, '_secrets', [])
        large_files = getattr(state, '_large_files', [])
        
        # Remove old mirror if exists
        if os.path.exists(state.mirror_path):
            print(f"🗑️  Removing old mirror...")
            shutil.rmtree(state.mirror_path)
        
        if os.path.exists(state.cleaned_path):
            print(f"🗑️  Removing old cleaned repo...")
            shutil.rmtree(state.cleaned_path)
        
        # Create mirror clone
        print(f"📦 Creating mirror clone...")
        success, output = self._run_command(
            ["git", "clone", "--mirror", state.local_path, state.mirror_path]
        )
        if not success:
            state.error = f"Failed to create mirror: {output}"
            print(f"❌ {state.error}")
            return state
        print(f"✅ Mirror created: {state.mirror_path}")
        
        # Run cleanup
        print()
        print("🧹 Running cleanup (this may take several minutes)...")
        
        cleanup_result = self.cleaner.full_cleanup(
            state.mirror_path,
            secrets=secrets,
            large_files=large_files,
            dry_run=False,
            show_progress=True,
        )
        
        print()
        print("📊 Cleanup Results:")
        print(f"   Secrets removed: {cleanup_result.secrets_removed}/{len(secrets)}")
        print(f"   Large files removed: {cleanup_result.large_files_removed}/{len(large_files)}")
        print(f"   Commits rewritten: {cleanup_result.commits_rewritten}")
        
        # Verify cleanup
        self._print_section("Verifying Cleanup")
        
        print("🔍 Re-scanning cleaned repository...")
        secrets_after = self.cleaner.scan_git_history(
            state.mirror_path,
            include_all_branches=True,
            show_progress=True
        )
        
        state.secrets_after = len(secrets_after)
        
        large_files_after = self.cleaner.scan_large_files(state.mirror_path, max_size_mb=100.0, show_progress=True)
        state.large_files_after = len(large_files_after)
        
        print()
        print("📊 Verification Results:")
        print(f"   Secrets: {state.secrets_before} → {state.secrets_after}")
        print(f"   Large files: {state.large_files_before} → {state.large_files_after}")
        
        if state.secrets_after == 0 and state.large_files_after == 0:
            print()
            print("✅ SUCCESS: Repository is now clean!")
            state.cleanup_complete = True
        else:
            print()
            print("⚠️  WARNING: Some items may still remain")
            if secrets_after:
                print("   Remaining secrets:")
                for s in secrets_after[:5]:
                    print(f"      - {s.secret_type}: {s.value[:30]}...")
        
        # Create working copy from mirror
        self._print_section("Creating Working Copy")
        print(f"📦 Cloning from mirror to {state.cleaned_path}...")
        success, output = self._run_command(
            ["git", "clone", state.mirror_path, state.cleaned_path]
        )
        if success:
            print(f"✅ Working copy created: {state.cleaned_path}")
        else:
            print(f"⚠️  Could not create working copy: {output}")
        
        return state
    
    def verify_build(self, state: WorkflowState, build_command: str = None) -> WorkflowState:
        """Phase 3: Verify project builds correctly."""
        self._print_header("PHASE 3: Build Verification")
        
        if not state.cleanup_complete:
            print("❌ Cleanup must complete successfully first!")
            return state
        
        if not os.path.exists(state.cleaned_path):
            print(f"❌ Cleaned repository not found: {state.cleaned_path}")
            return state
        
        if build_command:
            print(f"🔨 Running build command: {build_command}")
            print(f"   Working directory: {state.cleaned_path}")
            print()
            
            # Run build
            success, output = self._run_command(
                build_command.split(),
                cwd=state.cleaned_path
            )
            
            if success:
                print("✅ Build successful!")
                state.build_verified = True
            else:
                print("❌ Build failed!")
                print(output)
                state.error = "Build failed"
        else:
            print("⚠️  No build command specified.")
            print(f"   Please manually verify the build in: {state.cleaned_path}")
            print()
            response = input("   Has the build been verified? [y/N]: ").strip().lower()
            if response == 'y':
                state.build_verified = True
                print("✅ Build marked as verified")
            else:
                print("⏸️  Build verification pending")
        
        return state
    
    def push_secrets_to_github(self, state: WorkflowState, github_repo: str, 
                                environment: str = None) -> WorkflowState:
        """Phase 4: Push secrets to GitHub."""
        self._print_header("PHASE 4: Pushing Secrets to GitHub")
        
        if not self.github_token:
            print("❌ GitHub token not set!")
            print("   Set GITHUB_TOKEN environment variable or pass --token")
            return state
        
        if not os.path.exists(state.secrets_file):
            print(f"❌ Secrets file not found: {state.secrets_file}")
            return state
        
        print(f"📦 Repository: {github_repo}")
        print(f"🔒 Environment: {environment or 'repository-level'}")
        print()
        
        # Load secrets
        with open(state.secrets_file, 'r') as f:
            data = json.load(f)
        secrets = data.get("secrets", [])
        
        if not secrets:
            print("✅ No secrets to push")
            state.secrets_pushed = True
            return state
        
        # Import GitHub manager
        try:
            from push_secrets_to_github import GitHubSecretsManager, sanitize_secret_name, extract_clean_value
        except ImportError:
            print("❌ push_secrets_to_github.py not found!")
            return state
        
        owner, repo = github_repo.split("/", 1)
        manager = GitHubSecretsManager(self.github_token, owner, repo)
        
        # Verify access
        print("🔍 Verifying GitHub access...")
        if not manager.verify_token():
            state.error = "GitHub authentication failed"
            return state
        print("✅ Token verified")
        print()
        
        # Push secrets
        success_count = 0
        fail_count = 0
        processed = set()
        
        for secret in secrets:
            env_var = secret.get("env_var", "")
            raw_value = secret.get("value", "")
            secret_type = secret.get("type", "unknown")
            
            if not raw_value:
                continue
            
            name = sanitize_secret_name(env_var)
            if name in processed:
                continue
            processed.add(name)
            
            clean_value = extract_clean_value(raw_value)
            
            print(f"   📤 {name} ({secret_type})...", end=" ")
            
            if environment:
                success = manager.create_or_update_environment_secret(
                    environment, name, clean_value
                )
            else:
                success = manager.create_or_update_repo_secret(name, clean_value)
            
            if success:
                print("✅")
                success_count += 1
            else:
                print("❌")
                fail_count += 1
        
        print()
        print(f"📊 Results: {success_count} pushed, {fail_count} failed")
        
        if fail_count == 0:
            state.secrets_pushed = True
            print("✅ All secrets pushed successfully!")
        
        return state
    
    def push_repo_to_github(self, state: WorkflowState, github_repo: str, 
                            force: bool = True) -> WorkflowState:
        """Phase 5: Push cleaned repository to GitHub."""
        self._print_header("PHASE 5: Pushing Cleaned Repository to GitHub")
        
        if not state.build_verified:
            print("⚠️  WARNING: Build has not been verified!")
            response = input("   Continue anyway? [y/N]: ").strip().lower()
            if response != 'y':
                print("⏸️  Push cancelled")
                return state
        
        source_path = state.mirror_path
        if not os.path.exists(source_path):
            source_path = state.cleaned_path
        
        if not os.path.exists(source_path):
            print(f"❌ No cleaned repository found!")
            return state
        
        github_url = f"https://github.com/{github_repo}.git"
        
        print(f"📦 Source: {source_path}")
        print(f"🎯 Target: {github_url}")
        print()
        
        # Check if remote exists
        success, output = self._run_command(
            ["git", "remote", "get-url", "github"],
            cwd=source_path
        )
        
        if not success:
            print("📡 Adding GitHub remote...")
            self._run_command(
                ["git", "remote", "add", "github", github_url],
                cwd=source_path
            )
        
        # Push all branches
        print("🚀 Pushing all branches...")
        force_flag = ["--force"] if force else []
        
        success, output = self._run_command(
            ["git", "push", "github", "--all"] + force_flag,
            cwd=source_path,
            env={"GIT_ASKPASS": "echo", "GIT_USERNAME": "git", "GIT_PASSWORD": self.github_token}
        )
        
        if not success:
            print(f"❌ Failed to push branches: {output}")
            state.error = "Failed to push branches"
            return state
        
        # Push tags
        print("🏷️  Pushing tags...")
        success, output = self._run_command(
            ["git", "push", "github", "--tags"] + force_flag,
            cwd=source_path,
            env={"GIT_ASKPASS": "echo", "GIT_USERNAME": "git", "GIT_PASSWORD": self.github_token}
        )
        
        if not success:
            print(f"⚠️  Warning: Failed to push tags: {output}")
        
        print()
        print("✅ Repository pushed successfully!")
        print(f"   View at: https://github.com/{github_repo}")
        state.repo_pushed = True
        
        return state
    
    def run_full_workflow(self, config: RepoConfig, interactive: bool = True) -> WorkflowState:
        """Run the complete workflow for a repository."""
        start_time = datetime.now()
        
        self._print_header(f"DeployGuard Workflow: {os.path.basename(config.local_path)}", "═")
        
        # Create state
        state = self.create_state(config.local_path)
        
        print(f"📁 Repository: {config.local_path}")
        print(f"🎯 GitHub: {config.github_repo}")
        print(f"📂 Output: {state.output_dir}")
        print(f"⏱️  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Phase 1: Scan
        state = self.scan_repository(state)
        if state.error:
            return state
        
        if interactive:
            print()
            response = input("Proceed with cleanup? [Y/n]: ").strip().lower()
            if response == 'n':
                print("⏸️  Workflow paused after scan")
                return state
        
        # Phase 2: Cleanup
        state = self.cleanup_repository(state)
        if state.error or not state.cleanup_complete:
            return state
        
        # Phase 3: Build verification
        if config.build_command and not config.skip_build:
            state = self.verify_build(state, config.build_command)
        elif not config.skip_build and interactive:
            state = self.verify_build(state)
        else:
            state.build_verified = True  # Skip build verification
        
        if not state.build_verified:
            print()
            print("⏸️  Workflow paused. Run again with --resume after verifying build.")
            self._save_state(state)
            return state
        
        # Phase 4: Push secrets
        if self.github_token and config.github_repo:
            state = self.push_secrets_to_github(
                state, 
                config.github_repo, 
                config.github_environment
            )
        
        # Phase 5: Push repo
        if config.push_to_github and state.secrets_pushed:
            if interactive:
                print()
                response = input("Push cleaned repository to GitHub? [Y/n]: ").strip().lower()
                if response == 'n':
                    print("⏸️  Repository not pushed")
                else:
                    state = self.push_repo_to_github(state, config.github_repo)
            else:
                state = self.push_repo_to_github(state, config.github_repo)
        
        # Final summary
        end_time = datetime.now()
        duration = end_time - start_time
        
        self._print_header("WORKFLOW COMPLETE", "═")
        
        print(f"⏱️  Duration: {duration}")
        print()
        print("📊 Summary:")
        print(f"   ✅ Scan complete: {state.scan_complete}")
        print(f"   ✅ Cleanup complete: {state.cleanup_complete}")
        print(f"   ✅ Build verified: {state.build_verified}")
        print(f"   ✅ Secrets pushed: {state.secrets_pushed}")
        print(f"   ✅ Repo pushed: {state.repo_pushed}")
        print()
        print(f"   Secrets: {state.secrets_before} → {state.secrets_after}")
        print(f"   Large files: {state.large_files_before} → {state.large_files_after}")
        
        return state
    
    def _save_state(self, state: WorkflowState):
        """Save workflow state for resume."""
        state_file = os.path.join(state.output_dir, "workflow_state.json")
        data = {
            "repo_name": state.repo_name,
            "local_path": state.local_path,
            "output_dir": state.output_dir,
            "mirror_path": state.mirror_path,
            "cleaned_path": state.cleaned_path,
            "secrets_file": state.secrets_file,
            "scan_complete": state.scan_complete,
            "cleanup_complete": state.cleanup_complete,
            "build_verified": state.build_verified,
            "secrets_pushed": state.secrets_pushed,
            "repo_pushed": state.repo_pushed,
            "secrets_before": state.secrets_before,
            "secrets_after": state.secrets_after,
        }
        with open(state_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"💾 State saved: {state_file}")


def main():
    parser = argparse.ArgumentParser(
        description="DeployGuard - Dynamic Repository Cleaner Workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full workflow for a single repository
  python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo

  # Scan only (no cleanup)
  python deployguard_workflow.py --repo /path/to/repo --scan-only

  # Push secrets only (after manual build)
  python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo --push-secrets-only

  # With build command
  python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo --build "dotnet build"

  # Non-interactive mode
  python deployguard_workflow.py --repo /path/to/repo --github-repo owner/repo --yes
        """
    )
    
    # Required arguments
    parser.add_argument(
        "--repo", "-r",
        required=True,
        help="Path to the local git repository to clean"
    )
    
    # GitHub settings
    parser.add_argument(
        "--github-repo", "-g",
        help="GitHub repository in format 'owner/repo'"
    )
    parser.add_argument(
        "--github-environment", "-e",
        help="GitHub environment for secrets (e.g., 'production')"
    )
    parser.add_argument(
        "--token", "-t",
        help="GitHub PAT (or set GITHUB_TOKEN env var)"
    )
    
    # Build settings
    parser.add_argument(
        "--build", "-b",
        help="Build command to verify (e.g., 'dotnet build', 'npm run build')"
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip build verification step"
    )
    
    # Workflow control
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan, don't clean"
    )
    parser.add_argument(
        "--push-secrets-only",
        action="store_true",
        help="Only push secrets (assumes cleanup already done)"
    )
    parser.add_argument(
        "--push-repo-only",
        action="store_true",
        help="Only push repository (assumes secrets already pushed)"
    )
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="Don't push to GitHub (local cleanup only)"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Non-interactive mode, answer yes to all prompts"
    )
    
    # Output settings
    parser.add_argument(
        "--output", "-o",
        help="Output directory base path (default: same as repo parent)"
    )
    
    args = parser.parse_args()
    
    # Validate repository path
    if not os.path.isdir(args.repo):
        print(f"❌ Repository not found: {args.repo}")
        sys.exit(1)
    
    if not os.path.isdir(os.path.join(args.repo, ".git")):
        print(f"❌ Not a git repository: {args.repo}")
        sys.exit(1)
    
    # Create config
    config = RepoConfig(
        local_path=os.path.abspath(args.repo),
        github_repo=args.github_repo or "",
        github_environment=args.github_environment,
        build_command=args.build,
        skip_build=args.skip_build,
        push_to_github=not args.no_push and args.github_repo is not None,
    )
    
    # Get token
    token = args.token or os.environ.get("GITHUB_TOKEN")
    
    # Create workflow
    workflow = DeployGuardWorkflow(github_token=token)
    
    # Handle different modes
    if args.scan_only:
        state = workflow.create_state(config.local_path, args.output)
        workflow.scan_repository(state)
        print()
        print(f"📄 Secrets file: {state.secrets_file}")
        
    elif args.push_secrets_only:
        if not config.github_repo:
            print("❌ --github-repo required for pushing secrets")
            sys.exit(1)
        if not token:
            print("❌ GitHub token required (--token or GITHUB_TOKEN env var)")
            sys.exit(1)
        
        state = workflow.create_state(config.local_path, args.output)
        state.scan_complete = True
        state.cleanup_complete = True
        state.build_verified = True
        workflow.push_secrets_to_github(state, config.github_repo, config.github_environment)
        
    elif args.push_repo_only:
        if not config.github_repo:
            print("❌ --github-repo required for pushing repo")
            sys.exit(1)
        
        state = workflow.create_state(config.local_path, args.output)
        state.scan_complete = True
        state.cleanup_complete = True
        state.build_verified = True
        state.secrets_pushed = True
        workflow.push_repo_to_github(state, config.github_repo)
        
    else:
        # Full workflow
        workflow.run_full_workflow(config, interactive=not args.yes)


if __name__ == "__main__":
    main()
