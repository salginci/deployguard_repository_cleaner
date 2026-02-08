#!/usr/bin/env python3
"""
DeployGuard - Batch Repository Processor
=========================================

Process multiple repositories from a YAML configuration file.

Usage:
    python batch_process_repos.py --config repos.yaml
    python batch_process_repos.py --config repos.yaml --scan-only
    python batch_process_repos.py --config repos.yaml --yes

Example repos.yaml:
    github_token_env: GITHUB_TOKEN  # or provide directly
    output_base: /Users/me/cleaned_repos
    
    repositories:
      - local_path: /path/to/repo1
        github_repo: owner/repo1
        build_command: dotnet build
        environment: production
        
      - local_path: /path/to/repo2
        github_repo: owner/repo2
        build_command: npm run build
        skip_build: true
"""

import argparse
import os
import sys
import yaml
from datetime import datetime
from typing import List, Dict, Any

from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deployguard_workflow import DeployGuardWorkflow, RepoConfig, WorkflowState


def load_config(config_path: str) -> Dict[str, Any]:
    """Load repository configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def create_repo_configs(config: Dict[str, Any]) -> List[RepoConfig]:
    """Create RepoConfig objects from YAML config."""
    repos = []
    
    for repo_data in config.get('repositories', []):
        repos.append(RepoConfig(
            local_path=os.path.expanduser(repo_data['local_path']),
            github_repo=repo_data.get('github_repo', ''),
            github_environment=repo_data.get('environment'),
            build_command=repo_data.get('build_command'),
            skip_build=repo_data.get('skip_build', False),
            push_to_github=repo_data.get('push_to_github', True),
            create_backup=repo_data.get('create_backup', True),
        ))
    
    return repos


def print_summary(results: List[Dict[str, Any]]):
    """Print final summary of all processed repositories."""
    print()
    print("=" * 70)
    print("📊 BATCH PROCESSING SUMMARY")
    print("=" * 70)
    print()
    
    total = len(results)
    successful = sum(1 for r in results if r['success'])
    failed = total - successful
    
    print(f"Total repositories: {total}")
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    print()
    
    print("Details:")
    print("-" * 70)
    
    for result in results:
        status = "✅" if result['success'] else "❌"
        repo_name = result['repo_name']
        
        if result['success']:
            state = result['state']
            print(f"{status} {repo_name}")
            print(f"   Secrets: {state.secrets_before} → {state.secrets_after}")
            print(f"   Scan: {'✅' if state.scan_complete else '❌'} | "
                  f"Clean: {'✅' if state.cleanup_complete else '❌'} | "
                  f"Build: {'✅' if state.build_verified else '❌'} | "
                  f"Push: {'✅' if state.repo_pushed else '❌'}")
        else:
            print(f"{status} {repo_name}")
            print(f"   Error: {result.get('error', 'Unknown error')}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Process multiple repositories with DeployGuard"
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to YAML configuration file"
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan repositories, don't clean"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Non-interactive mode"
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue processing even if a repository fails"
    )
    parser.add_argument(
        "--repos",
        nargs="+",
        help="Process only specific repositories by name"
    )
    
    args = parser.parse_args()
    
    # Load config
    if not os.path.exists(args.config):
        print(f"❌ Config file not found: {args.config}")
        sys.exit(1)
    
    config = load_config(args.config)
    
    # Get token
    token_env = config.get('github_token_env', 'GITHUB_TOKEN')
    token = config.get('github_token') or os.environ.get(token_env)
    
    if not token:
        print(f"⚠️  Warning: No GitHub token found (checked {token_env} env var)")
        print("   Secrets cannot be pushed to GitHub without a token")
    
    # Create repo configs
    repos = create_repo_configs(config)
    
    if not repos:
        print("❌ No repositories found in config")
        sys.exit(1)
    
    # Filter repos if specified
    if args.repos:
        repos = [r for r in repos if os.path.basename(r.local_path) in args.repos]
        if not repos:
            print(f"❌ No matching repositories found: {args.repos}")
            sys.exit(1)
    
    # Print overview
    print("=" * 70)
    print("🔐 DeployGuard Batch Processor")
    print("=" * 70)
    print()
    print(f"Repositories to process: {len(repos)}")
    for i, repo in enumerate(repos, 1):
        print(f"   {i}. {os.path.basename(repo.local_path)} → {repo.github_repo or 'N/A'}")
    print()
    
    if not args.yes:
        response = input("Proceed? [Y/n]: ").strip().lower()
        if response == 'n':
            print("Cancelled.")
            sys.exit(0)
    
    # Process each repository
    workflow = DeployGuardWorkflow(github_token=token)
    results = []
    
    for i, repo_config in enumerate(repos, 1):
        repo_name = os.path.basename(repo_config.local_path)
        
        print()
        print("=" * 70)
        print(f"📦 Processing {i}/{len(repos)}: {repo_name}")
        print("=" * 70)
        
        try:
            if args.scan_only:
                state = workflow.create_state(
                    repo_config.local_path,
                    config.get('output_base')
                )
                state = workflow.scan_repository(state)
                results.append({
                    'repo_name': repo_name,
                    'success': state.scan_complete,
                    'state': state,
                    'error': state.error,
                })
            else:
                state = workflow.run_full_workflow(
                    repo_config,
                    interactive=not args.yes
                )
                results.append({
                    'repo_name': repo_name,
                    'success': not state.error,
                    'state': state,
                    'error': state.error,
                })
            
        except Exception as e:
            results.append({
                'repo_name': repo_name,
                'success': False,
                'error': str(e),
            })
            
            if not args.continue_on_error:
                print(f"❌ Error processing {repo_name}: {e}")
                print("   Use --continue-on-error to skip failed repos")
                break
    
    # Print summary
    print_summary(results)
    
    # Exit with error code if any failed
    if any(not r['success'] for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
