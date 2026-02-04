"""
DeployGuard CLI - Main entry point
"""
import click
from pathlib import Path
from deployguard.utils.config import ConfigManager
from deployguard.cli import auth, scan, report, clean, remediate, hooks
from deployguard.cli.verify import verify_cmd


@click.group()
@click.version_option(version="0.1.0")
@click.pass_context
def cli(ctx):
    """
    🛡️  DeployGuard - Repository Security Scanner & Cleaner
    
    Detect, remove, and manage exposed secrets in Git repositories.
    Replaces the need for BFG Repo-Cleaner and Gitleaks.
    
    WORKFLOW:
    
    1. Authenticate (for remote repos):
       deployguard auth --github-token YOUR_TOKEN
    
    2. Scan for secrets:
       deployguard scan local --path /path/to/repo
       deployguard scan history --path repo.git
    
    3. Verify if secrets are active:
       deployguard verify --only-active
    
    4. Auto-fix secrets (replace with env vars):
       deployguard remediate auto --path /path/to/repo --execute
    
    5. Clean git history:
       git clone --mirror <repo_url> repo.git
       deployguard clean history --path repo.git --execute
    
    6. Generate reports:
       deployguard report --latest
    """
    # Initialize config manager
    ctx.ensure_object(dict)
    ctx.obj['config'] = ConfigManager()


# Register subcommands
cli.add_command(auth.auth)
cli.add_command(scan.scan)
cli.add_command(report.report)
cli.add_command(clean.clean)
cli.add_command(remediate.remediate)
cli.add_command(hooks.hooks)
cli.add_command(verify_cmd)


if __name__ == '__main__':
    cli()
