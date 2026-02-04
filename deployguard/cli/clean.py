"""
DeployGuard CLI - Clean Command

Provides commands for cleaning secrets from git history.
This replaces BFG Repo-Cleaner with native Python implementation.
"""
import os
import click
from pathlib import Path
from typing import Optional

from deployguard.core.history_cleaner import GitHistoryCleaner


@click.group()
def clean():
    """🧹 Clean secrets from git repository history."""
    pass


@clean.command("history")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to bare/mirror git repository"
)
@click.option(
    "--purge-file", "-f",
    type=click.Path(exists=True),
    help="Path to secrets_to_purge.txt file"
)
@click.option(
    "--use-env-vars/--use-placeholder",
    default=False,
    help="Replace secrets with ${ENV_VAR} instead of ***REMOVED***"
)
@click.option(
    "--dry-run/--execute",
    default=True,
    help="Show what would be done without making changes"
)
@click.option(
    "--scan-first/--no-scan",
    default=True,
    help="Scan for secrets before cleaning (ignored if --purge-file provided)"
)
@click.pass_context
def clean_history(ctx, path: str, purge_file: Optional[str], 
                  use_env_vars: bool, dry_run: bool, scan_first: bool):
    """
    Clean secrets from git history by rewriting commits.
    
    ⚠️  WARNING: This is a DESTRUCTIVE operation that rewrites git history!
    Always work on a mirror clone, not the original repository.
    
    Workflow:
        1. Create mirror clone: git clone --mirror <repo_url> repo.git
        2. Run this command on the clone
        3. Review changes
        4. Push to new remote: git push --mirror <new_remote>
    
    Examples:
        # Scan and show what would be cleaned (dry run)
        deployguard clean history --path repo.git --dry-run
        
        # Actually clean the history
        deployguard clean history --path repo.git --execute
        
        # Use a pre-generated purge file
        deployguard clean history --path repo.git -f secrets.txt --execute
        
        # Replace with environment variables
        deployguard clean history --path repo.git --use-env-vars --execute
    """
    click.echo("\n🧹 DeployGuard History Cleaner")
    click.echo("=" * 60)
    
    # Verify it's a git repository
    git_dir = Path(path)
    is_bare = (git_dir / "HEAD").exists() and (git_dir / "objects").exists()
    is_normal = (git_dir / ".git").exists()
    
    if not is_bare and not is_normal:
        click.echo(f"❌ Not a git repository: {path}", err=True)
        ctx.exit(1)
    
    if not is_bare and not dry_run:
        click.echo("⚠️  WARNING: This is not a bare/mirror repository!")
        click.echo("   For safety, create a mirror clone first:")
        click.echo(f"   git clone --mirror <url> {path}.git")
        if not click.confirm("Continue anyway? (NOT RECOMMENDED)"):
            ctx.exit(1)
    
    try:
        cleaner = GitHistoryCleaner()
        secrets = []
        
        # Get secrets to clean
        if purge_file:
            click.echo(f"\n📄 Loading secrets from: {purge_file}")
            secrets = _load_purge_file(purge_file)
            click.echo(f"   Loaded {len(secrets)} secrets to purge")
        elif scan_first:
            click.echo("\n🔍 Scanning git history for secrets...")
            secrets = cleaner.scan_git_history(path)
            click.echo(f"   Found {len(secrets)} unique secrets")
        
        if not secrets:
            click.echo("\n✅ No secrets to clean!")
            ctx.exit(0)
        
        # Display what will be cleaned
        click.echo("\n" + "-" * 60)
        click.echo("SECRETS TO BE CLEANED:")
        click.echo("-" * 60)
        
        for i, secret in enumerate(secrets[:20], 1):
            replacement = f"${{{secret.suggested_env_var}}}" if use_env_vars else "***REMOVED***"
            
            # Mask the secret value for display
            if len(secret.value) > 30:
                display_value = secret.value[:15] + "..." + secret.value[-10:]
            else:
                display_value = secret.value
            
            click.echo(f"\n{i}. {secret.secret_type} ({secret.severity})")
            click.echo(f"   📄 Value: {display_value}")
            click.echo(f"   ➡️  Replace with: {replacement}")
            click.echo(f"   📜 In {len(secret.commits)} commit(s), {len(secret.files)} file(s)")
        
        if len(secrets) > 20:
            click.echo(f"\n... and {len(secrets) - 20} more secrets")
        
        click.echo("\n" + "=" * 60)
        
        if dry_run:
            click.echo("🔍 DRY RUN - No changes made")
            click.echo("\nTo actually clean history, run with --execute flag")
            click.echo(f"   deployguard clean history --path {path} --execute")
            
            # Generate purge file for reference
            purge_output = Path(path).parent / "secrets_to_purge.txt"
            cleaner.generate_purge_file(secrets, str(purge_output), use_env_vars)
            click.echo(f"\n📄 Purge file saved: {purge_output}")
            
            # Generate env template
            env_output = Path(path).parent / ".env.template"
            cleaner.generate_env_template(secrets, str(env_output))
            click.echo(f"📄 Env template saved: {env_output}")
            
            ctx.exit(0)
        
        # Confirm before execution
        click.echo("⚠️  THIS WILL REWRITE GIT HISTORY!")
        click.echo("   This operation cannot be undone easily.")
        
        if not click.confirm("Proceed with history rewriting?"):
            click.echo("❌ Operation cancelled")
            ctx.exit(1)
        
        # Execute the cleanup
        click.echo("\n🔄 Rewriting git history...")
        
        result = cleaner.clean_history(
            repo_path=path,
            secrets=secrets,
            use_env_vars=use_env_vars,
            dry_run=False,
        )
        
        # Show results
        click.echo("\n" + "=" * 60)
        click.echo("✅ CLEANUP COMPLETE")
        click.echo("=" * 60)
        click.echo(f"🔍 Secrets found: {result.secrets_found}")
        click.echo(f"🧹 Secrets removed: {result.secrets_removed}")
        
        if result.errors:
            click.echo("\n⚠️  Errors encountered:")
            for error in result.errors:
                click.echo(f"   - {error}")
        
        click.echo("\n" + "-" * 60)
        click.echo("NEXT STEPS:")
        click.echo("-" * 60)
        click.echo("1. Verify the cleanup: git log --all --oneline")
        click.echo("2. Run garbage collection: git gc --prune=now --aggressive")
        click.echo("3. Push to new remote:")
        click.echo("   git push --mirror --force-with-lease <new_remote_url>")
        click.echo("\n⚠️  Never force-push to the original remote without coordination!")
        
        ctx.exit(0 if not result.errors else 1)
        
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        ctx.exit(3)


@clean.command("verify")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to git repository to verify"
)
@click.option(
    "--purge-file", "-f",
    type=click.Path(exists=True),
    help="Original purge file to check against"
)
@click.pass_context
def verify_clean(ctx, path: str, purge_file: Optional[str]):
    """
    Verify that secrets have been removed from history.
    
    Run this after cleaning to confirm all secrets are gone.
    
    Examples:
        deployguard clean verify --path repo.git
        deployguard clean verify --path repo.git -f secrets_to_purge.txt
    """
    click.echo("\n🔍 Verifying cleanup...")
    click.echo("=" * 60)
    
    try:
        cleaner = GitHistoryCleaner()
        
        # Scan for remaining secrets
        remaining_secrets = cleaner.scan_git_history(path)
        
        if not remaining_secrets:
            click.echo("\n✅ SUCCESS: No secrets found in git history!")
            ctx.exit(0)
        else:
            click.echo(f"\n⚠️  WARNING: {len(remaining_secrets)} secrets still present!")
            
            for i, secret in enumerate(remaining_secrets[:10], 1):
                click.echo(f"\n{i}. {secret.secret_type}")
                click.echo(f"   📄 Still in: {', '.join(secret.files[:3])}")
            
            click.echo("\nCleanup may have missed some secrets. Try running again.")
            ctx.exit(1)
            
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        ctx.exit(3)


@clean.command("gc")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to git repository"
)
@click.pass_context
def run_gc(ctx, path: str):
    """
    Run aggressive garbage collection to physically remove old data.
    
    After rewriting history, the old commits still exist on disk.
    This command permanently removes them.
    
    Examples:
        deployguard clean gc --path repo.git
    """
    import subprocess
    
    click.echo("\n🗑️  Running garbage collection...")
    click.echo("=" * 60)
    
    try:
        click.echo("📌 Expiring reflog...")
        subprocess.run(
            ["git", "reflog", "expire", "--expire=now", "--all"],
            cwd=path,
            check=True,
        )
        
        click.echo("🧹 Running aggressive GC...")
        subprocess.run(
            ["git", "gc", "--prune=now", "--aggressive"],
            cwd=path,
            check=True,
        )
        
        click.echo("\n✅ Garbage collection complete!")
        click.echo("   Old data has been physically removed from disk.")
        
        ctx.exit(0)
        
    except subprocess.CalledProcessError as e:
        click.echo(f"\n❌ GC failed: {e}", err=True)
        ctx.exit(1)


@clean.command("push")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to cleaned repository"
)
@click.option(
    "--remote", "-r",
    required=True,
    help="Remote URL to push to"
)
@click.option(
    "--force/--no-force",
    default=False,
    help="Use force push (required for rewritten history)"
)
@click.pass_context
def push_cleaned(ctx, path: str, remote: str, force: bool):
    """
    Push cleaned repository to a remote.
    
    Uses --force-with-lease for safety (prevents overwriting
    concurrent changes from other users).
    
    Examples:
        deployguard clean push --path repo.git -r git@github.com:org/repo.git --force
    """
    import subprocess
    
    click.echo(f"\n📤 Pushing to: {remote}")
    click.echo("=" * 60)
    
    if not force:
        click.echo("⚠️  This requires --force flag because history was rewritten.")
        click.echo("   Add --force to confirm you want to overwrite remote history.")
        ctx.exit(1)
    
    if not click.confirm("⚠️  This will OVERWRITE the remote repository history. Continue?"):
        click.echo("❌ Push cancelled")
        ctx.exit(1)
    
    try:
        # Set remote
        subprocess.run(
            ["git", "remote", "set-url", "origin", remote],
            cwd=path,
            check=True,
        )
        
        click.echo("🔄 Pushing with --force-with-lease...")
        result = subprocess.run(
            ["git", "push", "--mirror", "--force-with-lease"],
            cwd=path,
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            click.echo(f"❌ Push failed: {result.stderr}", err=True)
            ctx.exit(1)
        
        click.echo("\n✅ Push complete!")
        click.echo("   The cleaned repository is now on the remote.")
        click.echo("\n⚠️  All collaborators need to re-clone the repository!")
        
        ctx.exit(0)
        
    except subprocess.CalledProcessError as e:
        click.echo(f"\n❌ Push failed: {e}", err=True)
        ctx.exit(1)


def _load_purge_file(file_path: str) -> list:
    """Load secrets from a purge file."""
    from deployguard.core.history_cleaner import SecretMatch
    import hashlib
    
    secrets = []
    
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            if "==>" in line:
                value, replacement = line.split("==>", 1)
            else:
                value = line
                replacement = "***REMOVED***"
            
            value_hash = hashlib.sha256(value.encode()).hexdigest()[:16]
            
            secrets.append(SecretMatch(
                value=value,
                value_hash=value_hash,
                secret_type="unknown",
                severity="high",
                replacement=replacement,
            ))
    
    return secrets
