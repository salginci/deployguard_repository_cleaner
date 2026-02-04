"""
DeployGuard CLI - Git Hooks Management

Provides commands for installing and managing pre-commit hooks
to prevent secrets from being committed to the repository.
"""
import os
import stat
import subprocess
import click
from pathlib import Path
from typing import Optional, List

from deployguard.core.scanner import SecretScanner


# Pre-commit hook script template
PRE_COMMIT_HOOK = '''#!/bin/sh
#
# DeployGuard Pre-Commit Hook
# Prevents committing secrets to the repository
#
# To skip this hook (use with caution):
#   git commit --no-verify
#
# To uninstall:
#   deployguard hooks uninstall
#

# Get the directory where git is being run
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)

# Check if deployguard is installed
if ! command -v deployguard &> /dev/null; then
    echo "⚠️  DeployGuard not found. Skipping secret scan."
    echo "   Install with: pip install deployguard"
    exit 0
fi

echo ""
echo "🔍 DeployGuard: Scanning staged files for secrets..."
echo ""

# Run deployguard protect on staged files
deployguard hooks protect

# Capture the exit code
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Commit blocked: Secrets detected in staged files!"
    echo ""
    echo "Options:"
    echo "  1. Remove the secrets and stage the changes"
    echo "  2. Use 'deployguard remediate auto' to replace with env vars"
    echo "  3. Skip this check with: git commit --no-verify (not recommended)"
    echo ""
    exit 1
fi

echo "✅ No secrets detected. Proceeding with commit."
echo ""
exit 0
'''


@click.group()
def hooks():
    """🪝 Manage Git pre-commit hooks for secret detection."""
    pass


@hooks.command("install")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Overwrite existing pre-commit hook"
)
def install_hook(path: str, force: bool):
    """
    Install the DeployGuard pre-commit hook.
    
    This hook will scan staged files for secrets before each commit.
    If secrets are found, the commit will be blocked.
    
    Examples:
        deployguard hooks install
        deployguard hooks install --path /path/to/repo
        deployguard hooks install --force
    """
    repo_path = Path(path).resolve()
    git_dir = repo_path / ".git"
    
    if not git_dir.exists():
        click.echo(f"❌ Error: {repo_path} is not a git repository")
        click.echo("   Run 'git init' first or specify a valid repository path")
        raise SystemExit(1)
    
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    
    pre_commit_path = hooks_dir / "pre-commit"
    
    # Check for existing hook
    if pre_commit_path.exists() and not force:
        click.echo(f"⚠️  Pre-commit hook already exists at {pre_commit_path}")
        click.echo("   Use --force to overwrite")
        
        # Check if it's our hook
        with open(pre_commit_path, "r") as f:
            content = f.read()
            if "DeployGuard" in content:
                click.echo("   (This appears to be a DeployGuard hook)")
            else:
                click.echo("   (This is a custom hook - consider backing it up)")
        
        raise SystemExit(1)
    
    # Write the hook
    with open(pre_commit_path, "w") as f:
        f.write(PRE_COMMIT_HOOK)
    
    # Make executable
    os.chmod(pre_commit_path, os.stat(pre_commit_path).st_mode | stat.S_IEXEC)
    
    click.echo(f"✅ Pre-commit hook installed successfully!")
    click.echo(f"   Location: {pre_commit_path}")
    click.echo("")
    click.echo("📋 What happens now:")
    click.echo("   • Every commit will be scanned for secrets")
    click.echo("   • If secrets are found, the commit will be blocked")
    click.echo("   • To skip the check: git commit --no-verify")
    click.echo("")
    click.echo("🔧 Other commands:")
    click.echo("   • deployguard hooks status   - Check hook status")
    click.echo("   • deployguard hooks uninstall - Remove the hook")


@hooks.command("uninstall")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
def uninstall_hook(path: str):
    """
    Uninstall the DeployGuard pre-commit hook.
    
    Examples:
        deployguard hooks uninstall
        deployguard hooks uninstall --path /path/to/repo
    """
    repo_path = Path(path).resolve()
    git_dir = repo_path / ".git"
    
    if not git_dir.exists():
        click.echo(f"❌ Error: {repo_path} is not a git repository")
        raise SystemExit(1)
    
    pre_commit_path = git_dir / "hooks" / "pre-commit"
    
    if not pre_commit_path.exists():
        click.echo("ℹ️  No pre-commit hook found. Nothing to uninstall.")
        return
    
    # Check if it's our hook
    with open(pre_commit_path, "r") as f:
        content = f.read()
        if "DeployGuard" not in content:
            click.echo("⚠️  The existing pre-commit hook is not a DeployGuard hook.")
            if not click.confirm("   Do you still want to remove it?"):
                click.echo("   Aborted.")
                return
    
    # Remove the hook
    pre_commit_path.unlink()
    
    click.echo("✅ Pre-commit hook uninstalled successfully!")
    click.echo("   Secrets will no longer be scanned before commits.")


@hooks.command("status")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
def hook_status(path: str):
    """
    Check the status of the DeployGuard pre-commit hook.
    
    Examples:
        deployguard hooks status
        deployguard hooks status --path /path/to/repo
    """
    repo_path = Path(path).resolve()
    git_dir = repo_path / ".git"
    
    if not git_dir.exists():
        click.echo(f"❌ Error: {repo_path} is not a git repository")
        raise SystemExit(1)
    
    pre_commit_path = git_dir / "hooks" / "pre-commit"
    
    click.echo(f"\n🪝 Git Hook Status for: {repo_path}")
    click.echo("=" * 50)
    
    if not pre_commit_path.exists():
        click.echo("❌ Pre-commit hook: NOT INSTALLED")
        click.echo("\n   Run 'deployguard hooks install' to enable secret scanning")
        return
    
    # Check if it's our hook
    with open(pre_commit_path, "r") as f:
        content = f.read()
    
    if "DeployGuard" in content:
        click.echo("✅ Pre-commit hook: INSTALLED (DeployGuard)")
        
        # Check if executable
        if os.access(pre_commit_path, os.X_OK):
            click.echo("✅ Hook is executable")
        else:
            click.echo("⚠️  Hook is NOT executable - fixing...")
            os.chmod(pre_commit_path, os.stat(pre_commit_path).st_mode | stat.S_IEXEC)
            click.echo("   Fixed!")
    else:
        click.echo("⚠️  Pre-commit hook: INSTALLED (Custom/Other)")
        click.echo("   This is not a DeployGuard hook.")
    
    click.echo("")


@hooks.command("protect")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show detailed output"
)
def protect(path: str, verbose: bool):
    """
    Scan staged files for secrets (used by pre-commit hook).
    
    This command is called automatically by the pre-commit hook.
    It only scans files that are staged for commit.
    
    Exit codes:
        0 - No secrets found
        1 - Secrets found (commit should be blocked)
    
    Examples:
        deployguard hooks protect
        deployguard hooks protect --verbose
    """
    repo_path = Path(path).resolve()
    
    # Get list of staged files
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        staged_files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except subprocess.CalledProcessError as e:
        click.echo(f"⚠️  Error getting staged files: {e}")
        raise SystemExit(0)  # Don't block commit on error
    
    if not staged_files:
        if verbose:
            click.echo("ℹ️  No staged files to scan.")
        raise SystemExit(0)
    
    if verbose:
        click.echo(f"📁 Scanning {len(staged_files)} staged file(s)...")
    
    # Initialize scanner
    default_patterns = Path(__file__).parent.parent.parent / "config" / "secret_patterns.yaml"
    patterns_file = str(default_patterns) if default_patterns.exists() else None
    
    scanner = SecretScanner(patterns_file=patterns_file)
    
    all_findings = []
    
    for relative_path in staged_files:
        file_path = repo_path / relative_path
        
        if not file_path.exists() or not file_path.is_file():
            continue
        
        # Skip binary files
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue
        
        # Scan the file
        findings = scanner.scan_file(str(file_path), content)
        
        if findings:
            for finding in findings:
                finding.file_path = relative_path  # Use relative path for display
            all_findings.extend(findings)
    
    if not all_findings:
        if verbose:
            click.echo("✅ No secrets found in staged files.")
        raise SystemExit(0)
    
    # Secrets found - display and exit with error
    click.echo("")
    click.echo("🚨 SECRETS DETECTED IN STAGED FILES!")
    click.echo("=" * 60)
    
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢"
    }
    
    for i, finding in enumerate(all_findings, 1):
        # Handle both enum and string types for severity and type
        severity_val = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        type_val = finding.type.value if hasattr(finding.type, 'value') else str(finding.type)
        
        emoji = severity_emoji.get(severity_val, "⚪")
        var_name = finding.metadata.get("variable_name", finding.suggested_variable) or "-"
        
        # Mask the actual value for security
        actual_value = finding.metadata.get("actual_value") or finding.exposed_value
        if len(actual_value) > 10:
            masked_value = actual_value[:4] + "****" + actual_value[-4:]
        else:
            masked_value = "****"
        
        click.echo(f"\n{i}. {emoji} [{severity_val.upper()}] {type_val}")
        click.echo(f"   📁 File: {finding.file_path}:{finding.line_number}")
        click.echo(f"   🏷️  Variable: {var_name}")
        click.echo(f"   🔑 Value: {masked_value}")
    
    click.echo("")
    click.echo("=" * 60)
    click.echo(f"❌ Found {len(all_findings)} secret(s) in staged files!")
    click.echo("")
    click.echo("💡 To fix:")
    click.echo("   1. Remove secrets from your code")
    click.echo("   2. Use environment variables instead")
    click.echo("   3. Run: deployguard remediate auto --path .")
    
    raise SystemExit(1)


@hooks.command("test")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    default=".",
    help="Path to git repository"
)
def test_hook(path: str):
    """
    Test the pre-commit hook without making a commit.
    
    This is useful to verify the hook is working correctly.
    
    Examples:
        deployguard hooks test
    """
    click.echo("\n🧪 Testing pre-commit hook...")
    click.echo("=" * 50)
    
    repo_path = Path(path).resolve()
    
    # Get staged files
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        staged_files = [f for f in result.stdout.strip().split("\n") if f]
    except Exception as e:
        click.echo(f"❌ Error: {e}")
        return
    
    if not staged_files:
        click.echo("⚠️  No files are currently staged.")
        click.echo("   Stage some files with 'git add' and try again.")
        return
    
    click.echo(f"📁 Staged files: {len(staged_files)}")
    for f in staged_files[:5]:
        click.echo(f"   • {f}")
    if len(staged_files) > 5:
        click.echo(f"   ... and {len(staged_files) - 5} more")
    
    click.echo("\n🔍 Running secret scan...")
    click.echo("-" * 50)
    
    # Run the protect command
    from click.testing import CliRunner
    runner = CliRunner()
    result = runner.invoke(protect, ["--path", str(repo_path), "--verbose"])
    
    click.echo(result.output)
    
    if result.exit_code == 0:
        click.echo("\n✅ Hook test passed! No secrets detected.")
        click.echo("   Your commit would succeed.")
    else:
        click.echo("\n❌ Hook test failed! Secrets detected.")
        click.echo("   Your commit would be blocked.")
