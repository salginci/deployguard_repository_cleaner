"""
DeployGuard CLI - Clean Command

Provides commands for cleaning secrets from git history.
This replaces BFG Repo-Cleaner with native Python implementation.
"""
import os
import click
from pathlib import Path
from typing import Optional
from datetime import datetime

from deployguard.core.history_cleaner import GitHistoryCleaner
from deployguard.core.history_cleaner_fast import FastGitHistoryCleaner


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
@click.option(
    "--report-dir", "-r",
    type=click.Path(),
    help="Directory to save cleanup reports (default: parent of repo path)"
)
@click.option(
    "--auto-approve",
    is_flag=True,
    default=False,
    help="Skip interactive review and clean ALL detected secrets (USE WITH CAUTION - may include false positives)"
)
@click.pass_context
def clean_history(ctx, path: str, purge_file: Optional[str], 
                  use_env_vars: bool, dry_run: bool, scan_first: bool,
                  report_dir: Optional[str], auto_approve: bool):
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
        
        # Interactive selection mode - ALWAYS enabled unless --auto-approve is passed
        # User must confirm each secret one by one
        if not auto_approve and not purge_file:
            click.echo("\n" + "=" * 60)
            click.echo("🔍 INTERACTIVE SECRET REVIEW")
            click.echo("=" * 60)
            click.echo("\n⚠️  Review each detected item carefully!")
            click.echo("   Some detections may be FALSE POSITIVES (code, URLs, etc.)")
            click.echo("   Only select items that are ACTUAL SECRETS.\n")
            
            selected_secrets = _interactive_secret_selection(secrets, use_env_vars)
            
            if not selected_secrets:
                click.echo("\n❌ No secrets selected for cleanup. Exiting.")
                ctx.exit(0)
            
            # Update secrets to only include user-selected items
            original_count = len(secrets)
            secrets = selected_secrets
            skipped_count = original_count - len(secrets)
            
            click.echo(f"\n✅ Selected {len(secrets)} secrets for cleanup")
            if skipped_count > 0:
                click.echo(f"⏭️  Skipped {skipped_count} items (marked as false positives)")
        elif auto_approve:
            click.echo("\n⚠️  AUTO-APPROVE MODE: All detected secrets will be cleaned!")
            click.echo("   This may include false positives!")
            click.echo("   Use without --auto-approve to review each item individually.")
        
        # Display final list of what will be cleaned (user's selection)
        click.echo("\n" + "-" * 60)
        click.echo("SECRETS TO BE CLEANED (YOUR SELECTION):")
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
            
            # Determine report directory
            if report_dir:
                output_dir = Path(report_dir)
            else:
                output_dir = Path(path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate purge file for reference (only selected secrets)
            purge_output = output_dir / "secrets_to_purge.txt"
            cleaner.generate_purge_file(secrets, str(purge_output), use_env_vars)
            click.echo(f"\n📄 Purge file saved: {purge_output}")
            
            # Generate env template
            env_output = output_dir / ".env.template"
            cleaner.generate_env_template(secrets, str(env_output))
            click.echo(f"📄 Env template saved: {env_output}")
            
            # Generate pre-cleanup analysis report (based on user selection)
            click.echo("\n📊 Generating cleanup analysis report (based on your selection)...")
            fast_cleaner = FastGitHistoryCleaner()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Mark report as user-selected if not auto-approve
            is_user_selected = not auto_approve and not purge_file
            analysis_report = output_dir / f"cleanup_analysis_{timestamp}.md"
            _generate_pre_cleanup_analysis(secrets, str(analysis_report), is_user_selected)
            click.echo(f"📄 Analysis report: {analysis_report}")
            
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
        
        # Generate cleanup reports
        click.echo("\n📊 Generating cleanup reports...")
        if report_dir:
            reports_dir = Path(report_dir)
        else:
            reports_dir = Path(path).parent / "cleanup_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate reports in all formats using FastGitHistoryCleaner
        fast_cleaner = FastGitHistoryCleaner()
        
        # JSON report
        json_report = reports_dir / f"cleanup_report_{timestamp}.json"
        fast_cleaner.generate_cleanup_report(result, str(json_report), "json")
        click.echo(f"   📄 JSON report: {json_report}")
        
        # Markdown report
        md_report = reports_dir / f"cleanup_report_{timestamp}.md"
        fast_cleaner.generate_cleanup_report(result, str(md_report), "markdown")
        click.echo(f"   📄 Markdown report: {md_report}")
        
        # Text report
        txt_report = reports_dir / f"cleanup_report_{timestamp}.txt"
        fast_cleaner.generate_cleanup_report(result, str(txt_report), "txt")
        click.echo(f"   📄 Text report: {txt_report}")
        
        click.echo("\n" + "-" * 60)
        click.echo("NEXT STEPS:")
        click.echo("-" * 60)
        click.echo("1. Review the cleanup reports in: " + str(reports_dir))
        click.echo("2. Verify the cleanup: git log --all --oneline")
        click.echo("3. Run garbage collection: git gc --prune=now --aggressive")
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


def _interactive_secret_selection(secrets: list, use_env_vars: bool) -> list:
    """
    Interactively let user select which secrets to clean.
    
    Args:
        secrets: List of detected secrets
        use_env_vars: Whether env vars will be used for replacement
        
    Returns:
        List of user-confirmed secrets to clean
    """
    selected = []
    skipped = []
    
    total = len(secrets)
    
    click.echo(f"Found {total} potential secrets. Review each one:\n")
    click.echo("Commands: [y]es / [n]o / [a]ll remaining / [s]kip all remaining / [q]uit\n")
    
    for i, secret in enumerate(secrets, 1):
        replacement = f"${{{secret.suggested_env_var}}}" if use_env_vars else "***REMOVED***"
        
        # Show the full secret value for review (truncated if very long)
        if len(secret.value) > 80:
            display_value = secret.value[:40] + "..." + secret.value[-30:]
        else:
            display_value = secret.value
        
        click.echo("-" * 60)
        click.echo(f"[{i}/{total}] {secret.secret_type} ({secret.severity})")
        click.echo(f"   📄 Value: {display_value}")
        click.echo(f"   🏷️  Env Var: {secret.suggested_env_var}")
        click.echo(f"   ➡️  Will replace with: {replacement}")
        click.echo(f"   📁 Found in {len(secret.files)} file(s): {', '.join(secret.files[:3])}")
        if len(secret.files) > 3:
            click.echo(f"      ... and {len(secret.files) - 3} more files")
        click.echo(f"   📜 In {len(secret.commits)} commit(s)")
        
        # Provide hints for common false positives
        fp_hints = _check_false_positive_hints(secret)
        if fp_hints:
            click.echo(f"   ⚠️  POSSIBLE FALSE POSITIVE: {fp_hints}")
        
        while True:
            choice = click.prompt(
                "\n   Include in cleanup?",
                type=click.Choice(['y', 'n', 'a', 's', 'q'], case_sensitive=False),
                default='n',
                show_choices=True,
            )
            
            if choice.lower() == 'y':
                selected.append(secret)
                click.echo("   ✅ Added to cleanup list")
                break
            elif choice.lower() == 'n':
                skipped.append(secret)
                click.echo("   ⏭️  Skipped")
                break
            elif choice.lower() == 'a':
                # Add this and all remaining
                selected.append(secret)
                for remaining in secrets[i:]:
                    selected.append(remaining)
                click.echo(f"\n   ✅ Added this and {len(secrets) - i} remaining secrets")
                return selected
            elif choice.lower() == 's':
                # Skip this and all remaining
                skipped.append(secret)
                for remaining in secrets[i:]:
                    skipped.append(remaining)
                click.echo(f"\n   ⏭️  Skipped this and {len(secrets) - i} remaining secrets")
                return selected
            elif choice.lower() == 'q':
                click.echo("\n   ❌ Cancelled by user")
                return []
    
    click.echo("\n" + "=" * 60)
    click.echo(f"📊 Selection Summary:")
    click.echo(f"   ✅ Selected for cleanup: {len(selected)}")
    click.echo(f"   ⏭️  Skipped (false positives): {len(skipped)}")
    
    # Save feedback locally and optionally send to server for ML improvement
    _save_user_feedback(selected, skipped)
    
    return selected


def _save_user_feedback(selected: list, skipped: list) -> None:
    """
    Save user feedback on secret detection for ML improvement.
    
    This data is:
    1. Saved locally for user reference
    2. Optionally sent to DeployGuard server for ML training (anonymized)
    """
    import json
    import os
    from datetime import datetime
    
    # Prepare anonymized feedback data (NO actual secret values - only patterns/metadata)
    feedback_data = {
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "confirmed_secrets": [
            {
                "value_hash": s.value_hash,  # Hash only, not the actual value
                "secret_type": s.secret_type,
                "severity": s.severity,
                "value_length": len(s.value),
                "value_pattern": _extract_pattern(s.value),  # Pattern, not value
                "file_extension": os.path.splitext(s.files[0])[1] if s.files else "",
                "file_type": _classify_file(s.files[0]) if s.files else "unknown",
            }
            for s in selected
        ],
        "false_positives": [
            {
                "value_hash": s.value_hash,
                "secret_type": s.secret_type,
                "severity": s.severity,
                "value_length": len(s.value),
                "value_pattern": _extract_pattern(s.value),
                "file_extension": os.path.splitext(s.files[0])[1] if s.files else "",
                "file_type": _classify_file(s.files[0]) if s.files else "unknown",
            }
            for s in skipped
        ],
        "summary": {
            "total_detected": len(selected) + len(skipped),
            "confirmed_secrets": len(selected),
            "false_positives": len(skipped),
            "false_positive_rate": round(len(skipped) / (len(selected) + len(skipped)) * 100, 2) if (selected or skipped) else 0,
        }
    }
    
    # 1. Save locally
    feedback_dir = os.path.expanduser("~/.deployguard/feedback")
    os.makedirs(feedback_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    feedback_file = os.path.join(feedback_dir, f"feedback_{timestamp}.json")
    
    try:
        with open(feedback_file, "w") as f:
            json.dump(feedback_data, f, indent=2)
        click.echo(f"\n📁 Feedback saved locally: {feedback_file}")
    except Exception:
        pass
    
    # 2. Send to server for ML improvement (if enabled)
    _send_feedback_to_server(feedback_data)


def _send_feedback_to_server(feedback_data: dict) -> None:
    """
    Send anonymized feedback to DeployGuard server for ML training.
    
    Privacy notes:
    - NO actual secret values are sent
    - Only patterns, types, and metadata
    - User can opt-out via config
    
    Security:
    - Requests are signed with HMAC to prevent spam
    - Client ID is hashed for rate limiting
    """
    import os
    import json
    import hashlib
    import hmac
    import platform
    import uuid
    
    # Check if telemetry is enabled (opt-out via env var or config)
    if os.environ.get("DEPLOYGUARD_TELEMETRY_DISABLED", "").lower() in ("1", "true", "yes"):
        return
    
    # Check config file for opt-out
    config_file = os.path.expanduser("~/.deployguard/config.json")
    if os.path.exists(config_file):
        try:
            with open(config_file) as f:
                config = json.load(f)
                if not config.get("telemetry_enabled", True):
                    return
        except Exception:
            pass
    
    # DeployGuard feedback API endpoint
    feedback_url = os.environ.get(
        "DEPLOYGUARD_FEEDBACK_URL",
        "https://feedback.deployguard.net/v1/feedback"
    )
    
    # Generate client ID (anonymous, for rate limiting)
    client_id = _generate_client_id()
    
    # Add client ID to feedback
    feedback_data["client_id"] = client_id
    
    # Generate request signature for security
    signature = _generate_request_signature(feedback_data)
    
    try:
        import urllib.request
        import urllib.error
        
        req = urllib.request.Request(
            feedback_url,
            data=json.dumps(feedback_data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DeployGuard-CLI/1.0",
                "X-Client-ID": client_id,
                "X-Signature": signature,
                "X-Timestamp": feedback_data.get("timestamp", ""),
            },
            method="POST",
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                click.echo("📈 Feedback sent to DeployGuard for ML improvement. Thank you!")
            
    except urllib.error.URLError:
        # Server not available - that's fine, just skip
        click.echo("📈 Feedback stored locally (server unavailable)")
    except Exception:
        # Don't fail if feedback can't be sent
        pass


def _generate_client_id() -> str:
    """
    Generate anonymous client ID for rate limiting.
    
    Based on machine characteristics but NOT personally identifiable.
    Same machine will generate same ID for consistent rate limiting.
    """
    import hashlib
    import platform
    import os
    
    # Collect anonymous machine info
    machine_info = [
        platform.system(),
        platform.machine(),
        os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    ]
    
    # Try to get a stable machine identifier
    try:
        # On macOS, use hardware UUID
        if platform.system() == "Darwin":
            import subprocess
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split("\n"):
                if "Hardware UUID" in line:
                    machine_info.append(line.split(":")[1].strip())
                    break
    except Exception:
        pass
    
    # Hash the info
    combined = "|".join(machine_info)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


def _generate_request_signature(data: dict) -> str:
    """
    Generate HMAC signature for request validation.
    
    This prevents spam by ensuring requests come from actual CLI usage.
    The signing key is derived from the data itself + a public salt.
    """
    import hashlib
    import hmac
    import json
    
    # Public salt (not a secret - just adds complexity for spammers)
    PUBLIC_SALT = "deployguard-feedback-v1-2024"
    
    # Create signing payload from key fields
    signing_payload = json.dumps({
        "timestamp": data.get("timestamp", ""),
        "confirmed_count": len(data.get("confirmed_secrets", [])),
        "false_positive_count": len(data.get("false_positives", [])),
        "client_id": data.get("client_id", ""),
    }, sort_keys=True)
    
    # Generate signature
    signature = hmac.new(
        PUBLIC_SALT.encode(),
        signing_payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return signature


def _extract_pattern(value: str) -> str:
    """
    Extract a pattern from a secret value for ML training.
    
    Converts actual value to a pattern like:
    - "ghp_xxxxxxxxxxxxxxxxxxxx" -> "ghp_[alnum:20]"
    - "AKIA1234567890ABCDEF" -> "AKIA[alnum:16]"
    
    This preserves useful pattern info without exposing the secret.
    """
    import re
    
    # Common prefix patterns to preserve
    prefixes = [
        'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',  # GitHub tokens
        'AKIA', 'ABIA', 'ACCA', 'AGPA', 'AIDA',  # AWS keys
        'sk-', 'pk-',  # Stripe keys
        'xoxb-', 'xoxp-', 'xoxa-',  # Slack tokens
        'sha256/', 'sha1/',  # Certificate pins
        'eyJ',  # JWT tokens
    ]
    
    pattern = ""
    remaining = value
    
    # Check for known prefixes
    for prefix in prefixes:
        if value.startswith(prefix):
            pattern = prefix
            remaining = value[len(prefix):]
            break
    
    # Analyze the remaining part
    if remaining:
        # Count character types
        alpha = sum(1 for c in remaining if c.isalpha())
        digit = sum(1 for c in remaining if c.isdigit())
        special = len(remaining) - alpha - digit
        
        if alpha > 0 and digit > 0:
            pattern += f"[alnum:{len(remaining)}]"
        elif alpha > 0:
            pattern += f"[alpha:{len(remaining)}]"
        elif digit > 0:
            pattern += f"[digit:{len(remaining)}]"
        else:
            pattern += f"[mixed:{len(remaining)}]"
        
        if special > 0:
            pattern += f"+[special:{special}]"
    
    return pattern


def _classify_file(file_path: str) -> str:
    """
    Classify file type for ML training context.
    """
    import os
    
    ext = os.path.splitext(file_path)[1].lower()
    name = os.path.basename(file_path).lower()
    
    # Config files
    if name in ['.env', '.env.example', 'config.json', 'config.yaml', 'config.yml',
                'settings.json', 'settings.yaml', 'appsettings.json']:
        return "config"
    
    if ext in ['.yaml', '.yml', '.json', '.toml', '.ini', '.cfg']:
        return "config"
    
    # Android
    if ext == '.xml' and 'android' in file_path.lower():
        return "android_xml"
    if ext in ['.kt', '.java'] and 'android' in file_path.lower():
        return "android_code"
    if name == 'build.gradle' or name == 'build.gradle.kts':
        return "gradle"
    
    # iOS
    if ext == '.plist':
        return "ios_plist"
    if ext == '.swift':
        return "swift"
    
    # Web
    if ext in ['.js', '.ts', '.jsx', '.tsx']:
        return "javascript"
    if ext in ['.py']:
        return "python"
    
    # CI/CD
    if 'github/workflows' in file_path or 'gitlab-ci' in name or 'jenkinsfile' in name:
        return "cicd"
    
    # Docker
    if 'dockerfile' in name or name == 'docker-compose.yml':
        return "docker"
    
    return "other"


def _check_false_positive_hints(secret) -> str:
    """
    Check for common false positive patterns and return hints.
    
    Args:
        secret: SecretMatch object
        
    Returns:
        Hint string if potential false positive, empty string otherwise
    """
    value = secret.value.lower()
    original_value = secret.value
    
    # Common false positive patterns
    hints = []
    
    # SSL Certificate Pins / Public Key Hashes - NOT secrets!
    if original_value.startswith('sha256/') or original_value.startswith('sha1/'):
        hints.append("SSL Certificate Pin (public key hash) - NOT a secret, safe to keep")
    
    # Base64 encoded public hashes
    if '=' in original_value and len(original_value) in [44, 64, 88] and original_value.replace('+', '').replace('/', '').replace('=', '').isalnum():
        if 'sha' in value or 'certificate' in str(secret.files).lower() or 'pin' in str(secret.files).lower():
            hints.append("Likely a certificate pin or public hash - NOT a secret")
    
    # URLs to documentation
    if value.startswith(('http://', 'https://')) and any(x in value for x in [
        'android.com', 'google.com/tools', 'developer.', 'docs.', 
        'example.com', 'localhost', '127.0.0.1', 'schemas.', 
        'w3.org', 'xml', 'xmlns'
    ]):
        hints.append("Looks like a documentation/schema URL - NOT a secret")
    
    # Android XML namespaces and schema URLs
    if 'schemas.android.com' in value or 'xmlns' in value:
        hints.append("Android XML namespace - NOT a secret")
    
    # Android support library references
    if 'android.support.' in value or 'androidx.' in value:
        hints.append("Android library reference - NOT a secret")
    
    # Package names / hostnames in Android
    if value.startswith('com.') or value.startswith('org.') or value.startswith('net.'):
        if 'host=' in original_value or 'package=' in original_value:
            hints.append("Package name or host configuration - usually NOT a secret")
    
    # Code snippets
    if any(x in value for x in [
        '.lowercase()', '.uppercase()', '.tostring()', 
        'fullname', 'getname', 'setname', 'username:',
        'placeholder', 'example', 'sample', 'passenger:'
    ]):
        hints.append("Looks like code/variable name")
    
    # Common test/example values
    if value in ['password', 'secret', 'test', 'demo', 'example', 'placeholder']:
        hints.append("Generic placeholder value")
    
    # Short values that might be false positives
    if len(secret.value) < 8:
        hints.append("Very short value - might not be a real secret")
    
    # Strings that look like comments or descriptions
    if secret.value.strip().startswith(('#', '//', '/*', '*', '--')):
        hints.append("Looks like a comment")
    
    # Common Android/iOS false positives  
    if 'adapter' in value or 'instrumented' in value or 'test' in value:
        hints.append("Looks like test/adapter class name")
    
    # File provider paths
    if 'file_provider' in value or 'fileprovider' in value:
        hints.append("Android FileProvider path - NOT a secret")
    
    return "; ".join(hints)


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


def _generate_pre_cleanup_analysis(secrets: list, output_path: str, is_user_selected: bool = False) -> None:
    """Generate a pre-cleanup analysis report in Markdown format."""
    from collections import defaultdict
    
    # Aggregate statistics
    by_type = defaultdict(list)
    by_severity = defaultdict(list)
    by_file = defaultdict(list)
    all_commits = set()
    all_files = set()
    
    for secret in secrets:
        by_type[secret.secret_type].append(secret)
        by_severity[secret.severity].append(secret)
        
        for f in secret.files:
            by_file[f].append(secret)
            all_files.add(f)
        
        for c in secret.commits:
            all_commits.add(c)
    
    with open(output_path, "w") as f:
        if is_user_selected:
            f.write("# DeployGuard Cleanup Report (User Selected Secrets)\n\n")
            f.write("**Note:** This report contains only the secrets confirmed by the user for cleanup.\n")
            f.write("False positives have been filtered out during interactive review.\n\n")
        else:
            f.write("# DeployGuard Pre-Cleanup Analysis Report\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- **Total Secrets {'Selected' if is_user_selected else 'Found'}:** {len(secrets)}\n")
        f.write(f"- **Files Affected:** {len(all_files)}\n")
        f.write(f"- **Commits Affected:** {len(all_commits)}\n\n")
        
        f.write("## Secrets by Severity\n\n")
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                f.write(f"- **{severity.upper()}:** {len(by_severity[severity])}\n")
        f.write("\n")
        
        f.write("## Secrets by Type\n\n")
        f.write("| Type | Count | Files | Commits |\n")
        f.write("|------|-------|-------|----------|\n")
        for secret_type, type_secrets in sorted(by_type.items(), key=lambda x: -len(x[1])):
            type_files = set()
            type_commits = set()
            for s in type_secrets:
                type_files.update(s.files)
                type_commits.update(s.commits)
            f.write(f"| {secret_type} | {len(type_secrets)} | {len(type_files)} | {len(type_commits)} |\n")
        f.write("\n")
        
        f.write("## Files with Most Secrets\n\n")
        sorted_files = sorted(by_file.items(), key=lambda x: -len(x[1]))[:20]
        f.write("| File | Secrets Count | Secret Types |\n")
        f.write("|------|--------------|---------------|\n")
        for file_path, file_secrets in sorted_files:
            types = set(s.secret_type for s in file_secrets)
            f.write(f"| `{file_path}` | {len(file_secrets)} | {', '.join(types)} |\n")
        f.write("\n")
        
        f.write("## Detailed Secret Listing\n\n")
        for i, secret in enumerate(secrets, 1):
            # Mask the secret for display
            if len(secret.value) > 40:
                masked = secret.value[:10] + "..." + secret.value[-10:]
            else:
                masked = secret.value[:5] + "*" * (len(secret.value) - 10) + secret.value[-5:] if len(secret.value) > 10 else "***"
            
            f.write(f"### {i}. {secret.secret_type}\n\n")
            f.write(f"- **Severity:** {secret.severity}\n")
            f.write(f"- **Value (masked):** `{masked}`\n")
            f.write(f"- **Suggested Env Var:** `{secret.suggested_env_var}`\n")
            f.write(f"- **Replacement:** `{secret.replacement}`\n")
            f.write(f"- **Files ({len(secret.files)}):**\n")
            for file in secret.files[:5]:
                f.write(f"  - `{file}`\n")
            if len(secret.files) > 5:
                f.write(f"  - ... and {len(secret.files) - 5} more\n")
            f.write(f"- **Commits ({len(secret.commits)}):**\n")
            for commit in secret.commits[:5]:
                f.write(f"  - `{commit}`\n")
            if len(secret.commits) > 5:
                f.write(f"  - ... and {len(secret.commits) - 5} more\n")
            f.write("\n")
        
        f.write("---\n")
        f.write("*This report was generated by DeployGuard. Review carefully before proceeding with cleanup.*\n")
