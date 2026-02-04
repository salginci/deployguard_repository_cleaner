"""CLI command for verifying detected secrets."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import click

from deployguard.core.scanner import SecretScanner
from deployguard.core.verifier import SecretVerifier, VerificationStatus


@click.command("verify")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json", "table"]),
    default="table",
    help="Output format"
)
@click.option(
    "--only-active", "-a",
    is_flag=True,
    help="Only show verified active secrets"
)
@click.option(
    "--only-inactive", "-i",
    is_flag=True,
    help="Only show verified inactive secrets"
)
@click.option(
    "--timeout", "-t",
    type=int,
    default=10,
    help="Request timeout in seconds"
)
@click.option(
    "--concurrent", "-c",
    type=int,
    default=5,
    help="Maximum concurrent verification requests"
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Custom pattern configuration file"
)
@click.pass_context
def verify_cmd(
    ctx,
    path: str,
    output: str,
    only_active: bool,
    only_inactive: bool,
    timeout: int,
    concurrent: int,
    config: Optional[str]
):
    """
    Verify if detected secrets are active by testing against APIs.
    
    This command scans for secrets and then attempts to verify each one
    by making API calls to the respective services.
    
    \b
    Examples:
      deployguard verify                    # Verify secrets in current directory
      deployguard verify ./src --only-active  # Show only active secrets
      deployguard verify -o json            # Output as JSON
      deployguard verify -t 30 -c 10        # Custom timeout and concurrency
    
    \b
    Verification Status:
      ✓ VERIFIED_ACTIVE    - Secret is valid and working
      ✗ VERIFIED_INACTIVE  - Secret is invalid/revoked
      ? UNVERIFIED         - Could not verify (unsupported type)
      ! ERROR              - Verification failed due to error
      ⏱ RATE_LIMITED       - API rate limit hit during verification
    """
    # Initialize scanner
    scanner = SecretScanner(config_path=config)
    
    # Scan for secrets
    click.echo(f"🔍 Scanning {path} for secrets...")
    findings = scanner.scan_directory(Path(path))
    
    if not findings:
        click.echo("✅ No secrets found to verify.")
        return
    
    click.echo(f"📋 Found {len(findings)} potential secrets. Verifying...\n")
    
    # Verify findings
    async def run_verification():
        verifier = SecretVerifier(timeout=timeout, max_concurrent=concurrent)
        return await verifier.verify_findings(findings)
    
    results = asyncio.run(run_verification())
    
    # Filter results if requested
    if only_active:
        results = [r for r in results if r.status == VerificationStatus.VERIFIED_ACTIVE]
    elif only_inactive:
        results = [r for r in results if r.status == VerificationStatus.VERIFIED_INACTIVE]
    
    # Output results
    if output == "json":
        _output_json(results)
    elif output == "table":
        _output_table(results)
    else:
        _output_text(results)
    
    # Summary
    _print_summary(results)
    
    # Exit with error code if active secrets found
    active_count = sum(1 for r in results if r.status == VerificationStatus.VERIFIED_ACTIVE)
    if active_count > 0:
        ctx.exit(1)


def _output_json(results):
    """Output results as JSON."""
    output = []
    for r in results:
        output.append({
            "file": r.finding.file_path,
            "line": r.finding.line_number,
            "secret_type": str(r.finding.secret_type.value) if hasattr(r.finding.secret_type, 'value') else str(r.finding.secret_type),
            "status": r.status.value,
            "message": r.message,
            "details": r.details,
            "verified_at": r.verified_at.isoformat() if r.verified_at else None,
            "value_preview": _mask_secret(r.finding.value)
        })
    click.echo(json.dumps(output, indent=2))


def _output_table(results):
    """Output results as a formatted table."""
    # Status icons
    status_icons = {
        VerificationStatus.VERIFIED_ACTIVE: click.style("✓ ACTIVE", fg="red", bold=True),
        VerificationStatus.VERIFIED_INACTIVE: click.style("✗ INACTIVE", fg="green"),
        VerificationStatus.UNVERIFIED: click.style("? UNVERIFIED", fg="yellow"),
        VerificationStatus.ERROR: click.style("! ERROR", fg="red"),
        VerificationStatus.RATE_LIMITED: click.style("⏱ RATE LIMITED", fg="yellow"),
    }
    
    for r in results:
        secret_type = str(r.finding.secret_type.value) if hasattr(r.finding.secret_type, 'value') else str(r.finding.secret_type)
        
        click.echo("─" * 70)
        click.echo(f"📁 {click.style(r.finding.file_path, fg='cyan')}:{r.finding.line_number}")
        click.echo(f"   Type: {click.style(secret_type, fg='magenta')}")
        click.echo(f"   Value: {_mask_secret(r.finding.value)}")
        click.echo(f"   Status: {status_icons.get(r.status, r.status.value)}")
        click.echo(f"   Message: {r.message}")
        if r.details:
            click.echo(f"   Details: {json.dumps(r.details)}")
    
    click.echo("─" * 70)


def _output_text(results):
    """Output results as plain text."""
    for r in results:
        secret_type = str(r.finding.secret_type.value) if hasattr(r.finding.secret_type, 'value') else str(r.finding.secret_type)
        click.echo(f"{r.finding.file_path}:{r.finding.line_number} [{secret_type}] - {r.status.value}: {r.message}")


def _mask_secret(value: str) -> str:
    """Mask a secret value for display."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _print_summary(results):
    """Print verification summary."""
    total = len(results)
    active = sum(1 for r in results if r.status == VerificationStatus.VERIFIED_ACTIVE)
    inactive = sum(1 for r in results if r.status == VerificationStatus.VERIFIED_INACTIVE)
    unverified = sum(1 for r in results if r.status == VerificationStatus.UNVERIFIED)
    errors = sum(1 for r in results if r.status == VerificationStatus.ERROR)
    rate_limited = sum(1 for r in results if r.status == VerificationStatus.RATE_LIMITED)
    
    click.echo("\n📊 Verification Summary:")
    click.echo(f"   Total secrets found: {total}")
    
    if active > 0:
        click.echo(click.style(f"   ⚠️  ACTIVE (valid): {active}", fg="red", bold=True))
    else:
        click.echo(click.style(f"   ✓  Active (valid): {active}", fg="green"))
    
    click.echo(click.style(f"   ✗  Inactive (revoked): {inactive}", fg="green"))
    click.echo(f"   ?  Unverified: {unverified}")
    
    if errors > 0:
        click.echo(click.style(f"   !  Errors: {errors}", fg="yellow"))
    
    if rate_limited > 0:
        click.echo(click.style(f"   ⏱  Rate limited: {rate_limited}", fg="yellow"))
    
    if active > 0:
        click.echo(click.style(
            f"\n🚨 CRITICAL: {active} active secret(s) detected! Rotate these immediately!",
            fg="red", bold=True
        ))
