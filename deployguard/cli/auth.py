"""
DeployGuard CLI - Authentication commands
"""
import click
from deployguard.utils.config import ConfigManager


@click.group()
@click.pass_context
def auth(ctx):
    """Manage authentication credentials"""
    pass


@auth.command()
@click.option('--github-token', help='GitHub Personal Access Token')
@click.option('--bitbucket-username', help='BitBucket username/email')
@click.option('--bitbucket-password', help='BitBucket App Password')
@click.pass_context
def configure(ctx, github_token, bitbucket_username, bitbucket_password):
    """Configure platform credentials"""
    config: ConfigManager = ctx.obj['config']
    
    updates = {}
    if github_token:
        updates['github_token'] = github_token
        click.echo("✅ GitHub token configured")
    
    if bitbucket_username:
        updates['bitbucket_username'] = bitbucket_username
        click.echo("✅ BitBucket username configured")
    
    if bitbucket_password:
        updates['bitbucket_app_password'] = bitbucket_password
        click.echo("✅ BitBucket App Password configured")
    
    if not updates:
        click.echo("❌ No credentials provided. Use --help for options.")
        return
    
    config.update(**updates)
    click.echo(f"\n💾 Configuration saved to: {config.config_path}")


@auth.command()
@click.pass_context
def status(ctx):
    """Check authentication status"""
    config: ConfigManager = ctx.obj['config']
    
    click.echo("🔐 Authentication Status\n")
    
    # GitHub
    if config.has_github_auth():
        token = config.get_github_token()
        masked = f"{token[:7]}...{token[-4:]}" if token else "N/A"
        click.echo(f"✅ GitHub: Authenticated ({masked})")
    else:
        click.echo("❌ GitHub: Not authenticated")
    
    # BitBucket
    if config.has_bitbucket_auth():
        username, _ = config.get_bitbucket_credentials()
        click.echo(f"✅ BitBucket: Authenticated ({username})")
    else:
        click.echo("❌ BitBucket: Not authenticated")
    
    click.echo(f"\n📁 Config file: {config.config_path}")


@auth.command()
@click.confirmation_option(prompt='Are you sure you want to clear all credentials?')
@click.pass_context
def clear(ctx):
    """Clear all stored credentials"""
    config: ConfigManager = ctx.obj['config']
    config.clear()
    click.echo("✅ All credentials cleared")


@auth.command()
@click.pass_context
def show(ctx):
    """Show current configuration (sanitized)"""
    config: ConfigManager = ctx.obj['config']
    cfg = config.load()
    
    click.echo("⚙️  Current Configuration\n")
    click.echo(f"GitHub Token: {'***' if cfg.github_token else 'Not set'}")
    click.echo(f"BitBucket Username: {cfg.bitbucket_username or 'Not set'}")
    click.echo(f"BitBucket Password: {'***' if cfg.bitbucket_app_password else 'Not set'}")
    click.echo(f"Output Directory: {cfg.default_output_dir}")
    click.echo(f"Report Format: {cfg.default_report_format}")
    click.echo(f"Scan Git History: {cfg.scan_git_history}")
    click.echo(f"Auto Cleanup: {cfg.auto_cleanup}")
    click.echo(f"Max File Size: {cfg.max_file_size_mb}MB")
