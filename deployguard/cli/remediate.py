"""
DeployGuard CLI - Remediate Command

Provides commands for automatically fixing hardcoded secrets by:
1. Creating .env files with actual values
2. Replacing hardcoded values with environment variable references
"""
import os
import json
import click
from pathlib import Path
from typing import Optional, List, Dict

from deployguard.core.scanner import SecretScanner
from deployguard.core.remediator import CodeRemediator, RemediationResult, format_remediation_preview
from deployguard.core.models import Finding


@click.group()
def remediate():
    """🔧 Automatically fix hardcoded secrets in code."""
    pass


@remediate.command("auto")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to repository to remediate"
)
@click.option(
    "--findings-file", "-f",
    type=click.Path(exists=True),
    help="Path to findings.json file (from 'scan local --output')"
)
@click.option(
    "--env-file", "-e",
    type=click.Path(),
    default=".env",
    help="Path for the generated .env file"
)
@click.option(
    "--min-severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="high",
    help="Minimum severity to remediate"
)
@click.option(
    "--dry-run/--execute",
    default=True,
    help="Preview changes without modifying files"
)
@click.option(
    "--interactive/--batch",
    default=True,
    help="Select which findings to remediate interactively"
)
@click.pass_context
def remediate_auto(ctx, path: str, findings_file: Optional[str], env_file: str,
                   min_severity: str, dry_run: bool, interactive: bool):
    """
    Automatically replace hardcoded secrets with environment variables.
    
    This command will:
    1. Scan for secrets (or use existing findings.json)
    2. Show what changes will be made
    3. Create a .env file with the actual secret values
    4. Replace hardcoded values in code with env var references
    
    The replacement syntax is language-aware:
    - Bash: ${VAR_NAME}
    - Python: os.environ.get('VAR_NAME')
    - JavaScript: process.env.VAR_NAME
    - Java: System.getenv("VAR_NAME")
    - And more...
    
    Examples:
        # Preview changes (dry run)
        deployguard remediate auto --path ./myrepo --dry-run
        
        # Actually make changes
        deployguard remediate auto --path ./myrepo --execute
        
        # Use existing findings file
        deployguard remediate auto --path ./myrepo -f findings.json --execute
        
        # Interactive selection
        deployguard remediate auto --path ./myrepo --interactive --execute
    """
    click.echo("\n🔧 DeployGuard Code Remediation")
    click.echo("=" * 60)
    
    findings_list = []
    
    # Load findings from file or scan
    if findings_file:
        click.echo(f"📄 Loading findings from: {findings_file}")
        try:
            with open(findings_file, 'r') as f:
                data = json.load(f)
                findings_list = data.get('findings', [])
            click.echo(f"   Loaded {len(findings_list)} findings")
        except Exception as e:
            click.echo(f"❌ Error loading findings file: {e}", err=True)
            ctx.exit(1)
    else:
        click.echo(f"🔍 Scanning for secrets in: {path}")
        try:
            # Use the scanner
            default_patterns = Path(__file__).parent.parent.parent / "config" / "secret_patterns.yaml"
            scanner = SecretScanner(patterns_file=str(default_patterns) if default_patterns.exists() else None)
            
            results = scanner.scan_directory(path)
            
            # Convert findings to list format
            for file_path, findings in results.items():
                for f in findings:
                    findings_list.append({
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "type": f.type.value,
                        "severity": f.severity.value,
                        "variable_name": f.metadata.get("variable_name") or f.suggested_variable,
                        "actual_value": f.metadata.get("actual_value") or f.exposed_value,
                        "full_match": f.exposed_value,
                        "suggested_env_var": f.suggested_variable,
                        "description": f.description,
                    })
            
            click.echo(f"   Found {len(findings_list)} findings")
        except Exception as e:
            click.echo(f"❌ Error scanning: {e}", err=True)
            ctx.exit(1)
    
    if not findings_list:
        click.echo("\n✅ No findings to remediate!")
        ctx.exit(0)
    
    # Filter by severity
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_level = severity_order[min_severity]
    
    filtered_findings = [
        f for f in findings_list
        if severity_order.get(f.get('severity', 'low'), 0) >= min_level
    ]
    
    click.echo(f"\n📋 Findings to remediate: {len(filtered_findings)}")
    
    # Display findings
    click.echo("\n" + "-" * 60)
    for i, finding in enumerate(filtered_findings, 1):
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
        emoji = severity_emoji.get(finding.get('severity', 'medium'), "⚪")
        
        var_name = finding.get('variable_name') or finding.get('suggested_env_var', '-')
        value = finding.get('actual_value', '')
        display_value = value[:30] + "..." if len(value) > 30 else value
        
        click.echo(f"\n{i}. {emoji} {finding.get('type', 'unknown')}")
        click.echo(f"   📄 File: {finding['file_path']}:{finding['line_number']}")
        click.echo(f"   🏷️  Variable: {var_name}")
        click.echo(f"   🔑 Value: {display_value}")
    
    # Interactive selection
    selected_findings = filtered_findings
    if interactive and len(filtered_findings) > 0:
        click.echo("\n" + "=" * 60)
        click.echo("🎯 SELECT FINDINGS TO REMEDIATE")
        click.echo("=" * 60)
        
        selected_findings = []
        for i, finding in enumerate(filtered_findings, 1):
            var_name = finding.get('variable_name') or finding.get('suggested_env_var', 'SECRET')
            value = finding.get('actual_value', '')[:30]
            
            click.echo(f"\n{i}. {finding['file_path']}:{finding['line_number']}")
            click.echo(f"   Variable: {var_name} = \"{value}...\"")
            
            if click.confirm(f"   Remediate this finding?", default=True):
                # Allow user to change variable name
                new_name = click.prompt(
                    f"   Environment variable name",
                    default=var_name,
                    show_default=True
                )
                finding['variable_name'] = new_name
                selected_findings.append(finding)
        
        click.echo(f"\n✅ Selected {len(selected_findings)} findings to remediate")
    
    if not selected_findings:
        click.echo("\n⚠️  No findings selected for remediation")
        ctx.exit(0)
    
    # Create remediator
    remediator = CodeRemediator(dry_run=dry_run)
    
    # Perform remediation
    env_path = os.path.join(path, env_file) if not os.path.isabs(env_file) else env_file
    
    result = remediator.remediate_findings(
        findings=selected_findings,
        base_path=path,
        env_file_path=env_path,
    )
    
    # Show preview
    click.echo(format_remediation_preview(result))
    
    if dry_run:
        click.echo("\n" + "=" * 60)
        click.echo("🔍 DRY RUN - No changes made")
        click.echo("=" * 60)
        click.echo("\nTo apply changes, run with --execute flag:")
        click.echo(f"   deployguard remediate auto --path {path} --execute")
    else:
        click.echo("\n" + "=" * 60)
        click.echo("✅ REMEDIATION COMPLETE")
        click.echo("=" * 60)
        click.echo(f"\n📄 Environment file created: {result.env_file_path}")
        click.echo(f"📝 Files modified: {result.files_modified}")
        click.echo(f"🔄 Replacements made: {result.replacements_made}")
        
        if result.errors:
            click.echo(f"\n⚠️  Errors: {len(result.errors)}")
            for error in result.errors:
                click.echo(f"   - {error}")
        
        click.echo("\n" + "-" * 60)
        click.echo("NEXT STEPS:")
        click.echo("-" * 60)
        click.echo(f"1. Review the changes in your code")
        click.echo(f"2. Add {env_file} to .gitignore (if not already)")
        click.echo(f"3. Commit the code changes (NOT the .env file)")
        click.echo(f"4. Set up environment variables in your deployment")
    
    ctx.exit(0 if not result.errors else 1)


@remediate.command("preview")
@click.option(
    "--path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Path to repository"
)
@click.option(
    "--file", "-f",
    type=click.Path(exists=True),
    required=True,
    help="Specific file to show preview for"
)
@click.option(
    "--line", "-l",
    type=int,
    required=True,
    help="Line number of the finding"
)
@click.option(
    "--var-name", "-v",
    required=True,
    help="Environment variable name to use"
)
@click.pass_context
def preview_replacement(ctx, path: str, file: str, line: int, var_name: str):
    """
    Preview how a specific line would be replaced.
    
    Shows the language-specific replacement that would be made.
    
    Examples:
        deployguard remediate preview -p ./repo -f script.sh -l 5 -v DB_PASSWORD
        deployguard remediate preview -p ./repo -f app.py -l 10 -v API_KEY
    """
    from deployguard.core.remediator import CodeRemediator, Language
    
    file_path = os.path.join(path, file) if not os.path.isabs(file) else file
    
    if not os.path.exists(file_path):
        click.echo(f"❌ File not found: {file_path}", err=True)
        ctx.exit(1)
    
    remediator = CodeRemediator(dry_run=True)
    language = remediator.detect_language(file_path)
    
    # Read the line
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        if line < 1 or line > len(lines):
            click.echo(f"❌ Line {line} out of range (file has {len(lines)} lines)", err=True)
            ctx.exit(1)
        
        original_line = lines[line - 1].rstrip('\n')
        new_line, import_needed = remediator.get_env_var_syntax_for_assignment(
            language, var_name, original_line
        )
        
        click.echo(f"\n📄 File: {file_path}")
        click.echo(f"🔤 Language: {language.value}")
        click.echo(f"📍 Line: {line}")
        click.echo(f"\n" + "-" * 60)
        click.echo(f"Before: {original_line}")
        click.echo(f"After:  {new_line.rstrip()}")
        click.echo("-" * 60)
        
        if import_needed:
            click.echo(f"\n⚠️  Note: You may need to add this import:")
            click.echo(f"   {import_needed}")
        
        click.echo(f"\n📦 .env entry:")
        click.echo(f'   {var_name}="<your_secret_value>"')
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        ctx.exit(1)


@remediate.command("from-json")
@click.option(
    "--findings", "-f",
    type=click.Path(exists=True),
    required=True,
    help="Path to findings.json file"
)
@click.option(
    "--base-path", "-p",
    type=click.Path(exists=True),
    required=True,
    help="Base path for file paths in findings"
)
@click.option(
    "--env-file", "-e",
    type=click.Path(),
    default=".env",
    help="Path for the generated .env file"
)
@click.option(
    "--ids",
    help="Comma-separated list of finding IDs to remediate (e.g., '1,2,3')"
)
@click.option(
    "--dry-run/--execute",
    default=True,
    help="Preview changes without modifying files"
)
@click.pass_context
def remediate_from_json(ctx, findings: str, base_path: str, env_file: str,
                        ids: Optional[str], dry_run: bool):
    """
    Remediate findings from a JSON file.
    
    Use the findings.json exported from 'deployguard scan local --output'.
    
    Examples:
        # Preview all findings
        deployguard remediate from-json -f findings.json -p ./repo --dry-run
        
        # Remediate specific findings by ID
        deployguard remediate from-json -f findings.json -p ./repo --ids 1,2,3 --execute
    """
    click.echo("\n🔧 Remediating from JSON")
    click.echo("=" * 60)
    
    # Load findings
    try:
        with open(findings, 'r') as f:
            data = json.load(f)
            findings_list = data.get('findings', [])
    except Exception as e:
        click.echo(f"❌ Error loading findings: {e}", err=True)
        ctx.exit(1)
    
    click.echo(f"📄 Loaded {len(findings_list)} findings from {findings}")
    
    # Filter by IDs if specified
    if ids:
        selected_ids = set(int(i.strip()) for i in ids.split(','))
        findings_list = [f for f in findings_list if f.get('id') in selected_ids]
        click.echo(f"   Selected {len(findings_list)} findings by ID")
    
    if not findings_list:
        click.echo("\n⚠️  No findings to remediate")
        ctx.exit(0)
    
    # Display selected findings
    for finding in findings_list:
        var_name = finding.get('variable_name') or finding.get('suggested_env_var', '-')
        click.echo(f"\n   [{finding.get('id', '?')}] {finding['file_path']}:{finding['line_number']}")
        click.echo(f"       {var_name} = \"{finding.get('actual_value', '')[:30]}...\"")
    
    # Remediate
    remediator = CodeRemediator(dry_run=dry_run)
    env_path = os.path.join(base_path, env_file) if not os.path.isabs(env_file) else env_file
    
    result = remediator.remediate_findings(
        findings=findings_list,
        base_path=base_path,
        env_file_path=env_path,
    )
    
    # Show results
    click.echo(format_remediation_preview(result))
    
    if dry_run:
        click.echo("\n🔍 DRY RUN - No changes made. Use --execute to apply.")
    else:
        click.echo(f"\n✅ Remediation complete!")
        click.echo(f"   Created: {result.env_file_path}")
        click.echo(f"   Modified: {result.files_modified} files")
    
    ctx.exit(0)
