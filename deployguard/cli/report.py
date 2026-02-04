"""
DeployGuard CLI - Report commands
"""
import click
from pathlib import Path
import json
from datetime import datetime


@click.group()
@click.pass_context
def report(ctx):
    """Manage and view scan reports"""
    pass


@report.command()
@click.argument('report_file', type=click.Path(exists=True))
@click.option('--severity', type=click.Choice(['all', 'critical', 'high', 'medium', 'low']), default='all', help='Filter by severity')
@click.option('--type', help='Filter by secret type (e.g., AWS_ACCESS_KEY)')
@click.pass_context
def show(ctx, report_file, severity, type):
    """Display a saved report"""
    report_path = Path(report_file)
    
    if report_path.suffix == '.json':
        _show_json_report(report_path, severity, type)
    else:
        # Text report
        with open(report_path, 'r') as f:
            click.echo(f.read())


@report.command()
@click.argument('report_file', type=click.Path(exists=True))
@click.pass_context
def stats(ctx, report_file):
    """Show statistics from a report"""
    report_path = Path(report_file)
    
    if report_path.suffix != '.json':
        click.echo("❌ Stats only available for JSON reports")
        return
    
    with open(report_path, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    
    click.echo("📊 Report Statistics")
    click.echo("=" * 60)
    click.echo(f"Scan ID: {data.get('scan_id')}")
    click.echo(f"Scan Date: {data.get('started_at')}")
    click.echo(f"Files Scanned: {data.get('files_scanned', 0)}")
    click.echo(f"Total Findings: {len(findings)}")
    click.echo(f"Duration: {data.get('duration_seconds', 0):.2f}s")
    
    # By severity
    click.echo("\nBy Severity:")
    severity_counts = {}
    for finding in findings:
        severity = finding['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            click.echo(f"  {severity}: {count}")
    
    # By type
    click.echo("\nBy Secret Type:")
    type_counts = {}
    for finding in findings:
        secret_type = finding['secret_type']
        type_counts[secret_type] = type_counts.get(secret_type, 0) + 1
    
    for secret_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        click.echo(f"  {secret_type}: {count}")
    
    # Files with most secrets
    click.echo("\nFiles with Most Secrets:")
    file_counts = {}
    for finding in findings:
        file_path = finding['file_path']
        file_counts[file_path] = file_counts.get(file_path, 0) + 1
    
    for file_path, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        click.echo(f"  {file_path}: {count}")


@report.command()
@click.argument('input_report', type=click.Path(exists=True))
@click.argument('output_format', type=click.Choice(['json', 'csv', 'text', 'html']))
@click.option('--output', '-o', help='Output file path (default: auto-generated)')
@click.pass_context
def convert(ctx, input_report, output_format, output):
    """Convert report to different format"""
    input_path = Path(input_report)
    
    # Determine output path
    if not output:
        output = str(input_path.with_suffix(f'.{output_format}'))
    
    click.echo(f"Converting {input_path} → {output}")
    
    # Load input
    if input_path.suffix == '.json':
        with open(input_path, 'r') as f:
            data = json.load(f)
    else:
        click.echo("❌ Can only convert from JSON reports")
        return
    
    # Convert
    if output_format == 'csv':
        _convert_to_csv(data, output)
    elif output_format == 'text':
        _convert_to_text(data, output)
    elif output_format == 'html':
        _convert_to_html(data, output)
    else:
        click.echo(f"❌ Format {output_format} not implemented yet")
        return
    
    click.echo(f"✅ Report converted to: {output}")


def _show_json_report(report_path, severity_filter, type_filter):
    """Display JSON report with filters"""
    with open(report_path, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    
    # Apply filters
    if severity_filter != 'all':
        severity_map = {
            'critical': ['CRITICAL'],
            'high': ['CRITICAL', 'HIGH'],
            'medium': ['CRITICAL', 'HIGH', 'MEDIUM'],
            'low': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        }
        allowed = severity_map.get(severity_filter, [])
        findings = [f for f in findings if f['severity'] in allowed]
    
    if type_filter:
        findings = [f for f in findings if f['secret_type'] == type_filter]
    
    # Display
    click.echo(f"📄 Report: {data.get('scan_id')}")
    click.echo(f"Date: {data.get('started_at')}")
    click.echo(f"Findings: {len(findings)}/{data.get('total_findings', 0)}")
    click.echo("=" * 60)
    
    for finding in findings:
        click.echo(f"\n{finding['secret_type']} ({finding['severity']})")
        click.echo(f"  File: {finding['file_path']}:{finding['line_number']}")
        click.echo(f"  Value: {finding['masked_value']}")
        if finding.get('suggested_variable'):
            click.echo(f"  Variable: {finding['suggested_variable']}")


def _convert_to_csv(data, output_path):
    """Convert JSON report to CSV"""
    import csv
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Secret Type', 'Severity', 'File', 'Line', 'Masked Value', 'Suggested Variable'])
        for finding in data.get('findings', []):
            writer.writerow([
                finding['secret_type'],
                finding['severity'],
                finding['file_path'],
                finding['line_number'],
                finding['masked_value'],
                finding.get('suggested_variable', '')
            ])


def _convert_to_text(data, output_path):
    """Convert JSON report to text"""
    with open(output_path, 'w') as f:
        f.write(f"DeployGuard Security Scan Report\n")
        f.write(f"=" * 60 + "\n")
        f.write(f"Scan ID: {data.get('scan_id')}\n")
        f.write(f"Started: {data.get('started_at')}\n")
        f.write(f"Files Scanned: {data.get('files_scanned', 0)}\n")
        f.write(f"Total Findings: {data.get('total_findings', 0)}\n\n")
        
        for finding in data.get('findings', []):
            f.write(f"Secret Type: {finding['secret_type']}\n")
            f.write(f"Severity: {finding['severity']}\n")
            f.write(f"File: {finding['file_path']}:{finding['line_number']}\n")
            f.write(f"Masked Value: {finding['masked_value']}\n")
            if finding.get('suggested_variable'):
                f.write(f"Suggested Variable: {finding['suggested_variable']}\n")
            f.write(f"\n{'-' * 60}\n\n")


def _convert_to_html(data, output_path):
    """Convert JSON report to HTML"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DeployGuard Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .finding {{ border-left: 4px solid #ccc; padding: 10px; margin: 10px 0; }}
        .critical {{ border-color: #d32f2f; }}
        .high {{ border-color: #f57c00; }}
        .medium {{ border-color: #fbc02d; }}
        .low {{ border-color: #689f38; }}
        .severity {{ font-weight: bold; padding: 2px 8px; border-radius: 3px; color: white; }}
        .severity.critical {{ background: #d32f2f; }}
        .severity.high {{ background: #f57c00; }}
        .severity.medium {{ background: #fbc02d; color: #333; }}
        .severity.low {{ background: #689f38; }}
    </style>
</head>
<body>
    <h1>🛡️ DeployGuard Security Report</h1>
    <div class="summary">
        <p><strong>Scan ID:</strong> {data.get('scan_id')}</p>
        <p><strong>Date:</strong> {data.get('started_at')}</p>
        <p><strong>Files Scanned:</strong> {data.get('files_scanned', 0)}</p>
        <p><strong>Total Findings:</strong> {data.get('total_findings', 0)}</p>
    </div>
    <h2>Findings</h2>
"""
    
    for finding in data.get('findings', []):
        severity_class = finding['severity'].lower()
        html += f"""
    <div class="finding {severity_class}">
        <p><strong>{finding['secret_type']}</strong> <span class="severity {severity_class}">{finding['severity']}</span></p>
        <p><strong>File:</strong> {finding['file_path']}:{finding['line_number']}</p>
        <p><strong>Value:</strong> <code>{finding['masked_value']}</code></p>
"""
        if finding.get('suggested_variable'):
            html += f"        <p><strong>Suggested Variable:</strong> {finding['suggested_variable']}</p>\n"
        html += "    </div>\n"
    
    html += """
</body>
</html>
"""
    
    with open(output_path, 'w') as f:
        f.write(html)
